//! Privileged helper for Ashy Pass drive operations.
//!
//! Lifecycle: launched once via `pkexec` (single polkit prompt), then reads
//! requests from stdin as newline-delimited JSON and writes responses to
//! stdout. Stays alive for the duration of one encryption session, so a
//! whole `format` pipeline (wipe + luksFormat + open + mkfs + close) runs
//! under a single authentication.
//!
//! ## Request/Response protocol (JSON Lines)
//!
//! Request lines look like:
//! ```json
//! {"op":"luks-format","device":"/dev/sda","label":"vault","allow_discards":false,"passphrase_b64":"..."}
//! {"op":"wipe","device":"/dev/sda","mode":"encrypted-zero"}
//! {"op":"mkfs","mapped":"/dev/mapper/ashypass_vault","fs":"ext4","label":"vault"}
//! {"op":"close","mapper":"ashypass_vault"}
//! {"op":"shutdown"}
//! ```
//!
//! Each request produces one or more response lines:
//! ```json
//! {"progress":{"copied":1048576,"total":7516192768}}
//! {"ok":true}
//! {"error":"…"}
//! ```
//!
//! Passphrases are transmitted base64-encoded so newlines and shell-special
//! bytes in user input never collide with the line-based protocol.

use ashypass_drives::{
    fs::{mkfs, Filesystem},
    luks::{luks_close, luks_format, luks_open, FormatOptions},
    passphrase::Passphrase,
    runner::PlainRunner,
    wipe::{wipe_with_progress, WipeMode},
};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
enum Request {
    LuksFormat {
        device: PathBuf,
        label: String,
        #[serde(default)]
        allow_discards: bool,
        /// Base64-encoded passphrase (binary-safe over the JSON line protocol).
        passphrase_b64: String,
    },
    LuksOpen {
        device: PathBuf,
        mapper_name: String,
        passphrase_b64: String,
        #[serde(default)]
        allow_discards: bool,
    },
    LuksClose {
        mapper_name: String,
    },
    Wipe {
        device: PathBuf,
        mode: WipeModeReq,
    },
    Mkfs {
        mapped: PathBuf,
        fs: FsReq,
        label: String,
    },
    Shutdown,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum WipeModeReq {
    EncryptedZero,
    SecureDiscard,
    Random,
    None,
}
impl From<WipeModeReq> for WipeMode {
    fn from(m: WipeModeReq) -> Self {
        match m {
            WipeModeReq::EncryptedZero => WipeMode::EncryptedZero,
            WipeModeReq::SecureDiscard => WipeMode::SecureDiscard,
            WipeModeReq::Random => WipeMode::Random,
            WipeModeReq::None => WipeMode::None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum FsReq {
    Ext4,
    Btrfs,
    Xfs,
}
impl From<FsReq> for Filesystem {
    fn from(f: FsReq) -> Self {
        match f {
            FsReq::Ext4 => Filesystem::Ext4,
            FsReq::Btrfs => Filesystem::Btrfs,
            FsReq::Xfs => Filesystem::Xfs,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum Response {
    Ok { ok: bool },
    Error { error: String },
    Progress { progress: ProgressPayload },
}

#[derive(Debug, Serialize)]
struct ProgressPayload {
    copied: u64,
    total: u64,
}

fn main() {
    // We're invoked as root via pkexec. Bail loudly if not — running as a
    // regular user would silently fail at the first `cryptsetup`.
    if unsafe { libc_geteuid() } != 0 {
        eprintln!("ashypass-drives-helper: must run as root (via pkexec)");
        std::process::exit(2);
    }

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    let runner = PlainRunner;

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                write_response(&mut stdout, Response::Error { error: format!("stdin: {e}") });
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                write_response(&mut stdout, Response::Error { error: format!("parse: {e}") });
                continue;
            }
        };

        let res = handle(&runner, req, &mut stdout);
        write_response(&mut stdout, res);
    }
}

fn handle(
    runner: &PlainRunner,
    req: Request,
    stdout: &mut std::io::StdoutLock<'_>,
) -> Response {
    match req {
        Request::Shutdown => {
            std::process::exit(0);
        }
        Request::LuksFormat {
            device,
            label,
            allow_discards,
            passphrase_b64,
        } => {
            let pp = match decode_pp(&passphrase_b64) {
                Ok(p) => p,
                Err(e) => return Response::Error { error: e },
            };
            let opts = FormatOptions {
                label,
                subsystem: Some("ashypass".into()),
                allow_discards,
            };
            match luks_format(runner, &device, &pp, &opts) {
                Ok(()) => Response::Ok { ok: true },
                Err(e) => Response::Error { error: e.to_string() },
            }
        }
        Request::LuksOpen {
            device,
            mapper_name,
            passphrase_b64,
            allow_discards,
        } => {
            let pp = match decode_pp(&passphrase_b64) {
                Ok(p) => p,
                Err(e) => return Response::Error { error: e },
            };
            match luks_open(runner, &device, &mapper_name, &pp, allow_discards) {
                Ok(_) => Response::Ok { ok: true },
                Err(e) => Response::Error { error: e.to_string() },
            }
        }
        Request::LuksClose { mapper_name } => match luks_close(runner, &mapper_name) {
            Ok(()) => Response::Ok { ok: true },
            Err(e) => Response::Error { error: e.to_string() },
        },
        Request::Wipe { device, mode } => {
            let r = wipe_with_progress(runner, &device, mode.into(), &mut |copied| {
                // Use 0 as total when unknown — the GUI will fall back to
                // its own diskstats poller anyway. The point of emitting
                // here is so a non-GUI client (e.g. another CLI) can pipe
                // progress without poking /proc.
                write_response(
                    stdout,
                    Response::Progress {
                        progress: ProgressPayload { copied, total: 0 },
                    },
                );
            });
            match r {
                Ok(()) => Response::Ok { ok: true },
                Err(e) => Response::Error { error: e.to_string() },
            }
        }
        Request::Mkfs { mapped, fs, label } => match mkfs(runner, &mapped, fs.into(), &label) {
            Ok(()) => Response::Ok { ok: true },
            Err(e) => Response::Error { error: e.to_string() },
        },
    }
}

fn decode_pp(b64: &str) -> std::result::Result<Passphrase, String> {
    use base64_decode_minimal as b64dec;
    let bytes = b64dec::decode(b64).map_err(|e| format!("passphrase base64: {e}"))?;
    Ok(Passphrase::new(bytes))
}

fn write_response(out: &mut std::io::StdoutLock<'_>, r: Response) {
    let line = serde_json::to_string(&r).unwrap_or_else(|e| {
        format!(r#"{{"error":"serialise failed: {e}"}}"#)
    });
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

// Minimal, zero-dep base64 decoder so the helper has no extra crates.
// Standard base64 (RFC 4648); allows trailing `=` padding, ignores
// whitespace. Returns `Result<Vec<u8>, &'static str>`.
mod base64_decode_minimal {
    pub fn decode(input: &str) -> Result<Vec<u8>, &'static str> {
        let mut buf = Vec::with_capacity(input.len() / 4 * 3);
        let mut bits: u32 = 0;
        let mut nbits: u32 = 0;
        for &b in input.as_bytes() {
            if b == b'=' || b.is_ascii_whitespace() {
                continue;
            }
            let v: u32 = match b {
                b'A'..=b'Z' => (b - b'A') as u32,
                b'a'..=b'z' => (b - b'a' + 26) as u32,
                b'0'..=b'9' => (b - b'0' + 52) as u32,
                b'+' => 62,
                b'/' => 63,
                _ => return Err("invalid base64 byte"),
            };
            bits = (bits << 6) | v;
            nbits += 6;
            if nbits >= 8 {
                nbits -= 8;
                buf.push((bits >> nbits) as u8);
            }
        }
        Ok(buf)
    }
}

#[allow(non_snake_case)]
unsafe fn libc_geteuid() -> u32 {
    // We don't link libc directly to keep the helper small; the only thing
    // we need is geteuid(). Pull it via syscall(SYS_geteuid, ...).
    // SAFETY: SYS_geteuid is a parameterless syscall returning the EUID.
    const SYS_GETEUID: libc_min::c_long = 107; // x86_64 Linux
    libc_min::syscall(SYS_GETEUID) as u32
}

mod libc_min {
    #![allow(non_camel_case_types)]
    pub type c_long = i64;
    extern "C" {
        pub fn syscall(num: c_long, ...) -> c_long;
    }
}
