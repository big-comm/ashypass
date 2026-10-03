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
//! {"op":"luks-format","device":"/dev/disk/by-id/usb-…","label":"vault","allow_discards":false,"passphrase_b64":"...","expected":{"serial":"…","size_bytes":…,"model":"…"}}
//! {"op":"wipe","device":"/dev/disk/by-id/usb-…","mode":"encrypted-zero","expected":{…}}
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
//!
//! Destructive requests (`wipe`, `luks-format`) carry the identity (serial,
//! size, model) of the drive the user confirmed. The helper re-runs the
//! safety inspection on every such request and refuses if the device behind
//! the path is no longer that drive.

use ashypass_drives::{
    detect::{find_volume_owner, list_all},
    fs::{mkfs, Filesystem},
    luks::{luks_close, luks_format, luks_open, FormatOptions},
    passphrase::{Passphrase, SecretString},
    runner::PlainRunner,
    safety::{inspect, is_stable_link, resolve_by_id, DeviceIdentity, SafetyPolicy},
    validate,
    wipe::{wipe_with_progress, WipeMode},
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const MAX_REQUEST_BYTES: usize = 1024 * 1024;

#[derive(Default)]
struct SessionState {
    opened_mappers: HashSet<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
enum Request {
    LuksFormat {
        device: PathBuf,
        label: String,
        #[serde(default)]
        allow_discards: bool,
        /// Base64-encoded passphrase (binary-safe over the JSON line protocol).
        /// Redacted in `Debug`, wiped on drop.
        passphrase_b64: SecretString,
        /// Identity of the drive the user confirmed.
        expected: DeviceIdentity,
    },
    LuksOpen {
        device: PathBuf,
        mapper_name: String,
        passphrase_b64: SecretString,
        #[serde(default)]
        allow_discards: bool,
        #[serde(default)]
        expected: Option<DeviceIdentity>,
    },
    LuksClose {
        mapper_name: String,
    },
    Wipe {
        device: PathBuf,
        mode: WipeModeReq,
        expected: DeviceIdentity,
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
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("ashypass-drives-helper: must run as root (via pkexec)");
        std::process::exit(2);
    }

    std::env::set_var("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    let runner = PlainRunner;
    let mut state = SessionState::default();
    let mut input = stdin.lock();

    loop {
        let mut line = match read_request_line(&mut input) {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(e) => {
                write_response(
                    &mut stdout,
                    Response::Error {
                        error: format!("stdin: {e}"),
                    },
                );
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let parsed = serde_json::from_str::<Request>(&line);
        // The raw line may carry a base64 passphrase.
        line.zeroize();
        let req: Request = match parsed {
            Ok(r) => r,
            Err(e) => {
                write_response(
                    &mut stdout,
                    Response::Error {
                        error: format!("parse: {e}"),
                    },
                );
                continue;
            }
        };

        let res = handle(&runner, &mut state, req, &mut stdout);
        write_response(&mut stdout, res);
    }
    close_session_mappers(&runner, &mut state);
}

fn handle(
    runner: &PlainRunner,
    state: &mut SessionState,
    req: Request,
    stdout: &mut std::io::StdoutLock<'_>,
) -> Response {
    match req {
        Request::Shutdown => {
            close_session_mappers(runner, state);
            std::process::exit(0);
        }
        Request::LuksFormat {
            device,
            label,
            allow_discards,
            passphrase_b64,
            expected,
        } => {
            let device = match validate_destructive_device(&device, &expected) {
                Ok(device) => device,
                Err(error) => return Response::Error { error },
            };
            if let Err(error) = validate_label(&label) {
                return Response::Error { error };
            }
            let pp = match decode_pp(&passphrase_b64) {
                Ok(p) => p,
                Err(e) => return Response::Error { error: e },
            };
            if pp.is_empty() {
                return Response::Error {
                    error: "refusing empty passphrase".into(),
                };
            }
            let opts = FormatOptions {
                label,
                subsystem: Some("ashypass".into()),
                allow_discards,
            };
            match luks_format(runner, &device, &pp, &opts) {
                Ok(()) => Response::Ok { ok: true },
                Err(e) => Response::Error {
                    error: e.to_string(),
                },
            }
        }
        Request::LuksOpen {
            device,
            mapper_name,
            passphrase_b64,
            allow_discards,
            expected,
        } => {
            let device = match validate_luks_device(&device, expected.as_ref()) {
                Ok(device) => device,
                Err(error) => return Response::Error { error },
            };
            if let Err(error) = validate_mapper_name(&mapper_name) {
                return Response::Error { error };
            }
            let pp = match decode_pp(&passphrase_b64) {
                Ok(p) => p,
                Err(e) => return Response::Error { error: e },
            };
            match luks_open(runner, &device, &mapper_name, &pp, allow_discards) {
                Ok(_) => {
                    state.opened_mappers.insert(mapper_name);
                    Response::Ok { ok: true }
                }
                Err(e) => Response::Error {
                    error: e.to_string(),
                },
            }
        }
        Request::LuksClose { mapper_name } => {
            if !state.opened_mappers.contains(&mapper_name) {
                return Response::Error {
                    error: "refusing to close a mapper not opened by this session".into(),
                };
            }
            match luks_close(runner, &mapper_name) {
                Ok(()) => {
                    state.opened_mappers.remove(&mapper_name);
                    Response::Ok { ok: true }
                }
                Err(e) => Response::Error {
                    error: e.to_string(),
                },
            }
        }
        Request::Wipe {
            device,
            mode,
            expected,
        } => {
            let device = match validate_destructive_device(&device, &expected) {
                Ok(device) => device,
                Err(error) => return Response::Error { error },
            };
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
                Err(e) => Response::Error {
                    error: e.to_string(),
                },
            }
        }
        Request::Mkfs { mapped, fs, label } => {
            let Some(mapper_name) = mapped.file_name().and_then(|name| name.to_str()) else {
                return Response::Error {
                    error: "invalid mapper path".into(),
                };
            };
            let expected = PathBuf::from("/dev/mapper").join(mapper_name);
            if mapped != expected || !state.opened_mappers.contains(mapper_name) {
                return Response::Error {
                    error: "refusing to format a mapper not opened by this session".into(),
                };
            }
            let fs: Filesystem = fs.into();
            if let Err(error) = validate::validate_label_for_fs(&label, fs) {
                return Response::Error {
                    error: error.to_string(),
                };
            }
            match mkfs(runner, &mapped, fs, &label) {
                Ok(()) => Response::Ok { ok: true },
                Err(e) => Response::Error {
                    error: e.to_string(),
                },
            }
        }
    }
}

fn close_session_mappers(runner: &PlainRunner, state: &mut SessionState) {
    for mapper in std::mem::take(&mut state.opened_mappers) {
        if let Err(error) = luks_close(runner, &mapper) {
            eprintln!("ashypass-drives-helper: could not close {mapper}: {error}");
        }
    }
}

fn read_request_line(reader: &mut impl BufRead) -> std::io::Result<Option<String>> {
    let mut bytes = Vec::new();
    let read = {
        let mut limited = std::io::Read::take(&mut *reader, (MAX_REQUEST_BYTES + 1) as u64);
        limited.read_until(b'\n', &mut bytes)?
    };
    if read == 0 {
        return Ok(None);
    }
    if bytes.len() > MAX_REQUEST_BYTES {
        if !bytes.ends_with(b"\n") {
            let mut discarded = Vec::new();
            reader.read_until(b'\n', &mut discarded)?;
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "request exceeds 1 MiB",
        ));
    }
    if bytes.ends_with(b"\n") {
        bytes.pop();
        if bytes.ends_with(b"\r") {
            bytes.pop();
        }
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "request is not UTF-8"))
}

/// Re-inspect a whole-disk target right before a destructive step: it must
/// pass every safety guard **and** still be the drive the user confirmed.
fn validate_destructive_device(
    device: &Path,
    expected: &DeviceIdentity,
) -> std::result::Result<PathBuf, String> {
    let report = inspect(device, SafetyPolicy::default()).map_err(|error| error.to_string())?;
    report.assert_safe().map_err(|error| error.to_string())?;
    expected
        .verify(&report.identity())
        .map_err(|error| error.to_string())?;
    require_stable_device(report.canonical_path)
}

/// Validate the target of `luks-open`: a whole disk or partition of a
/// detected removable drive, addressed by its node or a `/dev/disk/` link.
fn validate_luks_device(
    device: &Path,
    expected: Option<&DeviceIdentity>,
) -> std::result::Result<PathBuf, String> {
    let node = std::fs::canonicalize(device)
        .map_err(|_| format!("device not found: {}", device.display()))?;
    if node != device && !is_stable_link(device) {
        return Err("device must be a kernel node or a /dev/disk/by-id link".into());
    }
    let drives = list_all().map_err(|error| error.to_string())?;
    let parent = find_volume_owner(&drives, &node)
        .ok_or_else(|| "device is not a detected removable drive or partition".to_string())?;
    let report = inspect(Path::new(&parent.path), SafetyPolicy::default())
        .map_err(|error| error.to_string())?;
    report.assert_safe().map_err(|error| error.to_string())?;
    if let Some(expected) = expected {
        expected
            .verify(&report.identity())
            .map_err(|error| error.to_string())?;
    }
    let stable = if device.starts_with("/dev/disk/by-id") {
        device.to_path_buf()
    } else {
        resolve_by_id(&node)
            .ok_or_else(|| "device has no stable /dev/disk/by-id path".to_string())?
    };
    require_stable_device(stable)
}

fn require_stable_device(path: PathBuf) -> std::result::Result<PathBuf, String> {
    if !path.starts_with("/dev/disk/by-id") {
        return Err("device has no stable /dev/disk/by-id path".into());
    }
    Ok(path)
}

fn validate_mapper_name(name: &str) -> std::result::Result<(), String> {
    validate::validate_mapper_name(name).map_err(|error| error.to_string())
}

fn validate_label(label: &str) -> std::result::Result<(), String> {
    validate::validate_label(label).map_err(|error| error.to_string())
}

fn decode_pp(b64: &SecretString) -> std::result::Result<Passphrase, String> {
    use base64_decode_minimal as b64dec;
    let bytes = b64dec::decode(b64.expose()).map_err(|e| format!("passphrase base64: {e}"))?;
    Ok(Passphrase::new(bytes))
}

fn write_response(out: &mut std::io::StdoutLock<'_>, r: Response) {
    let line = serde_json::to_string(&r)
        .unwrap_or_else(|e| format!(r#"{{"error":"serialise failed: {e}"}}"#));
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_mapper_names() {
        assert!(validate_mapper_name("ashypass_vault-1").is_ok());
        assert!(validate_mapper_name("system-root").is_err());
        assert!(validate_mapper_name("ashypass_../../root").is_err());
    }

    #[test]
    fn validates_labels() {
        assert!(validate_label("vault").is_ok());
        assert!(validate_label("").is_err());
        assert!(validate_label("a\nb").is_err());
        assert!(validate_label(&"a".repeat(48)).is_err());
    }

    #[test]
    fn destructive_requests_require_the_confirmed_identity() {
        // No `expected`: refused at parse time, before any device access.
        let missing = r#"{"op":"wipe","device":"/dev/sdb","mode":"none"}"#;
        assert!(serde_json::from_str::<Request>(missing).is_err());
        let missing =
            r#"{"op":"luks-format","device":"/dev/sdb","label":"v","passphrase_b64":"cHc="}"#;
        assert!(serde_json::from_str::<Request>(missing).is_err());

        let ok = r#"{"op":"wipe","device":"/dev/disk/by-id/usb-X-0:0","mode":"encrypted-zero","expected":{"serial":"E0D55EA5","size_bytes":42,"model":null}}"#;
        match serde_json::from_str::<Request>(ok).unwrap() {
            Request::Wipe { expected, .. } => {
                assert_eq!(expected.serial.as_deref(), Some("E0D55EA5"));
                assert_eq!(expected.size_bytes, 42);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn request_debug_never_shows_the_passphrase() {
        let line = r#"{"op":"luks-open","device":"/dev/sdb","mapper_name":"ashypass_v","passphrase_b64":"c2VjcmV0LXBhc3M="}"#;
        let req: Request = serde_json::from_str(line).unwrap();
        let debug = format!("{req:?}");
        assert!(!debug.contains("c2VjcmV0LXBhc3M"), "{debug}");
    }

    #[test]
    fn base64_decoder_roundtrip() {
        assert_eq!(
            base64_decode_minimal::decode("Zm9vYmFy").unwrap(),
            b"foobar"
        );
        assert_eq!(base64_decode_minimal::decode("Zg==").unwrap(), b"f");
        assert!(base64_decode_minimal::decode("Zm9v*").is_err());
    }

    #[test]
    fn bounds_protocol_lines() {
        let mut valid = std::io::Cursor::new(b"{\"op\":\"shutdown\"}\n".to_vec());
        assert_eq!(
            read_request_line(&mut valid).unwrap().as_deref(),
            Some("{\"op\":\"shutdown\"}")
        );

        let mut oversized = std::io::Cursor::new(vec![b'x'; MAX_REQUEST_BYTES + 2]);
        assert!(read_request_line(&mut oversized).is_err());
    }
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
