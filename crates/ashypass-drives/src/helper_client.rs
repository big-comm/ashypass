//! Client for the privileged `ashypass-drives-helper`.
//!
//! Spawns the helper via `pkexec` once (a single polkit authentication
//! covers the whole encryption session) and streams JSON-Lines requests to
//! its stdin, reading JSON-Lines responses from stdout.
//!
//! Wiring the GUI to this client is a follow-up: the wizard today goes
//! through `PkexecRunner`, which prompts polkit per privileged command.
//! This module ships so that swap can happen with no further protocol work.

use crate::passphrase::Passphrase;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

const HELPER_PATH: &str = "/usr/libexec/ashypass/ashypass-drives-helper";

/// Honour `$ASHYPASS_HELPER_PATH` for development: lets you point at a
/// freshly-built `target/release/ashypass-drives-helper` without pkg install.
/// Falls back to the production path otherwise.
fn helper_path() -> std::path::PathBuf {
    std::env::var_os("ASHYPASS_HELPER_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(HELPER_PATH))
}

#[derive(Debug, Serialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
enum HelperRequest<'a> {
    LuksFormat {
        device: &'a Path,
        label: &'a str,
        #[serde(default)]
        allow_discards: bool,
        passphrase_b64: String,
    },
    LuksOpen {
        device: &'a Path,
        mapper_name: &'a str,
        passphrase_b64: String,
        allow_discards: bool,
    },
    LuksClose {
        mapper_name: &'a str,
    },
    Wipe {
        device: &'a Path,
        mode: &'a str,
    },
    Mkfs {
        mapped: &'a Path,
        fs: &'a str,
        label: &'a str,
    },
    Shutdown,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum HelperResponse {
    Ok {
        #[expect(dead_code, reason = "protocol marker; presence means success")]
        ok: bool,
    },
    Error {
        error: String,
    },
    Progress {
        progress: ProgressPayload,
    },
}

#[derive(Debug, Deserialize)]
struct ProgressPayload {
    copied: u64,
    #[allow(dead_code)]
    total: u64,
}

pub struct HelperClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl HelperClient {
    /// Spawn the helper via `pkexec`. Triggers exactly one polkit prompt.
    pub fn spawn() -> Result<Self> {
        let path = helper_path();
        let mut cmd = Command::new("pkexec");
        cmd.arg(&path);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cmd.spawn().map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::MissingTool("pkexec".into()),
            _ => Error::Io(e),
        })?;
        let stdin = child.stdin.take().expect("piped");
        let stdout = BufReader::new(child.stdout.take().expect("piped"));
        Ok(Self {
            child,
            stdin,
            stdout,
        })
    }

    fn round_trip(
        &mut self,
        req: &HelperRequest<'_>,
        on_progress: &mut dyn FnMut(u64),
    ) -> Result<()> {
        let line = serde_json::to_string(req)
            .map_err(|e| Error::Refused(format!("encode request: {e}")))?;
        self.stdin.write_all(line.as_bytes())?;
        self.stdin.write_all(b"\n")?;
        self.stdin.flush()?;

        loop {
            let mut buf = String::new();
            let n = self.stdout.read_line(&mut buf)?;
            if n == 0 {
                return Err(Error::Refused("helper closed stdout".into()));
            }
            let resp: HelperResponse = serde_json::from_str(buf.trim())
                .map_err(|e| Error::Refused(format!("decode response: {e}; line was: {buf:?}")))?;
            match resp {
                HelperResponse::Ok { .. } => return Ok(()),
                HelperResponse::Error { error } => return Err(Error::Refused(error)),
                HelperResponse::Progress { progress } => on_progress(progress.copied),
            }
        }
    }

    pub fn luks_format(
        &mut self,
        device: &Path,
        label: &str,
        passphrase: &Passphrase,
        allow_discards: bool,
    ) -> Result<()> {
        self.round_trip(
            &HelperRequest::LuksFormat {
                device,
                label,
                allow_discards,
                passphrase_b64: b64_encode(passphrase.as_bytes()),
            },
            &mut |_| {},
        )
    }

    pub fn luks_open(
        &mut self,
        device: &Path,
        mapper_name: &str,
        passphrase: &Passphrase,
        allow_discards: bool,
    ) -> Result<PathBuf> {
        self.round_trip(
            &HelperRequest::LuksOpen {
                device,
                mapper_name,
                allow_discards,
                passphrase_b64: b64_encode(passphrase.as_bytes()),
            },
            &mut |_| {},
        )?;
        Ok(PathBuf::from(format!("/dev/mapper/{mapper_name}")))
    }

    pub fn luks_close(&mut self, mapper_name: &str) -> Result<()> {
        self.round_trip(&HelperRequest::LuksClose { mapper_name }, &mut |_| {})
    }

    pub fn wipe(
        &mut self,
        device: &Path,
        mode: &str,
        on_progress: &mut dyn FnMut(u64),
    ) -> Result<()> {
        self.round_trip(&HelperRequest::Wipe { device, mode }, on_progress)
    }

    pub fn mkfs(&mut self, mapped: &Path, fs: &str, label: &str) -> Result<()> {
        self.round_trip(&HelperRequest::Mkfs { mapped, fs, label }, &mut |_| {})
    }
}

impl Drop for HelperClient {
    fn drop(&mut self) {
        // Best-effort graceful shutdown. If the helper has already exited
        // these writes fail silently — fine.
        if let Ok(line) = serde_json::to_string(&HelperRequest::Shutdown) {
            let _ = self.stdin.write_all(line.as_bytes());
            let _ = self.stdin.write_all(b"\n");
        }
        let _ = self.child.wait();
    }
}

/// Minimal RFC 4648 base64 encoder so this module has zero extra crates.
fn b64_encode(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let b = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(T[((b >> 18) & 0x3f) as usize] as char);
        out.push(T[((b >> 12) & 0x3f) as usize] as char);
        out.push(T[((b >> 6) & 0x3f) as usize] as char);
        out.push(T[(b & 0x3f) as usize] as char);
        i += 3;
    }
    match bytes.len() - i {
        2 => {
            let b = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
            out.push(T[((b >> 18) & 0x3f) as usize] as char);
            out.push(T[((b >> 12) & 0x3f) as usize] as char);
            out.push(T[((b >> 6) & 0x3f) as usize] as char);
            out.push('=');
        }
        1 => {
            let b = (bytes[i] as u32) << 16;
            out.push(T[((b >> 18) & 0x3f) as usize] as char);
            out.push(T[((b >> 12) & 0x3f) as usize] as char);
            out.push_str("==");
        }
        _ => {}
    }
    out
}
