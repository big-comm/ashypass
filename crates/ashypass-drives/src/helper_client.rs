//! Client for the privileged `ashypass-drives-helper`.
//!
//! Spawns the helper via `pkexec` once (a single polkit authentication
//! covers the whole encryption session) and streams JSON-Lines requests to
//! its stdin, reading JSON-Lines responses from stdout.
//!
//! The GUI encryption wizard uses this client through
//! [`crate::pipeline::encrypt_via_helper`]. Destructive requests carry the
//! [`DeviceIdentity`] the user confirmed; the helper re-inspects the device
//! and refuses if it no longer matches.

use crate::passphrase::{Passphrase, SecretString};
use crate::safety::DeviceIdentity;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use zeroize::Zeroize;

const HELPER_PATH: &str = "/usr/libexec/ashypass/ashypass-drives-helper";

/// Debug builds honour `$ASHYPASS_HELPER_PATH` so a freshly built helper can
/// be tested without installing the package. Release builds always use the
/// installed path: the polkit action is bound to it, and an environment
/// variable must never decide which binary gets elevated.
fn helper_path() -> PathBuf {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("ASHYPASS_HELPER_PATH") {
        return PathBuf::from(path);
    }
    PathBuf::from(HELPER_PATH)
}

#[derive(Debug, Serialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
enum HelperRequest<'a> {
    LuksFormat {
        device: &'a Path,
        label: &'a str,
        allow_discards: bool,
        passphrase_b64: SecretString,
        expected: &'a DeviceIdentity,
    },
    LuksOpen {
        device: &'a Path,
        mapper_name: &'a str,
        passphrase_b64: SecretString,
        allow_discards: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        expected: Option<&'a DeviceIdentity>,
        /// Leave the mapping open when the session ends (a user unlock)
        /// instead of tearing it down with the session (format pipeline).
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        keep_open: bool,
    },
    LuksClose {
        mapper_name: &'a str,
    },
    /// Close a mapping opened outside this session (the user's Lock button).
    LuksLock {
        mapper_name: &'a str,
    },
    EnrollFido2 {
        device: &'a Path,
        passphrase_b64: SecretString,
        pin_required: bool,
        user_presence_required: bool,
    },
    Wipe {
        device: &'a Path,
        mode: &'a str,
        expected: &'a DeviceIdentity,
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
        // pkexec reports a missing program with the same exit code (127) as
        // a refused authorisation; check first so the two are not confused.
        if !path.is_file() {
            return Err(Error::MissingTool(path.display().to_string()));
        }
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

    /// Error to report once the helper stopped talking: reap the child and
    /// translate its exit status.
    fn exit_error(&mut self) -> Error {
        match self.child.wait() {
            Ok(status) => exit_status_error(status.code()),
            Err(error) => Error::Io(error),
        }
    }

    fn round_trip(
        &mut self,
        req: &HelperRequest<'_>,
        on_progress: &mut dyn FnMut(u64),
    ) -> Result<()> {
        let mut line =
            serde_json::to_vec(req).map_err(|e| Error::Refused(format!("encode request: {e}")))?;
        line.push(b'\n');
        let written = self
            .stdin
            .write_all(&line)
            .and_then(|()| self.stdin.flush());
        // The line may carry a base64 passphrase.
        line.zeroize();
        if written.is_err() {
            // Broken pipe: pkexec (or the helper) is already gone. Its exit
            // status says why, which is more useful than EPIPE.
            return Err(self.exit_error());
        }

        loop {
            let mut buf = String::new();
            let n = self.stdout.read_line(&mut buf)?;
            if n == 0 {
                return Err(self.exit_error());
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
        expected: &DeviceIdentity,
    ) -> Result<()> {
        self.round_trip(
            &HelperRequest::LuksFormat {
                device,
                label,
                allow_discards,
                passphrase_b64: SecretString::new(b64_encode(passphrase.as_bytes())),
                expected,
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
        expected: Option<&DeviceIdentity>,
    ) -> Result<PathBuf> {
        self.round_trip(
            &HelperRequest::LuksOpen {
                device,
                mapper_name,
                allow_discards,
                passphrase_b64: SecretString::new(b64_encode(passphrase.as_bytes())),
                expected,
                keep_open: false,
            },
            &mut |_| {},
        )?;
        Ok(PathBuf::from(format!("/dev/mapper/{mapper_name}")))
    }

    /// Unlock an existing LUKS volume for the user. Unlike [`Self::luks_open`]
    /// the mapping stays open after the helper exits.
    pub fn luks_unlock(
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
                passphrase_b64: SecretString::new(b64_encode(passphrase.as_bytes())),
                expected: None,
                keep_open: true,
            },
            &mut |_| {},
        )?;
        Ok(PathBuf::from(format!("/dev/mapper/{mapper_name}")))
    }

    pub fn luks_close(&mut self, mapper_name: &str) -> Result<()> {
        self.round_trip(&HelperRequest::LuksClose { mapper_name }, &mut |_| {})
    }

    /// Lock an Ashy Pass mapping on a removable drive (opened earlier by
    /// [`Self::luks_unlock`], the CLI, or a previous session). The mapping
    /// must already be unmounted.
    pub fn luks_lock(&mut self, mapper_name: &str) -> Result<()> {
        self.round_trip(&HelperRequest::LuksLock { mapper_name }, &mut |_| {})
    }

    /// Add a FIDO2 keyslot with `systemd-cryptenroll`, authorised by the
    /// current passphrase.
    pub fn enroll_fido2(
        &mut self,
        device: &Path,
        passphrase: &Passphrase,
        pin_required: bool,
        user_presence_required: bool,
    ) -> Result<()> {
        self.round_trip(
            &HelperRequest::EnrollFido2 {
                device,
                passphrase_b64: SecretString::new(b64_encode(passphrase.as_bytes())),
                pin_required,
                user_presence_required,
            },
            &mut |_| {},
        )
    }

    pub fn wipe(
        &mut self,
        device: &Path,
        mode: &str,
        expected: &DeviceIdentity,
        on_progress: &mut dyn FnMut(u64),
    ) -> Result<()> {
        self.round_trip(
            &HelperRequest::Wipe {
                device,
                mode,
                expected,
            },
            on_progress,
        )
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

/// Map the exit code of `pkexec <helper>` to an error. pkexec exits with
/// 126 when the authentication dialog was dismissed and 127 when the user is
/// not authorised (or authentication failed); the helper itself never uses
/// those codes.
fn exit_status_error(code: Option<i32>) -> Error {
    match code {
        Some(126 | 127) => Error::AuthCancelled,
        Some(code) => Error::Refused(format!("the privileged helper exited with status {code}")),
        None => Error::Refused("the privileged helper was terminated by a signal".into()),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> DeviceIdentity {
        DeviceIdentity {
            serial: Some("E0D55EA5".into()),
            size_bytes: 61_991_813_120,
            model: Some("DataTraveler 3.0".into()),
            by_id: Some("usb-Kingston_DataTraveler_3.0_E0D55EA5-0:0".into()),
            wwn: None,
            ptuuid: None,
        }
    }

    #[test]
    fn identity_carries_the_by_id_link_and_omits_unknown_fields() {
        let id = identity();
        let wipe = serde_json::to_value(HelperRequest::Wipe {
            device: Path::new("/dev/disk/by-id/usb-Kingston-0:0"),
            mode: "none",
            expected: &id,
        })
        .unwrap();
        assert_eq!(
            wipe["expected"]["by_id"],
            "usb-Kingston_DataTraveler_3.0_E0D55EA5-0:0"
        );
        assert!(wipe["expected"].get("wwn").is_none());
    }

    #[test]
    fn unlock_lock_and_enrol_requests() {
        let device = Path::new("/dev/disk/by-id/usb-Kingston-0:0-part1");
        let session = serde_json::to_value(HelperRequest::LuksOpen {
            device,
            mapper_name: "ashypass_vault",
            passphrase_b64: SecretString::new(b64_encode(b"pw")),
            allow_discards: false,
            expected: None,
            keep_open: false,
        })
        .unwrap();
        // Format-session opens keep the original wire format.
        assert!(session.get("keep_open").is_none());

        let unlock = serde_json::to_value(HelperRequest::LuksOpen {
            device,
            mapper_name: "ashypass_vault",
            passphrase_b64: SecretString::new(b64_encode(b"pw")),
            allow_discards: false,
            expected: None,
            keep_open: true,
        })
        .unwrap();
        assert_eq!(unlock["keep_open"], true);

        let lock = serde_json::to_value(HelperRequest::LuksLock {
            mapper_name: "ashypass_vault",
        })
        .unwrap();
        assert_eq!(lock["op"], "luks-lock");

        let enrol = serde_json::to_value(HelperRequest::EnrollFido2 {
            device,
            passphrase_b64: SecretString::new(b64_encode(b"pw")),
            pin_required: true,
            user_presence_required: false,
        })
        .unwrap();
        assert_eq!(enrol["op"], "enroll-fido2");
        assert_eq!(enrol["passphrase_b64"], "cHc=");
        assert_eq!(enrol["user_presence_required"], false);
    }

    #[test]
    fn pkexec_refusals_mean_authentication_was_cancelled() {
        assert!(matches!(exit_status_error(Some(126)), Error::AuthCancelled));
        assert!(matches!(exit_status_error(Some(127)), Error::AuthCancelled));
        assert!(matches!(exit_status_error(Some(2)), Error::Refused(_)));
        assert!(matches!(exit_status_error(None), Error::Refused(_)));
    }

    #[test]
    fn destructive_requests_carry_the_confirmed_identity() {
        let id = identity();
        let device = Path::new("/dev/disk/by-id/usb-Kingston-0:0");
        let wipe = serde_json::to_value(HelperRequest::Wipe {
            device,
            mode: "encrypted-zero",
            expected: &id,
        })
        .unwrap();
        assert_eq!(wipe["op"], "wipe");
        assert_eq!(wipe["expected"]["serial"], "E0D55EA5");
        assert_eq!(wipe["expected"]["size_bytes"], 61_991_813_120u64);

        let format = serde_json::to_value(HelperRequest::LuksFormat {
            device,
            label: "vault",
            allow_discards: false,
            passphrase_b64: SecretString::new(b64_encode(b"pw")),
            expected: &id,
        })
        .unwrap();
        assert_eq!(format["op"], "luks-format");
        assert_eq!(format["passphrase_b64"], "cHc=");
        assert_eq!(format["expected"]["model"], "DataTraveler 3.0");
    }

    #[test]
    fn request_debug_output_redacts_passphrases() {
        let id = identity();
        let req = HelperRequest::LuksOpen {
            device: Path::new("/dev/sdb"),
            mapper_name: "ashypass_vault",
            passphrase_b64: SecretString::new(b64_encode(b"correct horse")),
            allow_discards: false,
            expected: Some(&id),
            keep_open: false,
        };
        let debug = format!("{req:?}");
        assert!(!debug.contains(&b64_encode(b"correct horse")), "{debug}");
        assert!(debug.contains("redacted"), "{debug}");
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
    }

    /// Runs under `cargo test --release` (the PKGBUILD `check()`).
    #[cfg(not(debug_assertions))]
    #[test]
    fn release_builds_ignore_the_helper_path_override() {
        std::env::set_var("ASHYPASS_HELPER_PATH", "/tmp/not-the-helper");
        assert_eq!(helper_path(), PathBuf::from(HELPER_PATH));
    }
}
