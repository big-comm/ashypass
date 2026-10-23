//! LUKS2 wrapper around `cryptsetup`.
//!
//! Parameter choices follow `cryptsetup`'s own defaults for full-disk
//! encryption plus a few explicit hardenings. See `CRYPTO_SPEC.md` § External
//! drives for the rationale; this file is the source of truth for argv.
//!
//! # Why not implement block crypto in Rust?
//!
//! `dm-crypt` in the kernel is the same module that protects every Linux FDE
//! deployment on the planet (Ubuntu, Fedora, Tails, Qubes). Reimplementing it
//! in userspace would be both pointless and dangerous — pointless because the
//! kernel is already audited and AES-NI-accelerated, dangerous because subtle
//! mistakes in IV derivation, key splitting, or sector framing produce
//! catastrophic weaknesses that no test catches.
//!
//! # Hardening choices
//!
//! - **aes-xts-plain64 / key-size 512.** XTS with two 256-bit keys is the
//!   only NIST-approved mode for storage-at-rest. `plain64` IV avoids the
//!   "plain" 32-bit truncation that bites devices larger than 2 TiB.
//! - **Argon2id KDF, ≥ 1 GiB memory, 2000 ms iter-time.** Memory-hard against
//!   GPU/ASIC dictionary attacks; the cryptsetup default already tunes for
//!   the host RAM but we set a floor.
//! - **--sector-size 4096** matches all modern flash; using 512 silently on
//!   a 4K-native device costs a measurable IO penalty.
//! - **--use-random** pulls the master volume key from `/dev/random` rather
//!   than `/dev/urandom`. On modern kernels they're equivalent post-seed,
//!   but we accept the brief format-time stall for the stronger guarantee.
//! - **--batch-mode + explicit safety pre-flight.** We do our own checks in
//!   `safety.rs` so we can suppress cryptsetup's interactive confirmation
//!   without losing the safety net.
//! - **--key-file=-** routes the passphrase through stdin, so it never
//!   appears in `/proc/<pid>/cmdline`.

use crate::passphrase::Passphrase;
use crate::runner::{CommandSpec, Runner};
use crate::{Error, Result};
use std::path::{Path, PathBuf};

pub const CIPHER: &str = "aes-xts-plain64";
pub const KEY_SIZE: u32 = 512;
pub const HASH: &str = "sha256";
pub const KDF: &str = "argon2id";
pub const ITER_TIME_MS: u32 = 2000;
pub const PBKDF_MEMORY_KIB: u32 = 1_048_576; // 1 GiB
pub const PBKDF_PARALLEL: u32 = 4;
pub const SECTOR_SIZE: u32 = 4096;

#[derive(Debug, Clone, Default)]
pub struct FormatOptions {
    pub label: String,
    /// LUKS2 *user-friendly* device label (`--subsystem`). Helps users find
    /// the drive in `lsblk -o LABEL` without unlocking it.
    pub subsystem: Option<String>,
    /// `--allow-discards` at unlock time leaks free-space patterns to the
    /// device. Off by default; useful for SSDs where you accept the leak in
    /// exchange for TRIM-driven wear levelling.
    pub allow_discards: bool,
}

/// Build the argv for `cryptsetup luksFormat`. Pure function — no I/O — so
/// unit tests can pin the exact parameter set.
pub fn build_format_spec(device: &Path, opts: &FormatOptions) -> CommandSpec {
    let mut s = CommandSpec::new("cryptsetup")
        .arg("luksFormat")
        .arg("--type")
        .arg("luks2")
        .arg("--cipher")
        .arg(CIPHER)
        .arg("--key-size")
        .arg(KEY_SIZE.to_string())
        .arg("--hash")
        .arg(HASH)
        .arg("--pbkdf")
        .arg(KDF)
        .arg("--iter-time")
        .arg(ITER_TIME_MS.to_string())
        .arg("--pbkdf-memory")
        .arg(PBKDF_MEMORY_KIB.to_string())
        .arg("--pbkdf-parallel")
        .arg(PBKDF_PARALLEL.to_string())
        .arg("--sector-size")
        .arg(SECTOR_SIZE.to_string())
        .arg("--use-random")
        .arg("--batch-mode")
        .arg("--key-file=-");
    if !opts.label.is_empty() {
        s = s.arg("--label").arg(&opts.label);
    }
    if let Some(sub) = &opts.subsystem {
        s = s.arg("--subsystem").arg(sub);
    }
    s.arg(device.to_string_lossy().into_owned())
}

pub fn build_open_spec(device: &Path, mapper_name: &str, allow_discards: bool) -> CommandSpec {
    let mut s = CommandSpec::new("cryptsetup")
        .arg("open")
        .arg("--type")
        .arg("luks2")
        .arg("--key-file=-");
    if allow_discards {
        s = s.arg("--allow-discards");
    }
    s.arg(device.to_string_lossy().into_owned())
        .arg(mapper_name.to_string())
}

pub fn build_close_spec(mapper_name: &str) -> CommandSpec {
    CommandSpec::new("cryptsetup")
        .arg("close")
        .arg(mapper_name.to_string())
}

/// Format `device` as a fresh LUKS2 volume. **Destructive.**
///
/// `device` must already have passed [`crate::safety::inspect`]. This
/// function does not re-check — the caller is responsible for not racing
/// hotplug events between safety check and format.
pub fn luks_format(
    runner: &dyn Runner,
    device: &Path,
    passphrase: &Passphrase,
    opts: &FormatOptions,
) -> Result<()> {
    crate::validate::validate_passphrase(passphrase)?;
    if !opts.label.is_empty() {
        crate::validate::validate_label(&opts.label)?;
    }
    let spec = build_format_spec(device, opts).with_passphrase(passphrase);
    runner.run(spec).map(|_| ())
}

pub fn luks_open(
    runner: &dyn Runner,
    device: &Path,
    mapper_name: &str,
    passphrase: &Passphrase,
    allow_discards: bool,
) -> Result<PathBuf> {
    crate::validate::validate_mapper_name(mapper_name)?;
    let spec = build_open_spec(device, mapper_name, allow_discards).with_passphrase(passphrase);
    runner.run(spec)?;
    Ok(PathBuf::from(format!("/dev/mapper/{mapper_name}")))
}

/// Close an Ashy Pass mapping. Names without the `ashypass_` prefix are
/// refused so this can never tear down another tool's (or the system's)
/// dm-crypt device.
pub fn luks_close(runner: &dyn Runner, mapper_name: &str) -> Result<()> {
    crate::validate::validate_mapper_name(mapper_name)?;
    runner.run(build_close_spec(mapper_name)).map(|_| ())
}

/// Attempts made by [`luks_close_settled`] before giving up on a busy device.
const CLOSE_ATTEMPTS: u32 = 5;
const CLOSE_BACKOFF: std::time::Duration = std::time::Duration::from_millis(300);

/// Close a mapping that was just written to (e.g. right after `mkfs`).
///
/// udev reacts to the new filesystem by probing the mapping (blkid, and
/// udisks on desktops), which briefly holds it open; `cryptsetup close` then
/// fails with "device is still in use". Wait for the udev queue first (best
/// effort) and retry a few times with a growing backoff while it is busy.
pub fn luks_close_settled(runner: &dyn Runner, mapper_name: &str) -> Result<()> {
    close_settled_with(runner, mapper_name, CLOSE_BACKOFF)
}

fn close_settled_with(
    runner: &dyn Runner,
    mapper_name: &str,
    backoff: std::time::Duration,
) -> Result<()> {
    crate::validate::validate_mapper_name(mapper_name)?;
    settle_udev(runner);
    let mut attempt = 1;
    loop {
        match luks_close(runner, mapper_name) {
            Err(error) if attempt < CLOSE_ATTEMPTS && is_busy(&error) => {
                log::debug!("{mapper_name} still busy (attempt {attempt}); retrying");
                std::thread::sleep(backoff * attempt);
                attempt += 1;
            }
            other => return other,
        }
    }
}

/// `udevadm settle`, ignoring failures: it is only a hint that makes the
/// following `close` more likely to succeed on the first try.
pub fn settle_udev(runner: &dyn Runner) {
    let spec = CommandSpec::new("udevadm")
        .arg("settle")
        .arg("--timeout=10");
    if let Err(error) = runner.run(spec) {
        log::debug!("udevadm settle failed (ignored): {error}");
    }
}

/// True when `cryptsetup` refused because the device is in use. Exit code 5
/// is cryptsetup's "device already exists or device is busy".
fn is_busy(error: &Error) -> bool {
    match error {
        Error::CommandFailed { status, stderr, .. } => {
            let stderr = stderr.to_ascii_lowercase();
            *status == 5 || stderr.contains("in use") || stderr.contains("busy")
        }
        _ => false,
    }
}

/// Enrol a FIDO2 token on an existing LUKS2 device via
/// `systemd-cryptenroll --fido2-device=auto`. The user will be asked to
/// authorise on the token (tap / touch / PIN) by systemd-cryptenroll
/// itself; we just dispatch the call. The existing passphrase is consumed
/// via stdin because systemd-cryptenroll reads the unlock secret from there
/// when `--unlock-key-file=/dev/stdin` is supplied.
pub fn enroll_fido2(
    runner: &dyn Runner,
    device: &Path,
    unlock: &Passphrase,
    pin_required: bool,
    user_presence_required: bool,
) -> Result<()> {
    if unlock.is_empty() {
        return Err(Error::Refused("refusing empty unlock passphrase".into()));
    }
    let mut spec = crate::runner::CommandSpec::new("systemd-cryptenroll")
        .arg("--fido2-device=auto")
        .arg("--unlock-key-file=/dev/stdin");
    spec = spec.arg(format!(
        "--fido2-with-client-pin={}",
        if pin_required { "yes" } else { "no" }
    ));
    spec = spec.arg(format!(
        "--fido2-with-user-presence={}",
        if user_presence_required { "yes" } else { "no" }
    ));
    spec = spec.arg(device.to_string_lossy().into_owned());
    let spec = spec.with_passphrase(unlock);
    runner.run(spec).map(|_| ())
}

/// List currently-active keyslots / tokens on a LUKS2 device by parsing
/// `cryptsetup luksDump --dump-json-metadata`. Returns the raw JSON for
/// the UI to render.
pub fn dump_json(runner: &dyn Runner, device: &Path) -> Result<String> {
    let out = runner.run(
        crate::runner::CommandSpec::new("cryptsetup")
            .arg("luksDump")
            .arg("--dump-json-metadata")
            .arg(device.to_string_lossy().into_owned()),
    )?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_spec_pins_the_full_parameter_set() {
        let spec = build_format_spec(
            Path::new("/dev/sda"),
            &FormatOptions {
                label: "vault".into(),
                subsystem: Some("ashypass".into()),
                allow_discards: false,
            },
        );
        assert_eq!(spec.program, "cryptsetup");
        let joined = spec.args.join(" ");
        assert!(joined.contains("--type luks2"), "{joined}");
        assert!(joined.contains("--cipher aes-xts-plain64"), "{joined}");
        assert!(joined.contains("--key-size 512"), "{joined}");
        assert!(joined.contains("--pbkdf argon2id"), "{joined}");
        assert!(joined.contains("--pbkdf-memory 1048576"), "{joined}");
        assert!(joined.contains("--iter-time 2000"), "{joined}");
        assert!(joined.contains("--sector-size 4096"), "{joined}");
        assert!(joined.contains("--use-random"), "{joined}");
        assert!(joined.contains("--batch-mode"), "{joined}");
        assert!(joined.contains("--key-file=-"), "{joined}");
        assert!(joined.contains("--label vault"), "{joined}");
        assert!(joined.contains("--subsystem ashypass"), "{joined}");
        assert!(joined.ends_with("/dev/sda"), "{joined}");
    }

    #[test]
    fn open_spec_passes_discards_only_when_requested() {
        let with = build_open_spec(Path::new("/dev/sdb"), "ash0", true);
        let without = build_open_spec(Path::new("/dev/sdb"), "ash0", false);
        assert!(with.args.iter().any(|a| a == "--allow-discards"));
        assert!(!without.args.iter().any(|a| a == "--allow-discards"));
    }

    #[test]
    fn close_spec_is_minimal() {
        let s = build_close_spec("ash0");
        assert_eq!(s.args, vec!["close".to_string(), "ash0".to_string()]);
    }

    fn busy() -> Error {
        Error::CommandFailed {
            cmd: "cryptsetup close".into(),
            status: 5,
            stderr: "Device ashypass_vault is still in use.".into(),
        }
    }

    #[test]
    fn settled_close_waits_for_udev_and_retries_while_busy() {
        use crate::runner::fake::FakeRunner;
        let runner = FakeRunner::default()
            // `udevadm settle` failing must not stop the close.
            .reply(Err(Error::MissingTool("udevadm".into())))
            .reply(Err(busy()))
            .reply(Err(busy()));
        close_settled_with(&runner, "ashypass_vault", std::time::Duration::ZERO).unwrap();
        assert_eq!(
            runner.calls(),
            [
                "udevadm settle --timeout=10",
                "cryptsetup close ashypass_vault",
                "cryptsetup close ashypass_vault",
                "cryptsetup close ashypass_vault",
            ]
        );
    }

    #[test]
    fn settled_close_gives_up_and_does_not_retry_other_errors() {
        use crate::runner::fake::FakeRunner;
        let always_busy = FakeRunner::default().stdout("");
        for _ in 0..CLOSE_ATTEMPTS {
            always_busy.replies.lock().unwrap().push_back(Err(busy()));
        }
        assert!(
            close_settled_with(&always_busy, "ashypass_vault", std::time::Duration::ZERO).is_err()
        );
        assert_eq!(always_busy.calls().len(), 1 + CLOSE_ATTEMPTS as usize);

        let missing = FakeRunner::default()
            .stdout("")
            .reply(Err(Error::CommandFailed {
                cmd: "cryptsetup close".into(),
                status: 4,
                stderr: "Device ashypass_vault is not active.".into(),
            }));
        assert!(close_settled_with(&missing, "ashypass_vault", std::time::Duration::ZERO).is_err());
        assert_eq!(missing.calls().len(), 2);

        // Foreign mapper names are refused before anything runs.
        let none = FakeRunner::default();
        assert!(close_settled_with(&none, "cryptroot", std::time::Duration::ZERO).is_err());
        assert!(none.calls().is_empty());
    }
}
