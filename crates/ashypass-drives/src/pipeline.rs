//! End-to-end orchestrator for "encrypt this drive".
//!
//! Sequences: safety check → wipe → luksFormat → luksOpen → mkfs → luksClose.
//! Every step emits a [`Progress`] event so a UI can render a stepper without
//! polling.

use crate::fs::{mkfs, Filesystem};
use crate::helper_client::HelperClient;
use crate::luks::{luks_close, luks_format, luks_open, FormatOptions};
use crate::passphrase::Passphrase;
use crate::runner::Runner;
use crate::safety::{inspect, SafetyPolicy, SafetyReport};
use crate::wipe::{wipe_with_progress, WipeMode};
use crate::{Error, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy)]
pub enum Step {
    Safety,
    Wipe,
    LuksFormat,
    LuksOpen,
    MkFs,
    LuksClose,
}

#[derive(Debug, Clone)]
pub enum Progress {
    Started(Step),
    Finished(Step),
    /// Wiping is in progress. `copied` is bytes written so far, `total` is
    /// the device capacity. Emitted at the rate `dd status=progress` ticks
    /// (~once per second).
    Wiping { copied: u64, total: u64 },
}

#[derive(Debug, Clone)]
pub struct EncryptRequest {
    pub device: PathBuf,
    pub label: String,
    pub filesystem: Filesystem,
    pub wipe_mode: WipeMode,
    pub allow_discards: bool,
}

#[derive(Debug)]
pub struct EncryptOutcome {
    pub canonical_device: PathBuf,
    pub safety: SafetyReport,
}

pub fn encrypt_new_drive(
    runner: &dyn Runner,
    request: &EncryptRequest,
    passphrase: &Passphrase,
    mut on_progress: impl FnMut(Progress),
) -> Result<EncryptOutcome> {
    on_progress(Progress::Started(Step::Safety));
    let report = inspect(&request.device, SafetyPolicy::default())?;
    report.assert_safe()?;
    on_progress(Progress::Finished(Step::Safety));

    // Pin the device by its by-id symlink for the remainder of the pipeline.
    // If udev re-numbers /dev/sdX between steps (rare but possible during
    // hotplug storms), the by-id link still points at the same hardware.
    let pinned: &Path = &report.canonical_path;

    on_progress(Progress::Started(Step::Wipe));
    let total = report.size_bytes;
    wipe_with_progress(runner, pinned, request.wipe_mode, &mut |copied| {
        on_progress(Progress::Wiping { copied, total });
    })?;
    on_progress(Progress::Finished(Step::Wipe));

    let opts = FormatOptions {
        label: request.label.clone(),
        subsystem: Some("ashypass".into()),
        allow_discards: request.allow_discards,
    };
    on_progress(Progress::Started(Step::LuksFormat));
    luks_format(runner, pinned, passphrase, &opts)?;
    on_progress(Progress::Finished(Step::LuksFormat));

    let mapper_name = mapper_name_for(&request.label);

    on_progress(Progress::Started(Step::LuksOpen));
    let mapped = luks_open(runner, pinned, &mapper_name, passphrase, request.allow_discards)?;
    on_progress(Progress::Finished(Step::LuksOpen));

    on_progress(Progress::Started(Step::MkFs));
    let mkfs_result = mkfs(runner, &mapped, request.filesystem, &request.label);
    on_progress(Progress::Finished(Step::MkFs));

    on_progress(Progress::Started(Step::LuksClose));
    let close_result = luks_close(runner, &mapper_name);
    on_progress(Progress::Finished(Step::LuksClose));

    // Surface mkfs failure first; if both failed, mkfs is the more useful
    // signal because close failure usually just means "device busy".
    if let Err(e) = mkfs_result {
        let _ = close_result;
        return Err(e);
    }
    close_result?;

    Ok(EncryptOutcome {
        canonical_device: report.canonical_path.clone(),
        safety: report,
    })
}

/// Same orchestration as [`encrypt_new_drive`] but routed through a single
/// privileged helper session (`HelperClient`). The user authenticates with
/// polkit **once** when the helper spawns; subsequent steps run inside that
/// elevated process. Pipeline ordering, progress events, and error handling
/// are identical — only the privilege-escalation strategy differs.
pub fn encrypt_via_helper(
    request: &EncryptRequest,
    passphrase: &Passphrase,
    mut on_progress: impl FnMut(Progress),
) -> Result<EncryptOutcome> {
    on_progress(Progress::Started(Step::Safety));
    let report = inspect(&request.device, SafetyPolicy::default())?;
    report.assert_safe()?;
    on_progress(Progress::Finished(Step::Safety));

    let pinned: &Path = &report.canonical_path;
    let total = report.size_bytes;

    let mut helper = HelperClient::spawn()?;

    on_progress(Progress::Started(Step::Wipe));
    helper.wipe(pinned, wipe_mode_tag(request.wipe_mode), &mut |copied| {
        on_progress(Progress::Wiping { copied, total });
    })?;
    on_progress(Progress::Finished(Step::Wipe));

    on_progress(Progress::Started(Step::LuksFormat));
    helper.luks_format(pinned, &request.label, passphrase, request.allow_discards)?;
    on_progress(Progress::Finished(Step::LuksFormat));

    let mapper_name = mapper_name_for(&request.label);

    on_progress(Progress::Started(Step::LuksOpen));
    let mapped = helper.luks_open(pinned, &mapper_name, passphrase, request.allow_discards)?;
    on_progress(Progress::Finished(Step::LuksOpen));

    on_progress(Progress::Started(Step::MkFs));
    let mkfs_result = helper.mkfs(&mapped, fs_tag(request.filesystem), &request.label);
    on_progress(Progress::Finished(Step::MkFs));

    on_progress(Progress::Started(Step::LuksClose));
    let close_result = helper.luks_close(&mapper_name);
    on_progress(Progress::Finished(Step::LuksClose));

    if let Err(e) = mkfs_result {
        let _ = close_result;
        return Err(e);
    }
    close_result?;

    Ok(EncryptOutcome {
        canonical_device: report.canonical_path.clone(),
        safety: report,
    })
}

fn wipe_mode_tag(m: WipeMode) -> &'static str {
    match m {
        WipeMode::EncryptedZero => "encrypted-zero",
        WipeMode::SecureDiscard => "secure-discard",
        WipeMode::Random => "random",
        WipeMode::None => "none",
    }
}

fn fs_tag(f: Filesystem) -> &'static str {
    match f {
        Filesystem::Ext4 => "ext4",
        Filesystem::Btrfs => "btrfs",
        Filesystem::Xfs => "xfs",
    }
}

/// Derive a stable dm-crypt mapper name from a user label. Constrains to
/// `[A-Za-z0-9_-]` so it round-trips through `/dev/mapper/...`.
pub fn mapper_name_for(label: &str) -> String {
    let cleaned: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        return "ashypass_drive".into();
    }
    format!("ashypass_{cleaned}")
}

/// Open an already-formatted drive.
///
/// Unlock is a non-destructive operation, so we don't run the full
/// [`safety::inspect`] pre-flight (which is designed around the format
/// pipeline and only accepts whole-disk top-level devices). We require
/// only that the path resolves to an existing block device — cryptsetup
/// itself returns a clear error for non-LUKS data or wrong passphrase.
pub fn unlock_existing(
    runner: &dyn Runner,
    device: &Path,
    label: &str,
    passphrase: &Passphrase,
    allow_discards: bool,
) -> Result<PathBuf> {
    if !device.exists() {
        return Err(Error::Refused(format!(
            "device not found: {}",
            device.display()
        )));
    }
    let mapper_name = mapper_name_for(label);
    let mapper_path = PathBuf::from(format!("/dev/mapper/{mapper_name}"));

    // Idempotency: if the mapping is already live (from a previous click,
    // a CLI session, or another tool), don't try to open it again — that
    // returns cryptsetup exit 5 ("device exists") which confuses users.
    // Surface the existing path so the caller can carry on.
    if mapper_path.exists() {
        return Ok(mapper_path);
    }
    luks_open(runner, device, &mapper_name, passphrase, allow_discards)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapper_name_sanitizes_unsafe_chars() {
        assert_eq!(mapper_name_for("my drive"), "ashypass_my_drive");
        assert_eq!(mapper_name_for("../etc/shadow"), "ashypass____etc_shadow");
        assert_eq!(mapper_name_for(""), "ashypass_drive");
        assert_eq!(mapper_name_for("vault-2026"), "ashypass_vault-2026");
    }
}
