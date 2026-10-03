//! End-to-end orchestrator for "encrypt this drive".
//!
//! Sequences: validation + safety check → wipe → luksFormat → luksOpen →
//! mkfs → luksClose. Every step emits a [`Progress`] event so a UI can render
//! a stepper without polling.
//!
//! Everything that can be checked without touching the device (label,
//! filesystem label limits, mapper name collisions, passphrase presence, the
//! identity of the device the user confirmed) is checked in [`preflight`],
//! **before** the first destructive step.

use crate::fs::{mkfs, Filesystem};
use crate::helper_client::HelperClient;
use crate::luks::{luks_close, luks_format, luks_open, FormatOptions};
use crate::mapper::{device_tag, mapper_state, pick_mapper, MapperState};
use crate::passphrase::Passphrase;
use crate::runner::Runner;
use crate::safety::{inspect, DeviceIdentity, SafetyPolicy, SafetyReport};
use crate::validate::{validate_label_for_fs, validate_mapper_name, validate_passphrase};
use crate::wipe::{wipe_with_progress, WipeMode};
use crate::{Error, Result};
use std::path::{Path, PathBuf};

pub use crate::mapper::{mapper_name_for, mapper_name_with_tag};

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
    Wiping {
        copied: u64,
        total: u64,
    },
}

#[derive(Debug, Clone)]
pub struct EncryptRequest {
    /// Whole-disk node (`/dev/sdb`) or `/dev/disk/by-id/...` link.
    pub device: PathBuf,
    /// What the user confirmed (serial / size / model). The pipeline and the
    /// privileged helper refuse to touch the device if it no longer matches.
    pub expected: DeviceIdentity,
    pub label: String,
    pub filesystem: Filesystem,
    pub wipe_mode: WipeMode,
    pub allow_discards: bool,
}

#[derive(Debug)]
pub struct EncryptOutcome {
    pub canonical_device: PathBuf,
    /// Mapper name used while formatting; the same name is preferred again by
    /// [`unlock_existing`] for this label.
    pub mapper_name: String,
    pub safety: SafetyReport,
}

/// Validation that must pass before anything destructive happens. Returns
/// the safety report (with the pinned device path) and the mapper name to
/// use for the format-time mapping.
pub fn preflight(
    request: &EncryptRequest,
    passphrase: &Passphrase,
) -> Result<(SafetyReport, String)> {
    validate_passphrase(passphrase)?;
    validate_label_for_fs(&request.label, request.filesystem)?;

    let report = inspect(&request.device, SafetyPolicy::default())?;
    report.assert_safe()?;
    request.expected.verify(&report.identity())?;

    let node = report.device_node.clone();
    let mapper_name = format_mapper_name(&request.label, &node, |name| mapper_state(name, &node))?;
    Ok((report, mapper_name))
}

/// Choose the format-time mapper name. The target device is never mapped at
/// this point (safety refuses open mappings), so a name that already exists
/// belongs to another device and must not be reused.
fn format_mapper_name(
    label: &str,
    node: &Path,
    state_of: impl FnMut(&str) -> MapperState,
) -> Result<String> {
    let candidates = [
        mapper_name_for(label),
        mapper_name_with_tag(label, &device_tag(node, None)),
    ];
    match pick_mapper(&candidates, state_of)? {
        (name, MapperState::Free) => Ok(name),
        (name, _) => Err(Error::Refused(format!(
            "/dev/mapper/{name} is already open; close it before encrypting"
        ))),
    }
}

pub fn encrypt_new_drive(
    runner: &dyn Runner,
    request: &EncryptRequest,
    passphrase: &Passphrase,
    mut on_progress: impl FnMut(Progress),
) -> Result<EncryptOutcome> {
    on_progress(Progress::Started(Step::Safety));
    let (report, mapper_name) = preflight(request, passphrase)?;
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

    on_progress(Progress::Started(Step::LuksOpen));
    let mapped = luks_open(
        runner,
        pinned,
        &mapper_name,
        passphrase,
        request.allow_discards,
    )?;
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
        mapper_name,
        safety: report,
    })
}

/// Same orchestration as [`encrypt_new_drive`] but routed through a single
/// privileged helper session (`HelperClient`). The user authenticates with
/// polkit **once** when the helper spawns; subsequent steps run inside that
/// elevated process, which re-validates the device and its identity before
/// every destructive request.
pub fn encrypt_via_helper(
    request: &EncryptRequest,
    passphrase: &Passphrase,
    mut on_progress: impl FnMut(Progress),
) -> Result<EncryptOutcome> {
    on_progress(Progress::Started(Step::Safety));
    let (report, mapper_name) = preflight(request, passphrase)?;
    on_progress(Progress::Finished(Step::Safety));

    let pinned: &Path = &report.canonical_path;
    let total = report.size_bytes;
    let expected = &request.expected;

    let mut helper = HelperClient::spawn()?;

    on_progress(Progress::Started(Step::Wipe));
    helper.wipe(
        pinned,
        wipe_mode_tag(request.wipe_mode),
        expected,
        &mut |copied| {
            on_progress(Progress::Wiping { copied, total });
        },
    )?;
    on_progress(Progress::Finished(Step::Wipe));

    on_progress(Progress::Started(Step::LuksFormat));
    helper.luks_format(
        pinned,
        &request.label,
        passphrase,
        request.allow_discards,
        expected,
    )?;
    on_progress(Progress::Finished(Step::LuksFormat));

    on_progress(Progress::Started(Step::LuksOpen));
    let mapped = helper.luks_open(
        pinned,
        &mapper_name,
        passphrase,
        request.allow_discards,
        Some(expected),
    )?;
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
        mapper_name,
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

/// How [`unlock_existing_with`] chooses the mapper name.
#[derive(Debug, Clone, Copy)]
pub enum MapperChoice<'a> {
    /// Derive from the label (`ashypass_<label>`), falling back to a
    /// device-tagged name when another drive already uses the plain one.
    FromLabel(&'a str),
    /// Use exactly this name; it must pass
    /// [`crate::validate::validate_mapper_name`].
    Explicit(&'a str),
}

/// Open an already-formatted drive, deriving the mapper name from `label`.
///
/// See [`unlock_existing_with`].
pub fn unlock_existing(
    runner: &dyn Runner,
    device: &Path,
    label: &str,
    passphrase: &Passphrase,
    allow_discards: bool,
) -> Result<PathBuf> {
    unlock_existing_with(
        runner,
        device,
        MapperChoice::FromLabel(label),
        passphrase,
        allow_discards,
    )
}

/// Open an already-formatted drive.
///
/// Unlock is a non-destructive operation, so we don't run the full
/// [`crate::safety::inspect`] pre-flight (which only accepts whole-disk
/// devices). We require that the path resolves to an existing block device;
/// cryptsetup itself returns a clear error for non-LUKS data or a wrong
/// passphrase.
///
/// An existing mapping is only reused when it is backed by **this** device;
/// a mapping with the same name that belongs to another drive is never
/// returned (a device-tagged name is used instead).
pub fn unlock_existing_with(
    runner: &dyn Runner,
    device: &Path,
    choice: MapperChoice<'_>,
    passphrase: &Passphrase,
    allow_discards: bool,
) -> Result<PathBuf> {
    use std::os::unix::fs::FileTypeExt;

    let node = std::fs::canonicalize(device)
        .map_err(|_| Error::Refused(format!("device not found: {}", device.display())))?;
    let is_block = std::fs::metadata(&node).is_ok_and(|m| m.file_type().is_block_device());
    if !is_block {
        return Err(Error::Refused(format!(
            "{} is not a block device",
            device.display()
        )));
    }

    let candidates = unlock_candidates(choice, &node, crate::mapper::uuid_of(&node).as_deref());
    let (mapper_name, state) = pick_mapper(&candidates, |name| mapper_state(name, &node))?;
    if state == MapperState::SameDevice {
        // Already unlocked from this very device (previous click, CLI
        // session). Re-opening would fail with "device in use".
        return Ok(PathBuf::from(format!("/dev/mapper/{mapper_name}")));
    }
    validate_passphrase(passphrase)?;
    validate_mapper_name(&mapper_name)?;
    luks_open(runner, device, &mapper_name, passphrase, allow_discards)
}

fn unlock_candidates(choice: MapperChoice<'_>, node: &Path, uuid: Option<&str>) -> Vec<String> {
    match choice {
        MapperChoice::Explicit(name) => vec![name.to_string()],
        MapperChoice::FromLabel(label) => vec![
            mapper_name_for(label),
            mapper_name_with_tag(label, &device_tag(node, uuid)),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_mapper_falls_back_to_device_tag() {
        let node = Path::new("/dev/sdb");
        assert_eq!(
            format_mapper_name("vault", node, |_| MapperState::Free).unwrap(),
            "ashypass_vault"
        );
        assert_eq!(
            format_mapper_name("vault", node, |n| if n == "ashypass_vault" {
                MapperState::OtherDevice
            } else {
                MapperState::Free
            })
            .unwrap(),
            "ashypass_vault_sdb"
        );
        // Both names taken: refused before anything is wiped.
        assert!(format_mapper_name("vault", node, |_| MapperState::OtherDevice).is_err());
        // The device itself mapped: also refused (never reuse during format).
        assert!(format_mapper_name("vault", node, |_| MapperState::SameDevice).is_err());
    }

    #[test]
    fn unlock_candidates_follow_the_choice() {
        let node = Path::new("/dev/sdc1");
        assert_eq!(
            unlock_candidates(MapperChoice::FromLabel("docs"), node, Some("aaaaaaaa-bbbb")),
            ["ashypass_docs", "ashypass_docs_aaaaaaaa"]
        );
        assert_eq!(
            unlock_candidates(MapperChoice::FromLabel("docs"), node, None),
            ["ashypass_docs", "ashypass_docs_sdc1"]
        );
        assert_eq!(
            unlock_candidates(MapperChoice::Explicit("ashypass_foo"), node, None),
            ["ashypass_foo"]
        );
    }

    #[test]
    fn explicit_mapper_names_are_validated() {
        let node = Path::new("/dev/sdc1");
        let candidates = unlock_candidates(MapperChoice::Explicit("foo"), node, None);
        assert!(pick_mapper(&candidates, |_| MapperState::Free).is_err());
    }

    #[test]
    fn unlock_refuses_missing_device_before_prompting_privileges() {
        struct NoRunner;
        impl Runner for NoRunner {
            fn run(&self, _: crate::runner::CommandSpec) -> Result<crate::runner::CommandOutput> {
                panic!("must not run anything");
            }
        }
        let pp = Passphrase::from_text("secret");
        assert!(unlock_existing(
            &NoRunner,
            Path::new("/dev/does-not-exist-ashypass"),
            "x",
            &pp,
            false
        )
        .is_err());
        // A regular file is not a block device.
        let file = tempfile::NamedTempFile::new().unwrap();
        assert!(unlock_existing(&NoRunner, file.path(), "x", &pp, false).is_err());
    }
}
