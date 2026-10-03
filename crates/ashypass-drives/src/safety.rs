//! Pre-condition checks that must pass before any destructive operation
//! touches a block device.
//!
//! The cost of a false positive here (refusing a legitimate format) is a
//! confused user. The cost of a false negative (formatting the rootfs) is
//! catastrophic data loss. We err strongly toward refusal.

use crate::detect::{find_disk, list_all, Drive};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// What the user saw and confirmed about a drive. Carried along with every
/// destructive request so a stale snapshot, or a swapped stick that happens
/// to get the same `/dev/sdX`, is refused instead of erased.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub serial: Option<String>,
    pub size_bytes: u64,
    pub model: Option<String>,
}

impl DeviceIdentity {
    pub fn of(drive: &Drive) -> Self {
        Self {
            serial: drive.serial.clone(),
            size_bytes: drive.size_bytes,
            model: drive.model.clone(),
        }
    }

    /// Refuse unless `actual` is the same device the user confirmed.
    pub fn verify(&self, actual: &DeviceIdentity) -> Result<()> {
        let none = "(none)";
        let mut diffs = Vec::new();
        if self.serial != actual.serial {
            diffs.push(format!(
                "serial is {} instead of {}",
                actual.serial.as_deref().unwrap_or(none),
                self.serial.as_deref().unwrap_or(none)
            ));
        }
        if self.size_bytes != actual.size_bytes {
            diffs.push(format!(
                "size is {} instead of {} bytes",
                actual.size_bytes, self.size_bytes
            ));
        }
        if self.model != actual.model {
            diffs.push(format!(
                "model is {} instead of {}",
                actual.model.as_deref().unwrap_or(none),
                self.model.as_deref().unwrap_or(none)
            ));
        }
        if diffs.is_empty() {
            Ok(())
        } else {
            Err(Error::Refused(format!(
                "device changed since it was confirmed: {}",
                diffs.join("; ")
            )))
        }
    }
}

/// Outcome of a safety inspection. Includes the resolved stable path
/// (`/dev/disk/by-id/...`) so the caller can pin the exact device for
/// subsequent operations even if udev re-numbers `sda`.
#[derive(Debug)]
pub struct SafetyReport {
    /// Stable path (`/dev/disk/by-id/...` when available) to use for every
    /// subsequent step.
    pub canonical_path: PathBuf,
    /// Kernel node the request resolved to (e.g. `/dev/sdb`).
    pub device_node: PathBuf,
    pub serial: Option<String>,
    pub size_bytes: u64,
    pub model: Option<String>,
    pub vendor: Option<String>,
    pub allow_destructive: bool,
    pub reasons: Vec<String>,
}

impl SafetyReport {
    pub fn identity(&self) -> DeviceIdentity {
        DeviceIdentity {
            serial: self.serial.clone(),
            size_bytes: self.size_bytes,
            model: self.model.clone(),
        }
    }

    pub fn assert_safe(&self) -> Result<()> {
        if self.allow_destructive {
            Ok(())
        } else {
            Err(Error::Refused(self.reasons.join("; ")))
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SafetyPolicy {
    /// If true, drives without the `removable` or `hotplug` flag are still
    /// accepted. Default: false. Only used in test environments.
    pub allow_fixed: bool,
    /// If true, ignore active mounts. **Never** set this in user-facing code.
    pub allow_mounted: bool,
}

/// Inspect `device` against every guard we know about. `device` is either a
/// whole-disk kernel node (`/dev/sda`) or a stable link under `/dev/disk/`
/// (`/dev/disk/by-id/usb-...`) that resolves to one.
pub fn inspect(device: &Path, policy: SafetyPolicy) -> Result<SafetyReport> {
    let drives = list_all()?;
    let resolved = fs::canonicalize(device)
        .map_err(|_| Error::Refused(format!("device not found: {}", device.display())))?;
    let drive = locate_disk(&drives, device, &resolved)?;
    let pinned = if is_stable_link(device) {
        device.to_path_buf()
    } else {
        resolve_by_id(&resolved).unwrap_or_else(|| resolved.clone())
    };

    let mut reasons = Vec::new();
    let mut allow = true;

    if !(policy.allow_fixed || drive.removable || drive.hotplug) {
        allow = false;
        reasons.push("device is not removable or hotplug-capable".into());
    }

    if drive.read_only {
        allow = false;
        reasons.push("device is read-only".into());
    }

    if !policy.allow_mounted {
        if let Some(mp) = first_mounted_volume(drive) {
            allow = false;
            reasons.push(format!("partition currently mounted at {mp}"));
        }
        if let Some(mapping) = first_active_mapping(drive) {
            allow = false;
            reasons.push(format!(
                "device has an open encrypted mapping (/dev/mapper/{mapping})"
            ));
        }
        if hosts_rootfs(drive)? {
            allow = false;
            reasons.push("device hosts the running root filesystem".into());
        }
        if hosts_active_swap(drive)? {
            allow = false;
            reasons.push("device holds an active swap area".into());
        }
    }

    if listed_in_crypttab(drive)? {
        allow = false;
        reasons.push("device is referenced in /etc/crypttab".into());
    }

    Ok(SafetyReport {
        canonical_path: pinned,
        device_node: resolved,
        serial: drive.serial.clone(),
        size_bytes: drive.size_bytes,
        model: drive.model.clone(),
        vendor: drive.vendor.clone(),
        allow_destructive: allow,
        reasons,
    })
}

/// True for the udev-maintained stable links (`/dev/disk/by-id/<name>`,
/// `/dev/disk/by-path/<name>`, …).
pub fn is_stable_link(path: &Path) -> bool {
    path.starts_with("/dev/disk/")
        && path.components().count() == 5
        && !path
            .components()
            .any(|c| c == std::path::Component::ParentDir)
}

/// Match a requested path to a detected whole disk. Pure: `resolved` is the
/// canonicalised `requested`.
///
/// The request is accepted only if `resolved` is a disk node (partitions and
/// mapper devices never match) and `requested` is either that node itself or
/// a stable `/dev/disk/...` link to it. Any other symlink is refused so a
/// user-writable link cannot redirect a destructive operation.
pub fn locate_disk<'a>(
    drives: &'a [Drive],
    requested: &Path,
    resolved: &Path,
) -> Result<&'a Drive> {
    let drive = find_disk(drives, resolved).ok_or_else(|| {
        Error::Refused(format!(
            "{} is not a detected whole-disk device",
            requested.display()
        ))
    })?;
    if requested != resolved && !is_stable_link(requested) {
        return Err(Error::Refused(format!(
            "{} is a symlink outside /dev/disk; pass the device node or a /dev/disk/by-id path",
            requested.display()
        )));
    }
    Ok(drive)
}

fn first_mounted_volume(drive: &Drive) -> Option<String> {
    drive.mountpoint.clone().or_else(|| {
        drive
            .volumes()
            .find_map(|p| p.mountpoint.clone().or_else(|| p.inner_mountpoint.clone()))
    })
}

/// First open dm-crypt mapping on the drive. A leftover wipe mapping from an
/// interrupted run is ignored here: the wipe step recognises it as ours and
/// closes it before reusing the device.
fn first_active_mapping(drive: &Drive) -> Option<String> {
    drive
        .volumes()
        .filter_map(|v| v.active_mapping.clone())
        .find(|name| !crate::wipe::is_wipe_mapper(name))
}

/// True if the device or any of its volumes backs `/`.
fn hosts_rootfs(drive: &Drive) -> Result<bool> {
    let mounts = fs::read_to_string("/proc/mounts")?;
    let root_source = mounts
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let source = parts.next()?;
            let target = parts.next()?;
            if target == "/" {
                Some(source.to_string())
            } else {
                None
            }
        })
        .next();

    let Some(root) = root_source else {
        return Ok(false);
    };

    // Resolve the root source through `/dev/disk/by-uuid/...` style symlinks.
    let resolved = fs::canonicalize(&root).unwrap_or_else(|_| PathBuf::from(&root));

    if resolved.as_path() == Path::new(&drive.path) {
        return Ok(true);
    }
    for p in drive.volumes() {
        if resolved.as_path() == Path::new(&p.path) {
            return Ok(true);
        }
        if p.active_mapping.as_ref().is_some_and(|name| {
            let mapper = PathBuf::from(format!("/dev/mapper/{name}"));
            resolved == mapper || fs::canonicalize(&mapper).is_ok_and(|m| m == resolved)
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn hosts_active_swap(drive: &Drive) -> Result<bool> {
    let Ok(swaps) = fs::read_to_string("/proc/swaps") else {
        return Ok(false);
    };
    for line in swaps.lines().skip(1) {
        let Some(source) = line.split_whitespace().next() else {
            continue;
        };
        let resolved = fs::canonicalize(source).unwrap_or_else(|_| PathBuf::from(source));
        if resolved.as_path() == Path::new(&drive.path) {
            return Ok(true);
        }
        for p in drive.volumes() {
            if resolved.as_path() == Path::new(&p.path) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn listed_in_crypttab(drive: &Drive) -> Result<bool> {
    let Ok(crypttab) = fs::read_to_string("/etc/crypttab") else {
        return Ok(false);
    };
    let devices: Vec<PathBuf> = std::iter::once(PathBuf::from(&drive.path))
        .chain(drive.volumes().map(|volume| PathBuf::from(&volume.path)))
        .map(|path| fs::canonicalize(&path).unwrap_or(path))
        .collect();
    Ok(crypttab.lines().any(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return false;
        }
        let Some(source) = trimmed.split_whitespace().nth(1) else {
            return false;
        };
        let source_path = if let Some(uuid) = source.strip_prefix("UUID=") {
            PathBuf::from("/dev/disk/by-uuid").join(uuid)
        } else if source.starts_with("/dev/") {
            PathBuf::from(source)
        } else {
            return false;
        };
        let resolved = fs::canonicalize(&source_path).unwrap_or(source_path);
        devices.iter().any(|device| device == &resolved)
    }))
}

/// Walk `/dev/disk/by-id/` looking for a symlink whose target is `device`.
/// The by-id name encodes vendor/model/serial and is stable across reboots
/// and re-plugs, which makes it the right handle to pin between the safety
/// check and the destructive call. Entries are visited in sorted order so
/// the choice is deterministic.
pub fn resolve_by_id(device: &Path) -> Option<PathBuf> {
    let dir = fs::read_dir("/dev/disk/by-id").ok()?;
    let target_canon = fs::canonicalize(device).ok()?;
    let mut entries: Vec<PathBuf> = dir.flatten().map(|e| e.path()).collect();
    entries.sort();
    entries
        .into_iter()
        .find(|path| fs::canonicalize(path).is_ok_and(|resolved| resolved == target_canon))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::parse_lsblk;

    const FIXTURE: &str = include_str!("../tests/fixtures/lsblk_mixed.json");

    fn drives() -> Vec<Drive> {
        parse_lsblk(FIXTURE.as_bytes()).unwrap()
    }

    #[test]
    fn locates_disk_by_node_and_by_id_link() {
        let drives = drives();
        let by_node = locate_disk(&drives, Path::new("/dev/sdb"), Path::new("/dev/sdb")).unwrap();
        assert_eq!(by_node.path, "/dev/sdb");

        let by_id = Path::new("/dev/disk/by-id/usb-Kingston_DataTraveler_3.0_E0D55EA5-0:0");
        let found = locate_disk(&drives, by_id, Path::new("/dev/sdb")).unwrap();
        assert_eq!(found.path, "/dev/sdb");
        assert_eq!(found.serial.as_deref(), Some("E0D55EA5"));
    }

    #[test]
    fn refuses_partitions_mappers_and_foreign_symlinks() {
        let drives = drives();
        // A partition is never a valid destructive target.
        assert!(locate_disk(&drives, Path::new("/dev/sdc1"), Path::new("/dev/sdc1")).is_err());
        // A by-id link that resolves to a partition is refused too.
        assert!(locate_disk(
            &drives,
            Path::new("/dev/disk/by-id/usb-SanDisk_Cruzer-0:0-part1"),
            Path::new("/dev/sdc1"),
        )
        .is_err());
        // Mapper devices are not disks.
        assert!(locate_disk(
            &drives,
            Path::new("/dev/mapper/ashypass_vault"),
            Path::new("/dev/dm-0"),
        )
        .is_err());
        // Unknown device.
        assert!(locate_disk(&drives, Path::new("/dev/sdz"), Path::new("/dev/sdz")).is_err());
        // A symlink planted outside /dev/disk is refused even if it points at
        // a real removable disk.
        assert!(locate_disk(&drives, Path::new("/tmp/stick"), Path::new("/dev/sdb")).is_err());
        assert!(locate_disk(
            &drives,
            Path::new("/dev/disk/by-id/../../sdb"),
            Path::new("/dev/sdb"),
        )
        .is_err());
    }

    #[test]
    fn stable_link_shape() {
        assert!(is_stable_link(Path::new("/dev/disk/by-id/usb-X-0:0")));
        assert!(is_stable_link(Path::new(
            "/dev/disk/by-path/pci-0000:00:14.0-usb-0:1:1.0-scsi-0:0:0:0"
        )));
        assert!(!is_stable_link(Path::new("/dev/disk/by-id")));
        assert!(!is_stable_link(Path::new("/dev/sdb")));
        assert!(!is_stable_link(Path::new("/dev/disk/by-id/a/b")));
    }

    #[test]
    fn identity_detects_swapped_or_stale_device() {
        let drives = drives();
        let confirmed = DeviceIdentity::of(find_disk(&drives, Path::new("/dev/sdb")).unwrap());
        assert!(confirmed.verify(&confirmed.clone()).is_ok());

        let mut other_serial = confirmed.clone();
        other_serial.serial = Some("DEADBEEF".into());
        assert!(confirmed.verify(&other_serial).is_err());

        let mut other_size = confirmed.clone();
        other_size.size_bytes += 512;
        assert!(confirmed.verify(&other_size).is_err());

        let mut no_serial = confirmed.clone();
        no_serial.serial = None;
        assert!(confirmed.verify(&no_serial).is_err());

        // A different stick that took over /dev/sdb is caught.
        let sdc = DeviceIdentity::of(find_disk(&drives, Path::new("/dev/sdc")).unwrap());
        assert!(confirmed.verify(&sdc).is_err());
    }

    #[test]
    fn identity_roundtrips_through_json() {
        let id = DeviceIdentity {
            serial: Some("ABC".into()),
            size_bytes: 42,
            model: None,
        };
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(serde_json::from_str::<DeviceIdentity>(&json).unwrap(), id);
    }

    #[test]
    fn open_mappings_block_destruction_except_stale_wipe() {
        let drives = drives();
        let unlocked = find_disk(&drives, Path::new("/dev/sdd")).unwrap();
        assert_eq!(
            first_active_mapping(unlocked).as_deref(),
            Some("ashypass_vault")
        );
        let stale_wipe = find_disk(&drives, Path::new("/dev/sde")).unwrap();
        assert_eq!(first_active_mapping(stale_wipe), None);
    }
}
