//! Pre-condition checks that must pass before any destructive operation
//! touches a block device.
//!
//! The cost of a false positive here (refusing a legitimate format) is a
//! confused user. The cost of a false negative (formatting the rootfs) is
//! catastrophic data loss. We err strongly toward refusal.

use crate::detect::{find_disk, list_all, Drive, Partition};
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
    /// File name of the `/dev/disk/by-id/` link (e.g.
    /// `usb-Kingston_DataTraveler_3.0_E0D55EA5-0:0`). Only known after a
    /// [`inspect`], never from `lsblk`. It is derived from the path being
    /// inspected, so on its own it proves nothing: it only counts as
    /// evidence when it embeds the serial number or WWN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_id: Option<String>,
    /// World Wide Name, when the device reports one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wwn: Option<String>,
    /// Partition table UUID. Legitimately disappears once the drive is
    /// wiped, so it only counts when both sides report it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ptuuid: Option<String>,
    /// Kernel disk sequence number (`/sys/block/<disk>/diskseq`, Linux 5.15
    /// and later). Never reused within a boot: a re-plugged or swapped
    /// device gets a new one. Compared only when both sides know it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diskseq: Option<u64>,
}

impl DeviceIdentity {
    pub fn of(drive: &Drive) -> Self {
        Self {
            serial: drive.serial.clone(),
            size_bytes: drive.size_bytes,
            model: drive.model.clone(),
            by_id: None,
            wwn: drive.wwn.clone(),
            ptuuid: drive.ptuuid.clone(),
            diskseq: drive.diskseq,
        }
    }

    /// Refuse unless `actual` is the same device the user confirmed.
    ///
    /// Serial, size and model must match exactly, as before. The by-id link,
    /// WWN, partition table UUID and disk sequence number are compared only
    /// when both sides know them (`lsblk` does not always report them, older
    /// kernels have no `diskseq`, and a wipe removes the partition table).
    /// On top of that at least one stable identifier (serial, WWN, PTUUID or
    /// disk sequence number) must be present on both sides and equal: two
    /// serial-less sticks of the same model and size are not "the same
    /// device" just because every field is empty. A matching by-id link only
    /// counts when it embeds the serial or WWN, since it is derived from the
    /// very path the caller asked for.
    pub fn verify(&self, actual: &DeviceIdentity) -> Result<()> {
        self.check_unchanged(actual)?;
        let positive = |a: &Option<String>, b: &Option<String>| a.is_some() && a == b;
        if positive(&self.serial, &actual.serial)
            || positive(&self.wwn, &actual.wwn)
            || positive(&self.ptuuid, &actual.ptuuid)
            || (self.diskseq.is_some() && self.diskseq == actual.diskseq)
            || (positive(&self.by_id, &actual.by_id) && self.by_id_embeds_hardware_id())
        {
            Ok(())
        } else {
            Err(Error::Refused(
                "the device has no serial number, WWN, partition table UUID or \
                 disk sequence number to confirm its identity"
                    .into(),
            ))
        }
    }

    /// True when the by-id link name contains the serial number or the WWN
    /// (udev replaces whitespace with `_` in link names).
    fn by_id_embeds_hardware_id(&self) -> bool {
        let Some(by_id) = self.by_id.as_deref() else {
            return false;
        };
        let by_id = by_id.to_ascii_lowercase();
        [&self.serial, &self.wwn]
            .into_iter()
            .flatten()
            .map(|id| {
                id.trim()
                    .replace(char::is_whitespace, "_")
                    .to_ascii_lowercase()
            })
            .any(|id| !id.is_empty() && by_id.contains(&id))
    }

    /// The field comparison of [`Self::verify`] without the requirement of
    /// a positively matching identifier. Only for checking a fresh
    /// inspection against the `lsblk` snapshot the UI displayed, which never
    /// carries a by-id link; anything destructive must use [`Self::verify`]
    /// with an identity taken from a [`SafetyReport`].
    pub fn check_unchanged(&self, actual: &DeviceIdentity) -> Result<()> {
        let none = "(none)";
        let mut diffs = Vec::new();
        for (name, confirmed, current) in [
            ("by-id link", &self.by_id, &actual.by_id),
            ("WWN", &self.wwn, &actual.wwn),
            ("partition table UUID", &self.ptuuid, &actual.ptuuid),
        ] {
            if let (Some(confirmed), Some(current)) = (confirmed, current) {
                if confirmed != current {
                    diffs.push(format!("{name} is {current} instead of {confirmed}"));
                }
            }
        }
        if let (Some(confirmed), Some(current)) = (self.diskseq, actual.diskseq) {
            if confirmed != current {
                diffs.push(format!(
                    "disk sequence number is {current} instead of {confirmed}"
                ));
            }
        }
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
    pub wwn: Option<String>,
    pub ptuuid: Option<String>,
    /// Kernel disk sequence number, when the kernel exposes it.
    pub diskseq: Option<u64>,
    pub allow_destructive: bool,
    pub reasons: Vec<String>,
}

impl SafetyReport {
    pub fn identity(&self) -> DeviceIdentity {
        DeviceIdentity {
            serial: self.serial.clone(),
            size_bytes: self.size_bytes,
            model: self.model.clone(),
            by_id: by_id_name(&self.canonical_path),
            wwn: self.wwn.clone(),
            ptuuid: self.ptuuid.clone(),
            diskseq: self.diskseq,
        }
    }

    /// True when the device is pinned by a `/dev/disk/by-id/` link. The
    /// privileged helper refuses anything else, so callers should check this
    /// before asking the user for a passphrase.
    pub fn pinned_by_id(&self) -> bool {
        by_id_name(&self.canonical_path).is_some()
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
    // Keep a hardware-derived by-id link the caller passed; anything else
    // (kernel node, by-path link, a content-derived by-id link that a wipe
    // would remove) is re-pinned to the best hardware-derived link.
    let pinned = if by_id_name(device).is_some_and(|name| by_id_rank(&name).is_some()) {
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
        if let Some(stacked) = drive.stacked.first() {
            allow = false;
            reasons.push(format!("device is in use by {stacked}"));
        }
        if let Some(holder) = first_holder(Path::new(SYS_BLOCK), drive) {
            allow = false;
            reasons.push(format!("device is in use: {holder}"));
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
        wwn: drive.wwn.clone(),
        ptuuid: drive.ptuuid.clone(),
        diskseq: drive.diskseq,
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

/// Check the target of a non-destructive LUKS operation (unlock, FIDO2
/// enrolment): `node` (canonical kernel node) must be a `crypto_LUKS` volume
/// (whole disk or partition) of a detected removable / hotplug drive. With
/// `require_locked`, the volume must not already have an open mapping.
pub fn check_luks_volume<'a>(
    drives: &'a [Drive],
    node: &Path,
    require_locked: bool,
) -> Result<&'a Partition> {
    let drive = crate::detect::find_volume_owner(drives, node).ok_or_else(|| {
        Error::Refused(format!(
            "{} is not a volume of a detected drive",
            node.display()
        ))
    })?;
    if !(drive.removable || drive.hotplug) {
        return Err(Error::Refused(
            "device is not removable or hotplug-capable".into(),
        ));
    }
    let volume = drive
        .volumes()
        .find(|v| Path::new(&v.path) == node)
        .ok_or_else(|| Error::Refused(format!("{} holds no volume", node.display())))?;
    if volume.fstype.as_deref() != Some("crypto_LUKS") {
        return Err(Error::Refused(format!(
            "{} is not a LUKS volume",
            node.display()
        )));
    }
    if require_locked {
        if let Some(mapping) = &volume.active_mapping {
            return Err(Error::Refused(format!(
                "{} is already unlocked as /dev/mapper/{mapping}",
                node.display()
            )));
        }
    }
    Ok(volume)
}

/// Check that `mapper_name` may be locked: an Ashy Pass mapping (by name)
/// of a volume on a detected removable / hotplug drive, and no longer
/// mounted. Returns the backing volume.
pub fn check_lock_target<'a>(drives: &'a [Drive], mapper_name: &str) -> Result<&'a Partition> {
    crate::validate::validate_mapper_name(mapper_name)?;
    let (drive, volume) = drives
        .iter()
        .find_map(|drive| {
            drive
                .volumes()
                .find(|v| v.active_mapping.as_deref() == Some(mapper_name))
                .map(|volume| (drive, volume))
        })
        .ok_or_else(|| {
            Error::Refused(format!(
                "/dev/mapper/{mapper_name} is not open on a detected drive"
            ))
        })?;
    if !(drive.removable || drive.hotplug) {
        return Err(Error::Refused(
            "device is not removable or hotplug-capable".into(),
        ));
    }
    if let Some(mountpoint) = &volume.inner_mountpoint {
        return Err(Error::Refused(format!(
            "/dev/mapper/{mapper_name} is still mounted at {mountpoint}"
        )));
    }
    Ok(volume)
}

const SYS_BLOCK: &str = "/sys/block";

/// First kernel holder of the disk or one of its partitions, read from
/// `<sys_block>/<disk>/holders` and `<sys_block>/<disk>/<part>/holders`.
/// Catches stacking `lsblk` may not show (bcache, a dm table set up by
/// another tool, an md array being assembled). Holders that are the
/// dm-crypt mappings already reported by [`first_active_mapping`], or a
/// stale wipe mapping of ours, are skipped.
fn first_holder(sys_block: &Path, drive: &Drive) -> Option<String> {
    let disk_dir = sys_block.join(&drive.name);
    let known_mappings: Vec<&str> = drive
        .volumes()
        .filter_map(|v| v.active_mapping.as_deref())
        .collect();
    let dirs = std::iter::once((drive.name.as_str(), disk_dir.join("holders"))).chain(
        drive
            .partitions
            .iter()
            .map(|p| (p.name.as_str(), disk_dir.join(&p.name).join("holders"))),
    );
    for (owner, dir) in dirs {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        let mut holders: Vec<String> = entries
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .collect();
        holders.sort();
        for holder in holders {
            let dm_name = fs::read_to_string(sys_block.join(&holder).join("dm").join("name"))
                .ok()
                .map(|name| name.trim().to_string());
            match dm_name.as_deref() {
                Some(name) if crate::wipe::is_wipe_mapper(name) => continue,
                Some(name) if known_mappings.contains(&name) => continue,
                Some(name) => return Some(format!("{owner} is held by {holder} ({name})")),
                None => return Some(format!("{owner} is held by {holder}")),
            }
        }
    }
    None
}

/// File name of `path` when it is a `/dev/disk/by-id/<name>` link.
fn by_id_name(path: &Path) -> Option<String> {
    if !path.starts_with("/dev/disk/by-id") || !is_stable_link(path) {
        return None;
    }
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
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

const BY_ID_DIR: &str = "/dev/disk/by-id";

/// Prefixes of `/dev/disk/by-id/` links that udev derives from the hardware
/// (WWN, or transport plus vendor/model/serial), in order of preference.
/// Links derived from the content of the device (`lvm-pv-uuid-*`, `md-*`,
/// `dm-*`, …) change or vanish once the drive is wiped, so they are never
/// used to pin a device.
const HARDWARE_BY_ID_PREFIXES: &[&str] = &[
    "wwn-",
    "usb-",
    "ata-",
    "scsi-",
    "nvme-",
    "mmc-",
    "ieee1394-",
    "memstick-",
];

/// Preference rank of a by-id link name, `None` when the name is not derived
/// from the hardware.
fn by_id_rank(name: &str) -> Option<usize> {
    HARDWARE_BY_ID_PREFIXES
        .iter()
        .position(|prefix| name.starts_with(prefix))
}

/// Best hardware-derived link name among `names`: lowest prefix rank, then
/// alphabetical so the choice is deterministic.
fn pick_by_id(names: impl IntoIterator<Item = String>) -> Option<String> {
    names
        .into_iter()
        .filter_map(|name| by_id_rank(&name).map(|rank| (rank, name)))
        .min()
        .map(|(_, name)| name)
}

/// Walk `/dev/disk/by-id/` looking for a hardware-derived symlink (see
/// [`HARDWARE_BY_ID_PREFIXES`]) whose target is `device`. Such a name encodes
/// the WWN or vendor/model/serial and survives reboots, re-plugs and wipes,
/// which makes it the right handle to pin between the safety check and the
/// destructive call.
pub fn resolve_by_id(device: &Path) -> Option<PathBuf> {
    let dir = fs::read_dir(BY_ID_DIR).ok()?;
    let target_canon = fs::canonicalize(device).ok()?;
    let names = dir
        .flatten()
        .filter(|entry| fs::canonicalize(entry.path()).is_ok_and(|r| r == target_canon))
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string));
    pick_by_id(names).map(|name| Path::new(BY_ID_DIR).join(name))
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
            by_id: Some("usb-X_ABC-0:0".into()),
            wwn: None,
            ptuuid: Some("1a2b3c4d".into()),
            diskseq: Some(17),
        };
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(serde_json::from_str::<DeviceIdentity>(&json).unwrap(), id);
        // Identities from before the new fields still parse.
        let old: DeviceIdentity =
            serde_json::from_str(r#"{"serial":"ABC","size_bytes":42,"model":null}"#).unwrap();
        assert_eq!((old.by_id, old.wwn, old.ptuuid), (None, None, None));
        assert_eq!(old.diskseq, None);
    }

    fn serialless(by_id: Option<&str>) -> DeviceIdentity {
        DeviceIdentity {
            serial: None,
            size_bytes: 8_053_063_680,
            model: Some("Flash Disk".into()),
            by_id: by_id.map(str::to_string),
            wwn: None,
            ptuuid: None,
            diskseq: None,
        }
    }

    #[test]
    fn empty_fields_alone_never_prove_identity() {
        // Same model and size, nothing else: two generic sticks would look
        // identical, so this must be refused.
        let bare = serialless(None);
        assert!(bare.verify(&bare.clone()).is_err());
        // The snapshot comparison alone does not demand evidence.
        assert!(bare.check_unchanged(&bare.clone()).is_ok());
        assert!(bare.check_unchanged(&serialless(Some("usb-x-0:0"))).is_ok());
        let drives = drives();
        let sde = DeviceIdentity::of(find_disk(&drives, Path::new("/dev/sde")).unwrap());
        assert!(sde.verify(&sde.clone()).is_err());

        // A matching by-id link is derived from the requested path, so it
        // proves nothing unless it embeds the serial or WWN.
        let linked = serialless(Some("usb-Generic_Flash_Disk_1234-0:0"));
        assert!(linked.verify(&linked.clone()).is_err());
        // A different link is a different device.
        assert!(linked
            .verify(&serialless(Some("usb-Generic_Flash_Disk_9999-0:0")))
            .is_err());
    }

    #[test]
    fn by_id_counts_only_when_it_embeds_the_serial_or_wwn() {
        // The WWN is in the link but `lsblk` did not report it this time.
        let mut confirmed = serialless(Some("wwn-0x5000c500a1b2c3d4"));
        confirmed.wwn = Some("0x5000C500A1B2C3D4".into());
        let mut current = confirmed.clone();
        current.wwn = None;
        assert!(confirmed.verify(&current).is_ok());
        // A link that does not carry the WWN does not count.
        let mut other = confirmed.clone();
        other.by_id = Some("usb-Generic_Flash_Disk-0:0".into());
        let mut other_current = other.clone();
        other_current.wwn = None;
        assert!(other.verify(&other_current).is_err());
        // A serial with spaces matches udev's underscore form.
        let mut spaced = serialless(Some("usb-Generic_Flash_AB_12-0:0"));
        spaced.serial = Some("AB 12".into());
        assert!(spaced.by_id_embeds_hardware_id());
        spaced.serial = Some("   ".into());
        assert!(!spaced.by_id_embeds_hardware_id());
    }

    #[test]
    fn disk_sequence_number_is_evidence_and_detects_a_replug() {
        let mut confirmed = serialless(None);
        confirmed.diskseq = Some(42);
        assert!(confirmed.verify(&confirmed.clone()).is_ok());
        // Re-plugged or swapped: new sequence number.
        let mut replugged = confirmed.clone();
        replugged.diskseq = Some(43);
        assert!(confirmed.verify(&replugged).is_err());
        assert!(confirmed.check_unchanged(&replugged).is_err());
        // Unknown on one side: not compared, and not evidence either.
        let mut unknown = confirmed.clone();
        unknown.diskseq = None;
        assert!(confirmed.check_unchanged(&unknown).is_ok());
        assert!(confirmed.verify(&unknown).is_err());
        assert!(unknown.verify(&confirmed).is_err());
    }

    #[test]
    fn pins_only_hardware_derived_by_id_links() {
        let names = |list: &[&str]| list.iter().map(|n| n.to_string()).collect::<Vec<_>>();
        // Content-derived links sort first alphabetically but are skipped.
        assert_eq!(
            pick_by_id(names(&[
                "dm-name-foo",
                "lvm-pv-uuid-abc",
                "md-uuid-1234",
                "usb-Kingston_DataTraveler_3.0_E0D55EA5-0:0",
            ]))
            .as_deref(),
            Some("usb-Kingston_DataTraveler_3.0_E0D55EA5-0:0")
        );
        // The WWN wins over the transport links.
        assert_eq!(
            pick_by_id(names(&[
                "ata-Samsung_SSD_870_S1234",
                "usb-X-0:0",
                "wwn-0x5002538e40000000",
            ]))
            .as_deref(),
            Some("wwn-0x5002538e40000000")
        );
        // Then usb-, ata-, scsi-, nvme-, mmc-, …
        assert_eq!(
            pick_by_id(names(&["scsi-SX", "ata-X", "usb-X"])).as_deref(),
            Some("usb-X")
        );
        assert_eq!(
            pick_by_id(names(&["scsi-SX", "ata-X"])).as_deref(),
            Some("ata-X")
        );
        assert_eq!(
            pick_by_id(names(&["mmc-SD_0x1", "nvme-eui.1"])).as_deref(),
            Some("nvme-eui.1")
        );
        // Same rank: alphabetical.
        assert_eq!(
            pick_by_id(names(&["usb-B-0:0", "usb-A-0:0"])).as_deref(),
            Some("usb-A-0:0")
        );
        // Nothing hardware-derived: no pin.
        assert_eq!(pick_by_id(names(&["lvm-pv-uuid-abc", "md-name-x"])), None);
        for name in ["ieee1394-0x1", "memstick-X"] {
            assert!(by_id_rank(name).is_some(), "{name}");
        }
    }

    #[test]
    fn optional_identifiers_are_compared_only_when_both_known() {
        let drives = drives();
        let mut confirmed = DeviceIdentity::of(find_disk(&drives, Path::new("/dev/sdb")).unwrap());
        confirmed.ptuuid = Some("1a2b3c4d".into());
        confirmed.by_id = Some("usb-Kingston_DataTraveler_3.0_E0D55EA5-0:0".into());

        // lsblk did not report it, or the wipe removed the partition table.
        let mut wiped = confirmed.clone();
        wiped.ptuuid = None;
        wiped.by_id = None;
        assert!(confirmed.verify(&wiped).is_ok());

        let mut other_table = confirmed.clone();
        other_table.ptuuid = Some("deadbeef".into());
        assert!(confirmed.verify(&other_table).is_err());

        let mut other_wwn = confirmed.clone();
        confirmed.wwn = Some("0x5000000000000001".into());
        other_wwn.wwn = Some("0x5000000000000002".into());
        assert!(confirmed.verify(&other_wwn).is_err());
    }

    #[test]
    fn unlock_targets_must_be_luks_volumes_on_removable_drives() {
        let drives = drives();
        // Locked whole-disk LUKS on a hotplug drive.
        let sdf = check_luks_volume(&drives, Path::new("/dev/sdf"), true).unwrap();
        assert_eq!(sdf.label.as_deref(), Some("backup"));
        // Already unlocked: refused for unlock, fine for FIDO2 enrolment.
        assert!(check_luks_volume(&drives, Path::new("/dev/sdc1"), true).is_err());
        assert!(check_luks_volume(&drives, Path::new("/dev/sdc1"), false).is_ok());
        // Not LUKS, not removable, not a volume, unknown.
        assert!(check_luks_volume(&drives, Path::new("/dev/sdb1"), false).is_err());
        assert!(check_luks_volume(&drives, Path::new("/dev/sda2"), false).is_err());
        assert!(check_luks_volume(&drives, Path::new("/dev/sdb"), false).is_err());
        assert!(check_luks_volume(&drives, Path::new("/dev/sdz1"), false).is_err());
    }

    #[test]
    fn lock_targets_must_be_unmounted_ashypass_mappings() {
        let drives = drives();
        // Still mounted: the GUI unmounts through udisks first.
        let mounted = check_lock_target(&drives, "ashypass_vault").unwrap_err();
        assert!(mounted.to_string().contains("still mounted"), "{mounted}");
        // Opened by udisks: not ours to close.
        assert!(check_lock_target(&drives, "luks-aaaaaaaa").is_err());
        // Not open anywhere.
        assert!(check_lock_target(&drives, "ashypass_nothing").is_err());

        let mut unmounted = drives.clone();
        let sdd = unmounted.iter_mut().find(|d| d.name == "sdd").unwrap();
        sdd.whole_disk.as_mut().unwrap().inner_mountpoint = None;
        let volume = check_lock_target(&unmounted, "ashypass_vault").unwrap();
        assert_eq!(volume.path, "/dev/sdd");
    }

    #[test]
    fn by_id_pinning() {
        assert_eq!(
            by_id_name(Path::new("/dev/disk/by-id/usb-X-0:0")).as_deref(),
            Some("usb-X-0:0")
        );
        assert_eq!(
            by_id_name(Path::new("/dev/disk/by-path/pci-0000:00:14.0")),
            None
        );
        assert_eq!(by_id_name(Path::new("/dev/sdb")), None);
    }

    #[test]
    fn sysfs_holders_mark_the_drive_in_use() {
        let all = drives();
        let sdb = find_disk(&all, Path::new("/dev/sdb")).unwrap();
        let sys = tempfile::tempdir().unwrap();
        let root = sys.path();
        std::fs::create_dir_all(root.join("sdb/holders")).unwrap();
        std::fs::create_dir_all(root.join("sdb/sdb1/holders")).unwrap();
        assert_eq!(first_holder(root, sdb), None);

        // Our own stale wipe mapping is tolerated (handled by the wipe step).
        std::fs::create_dir_all(root.join("dm-0/dm")).unwrap();
        std::fs::write(root.join("dm-0/dm/name"), "ashypass_wipe_tmp\n").unwrap();
        std::fs::write(root.join("sdb/holders/dm-0"), "").unwrap();
        assert_eq!(first_holder(root, sdb), None);

        // Anything else holding a partition is not.
        std::fs::write(root.join("sdb/sdb1/holders/md127"), "").unwrap();
        assert_eq!(
            first_holder(root, sdb).as_deref(),
            Some("sdb1 is held by md127")
        );

        // A named dm target on the disk is reported with its name.
        std::fs::create_dir_all(root.join("dm-1/dm")).unwrap();
        std::fs::write(root.join("dm-1/dm/name"), "vg0-data\n").unwrap();
        std::fs::write(root.join("sdb/holders/dm-1"), "").unwrap();
        assert_eq!(
            first_holder(root, sdb).as_deref(),
            Some("sdb is held by dm-1 (vg0-data)")
        );
    }

    #[test]
    fn known_crypt_mappings_are_not_reported_twice() {
        let all = drives();
        let sdd = find_disk(&all, Path::new("/dev/sdd")).unwrap();
        let sys = tempfile::tempdir().unwrap();
        let root = sys.path();
        std::fs::create_dir_all(root.join("dm-2/dm")).unwrap();
        std::fs::write(root.join("dm-2/dm/name"), "ashypass_vault\n").unwrap();
        std::fs::create_dir_all(root.join("sdd/holders")).unwrap();
        std::fs::write(root.join("sdd/holders/dm-2"), "").unwrap();
        // Reported by `first_active_mapping` instead.
        assert_eq!(first_holder(root, sdd), None);
        assert!(first_active_mapping(sdd).is_some());
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
