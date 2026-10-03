//! Removable block device enumeration via `lsblk -J`.
//!
//! Read-only, non-privileged. Filters to removable / hotplug devices so the
//! UI never accidentally lists the system disk.

use crate::{Error, Result};
use serde::Deserialize;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct Drive {
    pub path: String,
    pub name: String,
    pub size_bytes: u64,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub transport: Option<String>,
    pub removable: bool,
    pub hotplug: bool,
    pub read_only: bool,
    pub mountpoint: Option<String>,
    /// `true` for spinning disks, `false` for SSD/NVMe/USB-flash.
    pub rotational: bool,
    /// `"gpt"`, `"dos"` (MBR), or `None` if no partition table is present.
    pub partition_table: Option<String>,
    /// Signature found on the disk node itself (e.g. `crypto_LUKS` when the
    /// whole disk is one LUKS volume, `vfat` for a "superfloppy").
    pub fstype: Option<String>,
    /// The disk viewed as a single volume. `Some` when the disk node carries
    /// a filesystem or LUKS header directly (no partition table), which is
    /// exactly what [`crate::pipeline`] produces when it encrypts a drive.
    pub whole_disk: Option<Partition>,
    pub partitions: Vec<Partition>,
}

impl Drive {
    /// Every volume on the drive: the whole-disk volume (if any) followed by
    /// the partitions.
    pub fn volumes(&self) -> impl Iterator<Item = &Partition> {
        self.whole_disk.iter().chain(self.partitions.iter())
    }
}

#[derive(Debug, Clone)]
pub struct Partition {
    pub path: String,
    pub name: String,
    pub size_bytes: u64,
    pub fstype: Option<String>,
    pub mountpoint: Option<String>,
    pub label: Option<String>,
    /// Filesystem / LUKS UUID as reported by `lsblk`.
    pub uuid: Option<String>,
    /// Bytes used (only available when the filesystem is mounted).
    pub fs_used: Option<u64>,
    /// Filesystem capacity in bytes (only available when mounted).
    pub fs_size: Option<u64>,
    /// For `crypto_LUKS` partitions: the open dm-crypt mapping name
    /// (e.g. `ashypass_vault`) if the partition is currently unlocked.
    /// `None` means the partition is locked at rest.
    pub active_mapping: Option<String>,
    /// When `active_mapping` is Some, the filesystem type and mountpoint
    /// of the inner mapped device (e.g. ext4 mounted at /run/media/…).
    pub inner_fstype: Option<String>,
    pub inner_mountpoint: Option<String>,
    pub inner_fs_used: Option<u64>,
    pub inner_fs_size: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct LsblkRoot {
    blockdevices: Vec<LsblkNode>,
}

#[derive(Debug, Deserialize)]
struct LsblkNode {
    name: String,
    path: String,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default, rename = "type")]
    dev_type: Option<String>,
    #[serde(default)]
    rm: Option<bool>,
    #[serde(default)]
    hotplug: Option<bool>,
    #[serde(default)]
    ro: Option<bool>,
    #[serde(default)]
    tran: Option<String>,
    #[serde(default)]
    vendor: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    serial: Option<String>,
    #[serde(default)]
    fstype: Option<String>,
    #[serde(default)]
    mountpoint: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    rota: Option<bool>,
    #[serde(default)]
    pttype: Option<String>,
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    fsused: Option<u64>,
    #[serde(default)]
    fssize: Option<u64>,
    #[serde(default)]
    children: Vec<LsblkNode>,
}

/// List candidate drives for encryption (removable or hotplug only).
pub fn list_removable() -> Result<Vec<Drive>> {
    let all = list_all()?;
    Ok(all
        .into_iter()
        .filter(|d| d.removable || d.hotplug)
        .collect())
}

/// Columns requested from `lsblk`. Kept next to [`parse_lsblk`] so the
/// fixture-based tests exercise the same shape production sees.
const LSBLK_COLUMNS: &str =
    "NAME,PATH,SIZE,TYPE,RM,HOTPLUG,RO,ROTA,TRAN,VENDOR,MODEL,SERIAL,FSTYPE,FSUSED,FSSIZE,MOUNTPOINT,LABEL,PTTYPE,UUID";

/// List every disk-type block device. Caller is responsible for filtering.
pub fn list_all() -> Result<Vec<Drive>> {
    let output = Command::new("lsblk")
        .args(["-J", "-b", "-o", LSBLK_COLUMNS])
        .output()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::MissingTool("lsblk".into()),
            _ => Error::Io(e),
        })?;

    if !output.status.success() {
        return Err(Error::CommandFailed {
            cmd: "lsblk -J".into(),
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    parse_lsblk(&output.stdout)
}

/// Parse `lsblk -J -b -o LSBLK_COLUMNS` output into disks. Pure — no I/O —
/// so detection can be tested against captured fixtures.
pub fn parse_lsblk(json: &[u8]) -> Result<Vec<Drive>> {
    let parsed: LsblkRoot = serde_json::from_slice(json)?;

    let mut drives = Vec::new();
    for node in parsed.blockdevices {
        if node.dev_type.as_deref() != Some("disk") {
            continue;
        }
        let partitions = node
            .children
            .iter()
            .filter(|c| c.dev_type.as_deref() == Some("part"))
            .map(volume_from_node)
            .collect();

        // A disk formatted without a partition table (whole-disk LUKS, or a
        // filesystem written straight onto the device) either carries an
        // FSTYPE itself or, once unlocked, has a `crypt` child directly.
        let fstype = clean(node.fstype.clone());
        let has_direct_mapping = node
            .children
            .iter()
            .any(|c| c.dev_type.as_deref() == Some("crypt"));
        let whole_disk = (fstype.is_some() || has_direct_mapping).then(|| volume_from_node(&node));

        drives.push(Drive {
            path: node.path,
            name: node.name,
            size_bytes: node.size.unwrap_or(0),
            vendor: clean(node.vendor),
            model: clean(node.model),
            serial: clean(node.serial),
            transport: clean(node.tran),
            removable: node.rm.unwrap_or(false),
            hotplug: node.hotplug.unwrap_or(false),
            read_only: node.ro.unwrap_or(false),
            mountpoint: node.mountpoint.clone(),
            rotational: node.rota.unwrap_or(false),
            partition_table: clean(node.pttype),
            fstype,
            whole_disk,
            partitions,
        });
    }
    Ok(drives)
}

/// Build a [`Partition`] view of `node` (a partition or a whole disk). An
/// unlocked LUKS volume has a `crypt` child carrying the inner filesystem.
fn volume_from_node(node: &LsblkNode) -> Partition {
    let inner = node
        .children
        .iter()
        .find(|c| c.dev_type.as_deref() == Some("crypt"));
    Partition {
        path: node.path.clone(),
        name: node.name.clone(),
        size_bytes: node.size.unwrap_or(0),
        fstype: clean(node.fstype.clone()),
        mountpoint: node.mountpoint.clone(),
        label: clean(node.label.clone()),
        uuid: clean(node.uuid.clone()),
        fs_used: node.fsused,
        fs_size: node.fssize,
        active_mapping: inner.map(|i| i.name.clone()),
        inner_fstype: inner.and_then(|i| clean(i.fstype.clone())),
        inner_mountpoint: inner.and_then(|i| i.mountpoint.clone()),
        inner_fs_used: inner.and_then(|i| i.fsused),
        inner_fs_size: inner.and_then(|i| i.fssize),
    }
}

/// Find the disk whose kernel node is `node` (already canonicalised, e.g.
/// `/dev/sdb`). Partitions and mapper devices never match.
pub fn find_disk<'a>(drives: &'a [Drive], node: &std::path::Path) -> Option<&'a Drive> {
    drives
        .iter()
        .find(|d| std::path::Path::new(&d.path) == node)
}

/// Find the disk that owns `node`, where `node` is either the disk itself or
/// one of its volumes (partition or whole-disk volume).
pub fn find_volume_owner<'a>(drives: &'a [Drive], node: &std::path::Path) -> Option<&'a Drive> {
    drives.iter().find(|d| {
        std::path::Path::new(&d.path) == node
            || d.volumes().any(|v| std::path::Path::new(&v.path) == node)
    })
}

fn clean(s: Option<String>) -> Option<String> {
    s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// Format a byte count as a short human string (binary units).
pub fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.1} {}", value, UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const FIXTURE: &str = include_str!("../tests/fixtures/lsblk_mixed.json");

    fn drives() -> Vec<Drive> {
        parse_lsblk(FIXTURE.as_bytes()).unwrap()
    }

    #[test]
    fn only_disks_are_listed() {
        let names: Vec<String> = drives().into_iter().map(|d| d.name).collect();
        assert_eq!(names, ["sda", "sdb", "sdc", "sdd", "sde", "sdf"]);
    }

    #[test]
    fn partitioned_drive_has_no_whole_disk_volume() {
        let drives = drives();
        let sdb = find_disk(&drives, Path::new("/dev/sdb")).unwrap();
        assert!(sdb.whole_disk.is_none());
        assert_eq!(sdb.partitions.len(), 1);
        assert_eq!(sdb.partitions[0].label.as_deref(), Some("STICK"));
        assert_eq!(sdb.vendor.as_deref(), Some("Kingston"));
    }

    #[test]
    fn locked_whole_disk_luks_is_detected() {
        let drives = drives();
        let sdf = find_disk(&drives, Path::new("/dev/sdf")).unwrap();
        assert_eq!(sdf.fstype.as_deref(), Some("crypto_LUKS"));
        assert!(sdf.partitions.is_empty());
        let volume = sdf.whole_disk.as_ref().expect("whole-disk volume");
        assert_eq!(volume.path, "/dev/sdf");
        assert_eq!(volume.fstype.as_deref(), Some("crypto_LUKS"));
        assert_eq!(volume.label.as_deref(), Some("backup"));
        assert_eq!(
            volume.uuid.as_deref(),
            Some("9a8b7c6d-5e4f-3a2b-1c0d-ffeeddccbbaa")
        );
        assert!(volume.active_mapping.is_none());
        assert_eq!(sdf.volumes().count(), 1);
    }

    #[test]
    fn unlocked_whole_disk_luks_reports_its_mapping() {
        let drives = drives();
        let sdd = find_disk(&drives, Path::new("/dev/sdd")).unwrap();
        // The crypt child is not a partition.
        assert!(sdd.partitions.is_empty());
        let volume = sdd.whole_disk.as_ref().unwrap();
        assert_eq!(volume.active_mapping.as_deref(), Some("ashypass_vault"));
        assert_eq!(volume.inner_fstype.as_deref(), Some("ext4"));
        assert_eq!(
            volume.inner_mountpoint.as_deref(),
            Some("/run/media/user/vault")
        );
    }

    #[test]
    fn unlocked_luks_partition_reports_its_mapping() {
        let drives = drives();
        let sdc = find_disk(&drives, Path::new("/dev/sdc")).unwrap();
        assert!(sdc.whole_disk.is_none());
        let part = &sdc.partitions[0];
        assert_eq!(part.fstype.as_deref(), Some("crypto_LUKS"));
        assert_eq!(part.active_mapping.as_deref(), Some("luks-aaaaaaaa"));
    }

    #[test]
    fn mapping_without_signature_still_yields_a_volume() {
        // A plain dm-crypt mapping (e.g. a stale wipe mapping) leaves no
        // FSTYPE on the disk but must still be visible to safety checks.
        let drives = drives();
        let sde = find_disk(&drives, Path::new("/dev/sde")).unwrap();
        let volume = sde.whole_disk.as_ref().unwrap();
        assert_eq!(volume.active_mapping.as_deref(), Some("ashypass_wipe_tmp"));
        assert_eq!(sde.serial, None);
    }

    #[test]
    fn volume_owner_lookup() {
        let drives = drives();
        assert_eq!(
            find_volume_owner(&drives, Path::new("/dev/sdc1")).map(|d| d.name.as_str()),
            Some("sdc")
        );
        assert_eq!(
            find_volume_owner(&drives, Path::new("/dev/sdf")).map(|d| d.name.as_str()),
            Some("sdf")
        );
        assert!(find_volume_owner(&drives, Path::new("/dev/mapper/ashypass_vault")).is_none());
        // find_disk never matches partitions.
        assert!(find_disk(&drives, Path::new("/dev/sdc1")).is_none());
    }

    #[test]
    fn vendor_padding_is_trimmed() {
        let drives = drives();
        assert_eq!(drives[0].vendor.as_deref(), Some("ATA"));
    }
}
