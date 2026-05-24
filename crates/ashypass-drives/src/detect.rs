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
    /// `true` for spinning disks, `false` for SSD/NVMe/USB-flash.
    pub rotational: bool,
    /// `"gpt"`, `"dos"` (MBR), or `None` if no partition table is present.
    pub partition_table: Option<String>,
    pub partitions: Vec<Partition>,
}

#[derive(Debug, Clone)]
pub struct Partition {
    pub path: String,
    pub name: String,
    pub size_bytes: u64,
    pub fstype: Option<String>,
    pub mountpoint: Option<String>,
    pub label: Option<String>,
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

/// List every disk-type block device. Caller is responsible for filtering.
pub fn list_all() -> Result<Vec<Drive>> {
    let output = Command::new("lsblk")
        .args([
            "-J", "-b", "-o",
            "NAME,PATH,SIZE,TYPE,RM,HOTPLUG,RO,ROTA,TRAN,VENDOR,MODEL,SERIAL,FSTYPE,FSUSED,FSSIZE,MOUNTPOINT,LABEL,PTTYPE",
        ])
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

    let parsed: LsblkRoot = serde_json::from_slice(&output.stdout)?;

    let mut drives = Vec::new();
    for node in parsed.blockdevices {
        if node.dev_type.as_deref() != Some("disk") {
            continue;
        }
        let partitions = node
            .children
            .iter()
            .filter(|c| matches!(c.dev_type.as_deref(), Some("part") | Some("crypt")))
            .map(|c| {
                // A crypto_LUKS partition that's currently unlocked has a
                // `crypt`-type child carrying the inner filesystem info.
                let inner = c
                    .children
                    .iter()
                    .find(|cc| cc.dev_type.as_deref() == Some("crypt"));
                Partition {
                    path: c.path.clone(),
                    name: c.name.clone(),
                    size_bytes: c.size.unwrap_or(0),
                    fstype: c.fstype.clone(),
                    mountpoint: c.mountpoint.clone(),
                    label: c.label.clone(),
                    fs_used: c.fsused,
                    fs_size: c.fssize,
                    active_mapping: inner.map(|i| i.name.clone()),
                    inner_fstype: inner.and_then(|i| i.fstype.clone()),
                    inner_mountpoint: inner.and_then(|i| i.mountpoint.clone()),
                    inner_fs_used: inner.and_then(|i| i.fsused),
                    inner_fs_size: inner.and_then(|i| i.fssize),
                }
            })
            .collect();

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
            rotational: node.rota.unwrap_or(false),
            partition_table: clean(node.pttype),
            partitions,
        });
    }
    Ok(drives)
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
