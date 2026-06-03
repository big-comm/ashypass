//! Pre-condition checks that must pass before any destructive operation
//! touches a block device.
//!
//! The cost of a false positive here (refusing a legitimate format) is a
//! confused user. The cost of a false negative (formatting the rootfs) is
//! catastrophic data loss. We err strongly toward refusal.

use crate::detect::{list_all, Drive};
use crate::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Outcome of a safety inspection. `Allow` includes the resolved canonical
/// path (`/dev/disk/by-id/...`) so the caller can pin the exact device for
/// subsequent operations even if udev re-numbers `sda`.
#[derive(Debug)]
pub struct SafetyReport {
    pub canonical_path: PathBuf,
    pub serial: Option<String>,
    pub size_bytes: u64,
    pub model: Option<String>,
    pub vendor: Option<String>,
    pub allow_destructive: bool,
    pub reasons: Vec<String>,
}

impl SafetyReport {
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

/// Inspect `device` (e.g. `/dev/sda`) against every guard we know about.
pub fn inspect(device: &Path, policy: SafetyPolicy) -> Result<SafetyReport> {
    let drives = list_all()?;
    let drive = drives
        .iter()
        .find(|d| Path::new(&d.path) == device)
        .ok_or_else(|| Error::Refused(format!("device not found: {}", device.display())))?;

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
        if let Some(mp) = first_mounted_partition(drive) {
            allow = false;
            reasons.push(format!("partition currently mounted at {mp}"));
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

    let canonical = resolve_by_id(device).unwrap_or_else(|| device.to_path_buf());

    Ok(SafetyReport {
        canonical_path: canonical,
        serial: drive.serial.clone(),
        size_bytes: drive.size_bytes,
        model: drive.model.clone(),
        vendor: drive.vendor.clone(),
        allow_destructive: allow,
        reasons,
    })
}

fn first_mounted_partition(drive: &Drive) -> Option<String> {
    drive
        .partitions
        .iter()
        .find_map(|p| p.mountpoint.clone())
}

/// True if the device or any of its partitions backs `/`.
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
    for p in &drive.partitions {
        if resolved.as_path() == Path::new(&p.path) {
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
        for p in &drive.partitions {
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
    let needles: Vec<&str> = std::iter::once(drive.path.as_str())
        .chain(drive.partitions.iter().map(|p| p.path.as_str()))
        .collect();
    Ok(crypttab.lines().any(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return false;
        }
        needles.iter().any(|n| trimmed.contains(n))
    }))
}

/// Walk `/dev/disk/by-id/` looking for a symlink whose target is `device`.
/// The by-id name encodes vendor/model/serial and is stable across reboots
/// and re-plugs, which makes it the right handle to pin between the safety
/// check and the destructive call.
pub fn resolve_by_id(device: &Path) -> Option<PathBuf> {
    let dir = match fs::read_dir("/dev/disk/by-id") {
        Ok(d) => d,
        Err(_) => return None,
    };
    let target_canon = fs::canonicalize(device).ok()?;
    for entry in dir.flatten() {
        let path = entry.path();
        if let Ok(resolved) = fs::canonicalize(&path) {
            if resolved == target_canon {
                return Some(path);
            }
        }
    }
    None
}
