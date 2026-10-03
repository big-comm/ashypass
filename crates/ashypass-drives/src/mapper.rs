//! dm-crypt mapper naming and collision handling.
//!
//! A mapper name is global to the machine, so two drives labelled `vault`
//! would both want `/dev/mapper/ashypass_vault`. Before reusing or creating a
//! name we check which block device already backs it (via
//! `/sys/block/dm-N/slaves`) and fall back to a device-specific name instead
//! of silently handing out somebody else's mapping.

use crate::validate::{validate_mapper_name, MAPPER_NAME_MAX_BYTES, MAPPER_PREFIX};
use crate::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Longest label fragment kept in a derived mapper name.
const LABEL_FRAGMENT_MAX: usize = 40;

/// Derive a dm-crypt mapper name from a user label. Constrains to
/// `[A-Za-z0-9_-]` so it round-trips through `/dev/mapper/...`.
pub fn mapper_name_for(label: &str) -> String {
    let cleaned = sanitize(label, LABEL_FRAGMENT_MAX);
    if cleaned.is_empty() {
        return format!("{MAPPER_PREFIX}drive");
    }
    format!("{MAPPER_PREFIX}{cleaned}")
}

/// Same as [`mapper_name_for`] plus a device-specific `tag` (short UUID or
/// kernel name), used when the plain name is taken by another device.
pub fn mapper_name_with_tag(label: &str, tag: &str) -> String {
    let base = mapper_name_for(label);
    let tag = sanitize(tag, 16);
    if tag.is_empty() {
        return base;
    }
    let mut name = format!("{base}_{tag}");
    name.truncate(MAPPER_NAME_MAX_BYTES);
    name
}

fn sanitize(input: &str, max: usize) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(max)
        .collect()
}

/// What currently occupies a mapper name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapperState {
    /// No mapping with that name exists.
    Free,
    /// A mapping exists and is backed by the device we care about.
    SameDevice,
    /// A mapping exists and is backed by something else (or we could not
    /// tell — treated the same way, fail closed).
    OtherDevice,
}

/// Classify `name` relative to `device` (a canonical kernel node such as
/// `/dev/sdb1`).
pub fn mapper_state(name: &str, device: &Path) -> MapperState {
    if !Path::new("/dev/mapper").join(name).exists() {
        return MapperState::Free;
    }
    classify(&mapper_backing_devices(name), device)
}

/// Pure classification of an existing mapping given its backing devices.
pub fn classify(backing: &[PathBuf], device: &Path) -> MapperState {
    if backing.iter().any(|b| b == device) {
        MapperState::SameDevice
    } else {
        MapperState::OtherDevice
    }
}

/// Block devices backing `/dev/mapper/<name>`, read from
/// `/sys/block/dm-N/slaves/`. Empty when unknown.
pub fn mapper_backing_devices(name: &str) -> Vec<PathBuf> {
    let Ok(dm_node) = fs::canonicalize(Path::new("/dev/mapper").join(name)) else {
        return Vec::new();
    };
    let Some(dm_name) = dm_node.file_name().and_then(|n| n.to_str()) else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(format!("/sys/block/{dm_name}/slaves")) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            e.file_name()
                .to_str()
                .map(|n| PathBuf::from("/dev").join(n))
        })
        .collect()
}

/// Pick a mapper name for `device` among `candidates` (in preference order).
///
/// A candidate already backed by the same device wins (so a second unlock is
/// idempotent instead of opening the device twice); otherwise the first free
/// one. Names held by other devices are skipped; if nothing is usable the
/// call fails. Every candidate is validated first.
pub fn pick_mapper(
    candidates: &[String],
    mut state_of: impl FnMut(&str) -> MapperState,
) -> Result<(String, MapperState)> {
    for name in candidates {
        validate_mapper_name(name)?;
    }
    let states: Vec<(String, MapperState)> = candidates
        .iter()
        .map(|name| (name.clone(), state_of(name)))
        .collect();
    if let Some(found) = states.iter().find(|(_, s)| *s == MapperState::SameDevice) {
        return Ok(found.clone());
    }
    if let Some(found) = states.iter().find(|(_, s)| *s == MapperState::Free) {
        return Ok(found.clone());
    }
    Err(Error::Refused(format!(
        "mapper name(s) {} already in use by another device",
        candidates.join(", ")
    )))
}

/// Short, device-specific tag used to disambiguate mapper names: the first
/// 8 characters of the volume UUID when known, else the kernel name.
pub fn device_tag(device: &Path, uuid: Option<&str>) -> String {
    if let Some(uuid) = uuid.filter(|u| !u.is_empty()) {
        return uuid.chars().filter(|c| *c != '-').take(8).collect();
    }
    device
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("dev")
        .to_string()
}

/// Look up the UUID of `device` (canonical node) via `/dev/disk/by-uuid`.
pub fn uuid_of(device: &Path) -> Option<String> {
    let dir = fs::read_dir("/dev/disk/by-uuid").ok()?;
    for entry in dir.flatten() {
        if fs::canonicalize(entry.path()).ok().as_deref() == Some(device) {
            return entry.file_name().to_str().map(str::to_string);
        }
    }
    None
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
        assert_eq!(mapper_name_for("Cofre ç"), "ashypass_Cofre__");
    }

    #[test]
    fn derived_names_always_validate() {
        for label in ["", "a", "my drive", &"x".repeat(300), "ççç", "../.."] {
            validate_mapper_name(&mapper_name_for(label)).unwrap();
            validate_mapper_name(&mapper_name_with_tag(label, "1234abcd")).unwrap();
            validate_mapper_name(&mapper_name_with_tag(label, "sdb1")).unwrap();
        }
    }

    #[test]
    fn tag_prefers_uuid() {
        assert_eq!(
            device_tag(
                Path::new("/dev/sdb"),
                Some("0f6c1a2b-3c4d-5e6f-7a8b-9c0d1e2f3a4b")
            ),
            "0f6c1a2b"
        );
        assert_eq!(device_tag(Path::new("/dev/sdb1"), None), "sdb1");
        assert_eq!(mapper_name_with_tag("vault", "sdb1"), "ashypass_vault_sdb1");
    }

    #[test]
    fn classify_compares_backing_device() {
        let dev = Path::new("/dev/sdb");
        assert_eq!(
            classify(&[PathBuf::from("/dev/sdb")], dev),
            MapperState::SameDevice
        );
        assert_eq!(
            classify(&[PathBuf::from("/dev/sdc")], dev),
            MapperState::OtherDevice
        );
        // Unknown backing device: fail closed.
        assert_eq!(classify(&[], dev), MapperState::OtherDevice);
    }

    #[test]
    fn pick_prefers_same_device_then_free() {
        let names = vec![
            "ashypass_vault".to_string(),
            "ashypass_vault_sdb".to_string(),
        ];
        let picked = pick_mapper(&names, |_| MapperState::Free).unwrap();
        assert_eq!(picked, ("ashypass_vault".into(), MapperState::Free));

        // The plain name belongs to another drive: fall back to the tagged one.
        let picked = pick_mapper(&names, |n| {
            if n == "ashypass_vault" {
                MapperState::OtherDevice
            } else {
                MapperState::Free
            }
        })
        .unwrap();
        assert_eq!(picked, ("ashypass_vault_sdb".into(), MapperState::Free));

        // Already unlocked under the tagged name: reuse it, never open twice.
        let picked = pick_mapper(&names, |n| {
            if n == "ashypass_vault" {
                MapperState::Free
            } else {
                MapperState::SameDevice
            }
        })
        .unwrap();
        assert_eq!(
            picked,
            ("ashypass_vault_sdb".into(), MapperState::SameDevice)
        );

        // Everything taken by other devices: refuse.
        assert!(pick_mapper(&names, |_| MapperState::OtherDevice).is_err());
    }

    #[test]
    fn pick_validates_candidates() {
        assert!(pick_mapper(&["foo".to_string()], |_| MapperState::Free).is_err());
    }
}
