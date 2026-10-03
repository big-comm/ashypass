//! Input validation shared by the pipeline, the CLI and the privileged helper.
//!
//! Everything here runs **before** the first destructive step, so a bad label
//! or mapper name is rejected while the drive is still intact instead of
//! failing at `mkfs` time on a freshly wiped device.

use crate::fs::Filesystem;
use crate::passphrase::Passphrase;
use crate::{Error, Result};

/// The LUKS2 header stores the label in a 48-byte, NUL-terminated field.
pub const LUKS2_LABEL_MAX_BYTES: usize = 47;

/// Longest dm-crypt mapper name we create. The kernel limit is 127 bytes;
/// staying well below it leaves room for suffixes.
pub const MAPPER_NAME_MAX_BYTES: usize = 96;

/// Prefix shared by every mapping Ashy Pass creates. Lock / close paths only
/// ever touch names carrying it.
pub const MAPPER_PREFIX: &str = "ashypass_";

/// Why a label was refused. Kept structured so the GUI can show a translated
/// message instead of the English `Display` text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelError {
    Empty,
    TooLong { max_bytes: usize },
    InvalidCharacters,
}

impl std::fmt::Display for LabelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "label must not be empty"),
            Self::TooLong { max_bytes } => {
                write!(f, "label is longer than {max_bytes} bytes")
            }
            Self::InvalidCharacters => write!(
                f,
                "label must not contain control characters, '/' or start with '-'"
            ),
        }
    }
}

/// Maximum label length (in bytes) `mkfs` accepts for `fs`.
///
/// ext4: 16 bytes; XFS: 12 bytes; Btrfs: 255 bytes. Only these three are
/// offered by the wizard and CLI (exFAT would be 15 UTF-16 units, but it is
/// not an option).
pub fn fs_label_max_bytes(fs: Filesystem) -> usize {
    match fs {
        Filesystem::Ext4 => 16,
        Filesystem::Xfs => 12,
        Filesystem::Btrfs => 255,
    }
}

/// Generic label rules: what the LUKS2 header (and our argv) accept.
pub fn check_label(label: &str) -> std::result::Result<(), LabelError> {
    if label.is_empty() {
        return Err(LabelError::Empty);
    }
    if label.chars().any(char::is_control) || label.contains('/') || label.starts_with('-') {
        return Err(LabelError::InvalidCharacters);
    }
    if label.len() > LUKS2_LABEL_MAX_BYTES {
        return Err(LabelError::TooLong {
            max_bytes: LUKS2_LABEL_MAX_BYTES,
        });
    }
    Ok(())
}

/// Label rules for a label that will be written both to the LUKS2 header and
/// to a filesystem of type `fs`.
pub fn check_label_for_fs(label: &str, fs: Filesystem) -> std::result::Result<(), LabelError> {
    check_label(label)?;
    let max_bytes = fs_label_max_bytes(fs).min(LUKS2_LABEL_MAX_BYTES);
    if label.len() > max_bytes {
        return Err(LabelError::TooLong { max_bytes });
    }
    Ok(())
}

pub fn validate_label(label: &str) -> Result<()> {
    check_label(label).map_err(|e| Error::Refused(e.to_string()))
}

pub fn validate_label_for_fs(label: &str, fs: Filesystem) -> Result<()> {
    check_label_for_fs(label, fs).map_err(|e| Error::Refused(e.to_string()))
}

/// Mapper names must carry [`MAPPER_PREFIX`], stay short and only use
/// `[A-Za-z0-9_-]`, so they can never name a path outside `/dev/mapper` or
/// another tool's mapping.
pub fn validate_mapper_name(name: &str) -> Result<()> {
    let ok = name.len() > MAPPER_PREFIX.len()
        && name.starts_with(MAPPER_PREFIX)
        && name.len() <= MAPPER_NAME_MAX_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(Error::Refused(format!(
            "invalid mapper name {name:?}: must start with `{MAPPER_PREFIX}`, \
             use only letters, digits, '_' or '-', and be at most \
             {MAPPER_NAME_MAX_BYTES} bytes"
        )))
    }
}

pub fn validate_passphrase(passphrase: &Passphrase) -> Result<()> {
    if passphrase.is_empty() {
        return Err(Error::Refused("refusing empty passphrase".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_limits_follow_the_filesystem() {
        // XFS: 12 bytes.
        assert!(check_label_for_fs("abcdefghijkl", Filesystem::Xfs).is_ok());
        assert_eq!(
            check_label_for_fs("abcdefghijklm", Filesystem::Xfs),
            Err(LabelError::TooLong { max_bytes: 12 })
        );
        // ext4: 16 bytes.
        assert!(check_label_for_fs("abcdefghijklmnop", Filesystem::Ext4).is_ok());
        assert_eq!(
            check_label_for_fs("abcdefghijklmnopq", Filesystem::Ext4),
            Err(LabelError::TooLong { max_bytes: 16 })
        );
        // Btrfs allows 255, but the LUKS2 header caps the shared label at 47.
        assert!(check_label_for_fs(&"a".repeat(47), Filesystem::Btrfs).is_ok());
        assert_eq!(
            check_label_for_fs(&"a".repeat(48), Filesystem::Btrfs),
            Err(LabelError::TooLong { max_bytes: 47 })
        );
    }

    #[test]
    fn label_length_is_counted_in_bytes() {
        // 8 chars, 16 bytes in UTF-8: fits ext4 exactly, too long for XFS.
        let label = "ç".repeat(8);
        assert_eq!(label.len(), 16);
        assert!(check_label_for_fs(&label, Filesystem::Ext4).is_ok());
        assert!(check_label_for_fs(&label, Filesystem::Xfs).is_err());
    }

    #[test]
    fn label_rejects_empty_and_unsafe_characters() {
        assert_eq!(check_label(""), Err(LabelError::Empty));
        assert_eq!(check_label("a\nb"), Err(LabelError::InvalidCharacters));
        assert_eq!(check_label("a/b"), Err(LabelError::InvalidCharacters));
        assert_eq!(check_label("-F"), Err(LabelError::InvalidCharacters));
        assert!(check_label("my vault").is_ok());
        assert!(check_label("Cofre-2026_ç").is_ok());
    }

    #[test]
    fn mapper_names_are_whitelisted() {
        assert!(validate_mapper_name("ashypass_vault-1").is_ok());
        assert!(validate_mapper_name("ashypass_").is_err());
        assert!(validate_mapper_name("foo").is_err());
        assert!(validate_mapper_name("system-root").is_err());
        assert!(validate_mapper_name("luks-1234").is_err());
        assert!(validate_mapper_name("ashypass_../../root").is_err());
        assert!(validate_mapper_name("ashypass_a b").is_err());
        assert!(validate_mapper_name(&format!("ashypass_{}", "a".repeat(87))).is_ok());
        assert!(validate_mapper_name(&format!("ashypass_{}", "a".repeat(88))).is_err());
    }

    #[test]
    fn passphrase_presence_is_required() {
        assert!(validate_passphrase(&Passphrase::new(Vec::new())).is_err());
        assert!(validate_passphrase(&Passphrase::from_text("x")).is_ok());
    }
}
