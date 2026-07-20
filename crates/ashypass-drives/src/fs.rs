//! Filesystem creation on top of an opened LUKS mapping.
//!
//! Defaults to ext4 for predictability. Btrfs and XFS are wired but should
//! only be exposed in the UI under an "advanced" disclosure.

use crate::runner::{CommandSpec, Runner};
use crate::Result;
use std::path::Path;

#[derive(Debug, Clone, Copy, Default)]
pub enum Filesystem {
    #[default]
    Ext4,
    Btrfs,
    Xfs,
}

pub fn build_mkfs_spec(fs: Filesystem, mapped_device: &Path, label: &str) -> CommandSpec {
    let dev = mapped_device.to_string_lossy().into_owned();
    match fs {
        Filesystem::Ext4 => {
            let mut s = CommandSpec::new("mkfs.ext4")
                // -F: force; the mapper is freshly opened, no need to ask.
                .arg("-F")
                // No reserved blocks for root — this is removable media, not /.
                .arg("-m")
                .arg("0")
                // Lazy itable init is fine; speeds up mkfs on large volumes.
                .arg("-E")
                .arg("lazy_itable_init=1,lazy_journal_init=1");
            if !label.is_empty() {
                s = s.arg("-L").arg(label);
            }
            s.arg(dev)
        }
        Filesystem::Btrfs => {
            let mut s = CommandSpec::new("mkfs.btrfs").arg("-f");
            if !label.is_empty() {
                s = s.arg("-L").arg(label);
            }
            s.arg(dev)
        }
        Filesystem::Xfs => {
            let mut s = CommandSpec::new("mkfs.xfs").arg("-f");
            if !label.is_empty() {
                s = s.arg("-L").arg(label);
            }
            s.arg(dev)
        }
    }
}

pub fn mkfs(runner: &dyn Runner, mapped_device: &Path, fs: Filesystem, label: &str) -> Result<()> {
    runner
        .run(build_mkfs_spec(fs, mapped_device, label))
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ext4_uses_zero_reserved_blocks() {
        let s = build_mkfs_spec(Filesystem::Ext4, Path::new("/dev/mapper/x"), "vault");
        let j = s.args.join(" ");
        assert!(j.contains("-m 0"), "{j}");
        assert!(j.contains("-L vault"), "{j}");
    }
}
