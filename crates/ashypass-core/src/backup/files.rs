//! Private-file helpers shared by exporters, downloads and restore.
//!
//! Every write goes to an owner-only (0600) temporary file in the target
//! directory, is synced, and only then becomes visible under its final name.
//! A failed write never leaves a truncated file behind.

use crate::{Error, Result};
use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Largest file accepted from a remote backup service.
pub const MAX_DOWNLOAD_BYTES: u64 = 512 * 1024 * 1024;

pub(crate) fn unique_temporary_path(path: &Path, purpose: &str) -> PathBuf {
    let parent = parent_of(path);
    let mut random = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut random);
    parent.join(format!(
        ".ashypass-{purpose}-{:016x}.tmp",
        u64::from_ne_bytes(random)
    ))
}

fn parent_of(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Create a new owner-only temporary file next to `path`, fill it through
/// `fill`, and sync it. The file is removed again when `fill` fails.
pub(crate) fn write_temporary<F>(path: &Path, purpose: &str, fill: F) -> Result<PathBuf>
where
    F: FnOnce(&mut fs::File) -> Result<()>,
{
    fs::create_dir_all(parent_of(path))?;
    let temporary = unique_temporary_path(path, purpose);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        fill(&mut file)?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    })();
    match result {
        Ok(()) => Ok(temporary),
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(error)
        }
    }
}

/// Move a finished temporary file to `destination` without ever replacing an
/// existing file. Hard links give an atomic no-clobber publish; filesystems
/// without hard links (FAT, exFAT, some FUSE mounts) fall back to an
/// existence check followed by a rename.
pub(crate) fn publish_new(temporary: &Path, destination: &Path) -> io::Result<()> {
    publish_new_with(temporary, destination, |from, to| fs::hard_link(from, to))
}

fn publish_new_with<L>(temporary: &Path, destination: &Path, link: L) -> io::Result<()>
where
    L: FnOnce(&Path, &Path) -> io::Result<()>,
{
    let result = match link(temporary, destination) {
        Ok(()) => fs::remove_file(temporary),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(error),
        Err(_) => {
            if fs::symlink_metadata(destination).is_ok() {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} already exists", destination.display()),
                ))
            } else {
                fs::rename(temporary, destination)
            }
        }
    };
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    } else {
        sync_parent(destination);
    }
    result
}

/// Atomically replace `destination` with a finished temporary file. Used when
/// the user has already confirmed overwriting in a save dialog.
pub(crate) fn publish_replacing(temporary: &Path, destination: &Path) -> io::Result<()> {
    let result = fs::rename(temporary, destination);
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    } else {
        sync_parent(destination);
    }
    result
}

fn sync_parent(path: &Path) {
    if let Ok(directory) = OpenOptions::new().read(true).open(parent_of(path)) {
        let _ = directory.sync_all();
    }
}

/// Write `bytes` to a new owner-only file; fails if `path` already exists.
pub(crate) fn write_private_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = write_temporary(path, "write", |file| {
        file.write_all(bytes)?;
        Ok(())
    })?;
    publish_new(&temporary, path).map_err(Error::from)
}

/// Write `bytes` to an owner-only file, atomically replacing any existing one.
pub(crate) fn write_private_replacing(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = write_temporary(path, "write", |file| {
        file.write_all(bytes)?;
        Ok(())
    })?;
    publish_replacing(&temporary, path).map_err(Error::from)
}

/// Copy at most `limit` bytes; anything larger is an error rather than a
/// silently truncated file.
pub(crate) fn copy_limited(
    reader: &mut impl Read,
    writer: &mut impl Write,
    limit: u64,
) -> Result<u64> {
    let copied = io::copy(&mut reader.take(limit.saturating_add(1)), writer)?;
    if copied > limit {
        return Err(Error::InvalidInput(format!(
            "file is larger than the {} MiB limit",
            limit / (1024 * 1024)
        )));
    }
    Ok(copied)
}

/// Stream a download into a new private file at `destination` (never
/// replacing an existing file), enforcing `limit`.
pub(crate) fn write_stream_new(
    reader: &mut impl Read,
    destination: &Path,
    limit: u64,
) -> Result<()> {
    let temporary = write_temporary(destination, "download", |file| {
        copy_limited(reader, file, limit)?;
        Ok(())
    })?;
    publish_new(&temporary, destination).map_err(Error::from)
}

/// Reject a response up front when the server announces an oversized body.
pub(crate) fn check_content_length(length: Option<u64>, limit: u64) -> Result<()> {
    match length {
        Some(size) if size > limit => Err(Error::InvalidInput(format!(
            "remote file is larger than the {} MiB limit",
            limit / (1024 * 1024)
        ))),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn new_files_never_replace_existing_data() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("file");
        write_private_new(&path, b"first").unwrap();
        assert!(write_private_new(&path, b"second").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"first");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn replacing_write_overwrites_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("file");
        fs::write(&path, b"old").unwrap();
        write_private_replacing(&path, b"new").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn publish_new_falls_back_to_rename_without_hard_links() {
        // FAT/exFAT report EPERM for link(2).
        let no_links = |_: &Path, _: &Path| Err(io::Error::from_raw_os_error(1));
        let directory = tempfile::tempdir().unwrap();
        let temporary = directory.path().join("tmp");
        let destination = directory.path().join("dest");
        fs::write(&temporary, b"data").unwrap();
        publish_new_with(&temporary, &destination, no_links).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"data");
        assert!(!temporary.exists());

        // The fallback still refuses to clobber an existing file.
        fs::write(&temporary, b"other").unwrap();
        assert!(publish_new_with(&temporary, &destination, no_links).is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"data");
        assert!(!temporary.exists());
    }

    #[test]
    fn oversized_streams_are_rejected_and_cleaned_up() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("download");
        let mut reader = io::Cursor::new(vec![7u8; 11]);
        assert!(write_stream_new(&mut reader, &destination, 10).is_err());
        assert!(!destination.exists());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);

        let mut reader = io::Cursor::new(vec![7u8; 10]);
        write_stream_new(&mut reader, &destination, 10).unwrap();
        assert_eq!(fs::read(&destination).unwrap().len(), 10);
        assert!(check_content_length(Some(11), 10).is_err());
        assert!(check_content_length(None, 10).is_ok());
    }
}
