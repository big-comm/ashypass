//! Safe whole-database restore from a downloaded backup.
//!
//! [`restore_db_snapshot`] accepts a plain SQLite snapshot (`.db`) or a
//! `.ashy` export with an embedded snapshot, and replaces the live database
//! only after the candidate has been fully validated:
//!
//! 1. the candidate is copied (or decrypted) to a private temporary file in
//!    the live database's directory — the downloaded file is never modified;
//! 2. `PRAGMA integrity_check` must pass and the vault tables must exist;
//! 3. the master password must unlock it and every entry must decrypt;
//! 4. a consistent copy of the current database is kept next to it as
//!    `<name>.before-restore-<timestamp>`;
//! 5. only then is the candidate renamed over the live database.
//!
//! Any failure before step 5 leaves the live database untouched.
//!
//! **Precondition:** every connection to `live_db` must be closed (drop the
//! app's `Vault`) before calling, and the vault reopened afterwards. An open
//! connection would keep writing to the replaced file.

use crate::backup::files::{copy_limited, write_temporary};
use crate::db::vault::Vault;
use crate::importers::ashy;
use crate::{Error, Result};
use rusqlite::Connection;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
/// Largest backup accepted for restore.
const MAX_RESTORE_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupKind {
    /// Plain SQLite snapshot (`.db`).
    Database,
    /// Encrypted `.ashy` export with an embedded snapshot.
    Ashy,
}

/// Result of a validated backup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupInfo {
    pub kind: BackupKind,
    /// Number of entries in the backup.
    pub entries: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOutcome {
    pub kind: BackupKind,
    pub entries: usize,
    /// Copy of the database that was replaced. `None` when no database
    /// existed at `live_db`.
    pub previous_copy: Option<PathBuf>,
}

/// Restore `candidate` over `live_db`. `.ashy` backups are decrypted with
/// `master_password` (WebDAV sync snapshots use the vault master).
pub fn restore_db_snapshot(
    live_db: &Path,
    candidate: &Path,
    master_password: &str,
) -> Result<RestoreOutcome> {
    restore_db_snapshot_with(live_db, candidate, master_password, None)
}

/// Like [`restore_db_snapshot`], with a separate password for a `.ashy`
/// export that was not protected with the master password.
pub fn restore_db_snapshot_with(
    live_db: &Path,
    candidate: &Path,
    master_password: &str,
    ashy_password: Option<&str>,
) -> Result<RestoreOutcome> {
    let (temporary, info) = prepare(live_db, candidate, master_password, ashy_password)?;
    let result = (|| {
        let previous_copy = if live_db.exists() {
            Some(keep_previous_copy(live_db)?)
        } else {
            None
        };
        swap_in(&temporary, live_db)?;
        Ok(RestoreOutcome {
            kind: info.kind,
            entries: info.entries,
            previous_copy,
        })
    })();
    if result.is_err() {
        remove_with_sidecars(&temporary);
    }
    result
}

/// Validate a downloaded backup without restoring it.
pub fn validate_backup(
    candidate: &Path,
    master_password: &str,
    ashy_password: Option<&str>,
) -> Result<BackupInfo> {
    let (temporary, info) = prepare(candidate, candidate, master_password, ashy_password)?;
    remove_with_sidecars(&temporary);
    Ok(info)
}

/// Copy/decrypt `candidate` into a temporary file next to `beside` and
/// validate it. Returns the temporary path; the caller owns it.
fn prepare(
    beside: &Path,
    candidate: &Path,
    master_password: &str,
    ashy_password: Option<&str>,
) -> Result<(PathBuf, BackupInfo)> {
    let metadata = fs::metadata(candidate)?;
    if metadata.len() > MAX_RESTORE_BYTES {
        return Err(Error::InvalidInput("backup file is too large".into()));
    }
    let mut header = [0u8; 16];
    let header_len = {
        let mut file = fs::File::open(candidate)?;
        read_up_to(&mut file, &mut header)?
    };
    let header = &header[..header_len];

    let (kind, temporary) = if ashy::has_magic(header) {
        let snapshot = ashy::read_snapshot(candidate, ashy_password.unwrap_or(master_password))?;
        if !snapshot.starts_with(SQLITE_MAGIC) {
            return Err(Error::InvalidInput(
                "the .ashy snapshot is not a database".into(),
            ));
        }
        let temporary = write_temporary(beside, "restore", |file| {
            file.write_all(&snapshot)?;
            Ok(())
        })?;
        (BackupKind::Ashy, temporary)
    } else if header == SQLITE_MAGIC {
        let mut source = fs::File::open(candidate)?;
        let temporary = write_temporary(beside, "restore", |file| {
            copy_limited(&mut source, file, MAX_RESTORE_BYTES)?;
            Ok(())
        })?;
        (BackupKind::Database, temporary)
    } else {
        return Err(Error::InvalidInput(
            "not an Ashy Pass database or .ashy backup".into(),
        ));
    };

    match verify(&temporary, master_password) {
        Ok(entries) => Ok((temporary, BackupInfo { kind, entries })),
        Err(error) => {
            remove_with_sidecars(&temporary);
            Err(error)
        }
    }
}

fn read_up_to(reader: &mut impl Read, buffer: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        let n = reader.read(&mut buffer[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// Integrity check, master password, and decryption of every entry.
fn verify(path: &Path, master_password: &str) -> Result<usize> {
    Vault::validate_database(path)?;
    let entries = {
        let mut vault = Vault::open(path)?;
        if !vault.has_master_password()? {
            return Err(Error::InvalidInput("backup has no master password".into()));
        }
        vault.unlock(master_password)?;
        let list = vault.list(None)?;
        for summary in &list {
            vault.get_without_touch(summary.id)?.ok_or_else(|| {
                Error::InvalidInput("backup entry disappeared during validation".into())
            })?;
        }
        list.len()
    };
    // Unlocking a legacy (v1) snapshot migrates it and leaves a backup copy
    // next to the temporary file; it is not needed.
    let _ = fs::remove_file(path.with_extension("db.v1.bak"));
    // Re-check after open/migration, then fold the WAL into the main file
    // with a read-write connection so no side files are left behind.
    Vault::validate_database(path)?;
    checkpoint(path)?;
    let [_, shm] = sidecars(path);
    let _ = fs::remove_file(shm);
    OpenOptions::new().read(true).open(path)?.sync_all()?;
    Ok(entries)
}

/// Fold any WAL content into the main file and drop the side files.
fn checkpoint(path: &Path) -> Result<()> {
    {
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        connection.close().map_err(|(_, error)| error)?;
    }
    // Closing the last connection normally deletes the WAL. A WAL that is
    // still non-empty means another connection is open: refuse to swap.
    let [wal, _] = sidecars(path);
    match fs::metadata(&wal) {
        Ok(meta) if meta.len() == 0 => {
            let _ = fs::remove_file(&wal);
        }
        Ok(_) => {
            return Err(Error::Other(format!(
                "{} still has unwritten changes; close the vault first",
                path.display()
            )))
        }
        Err(_) => {}
    }
    Ok(())
}

fn sidecars(path: &Path) -> [PathBuf; 2] {
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    let mut shm = path.as_os_str().to_owned();
    shm.push("-shm");
    [PathBuf::from(wal), PathBuf::from(shm)]
}

fn remove_with_sidecars(path: &Path) {
    let _ = fs::remove_file(path);
    for sidecar in sidecars(path) {
        let _ = fs::remove_file(sidecar);
    }
    let _ = fs::remove_file(path.with_extension("db.v1.bak"));
}

/// Keep a consistent copy of the current database. Uses the SQLite backup
/// API (includes WAL content); if the live file is too damaged for that, the
/// raw bytes (plus WAL) are copied instead — the user may be restoring
/// precisely because the live database is corrupt.
fn keep_previous_copy(live_db: &Path) -> Result<PathBuf> {
    let destination = previous_copy_path(live_db);
    match sqlite_backup(live_db, &destination) {
        Ok(()) => Ok(destination),
        Err(error) => {
            log::warn!("consistent copy of {live_db:?} failed ({error}); copying raw bytes");
            let _ = fs::remove_file(&destination);
            raw_copy(live_db, &destination)?;
            let [wal, _] = sidecars(live_db);
            if wal.exists() {
                let [wal_copy, _] = sidecars(&destination);
                raw_copy(&wal, &wal_copy)?;
            }
            Ok(destination)
        }
    }
}

fn previous_copy_path(live_db: &Path) -> PathBuf {
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let name = live_db
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "passwords.db".into());
    let mut candidate = live_db.with_file_name(format!("{name}.before-restore-{stamp}"));
    let mut counter = 1;
    while candidate.exists() {
        candidate = live_db.with_file_name(format!("{name}.before-restore-{stamp}-{counter}"));
        counter += 1;
    }
    candidate
}

fn sqlite_backup(live_db: &Path, destination: &Path) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    let source = Connection::open(live_db)?;
    source.busy_timeout(Duration::from_secs(5))?;
    let mut target = Connection::open(destination)?;
    {
        let backup = rusqlite::backup::Backup::new(&source, &mut target)?;
        backup.run_to_completion(128, Duration::from_millis(10), None)?;
    }
    let integrity: String = target.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(Error::Other(format!(
            "copy of the current database failed the integrity check: {integrity}"
        )));
    }
    target.close().map_err(|(_, error)| error)?;
    source.close().map_err(|(_, error)| error)?;
    OpenOptions::new()
        .read(true)
        .open(destination)?
        .sync_all()?;
    Ok(())
}

fn raw_copy(from: &Path, to: &Path) -> Result<()> {
    let mut source = fs::File::open(from)?;
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(to)?;
    std::io::copy(&mut source, &mut target)?;
    target.sync_all()?;
    Ok(())
}

/// Replace `live_db` with the validated temporary file. The live WAL is
/// checkpointed and removed first so stale frames can never be replayed on
/// top of the restored database.
fn swap_in(temporary: &Path, live_db: &Path) -> Result<()> {
    if live_db.exists() {
        checkpoint(live_db)?;
    }
    fs::rename(temporary, live_db)?;
    if let Some(parent) = live_db.parent() {
        if let Ok(directory) = OpenOptions::new().read(true).open(parent) {
            let _ = directory.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::vault::NewEntry;

    const MASTER: &str = "correct horse battery";

    fn vault_with(path: &Path, titles: &[&str]) {
        let mut vault = Vault::open(path).unwrap();
        vault.set_master_password(MASTER).unwrap();
        for title in titles {
            vault
                .add(NewEntry {
                    title: (*title).into(),
                    password: format!("{title}-pw"),
                    ..NewEntry::default()
                })
                .unwrap();
        }
    }

    fn titles(path: &Path) -> Vec<String> {
        let mut vault = Vault::open(path).unwrap();
        vault.unlock(MASTER).unwrap();
        vault
            .list(None)
            .unwrap()
            .into_iter()
            .map(|e| e.title)
            .collect()
    }

    fn snapshot_of(source: &Path, destination: &Path) {
        let vault = Vault::open(source).unwrap();
        vault.backup_to(destination).unwrap();
    }

    fn file_names(directory: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(directory)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn restores_db_and_keeps_previous_copy() {
        let live_dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let live = live_dir.path().join("passwords.db");
        vault_with(&live, &["old"]);
        let source = other.path().join("source.db");
        vault_with(&source, &["new-a", "new-b"]);
        let candidate = other.path().join("backup.db");
        snapshot_of(&source, &candidate);

        let outcome = restore_db_snapshot(&live, &candidate, MASTER).unwrap();
        assert_eq!(outcome.kind, BackupKind::Database);
        assert_eq!(outcome.entries, 2);
        assert_eq!(titles(&live), vec!["new-a", "new-b"]);
        let previous = outcome.previous_copy.unwrap();
        assert!(previous
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("passwords.db.before-restore-"));
        assert_eq!(titles(&previous), vec!["old"]);
        assert!(candidate.exists(), "the downloaded file is left alone");
        // Only the live DB and the previous copy remain (no temporaries).
        let names = file_names(live_dir.path());
        assert!(
            names.iter().all(|n| n.starts_with("passwords.db")),
            "{names:?}"
        );
    }

    #[test]
    fn restores_ashy_snapshot() {
        let live_dir = tempfile::tempdir().unwrap();
        let live = live_dir.path().join("passwords.db");
        vault_with(&live, &["old"]);
        let other = tempfile::tempdir().unwrap();
        let source = other.path().join("source.db");
        vault_with(&source, &["from-ashy"]);
        let candidate = other.path().join("backup.ashy");
        {
            let mut vault = Vault::open(&source).unwrap();
            vault.unlock(MASTER).unwrap();
            ashy::export_vault(&vault, &candidate, MASTER).unwrap();
        }
        let outcome = restore_db_snapshot(&live, &candidate, MASTER).unwrap();
        assert_eq!(outcome.kind, BackupKind::Ashy);
        assert_eq!(titles(&live), vec!["from-ashy"]);

        // A separate export password is supported too.
        let other_pw = other.path().join("other.ashy");
        {
            let mut vault = Vault::open(&source).unwrap();
            vault.unlock(MASTER).unwrap();
            ashy::export_vault(&vault, &other_pw, "export only").unwrap();
        }
        assert!(restore_db_snapshot(&live, &other_pw, MASTER).is_err());
        let info = validate_backup(&other_pw, MASTER, Some("export only")).unwrap();
        assert_eq!(info.entries, 1);
        restore_db_snapshot_with(&live, &other_pw, MASTER, Some("export only")).unwrap();
    }

    #[test]
    fn wrong_master_password_refuses_and_changes_nothing() {
        let live_dir = tempfile::tempdir().unwrap();
        let live = live_dir.path().join("passwords.db");
        vault_with(&live, &["old"]);
        let before = file_names(live_dir.path());
        let other = tempfile::tempdir().unwrap();
        let source = other.path().join("source.db");
        vault_with(&source, &["new"]);
        let candidate = other.path().join("backup.db");
        snapshot_of(&source, &candidate);

        let error = restore_db_snapshot(&live, &candidate, "wrong password").unwrap_err();
        assert!(matches!(error, Error::InvalidMasterPassword), "{error}");
        assert_eq!(titles(&live), vec!["old"]);
        assert_eq!(file_names(live_dir.path()), before);
    }

    #[test]
    fn corrupted_or_foreign_files_are_refused() {
        let live_dir = tempfile::tempdir().unwrap();
        let live = live_dir.path().join("passwords.db");
        vault_with(&live, &["old"]);
        let before = file_names(live_dir.path());
        let other = tempfile::tempdir().unwrap();

        let random = other.path().join("random.db");
        fs::write(&random, vec![0x42u8; 4096]).unwrap();
        assert!(restore_db_snapshot(&live, &random, MASTER).is_err());

        // A real snapshot with its pages damaged.
        let source = other.path().join("source.db");
        vault_with(&source, &["new"]);
        let damaged = other.path().join("damaged.db");
        snapshot_of(&source, &damaged);
        let mut bytes = fs::read(&damaged).unwrap();
        let len = bytes.len();
        for byte in &mut bytes[100..len] {
            *byte ^= 0x5a;
        }
        fs::write(&damaged, &bytes).unwrap();
        assert!(restore_db_snapshot(&live, &damaged, MASTER).is_err());

        // Truncated .ashy.
        let truncated = other.path().join("t.ashy");
        fs::write(&truncated, b"ASHYP\x00\x01short").unwrap();
        assert!(restore_db_snapshot(&live, &truncated, MASTER).is_err());

        // A SQLite file that is not a vault.
        let foreign = other.path().join("foreign.db");
        Connection::open(&foreign)
            .unwrap()
            .execute_batch("CREATE TABLE t (x INTEGER);")
            .unwrap();
        assert!(restore_db_snapshot(&live, &foreign, MASTER).is_err());

        assert_eq!(titles(&live), vec!["old"]);
        assert_eq!(file_names(live_dir.path()), before);
    }

    #[test]
    fn restores_when_no_live_database_exists() {
        let live_dir = tempfile::tempdir().unwrap();
        let live = live_dir.path().join("passwords.db");
        let other = tempfile::tempdir().unwrap();
        let source = other.path().join("source.db");
        vault_with(&source, &["only"]);
        let candidate = other.path().join("backup.db");
        snapshot_of(&source, &candidate);
        let outcome = restore_db_snapshot(&live, &candidate, MASTER).unwrap();
        assert_eq!(outcome.previous_copy, None);
        assert_eq!(titles(&live), vec!["only"]);
    }
}
