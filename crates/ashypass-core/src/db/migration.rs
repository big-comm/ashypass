//! Migrations: bring legacy Python (v1, Fernet) DB to v2 (AES-256-GCM).
//!
//! Strategy:
//! 1. Add missing columns non-destructively (crypto_version default 1 if old master row
//!    predates this build).
//! 2. On unlock, if `master.crypto_version = 1`, do an atomic re-encryption pass:
//!    - decrypt every BLOB (active, history, trash and attachment tables) with
//!      legacy Fernet using the stored salt
//!    - re-encrypt with AES-GCM using a freshly-derived Argon2 key + new salt
//!    - update `master` row (new hash, new salt, crypto_version=2) and seal the
//!      key verifier
//! 3. Before the SQL transaction a consistent `.db.v1.bak` snapshot is taken
//!    with the SQLite online-backup API (WAL pages included). It is never
//!    deleted automatically; see `v1_backup` / `remove_v1_backup`.

use crate::config::ensure_private_file;
use crate::crypto::{aes_gcm_v2, argon2_kdf, fernet_legacy, DerivedKey};
use crate::{db::key_check, Error, Result};
use rusqlite::{params_from_iter, types::Value, Connection};
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Every table holding encrypted BLOBs: (table, id column, blob columns).
const ENCRYPTED_TABLES: &[(&str, &str, &[&str])] = &[
    (
        "passwords",
        "id",
        &[
            "password_encrypted",
            "notes_encrypted",
            "totp_secret_encrypted",
        ],
    ),
    (
        "passwords_trash",
        "id",
        &[
            "password_encrypted",
            "notes_encrypted",
            "totp_secret_encrypted",
        ],
    ),
    ("passwords_history", "id", &["password_encrypted"]),
    (
        "passwords_history_trash",
        "original_history_id",
        &["password_encrypted"],
    ),
    ("attachments", "id", &["ciphertext"]),
    (
        "attachments_trash",
        "original_attachment_id",
        &["ciphertext"],
    ),
];

/// Add columns introduced after the initial Python release (idempotent).
pub fn add_missing_columns(conn: &Connection) -> Result<()> {
    crate::db::schema::add_legacy_columns(conn);
    conn.execute(crate::db::schema::CREATE_FOLDERS, [])?;
    conn.execute(crate::db::schema::CREATE_NEXTCLOUD_FOLDER_MAPPING, [])?;
    Ok(())
}

/// Where the pre-migration snapshot of `db_path` lives.
pub fn v1_backup_path(db_path: &Path) -> PathBuf {
    db_path.with_extension("db.v1.bak")
}

/// The pre-migration snapshot, if one is still on disk. The app can use this
/// to offer removing it once the user is happy with the migrated vault.
pub fn v1_backup(db_path: &Path) -> Option<PathBuf> {
    let bak = v1_backup_path(db_path);
    bak.is_file().then_some(bak)
}

/// Overwrite the pre-migration snapshot with zeros, flush, and unlink it.
/// Returns `false` when there was nothing to remove. The snapshot holds the
/// whole vault under the weaker v1 crypto, so plain unlinking is not enough.
///
/// Best effort against recovery only: copy-on-write filesystems and SSD
/// wear-levelling may keep old blocks around regardless.
pub fn remove_v1_backup(db_path: &Path) -> Result<bool> {
    let bak = v1_backup_path(db_path);
    if !bak.is_file() {
        return Ok(false);
    }
    overwrite_and_unlink(&bak)?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = bak.clone().into_os_string();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        if sidecar.is_file() {
            overwrite_and_unlink(&sidecar)?;
        }
    }
    Ok(true)
}

fn overwrite_and_unlink(path: &Path) -> Result<()> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    let len = file.metadata()?.len();
    file.seek(SeekFrom::Start(0))?;
    let zeros = [0u8; 64 * 1024];
    let mut remaining = len;
    while remaining > 0 {
        let chunk = remaining.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..chunk])?;
        remaining -= chunk as u64;
    }
    file.sync_all()?;
    drop(file);
    std::fs::remove_file(path)?;
    Ok(())
}

/// File-level backup of the SQLite database before destructive migration.
///
/// Opens its own connection; prefer `backup_db_from` when a connection to the
/// database is already open.
pub fn backup_db_file(db_path: &Path) -> Result<()> {
    if !db_path.exists() {
        return Ok(());
    }
    let conn = Connection::open(db_path)?;
    conn.busy_timeout(Duration::from_secs(5))?;
    backup_db_from(&conn, db_path)
}

/// Snapshot the database behind `conn` to `v1_backup_path(db_path)` using the
/// SQLite online-backup API, so pages still sitting in the WAL are included
/// (a raw file copy of the main database would miss them). An existing
/// backup is never overwritten; a failed one is removed.
pub fn backup_db_from(conn: &Connection, db_path: &Path) -> Result<()> {
    if !db_path.exists() {
        return Ok(());
    }
    let bak = v1_backup_path(db_path);
    if bak.exists() {
        // Don't overwrite an earlier backup.
        return Ok(());
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&bak)?;
    let result = (|| {
        let mut destination = Connection::open(&bak)?;
        let backup = rusqlite::backup::Backup::new(conn, &mut destination)?;
        backup.run_to_completion(128, Duration::from_millis(10), None)?;
        drop(backup);
        let integrity: String =
            destination.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if integrity != "ok" {
            return Err(Error::Other(format!(
                "pre-migration backup integrity check failed: {integrity}"
            )));
        }
        destination.close().map_err(|(_, error)| error)?;
        ensure_private_file(&bak)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&bak);
    }
    result
}

/// Detect crypto version stored in `master`. Returns `None` if no master row exists.
pub fn detect_crypto_version(conn: &Connection) -> Result<Option<i64>> {
    let mut stmt = conn.prepare("SELECT crypto_version FROM master WHERE id = 1")?;
    let mut rows = stmt.query([])?;
    Ok(rows.next()?.map(|r| r.get::<_, i64>(0).unwrap_or(1)))
}

/// Read master.salt and master.password_hash for v1 unlock.
pub fn read_master_v1(conn: &Connection) -> Result<(String, String)> {
    let (hash, salt) = conn.query_row(
        "SELECT password_hash, salt FROM master WHERE id = 1",
        [],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    )?;
    Ok((hash, salt))
}

fn table_columns(conn: &Connection, table: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT name FROM pragma_table_info(?)")?;
    let columns = stmt
        .query_map([table], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(columns)
}

/// Convert every non-NULL blob column of `table` from Fernet to AES-GCM.
/// Tables or columns missing from this particular legacy schema are skipped.
fn convert_table(
    conn: &Connection,
    table: &str,
    id_column: &str,
    blob_columns: &[&str],
    fernet: &([u8; 16], [u8; 16]),
    new_key: &DerivedKey,
) -> Result<usize> {
    let existing = table_columns(conn, table)?;
    if !existing.iter().any(|c| c == id_column) {
        return Ok(0);
    }
    let columns: Vec<&str> = blob_columns
        .iter()
        .copied()
        .filter(|c| existing.iter().any(|e| e == c))
        .collect();
    if columns.is_empty() {
        return Ok(0);
    }

    let select = format!("SELECT {id_column}, {} FROM {table}", columns.join(", "));
    let mut stmt = conn.prepare(&select)?;
    let rows = stmt
        .query_map([], |r| {
            let id: Value = r.get(0)?;
            let blobs = (1..=columns.len())
                .map(|i| r.get::<_, Option<Vec<u8>>>(i))
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok((id, blobs))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);

    let assignments = columns
        .iter()
        .map(|c| format!("{c} = ?"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut update = conn.prepare(&format!(
        "UPDATE {table} SET {assignments} WHERE {id_column} = ?"
    ))?;
    let count = rows.len();
    for (id, blobs) in rows {
        let mut values: Vec<Value> = Vec::with_capacity(blobs.len() + 1);
        for blob in blobs {
            values.push(match blob {
                Some(token) => {
                    let plaintext = fernet_legacy::decrypt_token(&fernet.0, &fernet.1, &token)
                        .map_err(|e| Error::Crypto(format!("{table}: {e}")))?;
                    Value::Blob(aes_gcm_v2::encrypt(new_key, &plaintext)?)
                }
                None => Value::Null,
            });
        }
        values.push(id);
        update.execute(params_from_iter(values))?;
    }
    Ok(count)
}

/// Re-encrypt every BLOB column from Fernet (v1) to AES-GCM (v2). Atomic transaction.
///
/// Verifies the master password against the stored Argon2id hash first.
pub fn migrate_v1_to_v2(conn: &mut Connection, master_password: &str) -> Result<()> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    let (hash, old_salt_text) = read_master_v1(conn)?;
    if !argon2_kdf::verify_master(master_password, &hash)? {
        return Err(Error::InvalidMasterPassword);
    }

    // Legacy keys
    let fernet = fernet_legacy::derive_fernet_keys(master_password, &old_salt_text)?;

    // New AES-GCM key derivation: fresh random salt, Argon2id.
    let mut new_salt = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut new_salt);
    let new_salt_text = URL_SAFE_NO_PAD.encode(new_salt);
    let new_key = argon2_kdf::derive_key_v2(master_password, new_salt_text.as_bytes())?;
    let new_hash = argon2_kdf::hash_master(master_password)?;

    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    for (table, id_column, blob_columns) in ENCRYPTED_TABLES {
        let converted = convert_table(&tx, table, id_column, blob_columns, &fernet, &new_key)?;
        if converted > 0 {
            log::info!("migrated {converted} row(s) of {table} to crypto_version=2");
        }
    }
    tx.execute(
        "UPDATE master SET password_hash = ?, salt = ?, crypto_version = 2 WHERE id = 1",
        rusqlite::params![new_hash, new_salt_text],
    )?;
    key_check::write(&tx, &new_key, &new_salt_text)?;
    tx.commit()?;
    log::info!("Vault migrated to crypto_version=2");
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::db::Vault;
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    use base64::{engine::general_purpose::URL_SAFE, Engine as _};
    use hmac::{Hmac, Mac};
    use rand::RngCore;
    use rusqlite::params;

    const MASTER: &str = "legacy master password";
    const SALT: &str = "bGVnYWN5LXB5dGhvbi1zYWx0LXRleHQ";

    /// Produce a Fernet token exactly like Python's `cryptography` package.
    pub(crate) fn fernet_encrypt(password: &str, salt: &str, plaintext: &[u8]) -> Vec<u8> {
        let (signing, encryption) = fernet_legacy::derive_fernet_keys(password, salt).unwrap();
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);
        let ct = cbc::Encryptor::<aes::Aes128>::new(&encryption.into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
        let mut token = vec![0x80u8];
        token.extend_from_slice(&1_600_000_000u64.to_be_bytes());
        token.extend_from_slice(&iv);
        token.extend_from_slice(&ct);
        let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(&signing).unwrap();
        mac.update(&token);
        token.extend_from_slice(&mac.finalize().into_bytes());
        URL_SAFE.encode(token).into_bytes()
    }

    fn f(plaintext: &str) -> Vec<u8> {
        fernet_encrypt(MASTER, SALT, plaintext.as_bytes())
    }

    /// Build a Python-era database: no crypto_version / TOTP / category /
    /// favorite columns. Returns the connection so tests can keep it open
    /// (and the WAL un-checkpointed) while the vault migrates.
    fn python_v1_db(path: &Path) -> Connection {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA wal_autocheckpoint = 0;
             CREATE TABLE master (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 password_hash TEXT NOT NULL,
                 salt TEXT NOT NULL,
                 created_at INTEGER NOT NULL);
             CREATE TABLE passwords (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 title TEXT NOT NULL,
                 username TEXT,
                 password_encrypted BLOB NOT NULL,
                 notes_encrypted BLOB,
                 url TEXT,
                 created_at INTEGER NOT NULL,
                 updated_at INTEGER NOT NULL,
                 last_accessed INTEGER);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO master (id, password_hash, salt, created_at) VALUES (1, ?, ?, 0)",
            params![argon2_kdf::hash_session_secret(MASTER).unwrap(), SALT],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO passwords (title, username, password_encrypted, notes_encrypted,
                                    created_at, updated_at)
             VALUES ('Mail', 'alice', ?, ?, 1, 2)",
            params![f("mail-secret"), f("mail-notes")],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO passwords (title, password_encrypted, created_at, updated_at)
             VALUES ('Bank', ?, 3, 4)",
            params![f("bank-secret")],
        )
        .unwrap();
        conn
    }

    #[test]
    fn python_v1_vault_migrates_every_table_and_keeps_a_full_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passwords.db");
        let legacy = python_v1_db(&path);

        let mut vault = Vault::open(&path).unwrap();
        // Rows a v1 vault could hold in the auxiliary tables.
        legacy
            .execute(
                "INSERT INTO passwords_history (entry_id, password_encrypted, changed_at)
                 VALUES (1, ?, 5)",
                params![f("mail-old")],
            )
            .unwrap();
        legacy
            .execute(
                "INSERT INTO attachments (entry_id, filename, ciphertext, size_bytes, created_at)
                 VALUES (1, 'a.txt', ?, 4, 6)",
                params![f("data")],
            )
            .unwrap();
        legacy
            .execute(
                "INSERT INTO passwords_trash (original_id, title, password_encrypted,
                                              totp_secret_encrypted, deleted_at)
                 VALUES (99, 'Gone', ?, ?, 7)",
                params![f("gone-secret"), f("JBSWY3DPEHPK3PXP")],
            )
            .unwrap();
        let trash_id = legacy.last_insert_rowid();
        legacy
            .execute(
                "INSERT INTO passwords_history_trash
                     (original_history_id, trash_id, password_encrypted, changed_at)
                 VALUES (500, ?, ?, 8)",
                params![trash_id, f("gone-old")],
            )
            .unwrap();
        legacy
            .execute(
                "INSERT INTO attachments_trash (original_attachment_id, trash_id, filename,
                                                ciphertext, size_bytes, created_at)
                 VALUES (600, ?, 'b.txt', ?, 5, 9)",
                params![trash_id, f("bdata")],
            )
            .unwrap();
        assert_eq!(
            detect_crypto_version(&legacy).unwrap(),
            Some(1),
            "the added column defaults legacy rows to v1"
        );

        assert!(matches!(
            vault.unlock("wrong password"),
            Err(Error::InvalidMasterPassword)
        ));
        vault.unlock(MASTER).unwrap();

        let entries = vault.list(None).unwrap();
        assert_eq!(entries.len(), 2);
        let mail = vault.get_without_touch(1).unwrap().unwrap();
        assert_eq!(mail.password.as_deref(), Some("mail-secret"));
        assert_eq!(mail.notes.as_deref(), Some("mail-notes"));
        assert_eq!(mail.username.as_deref(), Some("alice"));
        assert_eq!((mail.created_at, mail.updated_at), (1, 2));
        assert_eq!(vault.password_history(1).unwrap()[0].password, "mail-old");
        let attachment = vault.list_attachments(1).unwrap()[0].id;
        assert_eq!(
            vault.get_attachment(attachment).unwrap().unwrap().1,
            b"data"
        );

        let restored = vault.restore_from_trash(trash_id).unwrap().unwrap();
        let gone = vault.get_without_touch(restored).unwrap().unwrap();
        assert_eq!(gone.password.as_deref(), Some("gone-secret"));
        assert_eq!(gone.totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(
            vault.password_history(restored).unwrap()[0].password,
            "gone-old"
        );
        let attachment = vault.list_attachments(restored).unwrap()[0].id;
        assert_eq!(
            vault.get_attachment(attachment).unwrap().unwrap().1,
            b"bdata"
        );

        // Migration sealed a verifier for the new key.
        let salt: String = legacy
            .query_row("SELECT salt FROM master", [], |r| r.get(0))
            .unwrap();
        assert!(key_check::read_for_salt(&legacy, &salt).unwrap().is_some());

        // Reopen and unlock again: now a plain v2 vault.
        drop(vault);
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(MASTER).unwrap();
        assert_eq!(vault.list(None).unwrap().len(), 3);

        // The backup was taken from the live connection, so it contains the
        // rows that only existed in the WAL, still in v1 form.
        let bak = v1_backup(&path).expect("backup kept");
        let mode = std::fs::metadata(&bak).unwrap().permissions();
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777,
            0o600
        );
        let snapshot = Connection::open(&bak).unwrap();
        assert_eq!(detect_crypto_version(&snapshot).unwrap(), Some(1));
        let (count, first): (i64, Vec<u8>) = snapshot
            .query_row(
                "SELECT COUNT(*), (SELECT password_encrypted FROM passwords WHERE id = 1)
                 FROM passwords",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(count, 2);
        let (signing, encryption) = fernet_legacy::derive_fernet_keys(MASTER, SALT).unwrap();
        assert_eq!(
            fernet_legacy::decrypt_token(&signing, &encryption, &first).unwrap(),
            b"mail-secret"
        );
        drop(snapshot);

        assert!(remove_v1_backup(&path).unwrap());
        assert!(v1_backup(&path).is_none());
        assert!(!remove_v1_backup(&path).unwrap());
        drop(legacy);
    }

    #[test]
    fn failed_migration_rolls_back_and_keeps_v1_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passwords.db");
        let legacy = python_v1_db(&path);
        let mut vault = Vault::open(&path).unwrap();
        legacy
            .execute(
                "INSERT INTO passwords_history (entry_id, password_encrypted, changed_at)
                 VALUES (1, ?, 5)",
                params![b"not a fernet token".to_vec()],
            )
            .unwrap();
        let before: Vec<u8> = legacy
            .query_row(
                "SELECT password_encrypted FROM passwords WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();

        assert!(vault.unlock(MASTER).is_err());
        assert!(!vault.is_unlocked());
        assert_eq!(detect_crypto_version(&legacy).unwrap(), Some(1));
        let after: Vec<u8> = legacy
            .query_row(
                "SELECT password_encrypted FROM passwords WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(before, after);
        let (_, salt) = read_master_v1(&legacy).unwrap();
        assert_eq!(salt, SALT);
    }

    #[test]
    fn backup_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passwords.db");
        let conn = python_v1_db(&path);
        backup_db_from(&conn, &path).unwrap();
        let bak = v1_backup_path(&path);
        std::fs::write(&bak, b"earlier").unwrap();
        backup_db_from(&conn, &path).unwrap();
        backup_db_file(&path).unwrap();
        assert_eq!(std::fs::read(&bak).unwrap(), b"earlier");
    }
}
