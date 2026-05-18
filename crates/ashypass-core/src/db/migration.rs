//! Migrations: bring legacy Python (v1, Fernet) DB to v2 (AES-256-GCM).
//!
//! Strategy:
//! 1. Add missing columns non-destructively (crypto_version default 1 if old master row
//!    predates this build).
//! 2. On unlock, if `master.crypto_version = 1`, do an atomic re-encryption pass:
//!    - decrypt every BLOB with legacy Fernet using the stored salt
//!    - re-encrypt with AES-GCM using a freshly-derived Argon2 key + new salt
//!    - update `master` row (new hash, new salt, crypto_version=2)
//! 3. On success, file-level `.db.v1.bak` backup is written *before* the SQL transaction.

use crate::crypto::{aes_gcm_v2, argon2_kdf, fernet_legacy};
use crate::{Error, Result};
use rusqlite::{params, Connection};
use std::path::Path;

type LegacyEncryptedRow = (i64, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>);

/// Add columns introduced after the initial Python release (idempotent).
pub fn add_missing_columns(conn: &Connection) -> Result<()> {
    let alters = [
        ("master",    "ALTER TABLE master ADD COLUMN crypto_version INTEGER NOT NULL DEFAULT 1"),
        ("passwords", "ALTER TABLE passwords ADD COLUMN totp_secret_encrypted BLOB"),
        ("passwords", "ALTER TABLE passwords ADD COLUMN totp_algorithm TEXT DEFAULT 'SHA1'"),
        ("passwords", "ALTER TABLE passwords ADD COLUMN totp_digits INTEGER DEFAULT 6"),
        ("passwords", "ALTER TABLE passwords ADD COLUMN totp_period INTEGER DEFAULT 30"),
        ("passwords", "ALTER TABLE passwords ADD COLUMN category TEXT"),
        ("passwords", "ALTER TABLE passwords ADD COLUMN favorite INTEGER DEFAULT 0"),
    ];
    for (_, sql) in &alters {
        // Ignore "duplicate column" — the cheapest way is to attempt and swallow.
        let _ = conn.execute(sql, []);
    }
    conn.execute(crate::db::schema::CREATE_FOLDERS, [])?;
    conn.execute(crate::db::schema::CREATE_NEXTCLOUD_FOLDER_MAPPING, [])?;
    Ok(())
}

/// File-level backup of the SQLite database before destructive migration.
pub fn backup_db_file(db_path: &Path) -> Result<()> {
    if !db_path.exists() {
        return Ok(());
    }
    let bak = db_path.with_extension("db.v1.bak");
    if bak.exists() {
        // Don't overwrite an earlier backup.
        return Ok(());
    }
    std::fs::copy(db_path, &bak)?;
    Ok(())
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

/// Re-encrypt every BLOB column from Fernet (v1) to AES-GCM (v2). Atomic transaction.
///
/// Caller must have verified the master password against Argon2id already
/// (via `argon2_kdf::verify_master`).
pub fn migrate_v1_to_v2(conn: &mut Connection, master_password: &str) -> Result<()> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    let (hash, old_salt_text) = read_master_v1(conn)?;
    if !argon2_kdf::verify_master(master_password, &hash)? {
        return Err(Error::InvalidMasterPassword);
    }

    // Legacy keys
    let (sig_key, enc_key) = fernet_legacy::derive_fernet_keys(master_password, &old_salt_text)?;

    // New AES-GCM key derivation: fresh random salt, Argon2id.
    let mut new_salt = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut new_salt);
    let new_salt_text = URL_SAFE_NO_PAD.encode(new_salt);
    let new_key = argon2_kdf::derive_key_v2(master_password, new_salt_text.as_bytes())?;
    let new_hash = argon2_kdf::hash_master(master_password)?;

    let tx = conn.transaction()?;
    {
        let mut select = tx.prepare(
            "SELECT id, password_encrypted, notes_encrypted, totp_secret_encrypted FROM passwords",
        )?;
        let rows: Vec<LegacyEncryptedRow> = select
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Option<Vec<u8>>>(2)?,
                    r.get::<_, Option<Vec<u8>>>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<_>>()?;
        drop(select);

        let mut upd = tx.prepare(
            "UPDATE passwords SET password_encrypted = ?, notes_encrypted = ?, totp_secret_encrypted = ? WHERE id = ?",
        )?;
        for (id, pw, notes, totp) in rows {
            let pw_pt = fernet_legacy::decrypt_token(&sig_key, &enc_key, &pw)?;
            let new_pw = aes_gcm_v2::encrypt(&new_key, &pw_pt)?;

            let new_notes = match notes {
                Some(b) => Some(aes_gcm_v2::encrypt(
                    &new_key,
                    &fernet_legacy::decrypt_token(&sig_key, &enc_key, &b)?,
                )?),
                None => None,
            };
            let new_totp = match totp {
                Some(b) => Some(aes_gcm_v2::encrypt(
                    &new_key,
                    &fernet_legacy::decrypt_token(&sig_key, &enc_key, &b)?,
                )?),
                None => None,
            };

            upd.execute(params![new_pw, new_notes, new_totp, id])?;
        }

        tx.execute(
            "UPDATE master SET password_hash = ?, salt = ?, crypto_version = 2 WHERE id = 1",
            params![new_hash, new_salt_text],
        )?;
    }
    tx.commit()?;
    log::info!("Vault migrated to crypto_version=2");
    Ok(())
}
