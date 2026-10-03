//! Key verifier: detects a wrong or stale vault key before it is installed.
//!
//! The `key_check` table holds one AES-GCM blob (the standard v2 envelope)
//! of a fixed constant, encrypted with the vault key, plus the `master.salt`
//! that key was derived from. A candidate key is accepted when it decrypts
//! the blob. The salt binding makes the row self-invalidating: an older build
//! that changes the master password (new salt) without knowing about this
//! table leaves a row whose salt no longer matches, and it is then ignored
//! instead of rejecting the new key.
//!
//! The table is purely additive. Vaults without it keep unlocking (the master
//! password is verified against the PHC hash instead) and it is written lazily
//! on the next master-password unlock.

use super::schema;
use crate::crypto::{aes_gcm_v2, DerivedKey};
use crate::Result;
use rusqlite::{params, Connection, OptionalExtension};

const PLAINTEXT: &[u8] = b"ashypass-key-check-v1";

/// Outcome of checking a candidate key against the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// The current `key_check` row decrypts with the key.
    Verified,
    /// No usable `key_check` row, but a stored entry decrypts with the key.
    VerifiedByEntry,
    /// No usable `key_check` row and nothing encrypted to test against.
    Unverifiable,
    /// The key does not open this vault.
    Mismatch,
}

impl KeyStatus {
    pub fn is_accepted(self) -> bool {
        !matches!(self, KeyStatus::Mismatch)
    }
}

/// Encrypt the verifier constant with `key`.
pub fn seal(key: &DerivedKey) -> Result<Vec<u8>> {
    aes_gcm_v2::encrypt(key, PLAINTEXT)
}

/// True when `blob` is a verifier sealed with `key`.
pub fn opens(key: &DerivedKey, blob: &[u8]) -> bool {
    aes_gcm_v2::decrypt(key, blob).is_ok_and(|pt| pt == PLAINTEXT)
}

/// Return the verifier blob if one exists *and* belongs to `salt`.
pub fn read_for_salt(conn: &Connection, salt: &str) -> Result<Option<Vec<u8>>> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'key_check')",
        [],
        |r| r.get(0),
    )?;
    if !exists {
        return Ok(None);
    }
    let row: Option<(Vec<u8>, String)> = conn
        .query_row("SELECT blob, salt FROM key_check WHERE id = 1", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?;
    Ok(row.and_then(|(blob, row_salt)| (row_salt == salt).then_some(blob)))
}

/// Insert or replace the verifier for `key` derived from `salt`.
pub fn write(conn: &Connection, key: &DerivedKey, salt: &str) -> Result<()> {
    conn.execute(schema::CREATE_KEY_CHECK, [])?;
    conn.execute(
        "INSERT INTO key_check (id, blob, salt) VALUES (1, ?, ?)
         ON CONFLICT(id) DO UPDATE SET blob = excluded.blob, salt = excluded.salt",
        params![seal(key)?, salt],
    )?;
    Ok(())
}

/// Classify `key` against the vault behind `conn`, using `salt` (the current
/// `master.salt`) to decide whether the stored verifier is still current.
pub fn check(conn: &Connection, key: &DerivedKey, salt: &str) -> Result<KeyStatus> {
    if let Some(blob) = read_for_salt(conn, salt)? {
        if opens(key, &blob) {
            return Ok(KeyStatus::Verified);
        }
    }
    // No (current) verifier, or one that did not open: fall back to any
    // stored ciphertext. Every protected column shares the vault key.
    for sql in [
        "SELECT password_encrypted FROM passwords LIMIT 1",
        "SELECT password_encrypted FROM passwords_trash LIMIT 1",
        "SELECT password_encrypted FROM passwords_history LIMIT 1",
        "SELECT ciphertext FROM attachments LIMIT 1",
    ] {
        let blob: Option<Vec<u8>> = conn.query_row(sql, [], |r| r.get(0)).optional()?;
        if let Some(blob) = blob {
            return Ok(if aes_gcm_v2::decrypt(key, &blob).is_ok() {
                KeyStatus::VerifiedByEntry
            } else {
                KeyStatus::Mismatch
            });
        }
    }
    // A verifier that exists for this salt but did not open, with nothing
    // else to test against, is still a mismatch.
    if read_for_salt(conn, salt)?.is_some() {
        return Ok(KeyStatus::Mismatch);
    }
    Ok(KeyStatus::Unverifiable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        schema::initialize(&conn).unwrap();
        conn
    }

    #[test]
    fn verifier_round_trip_and_salt_binding() {
        let conn = conn();
        let key = DerivedKey::new([7u8; 32]);
        let other = DerivedKey::new([8u8; 32]);
        assert_eq!(
            check(&conn, &key, "salt-a").unwrap(),
            KeyStatus::Unverifiable
        );
        write(&conn, &key, "salt-a").unwrap();
        assert_eq!(check(&conn, &key, "salt-a").unwrap(), KeyStatus::Verified);
        assert_eq!(check(&conn, &other, "salt-a").unwrap(), KeyStatus::Mismatch);
        // A verifier for another salt is stale and ignored.
        assert_eq!(
            check(&conn, &other, "salt-b").unwrap(),
            KeyStatus::Unverifiable
        );
    }

    #[test]
    fn falls_back_to_entries_without_verifier() {
        let conn = conn();
        let key = DerivedKey::new([7u8; 32]);
        let other = DerivedKey::new([8u8; 32]);
        conn.execute(
            "INSERT INTO passwords (title, password_encrypted, created_at, updated_at)
             VALUES ('t', ?, 0, 0)",
            [aes_gcm_v2::encrypt(&key, b"pw").unwrap()],
        )
        .unwrap();
        assert_eq!(check(&conn, &key, "s").unwrap(), KeyStatus::VerifiedByEntry);
        assert_eq!(check(&conn, &other, "s").unwrap(), KeyStatus::Mismatch);
        // A stale verifier sealed with the wrong key does not override the
        // entry evidence.
        write(&conn, &other, "s").unwrap();
        assert_eq!(check(&conn, &key, "s").unwrap(), KeyStatus::VerifiedByEntry);
    }
}
