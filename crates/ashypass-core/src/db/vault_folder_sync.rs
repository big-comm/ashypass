//! Entry access for the encrypted folder sync (`crate::sync::folder`): the
//! full content of an entry by its `uid`, and writing an entry from another
//! device with that device's `updated_at`, so the newest change keeps
//! winning wherever it is applied.

use super::{Value, Vault, ITEM_LOGIN};
use crate::{Error, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

/// Everything an entry holds, as carried between devices.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncItem {
    pub item_type: String,
    pub title: String,
    pub username: Option<String>,
    pub password: String,
    pub notes: Option<String>,
    pub url: Option<String>,
    pub totp_secret: Option<String>,
    pub totp_algorithm: String,
    pub totp_digits: u8,
    pub totp_period: u32,
    pub category: Option<String>,
    pub favorite: bool,
    pub extra: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl Vault {
    /// The connection, for the sync engine's own bookkeeping tables.
    pub(crate) fn sync_conn(&self) -> &Connection {
        &self.conn
    }

    /// Encrypt a secret of the sync engine with the vault key.
    pub(crate) fn sync_seal(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.ensure_session_current()?;
        crate::crypto::aes_gcm_v2::encrypt(self.key()?, data)
    }

    pub(crate) fn sync_open(&self, blob: &[u8]) -> Result<Vec<u8>> {
        crate::crypto::aes_gcm_v2::decrypt(self.key()?, blob)
    }

    /// `(uid, updated_at)` of every entry.
    pub fn sync_inventory(&self) -> Result<Vec<(String, i64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT uid, updated_at FROM passwords WHERE uid IS NOT NULL")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn sync_item(&self, uid: &str) -> Result<Option<SyncItem>> {
        let Some(id) = self.id_by_uid(uid)? else {
            return Ok(None);
        };
        let Some(e) = self.get_without_touch(id)? else {
            return Ok(None);
        };
        Ok(Some(SyncItem {
            item_type: e.item_type,
            title: e.title,
            username: e.username,
            password: e.password.unwrap_or_default(),
            notes: e.notes,
            url: e.url,
            totp_secret: e.totp_secret,
            totp_algorithm: e.totp_algorithm,
            totp_digits: e.totp_digits,
            totp_period: e.totp_period,
            category: e.category,
            favorite: e.favorite,
            extra: e.extra,
            tags: self.tags_of(id)?,
        }))
    }

    /// Create or replace the entry `uid` with `item`, stamped `updated_at`.
    /// A replaced password goes to the password history, as with any edit.
    pub fn sync_apply(&self, uid: &str, item: &SyncItem, updated_at: i64) -> Result<()> {
        crate::totp::Algorithm::parse(&item.totp_algorithm)?;
        let opt = |v: &Option<String>| -> Result<Value> {
            Ok(match v.as_deref().filter(|s| !s.is_empty()) {
                Some(s) => self.encrypt(s)?.into(),
                None => Value::Null,
            })
        };
        let password = self.encrypt(&item.password)?;
        let (notes, totp, extra) = (
            opt(&item.notes)?,
            opt(&item.totp_secret)?,
            opt(&item.extra)?,
        );
        let item_type = if item.item_type.is_empty() {
            ITEM_LOGIN
        } else {
            item.item_type.as_str()
        };
        let tx = self.conn.unchecked_transaction()?;
        let existing: Option<(i64, Vec<u8>)> = tx
            .query_row(
                "SELECT id, password_encrypted FROM passwords WHERE uid = ?",
                params![uid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let id = match existing {
            Some((id, old_password)) => {
                if self.decrypt(&old_password)? != item.password {
                    tx.execute(
                        "INSERT INTO passwords_history (entry_id, password_encrypted, changed_at)
                         VALUES (?, ?, ?)",
                        params![id, old_password, updated_at],
                    )?;
                }
                tx.execute(
                    "UPDATE passwords SET title = ?, username = ?, password_encrypted = ?,
                        notes_encrypted = ?, url = ?, totp_secret_encrypted = ?,
                        totp_algorithm = ?, totp_digits = ?, totp_period = ?, category = ?,
                        favorite = ?, item_type = ?, extra_encrypted = ?, updated_at = ?
                     WHERE id = ?",
                    params![
                        item.title,
                        item.username,
                        password,
                        notes,
                        item.url,
                        totp,
                        item.totp_algorithm,
                        item.totp_digits as i64,
                        item.totp_period as i64,
                        item.category,
                        item.favorite as i64,
                        item_type,
                        extra,
                        updated_at,
                        id
                    ],
                )?;
                id
            }
            None => {
                tx.execute(
                    "INSERT INTO passwords (uid, title, username, password_encrypted,
                        notes_encrypted, url, totp_secret_encrypted, totp_algorithm, totp_digits,
                        totp_period, category, favorite, item_type, extra_encrypted,
                        created_at, updated_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    params![
                        uid,
                        item.title,
                        item.username,
                        password,
                        notes,
                        item.url,
                        totp,
                        item.totp_algorithm,
                        item.totp_digits as i64,
                        item.totp_period as i64,
                        item.category,
                        item.favorite as i64,
                        item_type,
                        extra,
                        updated_at,
                        updated_at
                    ],
                )?;
                tx.last_insert_rowid()
            }
        };
        tx.commit()?;
        self.set_tags_unstamped(id, &item.tags)?;
        self.notify_change();
        Ok(())
    }

    /// Move the entry `uid` to the trash (a deletion made on another device).
    pub fn sync_remove(&self, uid: &str) -> Result<bool> {
        match self.id_by_uid(uid)? {
            Some(id) => self.delete(id),
            None => Ok(false),
        }
    }

    /// Reject a `uid` that is not 32 lower-case hex characters.
    pub fn check_uid(uid: &str) -> Result<()> {
        if uid.len() == 32
            && uid
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            Ok(())
        } else {
            Err(Error::InvalidInput("malformed entry uid".into()))
        }
    }
}
