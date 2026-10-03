//! Vault — the user-facing API on top of crypto + sqlite.
//!
//! Lifecycle:
//! 1. `Vault::open(path)` — opens connection, runs schema/migration columns.
//! 2. First run: `set_master_password()`. Returning user: `unlock()` which may
//!    transparently invoke `migration::migrate_v1_to_v2()` on legacy DBs.
//! 3. CRUD: `add`, `list`, `get` (decrypts), `update`, `delete`, `toggle_favorite`.

use crate::config::{ensure_private_file, MIN_MASTER_PASSWORD_LENGTH};
use crate::crypto::{aes_gcm_v2, argon2_kdf, DerivedKey};
use crate::db::key_check::{self, KeyStatus};
use crate::settings::QuickUnlockPrefs;
use crate::{db::migration, db::schema, Error, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use rusqlite::{
    params, params_from_iter, types::Value, Connection, OptionalExtension, Row, TransactionBehavior,
};
use std::cell::RefCell;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;
use zeroize::Zeroize;

type ChangeListener = Rc<dyn Fn() + 'static>;
type EncryptedEntryRow = (i64, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>);
type EncryptedPayload = (Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>);
type TrashRow = (
    String,
    Option<String>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<String>,
    Option<Vec<u8>>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
);
type AttachmentRow = (i64, i64, String, Option<String>, Vec<u8>, i64, i64);

pub struct Vault {
    db_path: PathBuf,
    conn: Connection,
    key: Option<DerivedKey>,
    /// In-memory cache of the derived key so the user can re-enter via a PIN
    /// after auto-lock without re-running Argon2 on the master password.
    /// Cleared on `full_lock()` or app exit.
    cached_key: Option<DerivedKey>,
    /// PHC-format Argon2id hash of the quick-unlock PIN. None means quick-
    /// unlock is not configured for this session.
    quick_pin_hash: Option<String>,
    /// Single-threaded change subscribers. The vault is owned by exactly one
    /// thread (a `RefCell<Vault>` in the GTK app) so a cross-thread `Arc<Mutex>`
    /// is unnecessary; a plain `Rc<RefCell>` is cheaper and lets listeners
    /// capture non-`Send` values like `glib` widgets directly. Each listener
    /// is held as an `Rc` so `notify_change` can snapshot the list cheaply
    /// before invoking handlers — handlers may re-enter the vault.
    listeners: Rc<RefCell<Vec<ChangeListener>>>,
}

#[derive(Debug, Clone, Default)]
pub struct NewEntry {
    pub title: String,
    pub username: Option<String>,
    pub password: String,
    pub notes: Option<String>,
    pub url: Option<String>,
    pub totp_secret: Option<String>,
    pub totp_algorithm: Option<String>,
    pub totp_digits: Option<u8>,
    pub totp_period: Option<u32>,
    pub category: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct UpdateEntry {
    pub title: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub notes: Option<Option<String>>,
    pub url: Option<Option<String>>,
    pub totp_secret: Option<Option<String>>,
    pub totp_algorithm: Option<String>,
    pub totp_digits: Option<u8>,
    pub totp_period: Option<u32>,
    pub category: Option<Option<String>>,
}

#[derive(Debug, Clone)]
pub struct PasswordHistoryEntry {
    pub id: i64,
    pub entry_id: i64,
    pub password: String,
    pub changed_at: i64,
}

#[derive(Debug, Clone)]
pub struct AttachmentInfo {
    pub id: i64,
    pub entry_id: i64,
    pub filename: String,
    pub mime_type: Option<String>,
    pub size_bytes: u64,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct NextcloudMapping {
    pub entry_id: i64,
    pub nc_uuid: String,
    pub last_synced_at: i64,
    pub local_updated_at_snapshot: i64,
    pub remote_edited_snapshot: i64,
    pub remote_revision_snapshot: String,
}

#[derive(Debug, Clone)]
pub struct NextcloudFolderMapping {
    pub local_name: String,
    pub nc_uuid: String,
    pub last_synced_at: i64,
    pub remote_edited_snapshot: i64,
    pub remote_revision_snapshot: String,
}

#[derive(Debug, Clone)]
pub struct TrashedEntry {
    pub trash_id: i64,
    pub original_id: i64,
    pub title: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub category: Option<String>,
    pub deleted_at: i64,
}

/// Public view of a password entry. `password`/`notes`/`totp_secret` are
/// `Some` only when fetched via `get()`.
#[derive(Debug, Clone)]
pub struct PasswordEntry {
    pub id: i64,
    pub title: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub password: Option<String>,
    pub notes: Option<String>,
    pub totp_secret: Option<String>,
    pub totp_algorithm: String,
    pub totp_digits: u8,
    pub totp_period: u32,
    pub has_totp: bool,
    pub category: Option<String>,
    pub favorite: bool,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_accessed: Option<i64>,
}

impl Vault {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db_path = path.as_ref().to_path_buf();
        if db_path != Path::new(":memory:") {
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(&db_path)?;
            ensure_private_file(&db_path)?;
        }
        let conn = Connection::open(&db_path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )?;
        prepare_schema(&conn)?;
        Ok(Self {
            db_path,
            conn,
            key: None,
            cached_key: None,
            quick_pin_hash: None,
            listeners: Rc::new(RefCell::new(Vec::new())),
        })
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Create a consistent online SQLite backup. Existing files are never
    /// overwritten, and a failed backup is removed before returning.
    pub fn backup_to(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        let result = (|| {
            let mut destination = Connection::open(path)?;
            let backup = rusqlite::backup::Backup::new(&self.conn, &mut destination)?;
            backup.run_to_completion(128, Duration::from_millis(10), None)?;
            drop(backup);
            let integrity: String =
                destination.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
            if integrity != "ok" {
                return Err(Error::Other(format!(
                    "backup integrity check failed: {integrity}"
                )));
            }
            destination.close().map_err(|(_, error)| error)?;
            ensure_private_file(path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(path);
        }
        result
    }

    /// Path of the snapshot taken before the v1 → v2 migration, if it is
    /// still on disk. It holds the whole vault under the legacy crypto.
    pub fn legacy_backup_path(&self) -> Option<PathBuf> {
        migration::v1_backup(&self.db_path)
    }

    /// Overwrite and delete the pre-migration snapshot. `Ok(false)` when
    /// there was none. Never called automatically: offer it to the user.
    pub fn remove_legacy_backup(&self) -> Result<bool> {
        migration::remove_v1_backup(&self.db_path)
    }

    pub fn validate_database(path: impl AsRef<Path>) -> Result<()> {
        let connection =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let integrity: String =
            connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if integrity != "ok" {
            return Err(Error::InvalidInput(format!(
                "database integrity check failed: {integrity}"
            )));
        }
        for table in ["master", "passwords"] {
            let exists: i64 = connection.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
                [table],
                |row| row.get(0),
            )?;
            if exists != 1 {
                return Err(Error::InvalidInput(format!(
                    "database is missing the {table} table"
                )));
            }
        }
        Ok(())
    }

    pub fn open_with_session_key(path: impl AsRef<Path>, key: DerivedKey) -> Result<Self> {
        let mut vault = Self::open(path)?;
        vault.key = Some(key.clone());
        vault.cached_key = Some(key);
        Ok(vault)
    }

    pub fn session_reopen_parts(&self) -> Result<(PathBuf, DerivedKey)> {
        Ok((self.db_path.clone(), self.key()?.clone()))
    }

    pub fn add_change_listener<F>(&self, f: F)
    where
        F: Fn() + 'static,
    {
        self.listeners.borrow_mut().push(Rc::new(f));
    }

    /// Run a group of vault operations atomically. Used by importers so a
    /// malformed or partially incompatible document cannot leave half an
    /// import behind.
    pub fn transaction<T, F>(&self, operation: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        let transaction = self.conn.unchecked_transaction()?;
        match operation() {
            Ok(value) => {
                transaction.commit()?;
                Ok(value)
            }
            Err(error) => {
                transaction.rollback()?;
                Err(error)
            }
        }
    }

    fn notify_change(&self) {
        // Every mutation bumps the sync generation. The remote-backup layer
        // uses this to skip no-op pushes and to detect concurrent writes from
        // another device. Errors are intentionally swallowed — a missing
        // sync_meta row should not break a mutation that already succeeded.
        let _ = self.conn.execute(
            "UPDATE sync_meta SET generation = generation + 1 WHERE id = 1",
            [],
        );
        // Snapshot first so a subscriber that re-enters notify_change (via a
        // mutation) doesn't trip the RefCell's borrow rules.
        let snapshot: Vec<ChangeListener> = self.listeners.borrow().clone();
        for cb in snapshot {
            cb();
        }
    }

    /// Current local generation counter. Starts at 0 on a fresh vault and is
    /// incremented by `notify_change()` on every mutation.
    pub fn current_generation(&self) -> Result<u64> {
        let g: i64 = self
            .conn
            .query_row("SELECT generation FROM sync_meta WHERE id = 1", [], |r| {
                r.get(0)
            })
            .unwrap_or(0);
        Ok(g.max(0) as u64)
    }

    /// Local generation that was last successfully uploaded to the remote.
    pub fn last_synced_generation(&self) -> Result<u64> {
        let g: i64 = self
            .conn
            .query_row(
                "SELECT last_synced_generation FROM sync_meta WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        Ok(g.max(0) as u64)
    }

    /// Highest remote generation observed at the last successful sync.
    pub fn last_remote_generation(&self) -> Result<u64> {
        let g: i64 = self
            .conn
            .query_row(
                "SELECT last_remote_generation FROM sync_meta WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        Ok(g.max(0) as u64)
    }

    /// Record a successful sync: local generation just pushed and the highest
    /// remote generation we saw at that moment. `when` is a unix timestamp.
    pub fn mark_synced(&self, local_gen: u64, remote_gen: u64, when: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE sync_meta
                SET last_synced_generation = ?,
                    last_remote_generation = ?,
                    last_synced_at         = ?
              WHERE id = 1",
            params![local_gen as i64, remote_gen as i64, when],
        )?;
        Ok(())
    }

    // ---------------------------------------------------------------
    // Nextcloud Passwords mapping
    // ---------------------------------------------------------------

    pub fn nc_mapping_for_entry(&self, entry_id: i64) -> Result<Option<NextcloudMapping>> {
        let m = self
            .conn
            .query_row(
                "SELECT entry_id, nc_uuid, last_synced_at,
                        local_updated_at_snapshot, remote_edited_snapshot,
                        remote_revision_snapshot
                 FROM nextcloud_mapping WHERE entry_id = ?",
                params![entry_id],
                |r| {
                    Ok(NextcloudMapping {
                        entry_id: r.get(0)?,
                        nc_uuid: r.get(1)?,
                        last_synced_at: r.get(2)?,
                        local_updated_at_snapshot: r.get(3)?,
                        remote_edited_snapshot: r.get(4)?,
                        remote_revision_snapshot: r.get(5)?,
                    })
                },
            )
            .optional()?;
        Ok(m)
    }

    pub fn nc_mapping_for_uuid(&self, uuid: &str) -> Result<Option<NextcloudMapping>> {
        let m = self
            .conn
            .query_row(
                "SELECT entry_id, nc_uuid, last_synced_at,
                        local_updated_at_snapshot, remote_edited_snapshot,
                        remote_revision_snapshot
                 FROM nextcloud_mapping WHERE nc_uuid = ?",
                params![uuid],
                |r| {
                    Ok(NextcloudMapping {
                        entry_id: r.get(0)?,
                        nc_uuid: r.get(1)?,
                        last_synced_at: r.get(2)?,
                        local_updated_at_snapshot: r.get(3)?,
                        remote_edited_snapshot: r.get(4)?,
                        remote_revision_snapshot: r.get(5)?,
                    })
                },
            )
            .optional()?;
        Ok(m)
    }

    pub fn nc_mapping_upsert(&self, m: &NextcloudMapping) -> Result<()> {
        self.conn.execute(
            "INSERT INTO nextcloud_mapping (
                 entry_id, nc_uuid, last_synced_at,
                 local_updated_at_snapshot, remote_edited_snapshot,
                 remote_revision_snapshot)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(entry_id) DO UPDATE SET
                 nc_uuid                    = excluded.nc_uuid,
                 last_synced_at             = excluded.last_synced_at,
                 local_updated_at_snapshot  = excluded.local_updated_at_snapshot,
                 remote_edited_snapshot     = excluded.remote_edited_snapshot,
                 remote_revision_snapshot   = excluded.remote_revision_snapshot",
            params![
                m.entry_id,
                m.nc_uuid,
                m.last_synced_at,
                m.local_updated_at_snapshot,
                m.remote_edited_snapshot,
                m.remote_revision_snapshot,
            ],
        )?;
        Ok(())
    }

    pub fn nc_all_mappings(&self) -> Result<Vec<NextcloudMapping>> {
        let mut stmt = self.conn.prepare(
            "SELECT entry_id, nc_uuid, last_synced_at,
                    local_updated_at_snapshot, remote_edited_snapshot,
                    remote_revision_snapshot
             FROM nextcloud_mapping",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(NextcloudMapping {
                    entry_id: r.get(0)?,
                    nc_uuid: r.get(1)?,
                    last_synced_at: r.get(2)?,
                    local_updated_at_snapshot: r.get(3)?,
                    remote_edited_snapshot: r.get(4)?,
                    remote_revision_snapshot: r.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn nc_folder_mapping_for_name(
        &self,
        local_name: &str,
    ) -> Result<Option<NextcloudFolderMapping>> {
        let m = self
            .conn
            .query_row(
                "SELECT local_name, nc_uuid, last_synced_at,
                        remote_edited_snapshot, remote_revision_snapshot
                 FROM nextcloud_folder_mapping WHERE local_name = ? COLLATE NOCASE",
                params![local_name],
                |r| {
                    Ok(NextcloudFolderMapping {
                        local_name: r.get(0)?,
                        nc_uuid: r.get(1)?,
                        last_synced_at: r.get(2)?,
                        remote_edited_snapshot: r.get(3)?,
                        remote_revision_snapshot: r.get(4)?,
                    })
                },
            )
            .optional()?;
        Ok(m)
    }

    pub fn nc_folder_mapping_for_uuid(&self, uuid: &str) -> Result<Option<NextcloudFolderMapping>> {
        let m = self
            .conn
            .query_row(
                "SELECT local_name, nc_uuid, last_synced_at,
                        remote_edited_snapshot, remote_revision_snapshot
                 FROM nextcloud_folder_mapping WHERE nc_uuid = ?",
                params![uuid],
                |r| {
                    Ok(NextcloudFolderMapping {
                        local_name: r.get(0)?,
                        nc_uuid: r.get(1)?,
                        last_synced_at: r.get(2)?,
                        remote_edited_snapshot: r.get(3)?,
                        remote_revision_snapshot: r.get(4)?,
                    })
                },
            )
            .optional()?;
        Ok(m)
    }

    pub fn nc_folder_mapping_upsert(&self, m: &NextcloudFolderMapping) -> Result<()> {
        self.conn.execute(
            "DELETE FROM nextcloud_folder_mapping
             WHERE nc_uuid = ? OR local_name = ? COLLATE NOCASE",
            params![m.nc_uuid, m.local_name],
        )?;
        self.conn.execute(
            "INSERT INTO nextcloud_folder_mapping (
                 local_name, nc_uuid, last_synced_at,
                 remote_edited_snapshot, remote_revision_snapshot)
             VALUES (?, ?, ?, ?, ?)",
            params![
                m.local_name,
                m.nc_uuid,
                m.last_synced_at,
                m.remote_edited_snapshot,
                m.remote_revision_snapshot,
            ],
        )?;
        Ok(())
    }

    pub fn nc_tombstones(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT nc_uuid FROM nextcloud_tombstones")?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn nc_clear_tombstone(&self, uuid: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM nextcloud_tombstones WHERE nc_uuid = ?",
            params![uuid],
        )?;
        Ok(())
    }

    /// Fetch `updated_at` for an entry — needed by the sync engine to seed
    /// `local_updated_at_snapshot` without re-fetching the full row.
    pub fn entry_updated_at(&self, entry_id: i64) -> Result<Option<i64>> {
        let ts: Option<i64> = self
            .conn
            .query_row(
                "SELECT updated_at FROM passwords WHERE id = ?",
                params![entry_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(ts)
    }

    pub fn has_master_password(&self) -> Result<bool> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM master", [], |r| r.get(0))?;
        Ok(n > 0)
    }

    pub fn is_unlocked(&self) -> bool {
        self.key.is_some()
    }

    pub fn lock(&mut self) {
        self.key = None;
    }

    pub fn set_master_password(&mut self, password: &str) -> Result<()> {
        if self.has_master_password()? {
            return Err(Error::MasterAlreadySet);
        }
        validate_new_master_password(password)?;
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        let salt_text = URL_SAFE_NO_PAD.encode(salt);

        let hash = argon2_kdf::hash_master(password)?;
        let key = argon2_kdf::derive_key_v2(password, salt_text.as_bytes())?;
        let ts = chrono::Utc::now().timestamp();

        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO master (id, password_hash, salt, crypto_version, created_at)
             VALUES (1, ?, ?, 2, ?)",
            params![hash, salt_text, ts],
        )?;
        key_check::write(&tx, &key, &salt_text)?;
        tx.commit()?;

        self.key = Some(key);
        Ok(())
    }

    /// Check whether `password` matches the on-disk master hash without
    /// changing the vault's lock state. Used by the system-keyring opt-in to
    /// confirm the user typed the right master before persisting it.
    pub fn verify_master_password(&self, password: &str) -> Result<bool> {
        let hash: String =
            self.conn
                .query_row("SELECT password_hash FROM master WHERE id = 1", [], |r| {
                    r.get(0)
                })?;
        argon2_kdf::verify_master(password, &hash)
    }

    /// Unlock with the master password. Migrates a v1 vault first (after a
    /// consistent backup), and seals the key verifier if it is missing.
    pub fn unlock(&mut self, password: &str) -> Result<()> {
        let crypto_version = migration::detect_crypto_version(&self.conn)?.unwrap_or(2);
        if crypto_version == 1 {
            // Check the password before touching the disk, then take a
            // consistent backup and migrate atomically.
            let (hash, _) = migration::read_master_v1(&self.conn)?;
            if !argon2_kdf::verify_master(password, &hash)? {
                return Err(Error::InvalidMasterPassword);
            }
            migration::backup_db_from(&self.conn, &self.db_path)?;
            migration::migrate_v1_to_v2(&mut self.conn, password)?;
        }

        let inputs = self.read_unlock_inputs()?;
        let key = derive_unlock_key(password, &inputs)?;
        // `derive_unlock_key` proved the password (via the verifier or the
        // PHC hash), so this key is authoritative for the current master
        // row: repair a missing, stale or damaged verifier.
        match key_check::check(&self.conn, &key, &inputs.salt)? {
            KeyStatus::Verified => {}
            status => {
                if status == KeyStatus::Mismatch {
                    log::warn!("vault key verifier did not match the master password; resealing");
                }
                self.store_key_check(&key, &inputs.salt);
            }
        }
        self.key = Some(key);
        Ok(())
    }

    /// Inputs for `derive_unlock_key`, so the expensive KDF can run off the
    /// thread that owns the vault. `Ok(None)` when that is not possible (no
    /// master password yet, or a v1 vault that must migrate first): use the
    /// synchronous `unlock()` instead.
    pub fn unlock_inputs(&self) -> Result<Option<UnlockInputs>> {
        match migration::detect_crypto_version(&self.conn)? {
            None | Some(1) => Ok(None),
            Some(_) => self.read_unlock_inputs().map(Some),
        }
    }

    /// Install a key produced by `derive_unlock_key(password, inputs)`.
    ///
    /// Fails with `Error::KeyMismatch` when the master row changed since
    /// `inputs` was read or the key does not open the vault; the caller should
    /// then retry with the synchronous `unlock()`, which also repairs a
    /// damaged verifier.
    pub fn unlock_with_key(&mut self, inputs: &UnlockInputs, key: DerivedKey) -> Result<()> {
        let current = self.read_unlock_inputs()?;
        if current.password_hash != inputs.password_hash || current.salt != inputs.salt {
            return Err(Error::KeyMismatch);
        }
        match key_check::check(&self.conn, &key, &current.salt)? {
            KeyStatus::Verified => {}
            KeyStatus::Mismatch => return Err(Error::KeyMismatch),
            KeyStatus::VerifiedByEntry | KeyStatus::Unverifiable => {
                self.store_key_check(&key, &current.salt)
            }
        }
        self.key = Some(key);
        Ok(())
    }

    /// Check that the active key (e.g. one handed to `open_with_session_key`)
    /// still opens this vault. `Error::KeyMismatch` if it does not.
    pub fn verify_session_key(&self) -> Result<()> {
        self.ensure_key_matches(self.key()?)
    }

    fn read_unlock_inputs(&self) -> Result<UnlockInputs> {
        let (password_hash, salt) = self.conn.query_row(
            "SELECT password_hash, salt FROM master WHERE id = 1",
            [],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )?;
        let key_check = key_check::read_for_salt(&self.conn, &salt)?;
        Ok(UnlockInputs {
            password_hash,
            salt,
            key_check,
        })
    }

    fn master_salt(&self) -> Result<String> {
        Ok(self
            .conn
            .query_row("SELECT salt FROM master WHERE id = 1", [], |r| r.get(0))?)
    }

    /// Reject `key` when it provably does not open this vault. A vault with
    /// no verifier and no encrypted data cannot be checked and is accepted.
    fn ensure_key_matches(&self, key: &DerivedKey) -> Result<()> {
        let salt = self.master_salt()?;
        if key_check::check(&self.conn, key, &salt)? == KeyStatus::Mismatch {
            return Err(Error::KeyMismatch);
        }
        Ok(())
    }

    /// Seal the verifier. Best effort: a read-only or busy database must not
    /// turn a successful unlock into a failure; the write is retried on the
    /// next unlock.
    fn store_key_check(&self, key: &DerivedKey, salt: &str) {
        if let Err(error) = key_check::write(&self.conn, key, salt) {
            log::warn!("could not store vault key verifier: {error}");
        }
    }

    /// Configure quick-unlock for the current session. Requires an unlocked
    /// vault. New PINs must contain at least 6 characters. The derived key is cached
    /// in memory; on session lock it can be restored with `quick_unlock(pin)`.
    pub fn enable_quick_unlock(&mut self, pin: &str) -> Result<()> {
        if pin.chars().count() < 6 {
            return Err(Error::InvalidInput(
                "PIN must contain at least 6 characters".into(),
            ));
        }
        let key = self.key.clone().ok_or(Error::Locked)?;
        self.quick_pin_hash = Some(argon2_kdf::hash_session_secret(pin)?);
        self.cached_key = Some(key);
        Ok(())
    }

    /// Configure quick-unlock and return the encrypted, device-local state that
    /// lets the app restore it after restart.
    ///
    /// The record holds no PIN hash: the AES-GCM tag of `encrypted_key`
    /// already authenticates the PIN, and a cheaper hash next to it would
    /// only give an attacker a faster brute-force target.
    pub fn enable_persistent_quick_unlock(&mut self, pin: &str) -> Result<QuickUnlockPrefs> {
        self.enable_quick_unlock(pin)?;
        let key = self.cached_key.as_ref().ok_or(Error::Locked)?;
        wrap_quick_unlock_key(pin, key)
    }

    /// Re-acquire the encryption key using a previously-set quick-unlock PIN.
    /// Fails if quick-unlock was never configured this session, or if the PIN
    /// is wrong. Wrong PIN does not clear the cache — caller decides whether
    /// to escalate to a full unlock after N failures. A cached key that no
    /// longer opens the vault yields `Error::KeyMismatch`.
    pub fn quick_unlock(&mut self, pin: &str) -> Result<()> {
        let hash = self
            .quick_pin_hash
            .as_deref()
            .ok_or(Error::Other("quick-unlock not configured".into()))?;
        if !argon2_kdf::verify_master(pin, hash)? {
            return Err(Error::InvalidMasterPassword);
        }
        let key = self
            .cached_key
            .clone()
            .ok_or(Error::Other("quick-unlock cache missing".into()))?;
        self.ensure_key_matches(&key)?;
        self.key = Some(key);
        Ok(())
    }

    /// Re-acquire the encryption key from persisted quick-unlock state.
    pub fn quick_unlock_persistent(&mut self, pin: &str, prefs: &QuickUnlockPrefs) -> Result<()> {
        self.quick_unlock_persistent_upgrading(pin, prefs)
            .map(|_| ())
    }

    /// Like `quick_unlock_persistent`, but also returns a replacement record
    /// when `prefs` is in an older format (it carries a PIN hash, or uses the
    /// pre-hardening wrapping KDF). The caller should persist the returned
    /// record in place of `prefs`; it has `failed_attempts = 0`.
    pub fn quick_unlock_persistent_upgrading(
        &mut self,
        pin: &str,
        prefs: &QuickUnlockPrefs,
    ) -> Result<Option<QuickUnlockPrefs>> {
        let (key, upgraded) = derive_quick_unlock_key(pin, prefs)?;
        let session_hash = match prefs.pin_hash.as_str() {
            "" => argon2_kdf::hash_session_secret(pin)?,
            legacy => legacy.to_string(),
        };
        self.install_quick_unlock_key(key)?;
        self.quick_pin_hash = Some(session_hash);
        Ok(upgraded)
    }

    /// Install a vault key recovered by `derive_quick_unlock_key`, after
    /// checking it still opens this vault (`Error::KeyMismatch` otherwise —
    /// fall back to the master password).
    ///
    /// The key is cached for the session, but no session PIN verifier is set,
    /// so `is_quick_unlock_available()` stays false and later PIN unlocks go
    /// through the persisted record again.
    pub fn install_quick_unlock_key(&mut self, key: DerivedKey) -> Result<()> {
        self.ensure_key_matches(&key)?;
        self.key = Some(key.clone());
        self.cached_key = Some(key);
        Ok(())
    }

    /// True when `quick_unlock(pin)` can succeed (cache + PIN hash both set).
    pub fn is_quick_unlock_available(&self) -> bool {
        self.cached_key.is_some() && self.quick_pin_hash.is_some()
    }

    /// Forget quick-unlock state for this session. Subsequent unlock requires
    /// the full master password again.
    pub fn disable_quick_unlock(&mut self) {
        self.cached_key = None;
        self.quick_pin_hash = None;
    }

    /// Full lock: clears both the active key and the quick-unlock cache. Use
    /// this on application exit or when the user explicitly wants to revoke
    /// session secrets.
    pub fn full_lock(&mut self) {
        self.key = None;
        self.disable_quick_unlock();
    }

    fn key(&self) -> Result<&DerivedKey> {
        self.key.as_ref().ok_or(Error::Locked)
    }

    fn encrypt(&self, plaintext: &str) -> Result<Vec<u8>> {
        aes_gcm_v2::encrypt(self.key()?, plaintext.as_bytes())
    }

    fn decrypt(&self, blob: &[u8]) -> Result<String> {
        let pt = aes_gcm_v2::decrypt(self.key()?, blob)?;
        String::from_utf8(pt).map_err(|e| Error::Crypto(format!("utf8: {e}")))
    }

    pub fn add(&self, entry: NewEntry) -> Result<i64> {
        let totp_algorithm = entry
            .totp_algorithm
            .clone()
            .unwrap_or_else(|| "SHA1".into());
        let totp_digits = entry.totp_digits.unwrap_or(6);
        let totp_period = entry.totp_period.unwrap_or(30);
        let algorithm = crate::totp::Algorithm::parse(&totp_algorithm)?;
        crate::totp::validate_parameters(totp_digits, totp_period)?;
        if let Some(secret) = entry
            .totp_secret
            .as_deref()
            .filter(|secret| !secret.is_empty())
        {
            crate::totp::generate_totp(secret, algorithm, totp_digits, totp_period, 0)?;
        }
        let ts = chrono::Utc::now().timestamp();
        let pw = self.encrypt(&entry.password)?;
        let notes = entry
            .notes
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| self.encrypt(s))
            .transpose()?;
        let totp = entry
            .totp_secret
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| self.encrypt(s))
            .transpose()?;

        self.conn.execute(
            "INSERT INTO passwords (title, username, password_encrypted, notes_encrypted, url,
                totp_secret_encrypted, totp_algorithm, totp_digits, totp_period,
                category, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                entry.title,
                entry.username,
                pw,
                notes,
                entry.url,
                totp,
                totp_algorithm,
                totp_digits as i64,
                totp_period as i64,
                entry.category,
                ts,
                ts,
            ],
        )?;
        let id = self.conn.last_insert_rowid();
        self.notify_change();
        Ok(id)
    }

    pub fn list(&self, search: Option<&str>) -> Result<Vec<PasswordEntry>> {
        self.list_filtered(search, None)
    }

    pub fn list_filtered(
        &self,
        search: Option<&str>,
        category: Option<&str>,
    ) -> Result<Vec<PasswordEntry>> {
        let base = "SELECT id, title, username, url,
                           totp_secret_encrypted IS NOT NULL, totp_algorithm, totp_digits, totp_period,
                           category, favorite, created_at, updated_at, last_accessed
                    FROM passwords";

        let mut clauses: Vec<&str> = Vec::new();
        let mut params_vec: Vec<Value> = Vec::new();

        let search = search.map(str::trim).filter(|s| !s.is_empty());
        if let Some(q) = search {
            if let Some(fts_query) = fts_query(q) {
                if let Ok(rows) = self.list_filtered_fts(&fts_query, category) {
                    return Ok(rows);
                }
            }

            let pat = like_pattern(q);
            clauses.push("(title LIKE ? ESCAPE '\\' OR username LIKE ? ESCAPE '\\' OR url LIKE ? ESCAPE '\\')");
            params_vec.push(pat.clone().into());
            params_vec.push(pat.clone().into());
            params_vec.push(pat.into());
        }

        if let Some(category) = category.filter(|s| !s.is_empty()) {
            clauses.push("category = ?");
            params_vec.push(category.to_string().into());
        }

        let sql = if clauses.is_empty() {
            format!("{base} ORDER BY title")
        } else {
            format!("{base} WHERE {} ORDER BY title", clauses.join(" AND "))
        };

        let mut stmt = self.conn.prepare_cached(&sql)?;
        let rows = stmt
            .query_map(params_from_iter(params_vec), password_summary_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn list_filtered_fts(
        &self,
        search: &str,
        category: Option<&str>,
    ) -> Result<Vec<PasswordEntry>> {
        let base = "SELECT p.id, p.title, p.username, p.url,
                           p.totp_secret_encrypted IS NOT NULL, p.totp_algorithm, p.totp_digits, p.totp_period,
                           p.category, p.favorite, p.created_at, p.updated_at, p.last_accessed
                    FROM passwords_fts
                    JOIN passwords p ON p.id = passwords_fts.rowid
                    WHERE passwords_fts MATCH ?";
        let mut params_vec: Vec<Value> = vec![search.to_string().into()];
        let sql = if let Some(category) = category.filter(|s| !s.is_empty()) {
            params_vec.push(category.to_string().into());
            format!("{base} AND p.category = ? ORDER BY p.title")
        } else {
            format!("{base} ORDER BY p.title")
        };
        let mut stmt = self.conn.prepare_cached(&sql)?;
        let rows = stmt
            .query_map(params_from_iter(params_vec), password_summary_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn totp_secret(&self, id: i64) -> Result<Option<String>> {
        let blob: Option<Option<Vec<u8>>> = self
            .conn
            .query_row(
                "SELECT totp_secret_encrypted FROM passwords WHERE id = ?",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        match blob.flatten() {
            Some(blob) => Ok(Some(self.decrypt(&blob)?)),
            None => Ok(None),
        }
    }

    pub fn get(&self, id: i64) -> Result<Option<PasswordEntry>> {
        self.get_inner(id, true)
    }

    pub fn get_without_touch(&self, id: i64) -> Result<Option<PasswordEntry>> {
        self.get_inner(id, false)
    }

    fn get_inner(&self, id: i64, touch: bool) -> Result<Option<PasswordEntry>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT id, title, username, password_encrypted, notes_encrypted, url,
                    totp_secret_encrypted, totp_algorithm, totp_digits, totp_period,
                    category, favorite, created_at, updated_at, last_accessed
             FROM passwords WHERE id = ?",
        )?;
        let mut rows = stmt.query(params![id])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };

        let pw_blob: Vec<u8> = row.get(3)?;
        let notes_blob: Option<Vec<u8>> = row.get(4)?;
        let totp_blob: Option<Vec<u8>> = row.get(6)?;

        let entry = PasswordEntry {
            id: row.get(0)?,
            title: row.get(1)?,
            username: row.get(2)?,
            password: Some(self.decrypt(&pw_blob)?),
            notes: notes_blob.as_ref().map(|b| self.decrypt(b)).transpose()?,
            url: row.get(5)?,
            totp_secret: totp_blob.as_ref().map(|b| self.decrypt(b)).transpose()?,
            has_totp: totp_blob.is_some(),
            totp_algorithm: row
                .get::<_, Option<String>>(7)?
                .unwrap_or_else(|| "SHA1".into()),
            totp_digits: row.get::<_, Option<i64>>(8)?.unwrap_or(6) as u8,
            totp_period: row.get::<_, Option<i64>>(9)?.unwrap_or(30) as u32,
            category: row.get(10)?,
            favorite: row.get::<_, Option<i64>>(11)?.unwrap_or(0) != 0,
            created_at: row.get(12)?,
            updated_at: row.get(13)?,
            last_accessed: row.get(14)?,
        };
        drop(rows);
        drop(stmt);
        if touch {
            let now = chrono::Utc::now().timestamp();
            self.conn.execute(
                "UPDATE passwords SET last_accessed = ? WHERE id = ?",
                params![now, id],
            )?;
        }
        Ok(Some(entry))
    }

    pub fn update(&self, id: i64, change: UpdateEntry) -> Result<bool> {
        if let Some(algorithm) = change.totp_algorithm.as_deref() {
            crate::totp::Algorithm::parse(algorithm)?;
        }
        crate::totp::validate_parameters(
            change.totp_digits.unwrap_or(6),
            change.totp_period.unwrap_or(30),
        )?;
        if let Some(Some(secret)) = change.totp_secret.as_ref() {
            if !secret.is_empty() {
                let algorithm = crate::totp::Algorithm::parse(
                    change.totp_algorithm.as_deref().unwrap_or("SHA1"),
                )?;
                crate::totp::generate_totp(
                    secret,
                    algorithm,
                    change.totp_digits.unwrap_or(6),
                    change.totp_period.unwrap_or(30),
                    0,
                )?;
            }
        }
        let tx = self.conn.unchecked_transaction()?;
        let mut sets: Vec<&'static str> = Vec::new();
        let mut vals: Vec<Value> = Vec::new();

        if let Some(t) = change.title {
            sets.push("title = ?");
            vals.push(t.into());
        }
        if let Some(u) = change.username {
            sets.push("username = ?");
            vals.push(u.into());
        }
        if let Some(p) = change.password {
            // Snapshot the previous encrypted password into history before
            // overwriting, so the user can recover old credentials.
            let prev: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT password_encrypted FROM passwords WHERE id = ?",
                    params![id],
                    |r| r.get(0),
                )
                .ok();
            if let Some(blob) = prev {
                let ts = chrono::Utc::now().timestamp();
                tx.execute(
                    "INSERT INTO passwords_history (entry_id, password_encrypted, changed_at)
                     VALUES (?, ?, ?)",
                    params![id, blob, ts],
                )?;
            }
            sets.push("password_encrypted = ?");
            vals.push(self.encrypt(&p)?.into());
        }
        if let Some(n) = change.notes {
            sets.push("notes_encrypted = ?");
            vals.push(match n {
                Some(s) if !s.is_empty() => self.encrypt(&s)?.into(),
                _ => Value::Null,
            });
        }
        if let Some(u) = change.url {
            sets.push("url = ?");
            vals.push(match u {
                Some(s) => s.into(),
                None => Value::Null,
            });
        }
        if let Some(t) = change.totp_secret {
            sets.push("totp_secret_encrypted = ?");
            vals.push(match t {
                Some(s) if !s.is_empty() => self.encrypt(&s)?.into(),
                _ => Value::Null,
            });
        }
        if let Some(a) = change.totp_algorithm {
            sets.push("totp_algorithm = ?");
            vals.push(a.into());
        }
        if let Some(d) = change.totp_digits {
            sets.push("totp_digits = ?");
            vals.push((d as i64).into());
        }
        if let Some(p) = change.totp_period {
            sets.push("totp_period = ?");
            vals.push((p as i64).into());
        }
        if let Some(c) = change.category {
            sets.push("category = ?");
            vals.push(match c {
                Some(s) if !s.is_empty() => s.into(),
                _ => Value::Null,
            });
        }

        if sets.is_empty() {
            return Ok(false);
        }
        sets.push("updated_at = ?");
        vals.push(chrono::Utc::now().timestamp().into());
        vals.push(id.into());

        let sql = format!("UPDATE passwords SET {} WHERE id = ?", sets.join(", "));
        let n = tx.execute(&sql, params_from_iter(vals))?;
        tx.commit()?;
        if n > 0 {
            self.notify_change();
        }
        Ok(n > 0)
    }

    /// Past passwords for an entry, newest first. Each row was the active
    /// password before being replaced by a later update.
    pub fn password_history(&self, entry_id: i64) -> Result<Vec<PasswordHistoryEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, password_encrypted, changed_at
             FROM passwords_history
             WHERE entry_id = ?
             ORDER BY changed_at DESC",
        )?;
        let rows = stmt
            .query_map(params![entry_id], |r| {
                let blob: Vec<u8> = r.get(1)?;
                Ok((r.get::<_, i64>(0)?, blob, r.get::<_, i64>(2)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(id, blob, changed_at)| {
                Ok(PasswordHistoryEntry {
                    id,
                    entry_id,
                    password: self.decrypt(&blob)?,
                    changed_at,
                })
            })
            .collect()
    }

    /// Drop all history rows for an entry. Used when the user wants to purge
    /// prior credentials (e.g. after a confirmed leak).
    pub fn clear_password_history(&self, entry_id: i64) -> Result<usize> {
        let n = self.conn.execute(
            "DELETE FROM passwords_history WHERE entry_id = ?",
            params![entry_id],
        )?;
        if n > 0 {
            self.notify_change();
        }
        Ok(n)
    }

    /// Soft-delete: moves the entry row to `passwords_trash` and removes it
    /// from `passwords`. Recovered with `restore_from_trash(trash_id)`.
    /// Permanent deletion happens via `purge_trash()` or `empty_trash()`.
    pub fn delete(&self, id: i64) -> Result<bool> {
        if crate::settings::Settings::load().trash_retention_days == 0 {
            return self.delete_permanent(id);
        }
        let now = chrono::Utc::now().timestamp();
        let uuid = self.nextcloud_uuid_for_entry(id)?;
        let tx = self.conn.unchecked_transaction()?;
        let copied = tx.execute(
            "INSERT INTO passwords_trash (
                original_id, title, username, password_encrypted, notes_encrypted,
                url, totp_secret_encrypted, totp_algorithm, totp_digits, totp_period,
                category, favorite, created_at, updated_at, deleted_at)
             SELECT id, title, username, password_encrypted, notes_encrypted,
                    url, totp_secret_encrypted, totp_algorithm, totp_digits, totp_period,
                    category, favorite, created_at, updated_at, ?
             FROM passwords WHERE id = ?",
            params![now, id],
        )?;
        if copied == 0 {
            return Ok(false);
        }
        let trash_id = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO passwords_history_trash
                (original_history_id, trash_id, password_encrypted, changed_at)
             SELECT id, ?, password_encrypted, changed_at
               FROM passwords_history WHERE entry_id = ?",
            params![trash_id, id],
        )?;
        tx.execute(
            "INSERT INTO attachments_trash
                (original_attachment_id, trash_id, filename, mime_type,
                 ciphertext, size_bytes, created_at)
             SELECT id, ?, filename, mime_type, ciphertext, size_bytes, created_at
               FROM attachments WHERE entry_id = ?",
            params![trash_id, id],
        )?;
        // If this entry was synced to Nextcloud Passwords, capture the UUID
        // as a tombstone so the next sync push deletes it remotely. The
        // mapping row itself disappears via ON DELETE CASCADE below; without
        // the tombstone we'd lose the link to the remote resource forever
        // and the next pull would re-create the entry.
        if let Some(uuid) = uuid {
            tx.execute(
                "INSERT OR REPLACE INTO nextcloud_tombstones (nc_uuid, deleted_at)
                 VALUES (?, ?)",
                params![uuid, now],
            )?;
        }

        let n = tx.execute("DELETE FROM passwords WHERE id = ?", params![id])?;
        if n > 0 {
            tx.commit()?;
            self.notify_change();
        } else {
            tx.rollback()?;
        }
        Ok(n > 0)
    }

    /// Hard delete with no trash copy. Used when trash retention is disabled.
    pub fn delete_permanent(&self, id: i64) -> Result<bool> {
        let now = chrono::Utc::now().timestamp();
        let uuid = self.nextcloud_uuid_for_entry(id)?;
        let tx = self.conn.unchecked_transaction()?;
        if let Some(uuid) = uuid {
            tx.execute(
                "INSERT OR REPLACE INTO nextcloud_tombstones (nc_uuid, deleted_at)
                 VALUES (?, ?)",
                params![uuid, now],
            )?;
        }
        let n = tx.execute("DELETE FROM passwords WHERE id = ?", params![id])?;
        if n > 0 {
            tx.commit()?;
            self.notify_change();
        } else {
            tx.rollback()?;
        }
        Ok(n > 0)
    }

    fn nextcloud_uuid_for_entry(&self, entry_id: i64) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT nc_uuid FROM nextcloud_mapping WHERE entry_id = ?",
                params![entry_id],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Summary of trashed entries, newest-deleted first. Passwords stay
    /// encrypted on disk; this listing only returns metadata.
    pub fn list_trash(&self) -> Result<Vec<TrashedEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, original_id, title, username, url, category, deleted_at
             FROM passwords_trash ORDER BY deleted_at DESC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(TrashedEntry {
                    trash_id: r.get(0)?,
                    original_id: r.get(1)?,
                    title: r.get(2)?,
                    username: r.get(3)?,
                    url: r.get(4)?,
                    category: r.get(5)?,
                    deleted_at: r.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Restore a trashed entry to the active table. Generates a new id.
    pub fn restore_from_trash(&self, trash_id: i64) -> Result<Option<i64>> {
        let row: Option<TrashRow> = self
            .conn
            .query_row(
                "SELECT title, username, password_encrypted, notes_encrypted, url,
                        totp_secret_encrypted, totp_algorithm, totp_digits, totp_period,
                        category, favorite, created_at, updated_at
                 FROM passwords_trash WHERE id = ?",
                params![trash_id],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                        r.get(9)?,
                        r.get(10)?,
                        r.get(11)?,
                        r.get(12)?,
                    ))
                },
            )
            .ok();
        let Some(row) = row else { return Ok(None) };
        let now = chrono::Utc::now().timestamp();
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO passwords (title, username, password_encrypted, notes_encrypted, url,
                totp_secret_encrypted, totp_algorithm, totp_digits, totp_period,
                category, favorite, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                row.0,
                row.1,
                row.2,
                row.3,
                row.4,
                row.5,
                row.6.unwrap_or_else(|| "SHA1".into()),
                row.7.unwrap_or(6),
                row.8.unwrap_or(30),
                row.9,
                row.10.unwrap_or(0),
                row.11.unwrap_or(now),
                row.12.unwrap_or(now),
            ],
        )?;
        let new_id = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO passwords_history (entry_id, password_encrypted, changed_at)
             SELECT ?, password_encrypted, changed_at
               FROM passwords_history_trash WHERE trash_id = ?
               ORDER BY changed_at, original_history_id",
            params![new_id, trash_id],
        )?;
        tx.execute(
            "INSERT INTO attachments
                (entry_id, filename, mime_type, ciphertext, size_bytes, created_at)
             SELECT ?, filename, mime_type, ciphertext, size_bytes, created_at
               FROM attachments_trash WHERE trash_id = ?
               ORDER BY original_attachment_id",
            params![new_id, trash_id],
        )?;
        tx.execute(
            "DELETE FROM passwords_trash WHERE id = ?",
            params![trash_id],
        )?;
        tx.commit()?;
        self.notify_change();
        Ok(Some(new_id))
    }

    /// Drop a single trash row. Skips the active table.
    pub fn delete_from_trash(&self, trash_id: i64) -> Result<bool> {
        let n = self.conn.execute(
            "DELETE FROM passwords_trash WHERE id = ?",
            params![trash_id],
        )?;
        if n > 0 {
            self.notify_change();
        }
        Ok(n > 0)
    }

    /// Drop all trash rows older than `retention_secs` seconds. Returns the
    /// number of rows removed. Call on app startup or before a backup so the
    /// trash doesn't grow unbounded.
    pub fn purge_trash(&self, retention_secs: i64) -> Result<usize> {
        let cutoff = chrono::Utc::now().timestamp() - retention_secs;
        let n = self.conn.execute(
            "DELETE FROM passwords_trash WHERE deleted_at < ?",
            params![cutoff],
        )?;
        if n > 0 {
            self.notify_change();
        }
        Ok(n)
    }

    /// Drop every row in trash.
    pub fn empty_trash(&self) -> Result<usize> {
        let n = self.conn.execute("DELETE FROM passwords_trash", [])?;
        if n > 0 {
            self.notify_change();
        }
        Ok(n)
    }

    pub fn toggle_favorite(&self, id: i64) -> Result<bool> {
        let current: Option<i64> = self
            .conn
            .query_row(
                "SELECT favorite FROM passwords WHERE id = ?",
                params![id],
                |r| r.get(0),
            )
            .ok();
        let Some(cur) = current else { return Ok(false) };
        let new = if cur == 0 { 1 } else { 0 };
        self.conn.execute(
            "UPDATE passwords SET favorite = ? WHERE id = ?",
            params![new, id],
        )?;
        self.notify_change();
        Ok(new != 0)
    }

    pub fn set_favorite(&self, id: i64, favorite: bool) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE passwords SET favorite = ? WHERE id = ?",
            params![i64::from(favorite), id],
        )?;
        if n > 0 {
            self.notify_change();
        }
        Ok(n > 0)
    }

    // -----------------------------------------------------------------
    // Folders
    // -----------------------------------------------------------------

    /// Create a local folder. Entries still reference folders through their
    /// `category` text so this can represent empty folders too.
    pub fn create_folder(&self, name: &str) -> Result<bool> {
        let name = normalize_folder_name(name)?;
        let ts = chrono::Utc::now().timestamp();
        let n = self.conn.execute(
            "INSERT OR IGNORE INTO folders (name, created_at, updated_at)
             VALUES (?, ?, ?)",
            params![name, ts, ts],
        )?;
        if n > 0 {
            self.notify_change();
        }
        Ok(n > 0)
    }

    // -----------------------------------------------------------------
    // Tags
    // -----------------------------------------------------------------

    /// Set the tags for an entry to exactly the given list. Unknown tag names
    /// are created on the fly; tags removed from the list are dissociated but
    /// stay in the catalog (call `prune_tags` to drop orphans).
    pub fn set_tags(&self, entry_id: i64, names: &[String]) -> Result<()> {
        let mut normalized: Vec<String> = names
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        normalized.sort_by_key(|a| a.to_lowercase());
        normalized.dedup_by(|a, b| a.to_lowercase() == b.to_lowercase());

        // A savepoint (not BEGIN) so this also works inside `transaction()`.
        let changed = self.with_savepoint("set_tags", || {
            let mut tag_ids: Vec<i64> = Vec::with_capacity(normalized.len());
            for name in &normalized {
                self.conn.execute(
                    "INSERT OR IGNORE INTO tags (name) VALUES (?)",
                    params![name],
                )?;
                let id: i64 = self.conn.query_row(
                    "SELECT id FROM tags WHERE name = ? COLLATE NOCASE",
                    params![name],
                    |r| r.get(0),
                )?;
                tag_ids.push(id);
            }
            tag_ids.sort_unstable();

            let mut current_stmt = self.conn.prepare_cached(
                "SELECT tag_id FROM entry_tags
                 WHERE entry_id = ?
                 ORDER BY tag_id",
            )?;
            let current_ids = current_stmt
                .query_map(params![entry_id], |r| r.get::<_, i64>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(current_stmt);
            if current_ids == tag_ids {
                return Ok(false);
            }

            self.conn.execute(
                "DELETE FROM entry_tags WHERE entry_id = ?",
                params![entry_id],
            )?;
            for tid in &tag_ids {
                self.conn.execute(
                    "INSERT OR IGNORE INTO entry_tags (entry_id, tag_id) VALUES (?, ?)",
                    params![entry_id, tid],
                )?;
            }
            Ok(true)
        })?;
        if changed {
            self.notify_change();
        }
        Ok(())
    }

    /// Run `operation` inside a named SQLite savepoint: released on success,
    /// rolled back on error. Unlike BEGIN, savepoints nest, so this is safe
    /// both standalone and within `transaction()`.
    fn with_savepoint<T, F>(&self, name: &str, operation: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        self.conn.execute_batch(&format!("SAVEPOINT {name}"))?;
        match operation() {
            Ok(value) => {
                if let Err(error) = self.conn.execute_batch(&format!("RELEASE {name}")) {
                    let _ = self
                        .conn
                        .execute_batch(&format!("ROLLBACK TO {name}; RELEASE {name}"));
                    return Err(error.into());
                }
                Ok(value)
            }
            Err(error) => {
                self.conn
                    .execute_batch(&format!("ROLLBACK TO {name}; RELEASE {name}"))?;
                Err(error)
            }
        }
    }

    pub fn tags_of(&self, entry_id: i64) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT t.name FROM tags t
             JOIN entry_tags et ON et.tag_id = t.id
             WHERE et.entry_id = ?
             ORDER BY t.name COLLATE NOCASE",
        )?;
        let rows = stmt
            .query_map(params![entry_id], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Every tag in the catalog with the number of entries using it.
    pub fn all_tags(&self) -> Result<Vec<(String, i64)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT t.name, COUNT(et.entry_id) AS cnt
             FROM tags t
             LEFT JOIN entry_tags et ON et.tag_id = t.id
             GROUP BY t.id
             ORDER BY t.name COLLATE NOCASE",
        )?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Delete tag rows that no entry references. Useful after bulk untagging.
    pub fn prune_tags(&self) -> Result<usize> {
        let n = self.conn.execute(
            "DELETE FROM tags WHERE id NOT IN (SELECT tag_id FROM entry_tags)",
            [],
        )?;
        if n > 0 {
            self.notify_change();
        }
        Ok(n)
    }

    /// Entry summaries that carry the given tag (case-insensitive).
    pub fn entries_with_tag(&self, tag_name: &str) -> Result<Vec<PasswordEntry>> {
        let id: Option<i64> = self
            .conn
            .query_row(
                "SELECT id FROM tags WHERE name = ? COLLATE NOCASE",
                params![tag_name],
                |r| r.get(0),
            )
            .ok();
        let Some(id) = id else { return Ok(Vec::new()) };
        let mut stmt = self.conn.prepare_cached(
            "SELECT p.id, p.title, p.username, p.url,
                    p.totp_secret_encrypted IS NOT NULL, p.totp_algorithm, p.totp_digits, p.totp_period,
                    p.category, p.favorite, p.created_at, p.updated_at, p.last_accessed
             FROM passwords p
             JOIN entry_tags et ON et.entry_id = p.id
             WHERE et.tag_id = ?
             ORDER BY p.title",
        )?;
        let rows = stmt
            .query_map(params![id], password_summary_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // ----- attachments -----

    /// Encrypt `data` with the current key and persist it as an attachment on
    /// `entry_id`. Returns the new attachment's id.
    pub fn add_attachment(
        &self,
        entry_id: i64,
        filename: &str,
        mime_type: Option<&str>,
        data: &[u8],
    ) -> Result<i64> {
        let ciphertext = aes_gcm_v2::encrypt(self.key()?, data)?;
        let size = data.len() as i64;
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "INSERT INTO attachments
                (entry_id, filename, mime_type, ciphertext, size_bytes, created_at)
             VALUES (?, ?, ?, ?, ?, ?)",
            params![entry_id, filename, mime_type, ciphertext, size, now],
        )?;
        let id = self.conn.last_insert_rowid();
        self.notify_change();
        Ok(id)
    }

    /// List the attachments on `entry_id` without decrypting the blobs.
    pub fn list_attachments(&self, entry_id: i64) -> Result<Vec<AttachmentInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, filename, mime_type, size_bytes, created_at
             FROM attachments
             WHERE entry_id = ?
             ORDER BY created_at DESC, id DESC",
        )?;
        let rows = stmt
            .query_map(params![entry_id], |r| {
                Ok(AttachmentInfo {
                    id: r.get(0)?,
                    entry_id,
                    filename: r.get(1)?,
                    mime_type: r.get(2)?,
                    size_bytes: r.get::<_, i64>(3)? as u64,
                    created_at: r.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Fetch a single attachment by id, decrypting its contents. Returns
    /// `None` if no such attachment exists.
    pub fn get_attachment(&self, att_id: i64) -> Result<Option<(AttachmentInfo, Vec<u8>)>> {
        let row: Option<AttachmentRow> = self
            .conn
            .query_row(
                "SELECT id, entry_id, filename, mime_type, ciphertext, size_bytes, created_at
                 FROM attachments WHERE id = ?",
                params![att_id],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .ok();
        let Some((id, entry_id, filename, mime_type, ciphertext, size_bytes, created_at)) = row
        else {
            return Ok(None);
        };
        let plaintext = aes_gcm_v2::decrypt(self.key()?, &ciphertext)?;
        Ok(Some((
            AttachmentInfo {
                id,
                entry_id,
                filename,
                mime_type,
                size_bytes: size_bytes as u64,
                created_at,
            },
            plaintext,
        )))
    }

    /// Delete an attachment. Returns true if a row was removed.
    pub fn delete_attachment(&self, att_id: i64) -> Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM attachments WHERE id = ?", params![att_id])?;
        if n > 0 {
            self.notify_change();
        }
        Ok(n > 0)
    }

    pub fn categories(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT name FROM folders
             UNION
             SELECT DISTINCT category AS name FROM passwords
             WHERE category IS NOT NULL AND category != ''
             ORDER BY name COLLATE NOCASE",
        )?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Change master password and re-encrypt every protected value atomically.
    pub fn change_master_password(&mut self, current: &str, new: &str) -> Result<()> {
        let hash: String =
            self.conn
                .query_row("SELECT password_hash FROM master WHERE id = 1", [], |row| {
                    row.get(0)
                })?;
        if !argon2_kdf::verify_master(current, &hash)? {
            return Err(Error::InvalidMasterPassword);
        }
        validate_new_master_password(new)?;

        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        let new_salt_text = URL_SAFE_NO_PAD.encode(salt);
        let new_key = argon2_kdf::derive_key_v2(new, new_salt_text.as_bytes())?;
        let new_hash = argon2_kdf::hash_master(new)?;
        let old_key = self.key()?.clone();

        // Take the write lock *before* reading the rows: another connection
        // (the auto-sync worker) must not be able to commit rows encrypted
        // with the old key between the read and the re-encryption.
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let entries = collect_encrypted_entries(&tx, "passwords")?;
        let trash_entries = collect_encrypted_entries(&tx, "passwords_trash")?;
        let history =
            collect_encrypted_blobs(&tx, "passwords_history", "id", "password_encrypted")?;
        let trash_history = collect_encrypted_blobs(
            &tx,
            "passwords_history_trash",
            "original_history_id",
            "password_encrypted",
        )?;
        let attachments = collect_encrypted_blobs(&tx, "attachments", "id", "ciphertext")?;
        let trash_attachments = collect_encrypted_blobs(
            &tx,
            "attachments_trash",
            "original_attachment_id",
            "ciphertext",
        )?;

        for (table, rows) in [("passwords", entries), ("passwords_trash", trash_entries)] {
            let sql = format!(
                "UPDATE {table} SET password_encrypted = ?, notes_encrypted = ?, \
                 totp_secret_encrypted = ? WHERE id = ?"
            );
            let mut update = tx.prepare(&sql)?;
            for (id, password, notes, totp) in rows {
                let (password, notes, totp) =
                    reencrypt_entry(&old_key, &new_key, password, notes, totp)?;
                update.execute(params![password, notes, totp, id])?;
            }
        }
        for (table, id_column, blob_column, rows) in [
            ("passwords_history", "id", "password_encrypted", history),
            (
                "passwords_history_trash",
                "original_history_id",
                "password_encrypted",
                trash_history,
            ),
            ("attachments", "id", "ciphertext", attachments),
            (
                "attachments_trash",
                "original_attachment_id",
                "ciphertext",
                trash_attachments,
            ),
        ] {
            let sql = format!("UPDATE {table} SET {blob_column} = ? WHERE {id_column} = ?");
            let mut update = tx.prepare(&sql)?;
            for (id, blob) in rows {
                update.execute(params![reencrypt_blob(&old_key, &new_key, &blob)?, id])?;
            }
        }
        tx.execute(
            "UPDATE master SET password_hash = ?, salt = ? WHERE id = 1",
            params![new_hash, new_salt_text],
        )?;
        key_check::write(&tx, &new_key, &new_salt_text)?;
        tx.commit()?;

        self.key = Some(new_key);
        self.cached_key = None;
        self.quick_pin_hash = None;
        self.notify_change();
        Ok(())
    }
}

/// Snapshot of what `derive_unlock_key` needs, taken by `Vault::unlock_inputs`.
/// Plain data (`Send`), so the KDF can run on a worker thread.
#[derive(Clone)]
pub struct UnlockInputs {
    password_hash: String,
    salt: String,
    /// The verifier sealed for `salt`, if any.
    key_check: Option<Vec<u8>>,
}

impl std::fmt::Debug for UnlockInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockInputs")
            .field("has_key_check", &self.key_check.is_some())
            .finish_non_exhaustive()
    }
}

/// Derive the vault key from the master password. Thread-agnostic: does not
/// touch the database. Returns `Error::InvalidMasterPassword` on a wrong
/// password.
///
/// When the vault has a current key verifier, one Argon2 run suffices (the
/// derived key either opens the verifier or the password is checked against
/// the PHC hash as a fallback); otherwise the PHC hash is verified as before.
pub fn derive_unlock_key(password: &str, inputs: &UnlockInputs) -> Result<DerivedKey> {
    let key = argon2_kdf::derive_key_v2(password, inputs.salt.as_bytes())?;
    if inputs
        .key_check
        .as_deref()
        .is_some_and(|blob| key_check::opens(&key, blob))
    {
        return Ok(key);
    }
    if !argon2_kdf::verify_master(password, &inputs.password_hash)? {
        return Err(Error::InvalidMasterPassword);
    }
    Ok(key)
}

/// Recover the vault key from a persisted quick-unlock record. Thread-agnostic:
/// does not touch the database; install the result with
/// `Vault::install_quick_unlock_key`.
///
/// Returns `Error::InvalidMasterPassword` for a wrong PIN (the AES-GCM tag of
/// the wrapped key authenticates it). The second value is a replacement
/// record when `prefs` is in an older format; persist it instead of `prefs`.
pub fn derive_quick_unlock_key(
    pin: &str,
    prefs: &QuickUnlockPrefs,
) -> Result<(DerivedKey, Option<QuickUnlockPrefs>)> {
    if !prefs.is_configured() {
        return Err(Error::Other("quick-unlock not configured".into()));
    }
    if prefs.attempts_exhausted() {
        return Err(Error::Other(
            "quick-unlock disabled after too many wrong PINs".into(),
        ));
    }

    let salt = URL_SAFE_NO_PAD.decode(&prefs.salt)?;
    let encrypted_key = URL_SAFE_NO_PAD.decode(&prefs.encrypted_key)?;
    // Blobs written before PIN hardening were wrapped with the standard
    // vault KDF; honour whichever generation produced this one.
    let wrapping_key = if prefs.kdf_version >= crate::settings::QUICK_UNLOCK_KDF_PIN_HARDENED {
        argon2_kdf::derive_key_pin(pin, &salt)?
    } else {
        argon2_kdf::derive_key_v2(pin, &salt)?
    };
    let mut key_bytes = aes_gcm_v2::decrypt(&wrapping_key, &encrypted_key)
        .map_err(|_| Error::InvalidMasterPassword)?;
    if key_bytes.len() != 32 {
        key_bytes.zeroize();
        return Err(Error::Crypto("quick-unlock key has invalid length".into()));
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&key_bytes);
    key_bytes.zeroize();
    let key = DerivedKey::new(raw);
    raw.zeroize();

    let upgraded = if prefs.needs_upgrade() {
        Some(wrap_quick_unlock_key(pin, &key)?)
    } else {
        None
    };
    Ok((key, upgraded))
}

/// Wrap `key` under a PIN-derived key in the current record format.
fn wrap_quick_unlock_key(pin: &str, key: &DerivedKey) -> Result<QuickUnlockPrefs> {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    let wrapping_key = argon2_kdf::derive_key_pin(pin, &salt)?;
    let encrypted_key = aes_gcm_v2::encrypt(&wrapping_key, key.as_bytes())?;
    Ok(QuickUnlockPrefs {
        pin_hash: String::new(),
        salt: URL_SAFE_NO_PAD.encode(salt),
        encrypted_key: URL_SAFE_NO_PAD.encode(encrypted_key),
        failed_attempts: 0,
        kdf_version: crate::settings::QUICK_UNLOCK_KDF_PIN_HARDENED,
    })
}

/// Bring the schema up to date on open.
///
/// Full setup (idempotent DDL, legacy columns, data fix-ups, FTS index, the
/// foreign-key audit) runs whenever `PRAGMA user_version` differs from
/// `schema::setup_version()`: fresh files, files last opened by an older or
/// newer build, and files whose FTS setup previously failed. Afterwards the
/// version is recorded so later opens skip straight to the cheap checks.
fn prepare_schema(conn: &Connection) -> Result<()> {
    let expected = schema::setup_version();
    let current: i32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if current == expected && schema::required_tables_present(conn)? {
        // Orphans can only come from builds without foreign keys; the probe
        // is read-only so the common case takes no write lock.
        if schema::has_orphaned_trash_children(conn)? {
            schema::migrate_orphaned_trash_children(conn)?;
        }
        return Ok(());
    }

    let search_ready = schema::initialize_reporting_search(conn)?;
    migration::add_missing_columns(conn)?;
    let violation_count: i64 =
        conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    if violation_count > 0 {
        log::warn!("vault contains {violation_count} foreign-key violation(s)");
    }
    if search_ready {
        // Best effort: failing to record it only means setup runs again.
        if let Err(error) = conn.execute_batch(&format!("PRAGMA user_version = {expected}")) {
            log::warn!("could not record schema version: {error}");
        }
    }
    Ok(())
}

fn validate_new_master_password(password: &str) -> Result<()> {
    if password.chars().count() < MIN_MASTER_PASSWORD_LENGTH {
        return Err(Error::InvalidInput(format!(
            "master password must contain at least {MIN_MASTER_PASSWORD_LENGTH} characters"
        )));
    }
    Ok(())
}

fn collect_encrypted_entries(conn: &Connection, table: &str) -> Result<Vec<EncryptedEntryRow>> {
    let sql = format!(
        "SELECT id, password_encrypted, notes_encrypted, totp_secret_encrypted FROM {table}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn collect_encrypted_blobs(
    conn: &Connection,
    table: &str,
    id_column: &str,
    blob_column: &str,
) -> Result<Vec<(i64, Vec<u8>)>> {
    let sql = format!("SELECT {id_column}, {blob_column} FROM {table}");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn reencrypt_blob(old_key: &DerivedKey, new_key: &DerivedKey, blob: &[u8]) -> Result<Vec<u8>> {
    aes_gcm_v2::encrypt(new_key, &aes_gcm_v2::decrypt(old_key, blob)?)
}

fn reencrypt_entry(
    old_key: &DerivedKey,
    new_key: &DerivedKey,
    password: Vec<u8>,
    notes: Option<Vec<u8>>,
    totp: Option<Vec<u8>>,
) -> Result<EncryptedPayload> {
    Ok((
        reencrypt_blob(old_key, new_key, &password)?,
        notes
            .map(|blob| reencrypt_blob(old_key, new_key, &blob))
            .transpose()?,
        totp.map(|blob| reencrypt_blob(old_key, new_key, &blob))
            .transpose()?,
    ))
}

fn normalize_folder_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        return Err(Error::InvalidInput("folder name is required".into()));
    }
    Ok(name.to_string())
}

/// Map a summary row. Column 4 is `totp_secret_encrypted IS NOT NULL`, so the
/// TOTP ciphertext is never pulled just to compute `has_totp`.
fn password_summary_from_row(r: &Row<'_>) -> rusqlite::Result<PasswordEntry> {
    let has_totp: bool = r.get(4)?;
    Ok(PasswordEntry {
        id: r.get(0)?,
        title: r.get(1)?,
        username: r.get(2)?,
        url: r.get(3)?,
        password: None,
        notes: None,
        totp_secret: None,
        has_totp,
        totp_algorithm: r
            .get::<_, Option<String>>(5)?
            .unwrap_or_else(|| "SHA1".into()),
        totp_digits: r.get::<_, Option<i64>>(6)?.unwrap_or(6) as u8,
        totp_period: r.get::<_, Option<i64>>(7)?.unwrap_or(30) as u32,
        category: r.get(8)?,
        favorite: r.get::<_, Option<i64>>(9)?.unwrap_or(0) != 0,
        created_at: r.get(10)?,
        updated_at: r.get(11)?,
        last_accessed: r.get(12)?,
    })
}

fn fts_query(search: &str) -> Option<String> {
    let trimmed = search.trim();
    if trimmed.chars().count() < 3 {
        return None;
    }
    Some(format!("\"{}\"", trimmed.replace('"', "\"\"")))
}

fn like_pattern(search: &str) -> String {
    let mut escaped = String::with_capacity(search.len() + 2);
    escaped.push('%');
    for ch in search.chars() {
        match ch {
            '%' | '_' | '\\' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            _ => escaped.push(ch),
        }
    }
    escaped.push('%');
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unlocked_vault(path: &Path) -> Vault {
        let mut vault = Vault::open(path).unwrap();
        vault.set_master_password("master password here").unwrap();
        vault
    }

    #[test]
    fn persistent_quick_unlock_round_trips_with_hardened_kdf() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut vault = unlocked_vault(tmp.path());
        let prefs = vault.enable_persistent_quick_unlock("123456").unwrap();
        assert_eq!(
            prefs.kdf_version,
            crate::settings::QUICK_UNLOCK_KDF_PIN_HARDENED,
            "new blobs must record the PIN-hardened KDF generation"
        );
        assert_eq!(prefs.failed_attempts, 0);

        let key_before = vault.key.clone().unwrap().as_bytes().to_owned();
        vault.full_lock();
        assert!(!vault.is_unlocked());

        vault.quick_unlock_persistent("123456", &prefs).unwrap();
        assert_eq!(vault.key.clone().unwrap().as_bytes(), &key_before);
    }

    fn add_sample(vault: &Vault) -> i64 {
        vault
            .add(NewEntry {
                title: "Sample".into(),
                password: "sample-secret".into(),
                ..NewEntry::default()
            })
            .unwrap()
    }

    #[test]
    fn new_quick_unlock_records_carry_no_pin_hash() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut vault = unlocked_vault(tmp.path());
        add_sample(&vault);
        let prefs = vault.enable_persistent_quick_unlock("123456").unwrap();
        assert!(prefs.pin_hash.is_empty());
        assert!(prefs.is_configured());
        assert!(!prefs.needs_upgrade());
        let json = serde_json::to_string(&prefs).unwrap();
        assert!(!json.contains("$argon2"));

        vault.full_lock();
        assert!(matches!(
            vault.quick_unlock_persistent_upgrading("654321", &prefs),
            Err(Error::InvalidMasterPassword)
        ));
        assert!(!vault.is_unlocked());
        assert!(vault
            .quick_unlock_persistent_upgrading("123456", &prefs)
            .unwrap()
            .is_none());
        assert_eq!(vault.list(None).unwrap().len(), 1);
        // The session PIN path keeps working after a persistent unlock.
        vault.lock();
        assert!(vault.is_quick_unlock_available());
        assert!(matches!(
            vault.quick_unlock("000000"),
            Err(Error::InvalidMasterPassword)
        ));
        vault.quick_unlock("123456").unwrap();
    }

    /// Exactly what the previous release wrote: PIN hash + hardened wrap.
    fn previous_release_prefs(pin: &str, key: &DerivedKey) -> QuickUnlockPrefs {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        let wrapping = argon2_kdf::derive_key_pin(pin, &salt).unwrap();
        QuickUnlockPrefs {
            pin_hash: argon2_kdf::hash_master(pin).unwrap(),
            salt: URL_SAFE_NO_PAD.encode(salt),
            encrypted_key: URL_SAFE_NO_PAD
                .encode(aes_gcm_v2::encrypt(&wrapping, key.as_bytes()).unwrap()),
            failed_attempts: 2,
            kdf_version: crate::settings::QUICK_UNLOCK_KDF_PIN_HARDENED,
        }
    }

    #[test]
    fn previous_release_quick_unlock_record_unlocks_and_upgrades() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut vault = unlocked_vault(tmp.path());
        add_sample(&vault);
        let old = previous_release_prefs("123456", &vault.key.clone().unwrap());
        assert!(old.needs_upgrade());
        vault.full_lock();

        assert!(matches!(
            vault.quick_unlock_persistent_upgrading("999999", &old),
            Err(Error::InvalidMasterPassword)
        ));
        let upgraded = vault
            .quick_unlock_persistent_upgrading("123456", &old)
            .unwrap()
            .expect("old record must be upgraded");
        assert!(upgraded.pin_hash.is_empty());
        assert_eq!(upgraded.failed_attempts, 0);
        assert_eq!(
            upgraded.kdf_version,
            crate::settings::QUICK_UNLOCK_KDF_PIN_HARDENED
        );
        assert!(!upgraded.needs_upgrade());

        // Both the old and the upgraded record open the vault.
        for prefs in [&old, &upgraded] {
            vault.full_lock();
            vault.quick_unlock_persistent("123456", prefs).unwrap();
            assert_eq!(vault.list(None).unwrap().len(), 1);
            vault.full_lock();
            assert!(matches!(
                vault.quick_unlock_persistent("123457", prefs),
                Err(Error::InvalidMasterPassword)
            ));
        }
    }

    #[test]
    fn quick_unlock_with_a_stale_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let mut vault = unlocked_vault(&path);
        add_sample(&vault);
        let prefs = vault.enable_persistent_quick_unlock("123456").unwrap();
        vault.lock();

        // The master password changes from another process / device.
        let mut other = Vault::open(&path).unwrap();
        other.unlock("master password here").unwrap();
        other
            .change_master_password("master password here", "a brand new master")
            .unwrap();
        drop(other);

        // Correct PIN, but the key it unwraps no longer opens the vault.
        assert!(matches!(
            vault.quick_unlock("123456"),
            Err(Error::KeyMismatch)
        ));
        assert!(matches!(
            vault.quick_unlock_persistent("123456", &prefs),
            Err(Error::KeyMismatch)
        ));
        // A wrong PIN is still reported as a wrong PIN (counts an attempt).
        assert!(matches!(
            vault.quick_unlock_persistent("654321", &prefs),
            Err(Error::InvalidMasterPassword)
        ));
        assert!(!vault.is_unlocked());
        vault.unlock("a brand new master").unwrap();
        assert_eq!(vault.list(None).unwrap().len(), 1);
    }

    #[test]
    fn quick_unlock_key_from_another_vault_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = unlocked_vault(&dir.path().join("a.db"));
        let prefs = a.enable_persistent_quick_unlock("123456").unwrap();
        let mut b = Vault::open(dir.path().join("b.db")).unwrap();
        b.set_master_password("another master pw").unwrap();
        b.full_lock();
        // Even an empty vault with a verifier detects the foreign key.
        assert!(matches!(
            b.quick_unlock_persistent("123456", &prefs),
            Err(Error::KeyMismatch)
        ));
        let (key, upgraded) = derive_quick_unlock_key("123456", &prefs).unwrap();
        assert!(upgraded.is_none());
        assert!(matches!(
            b.install_quick_unlock_key(key.clone()),
            Err(Error::KeyMismatch)
        ));
        a.full_lock();
        a.install_quick_unlock_key(key).unwrap();
        assert!(a.is_unlocked());
        assert!(!a.is_quick_unlock_available());
    }

    fn key_check_row(vault: &Vault) -> Option<(Vec<u8>, String)> {
        vault
            .conn
            .query_row("SELECT blob, salt FROM key_check WHERE id = 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()
            .unwrap()
    }

    #[test]
    fn vault_without_key_check_unlocks_and_gains_one() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut vault = unlocked_vault(tmp.path());
        let id = add_sample(&vault);
        let prefs = vault.enable_persistent_quick_unlock("123456").unwrap();
        // What a vault written by an older build looks like.
        vault.conn.execute_batch("DROP TABLE key_check").unwrap();
        drop(vault);

        let mut vault = Vault::open(tmp.path()).unwrap();
        assert!(key_check_row(&vault).is_none(), "table recreated empty");
        // Quick unlock without a verifier falls back to the entries.
        vault.quick_unlock_persistent("123456", &prefs).unwrap();
        assert!(
            key_check_row(&vault).is_none(),
            "only master unlock seals it"
        );
        vault.full_lock();
        assert!(matches!(
            vault.unlock("wrong master pw"),
            Err(Error::InvalidMasterPassword)
        ));
        vault.unlock("master password here").unwrap();
        assert!(key_check_row(&vault).is_some());
        assert_eq!(
            vault
                .get_without_touch(id)
                .unwrap()
                .unwrap()
                .password
                .as_deref(),
            Some("sample-secret")
        );
        vault.full_lock();
        vault.unlock("master password here").unwrap();
    }

    #[test]
    fn damaged_or_stale_key_check_never_locks_out_the_master_password() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut vault = unlocked_vault(tmp.path());
        add_sample(&vault);
        let salt = vault.master_salt().unwrap();
        // Damaged verifier for the current salt.
        let bogus = key_check::seal(&DerivedKey::new([9u8; 32])).unwrap();
        vault
            .conn
            .execute("UPDATE key_check SET blob = ?", [&bogus])
            .unwrap();
        vault.full_lock();
        assert!(matches!(
            vault.unlock("wrong master pw"),
            Err(Error::InvalidMasterPassword)
        ));
        vault.unlock("master password here").unwrap();
        let (blob, row_salt) = key_check_row(&vault).unwrap();
        assert_ne!(blob, bogus, "resealed");
        assert_eq!(row_salt, salt);

        // Stale verifier (an older build changed the master password).
        vault
            .conn
            .execute("UPDATE key_check SET salt = 'old-salt'", [])
            .unwrap();
        vault.full_lock();
        vault.unlock("master password here").unwrap();
        assert_eq!(key_check_row(&vault).unwrap().1, salt);
    }

    #[test]
    fn split_unlock_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let mut vault = unlocked_vault(&path);
        let id = add_sample(&vault);
        vault.full_lock();

        let inputs = vault.unlock_inputs().unwrap().unwrap();
        fn assert_send<T: Send>(_: &T) {}
        assert_send(&inputs);
        let worker_inputs = inputs.clone();
        let key = std::thread::spawn(move || {
            assert!(matches!(
                derive_unlock_key("wrong master pw", &worker_inputs),
                Err(Error::InvalidMasterPassword)
            ));
            derive_unlock_key("master password here", &worker_inputs).unwrap()
        })
        .join()
        .unwrap();
        assert!(matches!(
            vault.unlock_with_key(&inputs, DerivedKey::new([1u8; 32])),
            Err(Error::KeyMismatch)
        ));
        assert!(!vault.is_unlocked());
        vault.unlock_with_key(&inputs, key.clone()).unwrap();
        assert_eq!(
            vault
                .get_without_touch(id)
                .unwrap()
                .unwrap()
                .password
                .as_deref(),
            Some("sample-secret")
        );
        vault.verify_session_key().unwrap();

        // The master row changes between reading the inputs and installing.
        vault.full_lock();
        let stale_inputs = vault.unlock_inputs().unwrap().unwrap();
        let mut other = Vault::open(&path).unwrap();
        other.unlock("master password here").unwrap();
        other
            .change_master_password("master password here", "a brand new master")
            .unwrap();
        drop(other);
        assert!(matches!(
            vault.unlock_with_key(&stale_inputs, key.clone()),
            Err(Error::KeyMismatch)
        ));
        let session = Vault::open_with_session_key(&path, key).unwrap();
        assert!(matches!(
            session.verify_session_key(),
            Err(Error::KeyMismatch)
        ));

        // Vaults without a verifier still go through the PHC hash.
        vault.conn.execute("DELETE FROM key_check", []).unwrap();
        let inputs = vault.unlock_inputs().unwrap().unwrap();
        assert!(matches!(
            derive_unlock_key("master password here", &inputs),
            Err(Error::InvalidMasterPassword)
        ));
        let key = derive_unlock_key("a brand new master", &inputs).unwrap();
        vault.unlock_with_key(&inputs, key).unwrap();
        assert!(key_check_row(&vault).is_some());

        // A v1 vault must migrate through the synchronous path.
        vault
            .conn
            .execute("UPDATE master SET crypto_version = 1", [])
            .unwrap();
        assert!(vault.unlock_inputs().unwrap().is_none());
        let empty = Vault::open(dir.path().join("empty.db")).unwrap();
        assert!(empty.unlock_inputs().unwrap().is_none());
    }

    #[test]
    fn split_quick_unlock_path_upgrades_old_records() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut vault = unlocked_vault(tmp.path());
        add_sample(&vault);
        let old = previous_release_prefs("123456", &vault.key.clone().unwrap());
        vault.full_lock();
        let worker_prefs = old.clone();
        let (key, upgraded) = std::thread::spawn(move || {
            assert!(matches!(
                derive_quick_unlock_key("111111", &worker_prefs),
                Err(Error::InvalidMasterPassword)
            ));
            derive_quick_unlock_key("123456", &worker_prefs).unwrap()
        })
        .join()
        .unwrap();
        let upgraded = upgraded.unwrap();
        vault.install_quick_unlock_key(key).unwrap();
        assert_eq!(vault.list(None).unwrap().len(), 1);
        let (_, again) = derive_quick_unlock_key("123456", &upgraded).unwrap();
        assert!(again.is_none());
        let mut exhausted = upgraded;
        exhausted.failed_attempts = crate::settings::QUICK_UNLOCK_MAX_ATTEMPTS;
        assert!(matches!(
            derive_quick_unlock_key("123456", &exhausted),
            Err(Error::Other(_))
        ));
    }

    #[test]
    fn set_tags_is_atomic_and_nests_inside_transactions() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let vault = unlocked_vault(tmp.path());
        let id = add_sample(&vault);
        let updated_at = vault.entry_updated_at(id).unwrap();
        vault
            .set_tags(id, &["work".into(), "Work".into(), " home ".into()])
            .unwrap();
        assert_eq!(vault.tags_of(id).unwrap(), vec!["home", "work"]);
        assert_eq!(vault.entry_updated_at(id).unwrap(), updated_at);

        // Inside an outer transaction that commits.
        vault
            .transaction(|| vault.set_tags(id, &["bank".into()]))
            .unwrap();
        assert_eq!(vault.tags_of(id).unwrap(), vec!["bank"]);

        // Inside an outer transaction that fails: everything rolls back.
        let result: Result<()> = vault.transaction(|| {
            vault.set_tags(id, &["travel".into()])?;
            Err(Error::Other("abort".into()))
        });
        assert!(result.is_err());
        assert_eq!(vault.tags_of(id).unwrap(), vec!["bank"]);

        // A failure inside set_tags itself leaves nothing half-applied.
        vault
            .conn
            .execute_batch(
                "CREATE TRIGGER no_travel BEFORE INSERT ON tags
                 WHEN new.name = 'travel' BEGIN SELECT RAISE(ABORT, 'nope'); END;",
            )
            .unwrap();
        assert!(vault
            .set_tags(id, &["alpha".into(), "travel".into()])
            .is_err());
        assert_eq!(vault.tags_of(id).unwrap(), vec!["bank"]);
        assert!(!vault.all_tags().unwrap().iter().any(|(n, _)| n == "alpha"));
    }

    #[test]
    fn summaries_report_totp_without_decrypting() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let vault = unlocked_vault(tmp.path());
        let with = vault
            .add(NewEntry {
                title: "With".into(),
                password: "p".into(),
                totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
                ..NewEntry::default()
            })
            .unwrap();
        add_sample(&vault);
        vault.set_tags(with, &["t".into()]).unwrap();
        let list = vault.list(None).unwrap();
        let by_title = |t: &str| list.iter().find(|e| e.title == t).unwrap().has_totp;
        assert!(by_title("With"));
        assert!(!by_title("Sample"));
        assert!(vault.list(Some("Wit")).unwrap()[0].has_totp);
        assert!(vault.entries_with_tag("t").unwrap()[0].has_totp);
    }

    fn user_version(vault: &Vault) -> i32 {
        vault
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn open_records_setup_version_and_repairs_older_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let vault = unlocked_vault(&path);
        let id = add_sample(&vault);
        vault.set_tags(id, &["keep".into()]).unwrap();
        assert_eq!(user_version(&vault), schema::setup_version());
        drop(vault);

        // A file last touched by an older build: unmarked, missing tables.
        let raw = Connection::open(&path).unwrap();
        raw.execute_batch(
            "PRAGMA user_version = 0;
             DROP TABLE key_check;
             DROP TABLE nextcloud_folder_mapping;",
        )
        .unwrap();
        drop(raw);
        let mut vault = Vault::open(&path).unwrap();
        assert_eq!(user_version(&vault), schema::setup_version());
        vault.unlock("master password here").unwrap();
        assert!(key_check_row(&vault).is_some());
        assert_eq!(vault.tags_of(id).unwrap(), vec!["keep"]);
        drop(vault);

        // Marked as current but a table is gone: setup runs anyway.
        let raw = Connection::open(&path).unwrap();
        raw.execute_batch("DROP TABLE folders;").unwrap();
        drop(raw);
        let mut vault = Vault::open(&path).unwrap();
        vault.create_folder("Work").unwrap();
        vault.unlock("master password here").unwrap();
        vault
            .update(
                id,
                UpdateEntry {
                    password: Some("newer-secret".into()),
                    ..UpdateEntry::default()
                },
            )
            .unwrap();
        vault.add_attachment(id, "a.bin", None, b"blob").unwrap();
        drop(vault);

        // Orphans written by a build without foreign keys are still moved
        // into the trash on the fast path.
        let raw = Connection::open(&path).unwrap();
        raw.execute_batch(
            "PRAGMA foreign_keys = OFF;
             INSERT INTO passwords_trash (original_id, title, password_encrypted, deleted_at)
                 SELECT id, title, password_encrypted, 1 FROM passwords;
             DELETE FROM passwords;",
        )
        .unwrap();
        drop(raw);
        let mut vault = Vault::open(&path).unwrap();
        assert_eq!(user_version(&vault), schema::setup_version());
        let moved: (i64, i64) = vault
            .conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM passwords_history_trash),
                        (SELECT COUNT(*) FROM attachments_trash)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(moved, (1, 1));
        vault.unlock("master password here").unwrap();
        let trash = vault.list_trash().unwrap();
        assert_eq!(trash.len(), 1);
        let restored = vault
            .restore_from_trash(trash[0].trash_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            vault.password_history(restored).unwrap()[0].password,
            "sample-secret"
        );
        let attachment = vault.list_attachments(restored).unwrap()[0].id;
        assert_eq!(
            vault.get_attachment(attachment).unwrap().unwrap().1,
            b"blob"
        );
    }

    #[test]
    fn persistent_quick_unlock_rejects_wrong_pin() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut vault = unlocked_vault(tmp.path());
        let prefs = vault.enable_persistent_quick_unlock("123456").unwrap();
        vault.full_lock();

        assert!(matches!(
            vault.quick_unlock_persistent("654321", &prefs),
            Err(Error::InvalidMasterPassword)
        ));
        assert!(!vault.is_unlocked());
    }

    #[test]
    fn persistent_quick_unlock_refuses_once_attempts_are_exhausted() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut vault = unlocked_vault(tmp.path());
        let mut prefs = vault.enable_persistent_quick_unlock("123456").unwrap();
        vault.full_lock();

        prefs.failed_attempts = crate::settings::QUICK_UNLOCK_MAX_ATTEMPTS;
        // Even the *correct* PIN is refused: the budget is spent.
        assert!(vault.quick_unlock_persistent("123456", &prefs).is_err());
        assert!(!vault.is_unlocked());
    }

    #[test]
    fn legacy_quick_unlock_blobs_still_open() {
        // A blob written before PIN hardening records generation 0 and was
        // wrapped with the standard vault KDF. It must keep working.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut vault = unlocked_vault(tmp.path());
        let key = vault.key.clone().unwrap();

        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        let legacy = QuickUnlockPrefs {
            pin_hash: argon2_kdf::hash_master("123456").unwrap(),
            salt: URL_SAFE_NO_PAD.encode(salt),
            encrypted_key: URL_SAFE_NO_PAD.encode(
                aes_gcm_v2::encrypt(
                    &argon2_kdf::derive_key_v2("123456", &salt).unwrap(),
                    key.as_bytes(),
                )
                .unwrap(),
            ),
            failed_attempts: 0,
            kdf_version: crate::settings::QUICK_UNLOCK_KDF_LEGACY,
        };

        let key_before = key.as_bytes().to_owned();
        vault.full_lock();
        vault.quick_unlock_persistent("123456", &legacy).unwrap();
        assert_eq!(vault.key.clone().unwrap().as_bytes(), &key_before);
    }

    #[test]
    fn master_password_change_preserves_all_encrypted_data() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let mut vault = Vault::open(&path).unwrap();
        vault.set_master_password("old master password").unwrap();

        let active_id = vault
            .add(NewEntry {
                title: "Active".into(),
                password: "active-old".into(),
                notes: Some("active-notes".into()),
                totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
                ..NewEntry::default()
            })
            .unwrap();
        vault
            .update(
                active_id,
                UpdateEntry {
                    password: Some("active-current".into()),
                    ..UpdateEntry::default()
                },
            )
            .unwrap();
        let active_attachment = vault
            .add_attachment(active_id, "active.bin", None, b"active attachment")
            .unwrap();

        let trash_source_id = vault
            .add(NewEntry {
                title: "Trashed".into(),
                password: "trash-old".into(),
                notes: Some("trash-notes".into()),
                ..NewEntry::default()
            })
            .unwrap();
        vault
            .update(
                trash_source_id,
                UpdateEntry {
                    password: Some("trash-current".into()),
                    ..UpdateEntry::default()
                },
            )
            .unwrap();
        vault
            .add_attachment(trash_source_id, "trash.bin", None, b"trash attachment")
            .unwrap();

        let now = chrono::Utc::now().timestamp();
        let tx = vault.conn.unchecked_transaction().unwrap();
        tx.execute(
            "INSERT INTO passwords_trash (
                original_id, title, username, password_encrypted, notes_encrypted,
                url, totp_secret_encrypted, totp_algorithm, totp_digits, totp_period,
                category, favorite, created_at, updated_at, deleted_at)
             SELECT id, title, username, password_encrypted, notes_encrypted,
                    url, totp_secret_encrypted, totp_algorithm, totp_digits, totp_period,
                    category, favorite, created_at, updated_at, ?
               FROM passwords WHERE id = ?",
            params![now, trash_source_id],
        )
        .unwrap();
        let trash_id = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO passwords_history_trash
                (original_history_id, trash_id, password_encrypted, changed_at)
             SELECT id, ?, password_encrypted, changed_at
               FROM passwords_history WHERE entry_id = ?",
            params![trash_id, trash_source_id],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO attachments_trash
                (original_attachment_id, trash_id, filename, mime_type,
                 ciphertext, size_bytes, created_at)
             SELECT id, ?, filename, mime_type, ciphertext, size_bytes, created_at
               FROM attachments WHERE entry_id = ?",
            params![trash_id, trash_source_id],
        )
        .unwrap();
        tx.execute("DELETE FROM passwords WHERE id = ?", [trash_source_id])
            .unwrap();
        tx.commit().unwrap();

        let old_key = vault.key().unwrap().clone();
        vault
            .change_master_password("old master password", "new master password")
            .unwrap();
        vault.full_lock();
        assert!(matches!(
            vault.unlock("old master password"),
            Err(Error::InvalidMasterPassword)
        ));
        vault.unlock("new master password").unwrap();
        assert_eq!(
            key_check::check(
                &vault.conn,
                vault.key().unwrap(),
                &vault.master_salt().unwrap()
            )
            .unwrap(),
            KeyStatus::Verified,
            "verifier resealed inside the same transaction"
        );
        // No ciphertext anywhere still opens with the old key.
        for (table, column) in [
            ("passwords", "password_encrypted"),
            ("passwords_trash", "password_encrypted"),
            ("passwords_history", "password_encrypted"),
            ("passwords_history_trash", "password_encrypted"),
            ("attachments", "ciphertext"),
            ("attachments_trash", "ciphertext"),
        ] {
            let blobs = collect_encrypted_blobs(&vault.conn, table, "rowid", column).unwrap();
            assert!(!blobs.is_empty(), "{table} has rows in this fixture");
            for (_, blob) in blobs {
                assert!(aes_gcm_v2::decrypt(&old_key, &blob).is_err(), "{table}");
                assert!(aes_gcm_v2::decrypt(vault.key().unwrap(), &blob).is_ok());
            }
        }

        let active = vault.get_without_touch(active_id).unwrap().unwrap();
        assert_eq!(active.password.as_deref(), Some("active-current"));
        assert_eq!(active.notes.as_deref(), Some("active-notes"));
        assert_eq!(
            vault.password_history(active_id).unwrap()[0].password,
            "active-old"
        );
        assert_eq!(
            vault.get_attachment(active_attachment).unwrap().unwrap().1,
            b"active attachment"
        );

        let restored_id = vault.restore_from_trash(trash_id).unwrap().unwrap();
        let restored = vault.get_without_touch(restored_id).unwrap().unwrap();
        assert_eq!(restored.password.as_deref(), Some("trash-current"));
        assert_eq!(restored.notes.as_deref(), Some("trash-notes"));
        assert_eq!(
            vault.password_history(restored_id).unwrap()[0].password,
            "trash-old"
        );
        let restored_attachment = vault.list_attachments(restored_id).unwrap()[0].id;
        assert_eq!(
            vault
                .get_attachment(restored_attachment)
                .unwrap()
                .unwrap()
                .1,
            b"trash attachment"
        );
    }

    #[test]
    fn sqlite_safety_and_online_backup_are_enabled() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.db");
        let backup_path = directory.path().join("backup.db");
        let mut vault = Vault::open(&path).unwrap();
        vault.set_master_password("secure master password").unwrap();
        vault
            .add(NewEntry {
                title: "Example".into(),
                password: "secret".into(),
                ..NewEntry::default()
            })
            .unwrap();

        let foreign_keys: i64 = vault
            .conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(foreign_keys, 1);
        vault.backup_to(&backup_path).unwrap();
        assert!(vault.backup_to(&backup_path).is_err());

        let mut restored = Vault::open(&backup_path).unwrap();
        restored.unlock("secure master password").unwrap();
        assert_eq!(restored.list(None).unwrap().len(), 1);
    }

    #[test]
    fn rejects_short_new_master_passwords() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut vault = Vault::open(tmp.path()).unwrap();
        assert!(matches!(
            vault.set_master_password("short"),
            Err(Error::InvalidInput(_))
        ));
    }

    #[test]
    fn persistent_quick_unlock_survives_reopen() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let mut vault = Vault::open(&path).unwrap();
        vault
            .set_master_password("correct horse battery staple")
            .unwrap();
        vault
            .add(NewEntry {
                title: "Example".into(),
                password: "secret".into(),
                ..NewEntry::default()
            })
            .unwrap();
        let prefs = vault.enable_persistent_quick_unlock("123456").unwrap();
        drop(vault);

        let mut reopened = Vault::open(&path).unwrap();
        assert!(!reopened.is_unlocked());
        assert!(matches!(
            reopened.quick_unlock_persistent("000000", &prefs),
            Err(Error::InvalidMasterPassword)
        ));
        reopened.quick_unlock_persistent("123456", &prefs).unwrap();

        let entries = reopened.list(None).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "Example");
    }

    #[test]
    fn search_matches_substrings_and_escapes_like_wildcards() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut vault = Vault::open(tmp.path()).unwrap();
        vault
            .set_master_password("correct horse battery staple")
            .unwrap();
        vault
            .add(NewEntry {
                title: "Example".into(),
                username: Some("alice".into()),
                password: "secret".into(),
                url: Some("https://example.test".into()),
                ..NewEntry::default()
            })
            .unwrap();
        vault
            .add(NewEntry {
                title: "100% Literal".into(),
                password: "secret".into(),
                ..NewEntry::default()
            })
            .unwrap();

        let substring = vault.list(Some("amp")).unwrap();
        assert_eq!(substring.len(), 1);
        assert_eq!(substring[0].title, "Example");

        let wildcard = vault.list(Some("%")).unwrap();
        assert_eq!(wildcard.len(), 1);
        assert_eq!(wildcard[0].title, "100% Literal");
    }

    #[test]
    fn get_without_touch_does_not_update_last_accessed() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut vault = Vault::open(tmp.path()).unwrap();
        vault
            .set_master_password("correct horse battery staple")
            .unwrap();
        let id = vault
            .add(NewEntry {
                title: "Example".into(),
                password: "secret".into(),
                ..NewEntry::default()
            })
            .unwrap();

        assert!(vault.list(None).unwrap()[0].last_accessed.is_none());
        vault.get_without_touch(id).unwrap().unwrap();
        assert!(vault.list(None).unwrap()[0].last_accessed.is_none());

        vault.get(id).unwrap().unwrap();
        let touched = vault.list(None).unwrap()[0].last_accessed;
        assert!(touched.is_some());

        vault.get_without_touch(id).unwrap().unwrap();
        assert_eq!(vault.list(None).unwrap()[0].last_accessed, touched);
    }
}
