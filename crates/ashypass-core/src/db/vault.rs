//! Vault — the user-facing API on top of crypto + sqlite.
//!
//! Lifecycle:
//! 1. `Vault::open(path)` — opens connection, runs schema/migration columns.
//! 2. First run: `set_master_password()`. Returning user: `unlock()` which may
//!    transparently invoke `migration::migrate_v1_to_v2()` on legacy DBs.
//! 3. CRUD: `add`, `list`, `get` (decrypts), `update`, `delete`, `toggle_favorite`.

use crate::config::{ensure_private_file, MIN_MASTER_PASSWORD_LENGTH};
use crate::crypto::{aes_gcm_v2, argon2_kdf, DerivedKey};
use crate::settings::QuickUnlockPrefs;
use crate::{db::migration, db::schema, Error, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use rusqlite::{params, params_from_iter, types::Value, Connection, OptionalExtension, Row};
use std::cell::RefCell;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

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
        schema::initialize(&conn)?;
        migration::add_missing_columns(&conn)?;
        let violation_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })?;
        if violation_count > 0 {
            log::warn!("vault contains {violation_count} foreign-key violation(s)");
        }
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

        self.conn.execute(
            "INSERT INTO master (id, password_hash, salt, crypto_version, created_at)
             VALUES (1, ?, ?, 2, ?)",
            params![hash, salt_text, ts],
        )?;

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

    pub fn unlock(&mut self, password: &str) -> Result<()> {
        let crypto_version = migration::detect_crypto_version(&self.conn)?.unwrap_or(2);
        if crypto_version == 1 {
            // Pre-migration: ensure on-disk backup, then migrate atomically.
            migration::backup_db_file(&self.db_path)?;
            migration::migrate_v1_to_v2(&mut self.conn, password)?;
        }

        let (hash, salt_text) = self.conn.query_row(
            "SELECT password_hash, salt FROM master WHERE id = 1",
            [],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )?;
        if !argon2_kdf::verify_master(password, &hash)? {
            return Err(Error::InvalidMasterPassword);
        }
        self.key = Some(argon2_kdf::derive_key_v2(password, salt_text.as_bytes())?);
        Ok(())
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
        self.quick_pin_hash = Some(argon2_kdf::hash_master(pin)?);
        self.cached_key = Some(key);
        Ok(())
    }

    /// Configure quick-unlock and return the encrypted, device-local state that
    /// lets the app restore it after restart.
    pub fn enable_persistent_quick_unlock(&mut self, pin: &str) -> Result<QuickUnlockPrefs> {
        self.enable_quick_unlock(pin)?;
        let key = self.cached_key.as_ref().ok_or(Error::Locked)?;
        let pin_hash = self
            .quick_pin_hash
            .clone()
            .ok_or_else(|| Error::Other("quick-unlock hash missing".into()))?;

        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        let wrapping_key = argon2_kdf::derive_key_v2(pin, &salt)?;
        let encrypted_key = aes_gcm_v2::encrypt(&wrapping_key, key.as_bytes())?;

        Ok(QuickUnlockPrefs {
            pin_hash,
            salt: URL_SAFE_NO_PAD.encode(salt),
            encrypted_key: URL_SAFE_NO_PAD.encode(encrypted_key),
        })
    }

    /// Re-acquire the encryption key using a previously-set quick-unlock PIN.
    /// Fails if quick-unlock was never configured this session, or if the PIN
    /// is wrong. Wrong PIN does not clear the cache — caller decides whether
    /// to escalate to a full unlock after N failures.
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
        self.key = Some(key);
        Ok(())
    }

    /// Re-acquire the encryption key from persisted quick-unlock state.
    pub fn quick_unlock_persistent(&mut self, pin: &str, prefs: &QuickUnlockPrefs) -> Result<()> {
        if !prefs.is_configured() {
            return Err(Error::Other("quick-unlock not configured".into()));
        }
        if !argon2_kdf::verify_master(pin, &prefs.pin_hash)? {
            return Err(Error::InvalidMasterPassword);
        }

        let salt = URL_SAFE_NO_PAD.decode(&prefs.salt)?;
        let encrypted_key = URL_SAFE_NO_PAD.decode(&prefs.encrypted_key)?;
        let wrapping_key = argon2_kdf::derive_key_v2(pin, &salt)?;
        let key_bytes = aes_gcm_v2::decrypt(&wrapping_key, &encrypted_key)?;
        if key_bytes.len() != 32 {
            return Err(Error::Crypto("quick-unlock key has invalid length".into()));
        }

        let mut raw = [0u8; 32];
        raw.copy_from_slice(&key_bytes);
        let key = DerivedKey::new(raw);
        self.key = Some(key.clone());
        self.cached_key = Some(key);
        self.quick_pin_hash = Some(prefs.pin_hash.clone());
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
                           totp_secret_encrypted, totp_algorithm, totp_digits, totp_period,
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

        let mut stmt = self.conn.prepare(&sql)?;
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
                           p.totp_secret_encrypted, p.totp_algorithm, p.totp_digits, p.totp_period,
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
        let mut stmt = self.conn.prepare(&sql)?;
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
        let mut stmt = self.conn.prepare(
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

        let mut current_stmt = self.conn.prepare(
            "SELECT tag_id FROM entry_tags
             WHERE entry_id = ?
             ORDER BY tag_id",
        )?;
        let current_ids = current_stmt
            .query_map(params![entry_id], |r| r.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(current_stmt);
        if current_ids == tag_ids {
            return Ok(());
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
        self.notify_change();
        Ok(())
    }

    pub fn tags_of(&self, entry_id: i64) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
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
        let mut stmt = self.conn.prepare(
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
        let mut stmt = self.conn.prepare(
            "SELECT p.id, p.title, p.username, p.url,
                    p.totp_secret_encrypted, p.totp_algorithm, p.totp_digits, p.totp_period,
                    p.category, p.favorite, p.created_at, p.updated_at, p.last_accessed
             FROM passwords p
             JOIN entry_tags et ON et.entry_id = p.id
             WHERE et.tag_id = ?
             ORDER BY p.title",
        )?;
        let rows = stmt
            .query_map(params![id], |r| {
                let totp_blob: Option<Vec<u8>> = r.get(4)?;
                Ok(PasswordEntry {
                    id: r.get(0)?,
                    title: r.get(1)?,
                    username: r.get(2)?,
                    url: r.get(3)?,
                    password: None,
                    notes: None,
                    totp_secret: None,
                    has_totp: totp_blob.is_some(),
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
            })?
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

        let entries = collect_encrypted_entries(&self.conn, "passwords")?;
        let trash_entries = collect_encrypted_entries(&self.conn, "passwords_trash")?;
        let history =
            collect_encrypted_blobs(&self.conn, "passwords_history", "id", "password_encrypted")?;
        let trash_history = collect_encrypted_blobs(
            &self.conn,
            "passwords_history_trash",
            "original_history_id",
            "password_encrypted",
        )?;
        let attachments = collect_encrypted_blobs(&self.conn, "attachments", "id", "ciphertext")?;
        let trash_attachments = collect_encrypted_blobs(
            &self.conn,
            "attachments_trash",
            "original_attachment_id",
            "ciphertext",
        )?;

        let tx = self.conn.transaction()?;
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
        tx.commit()?;

        self.key = Some(new_key);
        self.cached_key = None;
        self.quick_pin_hash = None;
        self.notify_change();
        Ok(())
    }
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

fn password_summary_from_row(r: &Row<'_>) -> rusqlite::Result<PasswordEntry> {
    let totp_blob: Option<Vec<u8>> = r.get(4)?;
    Ok(PasswordEntry {
        id: r.get(0)?,
        title: r.get(1)?,
        username: r.get(2)?,
        url: r.get(3)?,
        password: None,
        notes: None,
        totp_secret: None,
        has_totp: totp_blob.is_some(),
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

        vault
            .change_master_password("old master password", "new master password")
            .unwrap();
        vault.full_lock();
        assert!(matches!(
            vault.unlock("old master password"),
            Err(Error::InvalidMasterPassword)
        ));
        vault.unlock("new master password").unwrap();

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
