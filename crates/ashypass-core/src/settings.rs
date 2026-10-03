//! User-facing settings persisted to `~/.config/ashypass/settings.json`.
//!
//! Mirrors the schema used by the original Python `core/config.py` so existing
//! settings files load without migration.

use crate::config::{
    atomic_write_private, ensure_private_file, settings_file, CLIPBOARD_CLEAR_SECONDS,
    DEFAULT_PASSWORD_LENGTH, SESSION_TIMEOUT_SECONDS,
};
use crate::crypto::autotune::TunedParams;
use crate::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneratorPrefs {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for GeneratorPrefs {
    fn default() -> Self {
        Self {
            length: DEFAULT_PASSWORD_LENGTH,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub show_favicons: bool,
    /// Allow falling back to Google's favicon service when a site serves no
    /// `/favicon.ico`. Off by default: the query string carries the hostname,
    /// so enabling it discloses part of the vault's contents to a third party.
    pub favicon_third_party_fallback: bool,
    /// Allow the browser native-messaging host to unlock the vault from the
    /// system keyring and answer extension queries. Off disables browser
    /// integration without having to remove the host manifests.
    pub browser_integration: bool,
    pub show_sync_badges: bool,
    pub compact_vault_list: bool,
    pub large_totp_codes: bool,
    pub lock_timeout: u64,
    pub clipboard_clear: u64,
    pub generator: GeneratorPrefs,
    pub argon2: TunedParams,
    pub audit_check_hibp: bool,
    /// Legacy fallback. New quick-unlock state is stored in Secret Service
    /// and this field is cleared after a successful migration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quick_unlock: Option<QuickUnlockPrefs>,
    /// Trash retention in days. Entries deleted longer ago are purged on app
    /// start. 0 disables the trash entirely (deletes are immediate).
    pub trash_retention_days: u32,
    /// Run a Nextcloud Passwords reconcile automatically: after every vault
    /// mutation (debounced) and at a periodic interval. Default on — the
    /// scheduler still no-ops when Nextcloud isn't configured.
    pub nextcloud_auto_sync: bool,
    /// Minutes between periodic background syncs. 0 disables periodic; the
    /// debounced post-edit sync still runs.
    pub nextcloud_auto_sync_interval_minutes: u32,
    /// Trigger one sync when the vault is unlocked.
    pub nextcloud_sync_on_unlock: bool,
}

/// Wrapping-KDF generation for `QuickUnlockPrefs::encrypted_key`.
///
/// Absent (0) means the blob predates PIN-specific hardening and was wrapped
/// with the standard vault parameters; it must keep being opened with those or
/// existing users lose their PIN. New blobs are written as generation 1.
pub const QUICK_UNLOCK_KDF_LEGACY: u32 = 0;
pub const QUICK_UNLOCK_KDF_PIN_HARDENED: u32 = 1;

/// Failed PIN attempts after which persisted quick-unlock state is destroyed
/// and the master password is required again.
pub const QUICK_UNLOCK_MAX_ATTEMPTS: u32 = 5;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct QuickUnlockPrefs {
    /// Legacy only. Records written before this field was retired carry an
    /// Argon2 PHC hash of the PIN; it is no longer written (the AES-GCM tag
    /// of `encrypted_key` authenticates the PIN, and a cheaper hash beside it
    /// would be a faster brute-force target). Empty in current records.
    pub pin_hash: String,
    pub salt: String,
    pub encrypted_key: String,
    /// Consecutive wrong PINs. Reset on success; at
    /// `QUICK_UNLOCK_MAX_ATTEMPTS` the caller wipes this state.
    pub failed_attempts: u32,
    /// See `QUICK_UNLOCK_KDF_*`.
    pub kdf_version: u32,
}

impl QuickUnlockPrefs {
    pub fn is_configured(&self) -> bool {
        !self.salt.is_empty() && !self.encrypted_key.is_empty()
    }

    /// True for records in an older format that should be rewritten after
    /// the next successful PIN unlock (see
    /// `Vault::quick_unlock_persistent_upgrading`).
    pub fn needs_upgrade(&self) -> bool {
        !self.pin_hash.is_empty() || self.kdf_version < QUICK_UNLOCK_KDF_PIN_HARDENED
    }

    pub fn attempts_exhausted(&self) -> bool {
        self.failed_attempts >= QUICK_UNLOCK_MAX_ATTEMPTS
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            show_favicons: true,
            favicon_third_party_fallback: false,
            browser_integration: true,
            show_sync_badges: true,
            compact_vault_list: false,
            large_totp_codes: true,
            lock_timeout: SESSION_TIMEOUT_SECONDS,
            clipboard_clear: CLIPBOARD_CLEAR_SECONDS,
            generator: GeneratorPrefs::default(),
            argon2: TunedParams::default(),
            audit_check_hibp: false,
            quick_unlock: None,
            trash_retention_days: 30,
            nextcloud_auto_sync: true,
            nextcloud_auto_sync_interval_minutes: 5,
            nextcloud_sync_on_unlock: true,
        }
    }
}

impl Settings {
    pub fn load() -> Self {
        Self::load_from(&settings_file())
    }

    pub fn save(&self) -> Result<()> {
        self.save_to(&settings_file())
    }

    /// Load settings from `path`. Missing fields take their defaults and
    /// unknown fields are ignored, so files from older and newer builds load.
    ///
    /// A file that does not parse is never silently discarded: the error is
    /// logged, the original bytes are copied next to it (see
    /// `preserve_unparseable`) before anything can overwrite them, and every
    /// field that is still valid is kept.
    pub fn load_from(path: &Path) -> Self {
        if let Err(error) = ensure_private_file(path) {
            log::warn!("could not secure settings permissions: {error}");
        }
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Self::default(),
            Err(error) => {
                log::error!(
                    "could not read settings file {}: {error}; using defaults",
                    path.display()
                );
                return Self::default();
            }
        };
        match serde_json::from_slice(&bytes) {
            Ok(settings) => settings,
            Err(error) => {
                log::error!(
                    "settings file {} could not be parsed: {error}",
                    path.display()
                );
                match preserve_unparseable(path, &bytes) {
                    Ok(copy) => log::warn!("kept a copy of it at {}", copy.display()),
                    Err(error) => log::error!("could not keep a copy of it: {error}"),
                }
                Self::from_partial(&bytes)
            }
        }
    }

    /// Write settings to `path` atomically. If the file currently on disk
    /// cannot be parsed (or read), it is preserved first; when that fails the
    /// save is refused rather than destroying the only copy.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        match fs::read(path) {
            Ok(bytes) => {
                if serde_json::from_slice::<Settings>(&bytes).is_err() {
                    preserve_unparseable(path, &bytes)?;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                // Unreadable: move it aside instead of replacing it.
                fs::rename(path, unused_backup_path(path))?;
            }
        }
        let json = serde_json::to_string_pretty(self)?;
        atomic_write_private(path, json.as_bytes())?;
        Ok(())
    }

    /// Best-effort recovery from a file that failed strict parsing: start
    /// from the defaults and apply each top-level field that still yields a
    /// valid `Settings`. Fields with a wrong type keep their defaults.
    fn from_partial(bytes: &[u8]) -> Self {
        let Ok(Value::Object(file)) = serde_json::from_slice::<Value>(bytes) else {
            return Self::default();
        };
        let Ok(Value::Object(mut merged)) = serde_json::to_value(Self::default()) else {
            return Self::default();
        };
        for (name, value) in file {
            let previous = merged.insert(name.clone(), value);
            if serde_json::from_value::<Self>(Value::Object(merged.clone())).is_err() {
                log::warn!("ignoring invalid settings field `{name}`");
                match previous {
                    Some(previous) => merged.insert(name, previous),
                    None => merged.remove(&name),
                };
            }
        }
        serde_json::from_value(Value::Object(merged)).unwrap_or_default()
    }
}

/// Copy the bytes of an unparseable settings file to `<file>.bak` (or a
/// timestamped name when a different `.bak` already exists) and return where
/// they went. Idempotent for identical content.
fn preserve_unparseable(path: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    let primary = with_suffix(path, ".bak");
    match fs::read(&primary) {
        Ok(existing) if existing == bytes => return Ok(primary),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            atomic_write_private(&primary, bytes)?;
            return Ok(primary);
        }
        _ => {}
    }
    let target = unused_backup_path(path);
    atomic_write_private(&target, bytes)?;
    Ok(target)
}

fn unused_backup_path(path: &Path) -> PathBuf {
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%S");
    let mut candidate = with_suffix(path, &format!(".{stamp}.bak"));
    let mut n = 1;
    while candidate.exists() {
        candidate = with_suffix(path, &format!(".{stamp}-{n}.bak"));
        n += 1;
    }
    candidate
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_and_unknown_fields_load_with_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(
            &path,
            r#"{"lock_timeout": 120, "argon2": {"t_cost": 4}, "from_the_future": [1, 2]}"#,
        )
        .unwrap();
        let settings = Settings::load_from(&path);
        assert_eq!(settings.lock_timeout, 120);
        assert_eq!(settings.argon2.t_cost, 4);
        assert_eq!(
            settings.argon2.m_cost_kib,
            TunedParams::default().m_cost_kib
        );
        assert_eq!(settings.trash_retention_days, 30);
        assert!(
            !with_suffix(&path, ".bak").exists(),
            "valid file needs no backup"
        );
    }

    #[test]
    fn unparseable_file_is_preserved_and_valid_fields_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let original = r#"{"lock_timeout": "soon", "clipboard_clear": 9, "show_favicons": false}"#;
        fs::write(&path, original).unwrap();

        let settings = Settings::load_from(&path);
        assert_eq!(settings.lock_timeout, SESSION_TIMEOUT_SECONDS);
        assert_eq!(settings.clipboard_clear, 9);
        assert!(!settings.show_favicons);
        let bak = with_suffix(&path, ".bak");
        assert_eq!(fs::read_to_string(&bak).unwrap(), original);

        settings.save_to(&path).unwrap();
        assert_eq!(fs::read_to_string(&bak).unwrap(), original);
        assert_eq!(Settings::load_from(&path).clipboard_clear, 9);
    }

    #[test]
    fn save_never_overwrites_the_only_copy_of_a_broken_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(with_suffix(&path, ".bak"), "older backup").unwrap();
        fs::write(&path, "{ not json").unwrap();

        Settings::default().save_to(&path).unwrap();
        assert_eq!(
            fs::read_to_string(with_suffix(&path, ".bak")).unwrap(),
            "older backup"
        );
        let copies: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| fs::read_to_string(e.unwrap().path()).unwrap_or_default())
            .collect();
        assert!(copies.iter().any(|c| c == "{ not json"));
        assert!(serde_json::from_str::<Settings>(&fs::read_to_string(&path).unwrap()).is_ok());
    }

    #[test]
    fn quick_unlock_records_old_and_new() {
        let legacy: QuickUnlockPrefs =
            serde_json::from_str(r#"{"pin_hash":"$argon2id$x","salt":"s","encrypted_key":"k"}"#)
                .unwrap();
        assert!(legacy.is_configured());
        assert!(legacy.needs_upgrade());
        let current = QuickUnlockPrefs {
            salt: "s".into(),
            encrypted_key: "k".into(),
            kdf_version: QUICK_UNLOCK_KDF_PIN_HARDENED,
            ..QuickUnlockPrefs::default()
        };
        assert!(current.is_configured());
        assert!(!current.needs_upgrade());
        assert!(!QuickUnlockPrefs::default().is_configured());
    }
}
