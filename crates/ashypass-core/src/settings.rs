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
use std::fs;

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
        !self.pin_hash.is_empty() && !self.salt.is_empty() && !self.encrypted_key.is_empty()
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
        let path = settings_file();
        if let Err(error) = ensure_private_file(&path) {
            log::warn!("could not secure settings permissions: {error}");
        }
        match fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = settings_file();
        let json = serde_json::to_string_pretty(self)?;
        atomic_write_private(&path, json.as_bytes())?;
        Ok(())
    }
}
