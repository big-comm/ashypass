//! User-facing settings persisted to `~/.config/ashypass/settings.json`.
//!
//! Mirrors the schema used by the original Python `core/config.py` so existing
//! settings files load without migration.

use crate::config::{
    settings_file, CLIPBOARD_CLEAR_SECONDS, DEFAULT_PASSWORD_LENGTH, SESSION_TIMEOUT_SECONDS,
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
    pub show_sync_badges: bool,
    pub compact_vault_list: bool,
    pub large_totp_codes: bool,
    pub lock_timeout: u64,
    pub clipboard_clear: u64,
    pub generator: GeneratorPrefs,
    pub argon2: TunedParams,
    pub audit_check_hibp: bool,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct QuickUnlockPrefs {
    pub pin_hash: String,
    pub salt: String,
    pub encrypted_key: String,
}

impl QuickUnlockPrefs {
    pub fn is_configured(&self) -> bool {
        !self.pin_hash.is_empty() && !self.salt.is_empty() && !self.encrypted_key.is_empty()
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            show_favicons: true,
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
        match fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = settings_file();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, json)?;
        Ok(())
    }
}
