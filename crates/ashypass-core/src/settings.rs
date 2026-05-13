//! User-facing settings persisted to `~/.config/ashypass/settings.json`.
//!
//! Mirrors the schema used by the original Python `core/config.py` so existing
//! settings files load without migration.

use crate::config::{settings_file, CLIPBOARD_CLEAR_SECONDS, DEFAULT_PASSWORD_LENGTH, SESSION_TIMEOUT_SECONDS};
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
    pub lock_timeout: u64,
    pub clipboard_clear: u64,
    pub generator: GeneratorPrefs,
    pub argon2: TunedParams,
    /// Trash retention in days. Entries deleted longer ago are purged on app
    /// start. 0 disables the trash entirely (deletes are immediate).
    pub trash_retention_days: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            show_favicons: true,
            lock_timeout: SESSION_TIMEOUT_SECONDS,
            clipboard_clear: CLIPBOARD_CLEAR_SECONDS,
            generator: GeneratorPrefs::default(),
            argon2: TunedParams::default(),
            trash_retention_days: 30,
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
