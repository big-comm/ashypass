//! Ashy Pass core library.
//!
//! Provides cryptography, encrypted SQLite storage, password generation,
//! TOTP (RFC 6238), CSV/Aegis/andOTP importers, Google Drive backup and
//! optional FIDO2 second-factor. UI-free; consumed by `ashypass-app`.

pub mod audit;
pub mod backup;
pub mod brand_icons;
pub mod browser_profiles;
pub mod config;
pub mod crypto;
pub mod db;
pub mod duplicates;
pub mod error;
pub mod favicons;
pub mod generator;
pub mod hibp;
pub mod importers;
pub mod quick_unlock;
pub mod server_url;
pub mod settings;
pub mod strength;
pub mod sync;
pub mod totp;
pub mod url_match;

pub mod fido2;
#[cfg(target_os = "linux")]
pub mod keyring;
#[cfg(not(target_os = "linux"))]
#[path = "keyring_unavailable.rs"]
pub mod keyring;

pub use error::{Error, Result};
