//! Ashy Pass core library.
//!
//! Provides cryptography, encrypted SQLite storage, password generation,
//! TOTP (RFC 6238), CSV/Aegis/andOTP importers, Google Drive backup and
//! optional FIDO2 second-factor. UI-free; consumed by `ashypass-app`.

pub mod config;
pub mod error;
pub mod crypto;
pub mod db;
pub mod generator;
pub mod strength;
pub mod totp;
pub mod importers;
pub mod backup;
pub mod sync;
pub mod settings;
pub mod favicons;
pub mod hibp;
pub mod audit;

pub mod fido2;
pub mod keyring;

pub use error::{Error, Result};
