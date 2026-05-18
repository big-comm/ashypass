//! Ashy Pass core library.
//!
//! Provides cryptography, encrypted SQLite storage, password generation,
//! TOTP (RFC 6238), CSV/Aegis/andOTP importers, Google Drive backup and
//! optional FIDO2 second-factor. UI-free; consumed by `ashypass-app`.

pub mod audit;
pub mod backup;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod favicons;
pub mod generator;
pub mod hibp;
pub mod importers;
pub mod settings;
pub mod strength;
pub mod sync;
pub mod totp;

pub mod fido2;
pub mod keyring;

pub use error::{Error, Result};
