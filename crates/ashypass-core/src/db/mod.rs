//! Encrypted SQLite storage.
//!
//! Schema v2 — adds `master.crypto_version` to distinguish AES-GCM (v2) from
//! the legacy Fernet (v1) imported from Python builds.

pub mod migration;
pub mod schema;
pub mod vault;

pub use vault::{NewEntry, PasswordEntry, UpdateEntry, Vault};
