//! Encrypted SQLite storage.
//!
//! Schema v2 — adds `master.crypto_version` to distinguish AES-GCM (v2) from
//! the legacy Fernet (v1) imported from Python builds.

pub mod key_check;
pub mod migration;
pub mod schema;
pub mod vault;

pub use vault::{
    derive_quick_unlock_key, derive_unlock_key, NewEntry, PasswordEntry, UnlockInputs, UpdateEntry,
    Vault,
};
