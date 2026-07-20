//! Cryptographic primitives.
//!
//! - `argon2_kdf`: Argon2id master verification + key derivation.
//! - `aes_gcm_v2`: AES-256-GCM authenticated encryption (current).
//! - `fernet_legacy`: read-only Fernet (AES-128-CBC + HMAC-SHA256) for v1 migration.

pub mod aes_gcm_v2;
pub mod argon2_kdf;
pub mod autotune;
pub mod fernet_legacy;
pub mod key;

pub use key::DerivedKey;
