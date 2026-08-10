//! Argon2id verification + Argon2id-based key derivation.

use super::key::DerivedKey;
use crate::{Error, Result};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};

/// Matches the original Python parameters in CRYPTO_SPEC.md.
fn params() -> Params {
    // t_cost=3, m_cost=65536 KiB, parallelism=4, output=32B
    Params::new(65536, 3, 4, Some(32)).expect("valid argon2 params")
}

fn argon2() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params())
}

/// Returns the Argon2 instance configured by user-tuned params from settings,
/// falling back to defaults if unreadable. Used for new master hashes so each
/// install can pick costs appropriate to its hardware.
fn argon2_tuned() -> Argon2<'static> {
    let s = crate::settings::Settings::load();
    let p = s.argon2.to_argon2_params().unwrap_or_else(|_| params());
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
}

/// Hash a master password to PHC-format string. Stored in `master.password_hash`.
/// Uses tuned parameters from settings so PHC string records the actual costs
/// used; verification reads them back from the hash regardless of current tune.
pub fn hash_master(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut rand::thread_rng());
    let hash = argon2_tuned()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| Error::Argon2(e.to_string()))?
        .to_string();
    Ok(hash)
}

/// Verify a master password against a PHC-format hash.
pub fn verify_master(password: &str, phc_hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(phc_hash).map_err(|e| Error::Argon2(e.to_string()))?;
    Ok(argon2()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// Deliberately expensive parameters for key material wrapped by a *short*
/// secret — today only the quick-unlock PIN.
///
/// A 6-digit PIN is ~20 bits of entropy, so an attacker who exfiltrates the
/// stored blob is limited only by the cost of one derivation. At 128 MiB and
/// 6 passes each guess costs several hundred milliseconds of memory-hard work,
/// which is the difference between minutes and weeks for an exhaustive search.
fn params_pin() -> Params {
    Params::new(131072, 6, 4, Some(32)).expect("valid argon2 params")
}

/// Derive a wrapping key from a short secret (PIN). See `params_pin`.
pub fn derive_key_pin(pin: &str, salt: &[u8]) -> Result<DerivedKey> {
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params_pin())
        .hash_password_into(pin.as_bytes(), salt, &mut out)
        .map_err(|e| Error::Argon2(e.to_string()))?;
    Ok(DerivedKey::new(out))
}

/// Derive a 32-byte encryption key from master + per-vault salt, using Argon2id.
///
/// This is the v2 KDF. v1 used PBKDF2-HMAC-SHA256(100k); the legacy code path
/// remains in `fernet_legacy` for backward read.
pub fn derive_key_v2(password: &str, salt: &[u8]) -> Result<DerivedKey> {
    let mut out = [0u8; 32];
    argon2()
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| Error::Argon2(e.to_string()))?;
    Ok(DerivedKey::new(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let phc = hash_master("correct horse battery staple").unwrap();
        assert!(verify_master("correct horse battery staple", &phc).unwrap());
        assert!(!verify_master("wrong", &phc).unwrap());
    }

    #[test]
    fn derive_key_is_deterministic() {
        let salt = b"some-fixed-salt-of-16+_bytes!";
        let k1 = derive_key_v2("hunter2", salt).unwrap();
        let k2 = derive_key_v2("hunter2", salt).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn derive_key_changes_with_salt() {
        let k1 = derive_key_v2("hunter2", b"salt-aaaaaaaaaaaaaaaa").unwrap();
        let k2 = derive_key_v2("hunter2", b"salt-bbbbbbbbbbbbbbbb").unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }
}
