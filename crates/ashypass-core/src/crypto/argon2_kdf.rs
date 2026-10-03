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
    let p = s
        .argon2
        .to_argon2_params()
        .ok()
        // Never write a hash that `verify_master` would later refuse.
        .filter(|p| {
            (1..=MAX_PHC_T_COST).contains(&p.t_cost())
                && (1..=MAX_PHC_P_COST).contains(&p.p_cost())
                && p.m_cost() >= 8 * p.p_cost()
                && p.m_cost() <= MAX_PHC_M_COST_KIB
        })
        .unwrap_or_else(params);
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

/// Upper bounds accepted for Argon2 parameters read back from a stored PHC
/// string. They match the `.ashy` importer limits and comfortably cover every
/// value `autotune` can produce (m <= 1 GiB, t <= 12, p <= 8).
pub const MAX_PHC_T_COST: u32 = 12;
pub const MAX_PHC_M_COST_KIB: u32 = 1_048_576;
pub const MAX_PHC_P_COST: u32 = 16;

/// Reject PHC parameters that would make a single verification consume an
/// unreasonable amount of memory or time. The hash lives in the vault
/// database (or the keyring), which may arrive through sync; a tampered
/// `m=4194304` must not be able to OOM the app on unlock.
fn check_phc_params(parsed: &PasswordHash<'_>) -> Result<()> {
    let params = Params::try_from(parsed).map_err(|e| Error::Argon2(e.to_string()))?;
    let (m, t, p) = (params.m_cost(), params.t_cost(), params.p_cost());
    if t == 0
        || t > MAX_PHC_T_COST
        || p == 0
        || p > MAX_PHC_P_COST
        || m < 8 * p
        || m > MAX_PHC_M_COST_KIB
    {
        return Err(Error::Argon2(format!(
            "stored hash uses out-of-range parameters (m={m}, t={t}, p={p})"
        )));
    }
    Ok(())
}

/// Verify a master password against a PHC-format hash.
///
/// The cost parameters embedded in the hash are bounds-checked first; an
/// out-of-range hash is an error, never a silent `false`.
pub fn verify_master(password: &str, phc_hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(phc_hash).map_err(|e| Error::Argon2(e.to_string()))?;
    check_phc_params(&parsed)?;
    Ok(argon2()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// Hash a short secret with the fixed default parameters (never the tuned
/// ones). Used for the in-memory session PIN verifier, which is never
/// written to disk and must stay cheap enough to check on every quick unlock.
pub fn hash_session_secret(secret: &str) -> Result<String> {
    let salt = SaltString::generate(&mut rand::thread_rng());
    let hash = argon2()
        .hash_password(secret.as_bytes(), &salt)
        .map_err(|e| Error::Argon2(e.to_string()))?
        .to_string();
    Ok(hash)
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
    fn session_secret_hash_verifies() {
        let phc = hash_session_secret("123456").unwrap();
        assert!(phc.contains("m=65536,t=3,p=4"));
        assert!(verify_master("123456", &phc).unwrap());
        assert!(!verify_master("654321", &phc).unwrap());
    }

    /// A syntactically valid PHC string; only its header is inspected before
    /// rejection, so absurd parameters never reach Argon2.
    fn phc_with_params(m: u32, t: u32, p: u32) -> String {
        format!(
            "$argon2id$v=19$m={m},t={t},p={p}$c29tZXNhbHRzb21lc2FsdA\
             $YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXphYmNkZWY"
        )
    }

    #[test]
    fn verify_rejects_out_of_range_phc_params() {
        for (m, t, p) in [
            (MAX_PHC_M_COST_KIB + 1, 3, 4),
            (4_194_304, 3, 4),
            (65536, MAX_PHC_T_COST + 1, 4),
            (65536, 3, MAX_PHC_P_COST + 1),
        ] {
            let phc = phc_with_params(m, t, p);
            assert!(
                matches!(verify_master("x", &phc), Err(Error::Argon2(_))),
                "m={m} t={t} p={p} must be rejected"
            );
        }
    }

    #[test]
    fn verify_accepts_in_range_phc_params() {
        // Python-era (argon2-cffi) and default hashes must keep verifying.
        let salt = SaltString::generate(&mut rand::thread_rng());
        for (m, t, p) in [(65536, 3, 4), (102400, 2, 8), (8 * 16, 1, 16)] {
            let argon = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(m, t, p, Some(32)).unwrap(),
            );
            let phc = argon.hash_password(b"secret", &salt).unwrap().to_string();
            assert!(verify_master("secret", &phc).unwrap());
            assert!(!verify_master("other", &phc).unwrap());
        }
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
