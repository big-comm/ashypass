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
    Argon2::new(Algorithm::Argon2id, Version::V0x13, tuned_params())
}

/// The auto-tuned parameters from settings, within the bounds every reader
/// accepts; the fixed defaults when unset or out of range.
pub fn tuned_params() -> Params {
    crate::settings::Settings::load()
        .argon2
        .to_argon2_params()
        .ok()
        // Never write a hash or salt that a later unlock would refuse.
        .filter(|p| params_in_bounds(p.m_cost(), p.t_cost(), p.p_cost()))
        .unwrap_or_else(params)
}

fn params_in_bounds(m: u32, t: u32, p: u32) -> bool {
    (1..=MAX_PHC_T_COST).contains(&t)
        && (1..=MAX_PHC_P_COST).contains(&p)
        && m >= 8 * p
        && m <= MAX_PHC_M_COST_KIB
}

/// Prefix of a master salt that carries its own Argon2 parameters (vault
/// format 3): `v3$m=<KiB>,t=<passes>,p=<lanes>$<random base64url>`.
///
/// A plain salt (format 2) uses the fixed defaults. Keeping the costs in the
/// salt means an older version that rewrites the master row (a password
/// change through its PIN unlock) writes a plain salt again, which this code
/// still reads correctly.
const STRONG_SALT_PREFIX: &str = "v3$";

/// Prefix of a master hash in format 3. Older versions cannot parse it, so
/// they refuse the master password instead of deriving the wrong key and
/// writing entries nobody could read.
pub const STRONG_HASH_PREFIX: &str = "ashyv3$";

/// A new salt for format 3 with `params` and `random` (base64url text).
pub fn strong_salt(params: &Params, random: &str) -> String {
    format!(
        "{STRONG_SALT_PREFIX}m={},t={},p={}${random}",
        params.m_cost(),
        params.t_cost(),
        params.p_cost()
    )
}

/// Whether `salt` is a format 3 salt (tuned costs for the vault key).
pub fn is_strong_salt(salt: &str) -> bool {
    salt.starts_with(STRONG_SALT_PREFIX)
}

fn salt_params(salt: &str) -> Result<Option<Params>> {
    let Some(rest) = salt.strip_prefix(STRONG_SALT_PREFIX) else {
        return Ok(None);
    };
    let bad = || Error::Argon2("malformed vault salt".into());
    let (costs, random) = rest.split_once('$').ok_or_else(bad)?;
    if random.is_empty() {
        return Err(bad());
    }
    let (mut m, mut t, mut p) = (None, None, None);
    for part in costs.split(',') {
        let (name, value) = part.split_once('=').ok_or_else(bad)?;
        let value: u32 = value.parse().map_err(|_| bad())?;
        match name {
            "m" => m = Some(value),
            "t" => t = Some(value),
            "p" => p = Some(value),
            _ => return Err(bad()),
        }
    }
    let (m, t, p) = (m.ok_or_else(bad)?, t.ok_or_else(bad)?, p.ok_or_else(bad)?);
    // The salt arrives with the database (restore, sync): a tampered cost
    // must not be able to exhaust memory on unlock.
    if !params_in_bounds(m, t, p) {
        return Err(Error::Argon2(format!(
            "vault salt uses out-of-range parameters (m={m}, t={t}, p={p})"
        )));
    }
    Params::new(m, t, p, Some(32))
        .map(Some)
        .map_err(|e| Error::Argon2(e.to_string()))
}

/// Derive the vault key for the master `salt` text: the costs in a format 3
/// salt, the fixed defaults otherwise. The whole salt text is the Argon2
/// salt, as in format 2.
pub fn derive_vault_key(password: &str, salt: &str) -> Result<DerivedKey> {
    match salt_params(salt)? {
        None => derive_key_v2(password, salt.as_bytes()),
        Some(params) => {
            let mut out = [0u8; 32];
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(password.as_bytes(), salt.as_bytes(), &mut out)
                .map_err(|e| Error::Argon2(e.to_string()))?;
            let key = DerivedKey::new(out);
            zeroize::Zeroize::zeroize(&mut out);
            Ok(key)
        }
    }
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
    let phc_hash = phc_hash
        .strip_prefix(STRONG_HASH_PREFIX)
        .unwrap_or(phc_hash);
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
    fn strong_salts_carry_their_costs() {
        let params = Params::new(8 * 1024, 1, 1, Some(32)).unwrap();
        let salt = strong_salt(&params, "c2FsdHNhbHRzYWx0");
        assert!(is_strong_salt(&salt));
        let parsed = salt_params(&salt).unwrap().unwrap();
        assert_eq!(
            (parsed.m_cost(), parsed.t_cost(), parsed.p_cost()),
            (8 * 1024, 1, 1)
        );
        // Plain salts keep the fixed defaults.
        assert!(salt_params("c2FsdHNhbHRzYWx0").unwrap().is_none());
        // Tampered or malformed costs are refused, never used.
        assert!(salt_params("v3$m=4194304,t=1,p=1$abc").is_err());
        assert!(salt_params("v3$m=8192,t=1$abc").is_err());
        assert!(salt_params("v3$m=8192,t=1,p=1$").is_err());
        // Different costs give different keys for the same password.
        let a = derive_vault_key("pw", &salt).unwrap();
        let b = derive_vault_key(
            "pw",
            &strong_salt(
                &Params::new(8 * 1024, 2, 1, Some(32)).unwrap(),
                "c2FsdHNhbHRzYWx0",
            ),
        )
        .unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn prefixed_hashes_verify() {
        let hash = hash_session_secret("secret").unwrap();
        let strong = format!("{STRONG_HASH_PREFIX}{hash}");
        assert!(verify_master("secret", &strong).unwrap());
        assert!(!verify_master("other", &strong).unwrap());
        // What an older version does with it: the PHC parser refuses it.
        assert!(PasswordHash::new(&strong).is_err());
    }

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
