//! FIDO2 / YubiKey 2nd-factor support.
//!
//! Persisted config: up to 2 credentials registered against the local relying
//! party `ashypass.local`. Each slot stores its `credential_id` and a random
//! `salt`; at unlock time we run a CTAP2 `getAssertion` with the `hmac-secret`
//! extension on that salt, and XOR the result into the Argon2-derived vault
//! key. A BIP39 backup phrase doubles as fallback when no token is around.
//!
//! Build with `--features fido2` to enable real CTAP2 calls; without the
//! feature, register/assert return a clear error so callers can fall back.

use crate::config::fido2_file;
use crate::{Error, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;

pub const RP_ID: &str = "ashypass.local";
pub const RP_NAME: &str = "Ashy Pass";
pub const MAX_SLOTS: usize = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2Slot {
    pub credential_id: Vec<u8>,
    pub salt: [u8; 32],
    pub registered_at: i64,
    pub nickname: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Fido2Config {
    pub enabled: bool,
    pub slots: Vec<Fido2Slot>,
    /// Argon2-style PHC string of the backup phrase, so it can be verified
    /// without storing the phrase itself.
    pub backup_code_hash: Option<String>,
}

impl Fido2Config {
    pub fn load() -> Self {
        let path = fido2_file();
        match fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = fido2_file();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn has_slot_capacity(&self) -> bool {
        self.slots.len() < MAX_SLOTS
    }
}

/// 12-word BIP39 phrase. Returned once to the user; we only keep its hash.
pub fn generate_backup_phrase() -> Result<String> {
    let mut entropy = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut entropy);
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
        .map_err(|e| Error::Other(format!("bip39: {e}")))?;
    Ok(mnemonic.to_string())
}

pub fn hash_backup_phrase(phrase: &str) -> Result<String> {
    crate::crypto::argon2_kdf::hash_master(phrase.trim())
}

pub fn verify_backup_phrase(phrase: &str, stored: &str) -> Result<bool> {
    crate::crypto::argon2_kdf::verify_master(phrase.trim(), stored)
}

/// Random 32-byte salt used as the input to CTAP2 hmac-secret.
pub fn fresh_salt() -> [u8; 32] {
    let mut s = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

/// Derive a 32-byte wrapping key from an hmac-secret response. Returned key
/// is meant to be XORed against the Argon2-derived vault key so that both
/// (password) AND (token OR backup-phrase) are required to unlock.
pub fn wrap_key_from_hmac(hmac_secret: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"ashypass-fido2-wrap");
    h.update(hmac_secret);
    let out = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&out);
    k
}

// ---------------------------------------------------------------------------
// CTAP2 helpers.
//
// The real CTAP2 wire calls live behind the `fido2` feature so the default
// build doesn't pull in HID dependencies. The current implementation of the
// feature path is intentionally a stub returning a descriptive error — the
// concrete `ctap-hid-fido2` API surface changes between minor versions and we
// can't validate without a physical authenticator on the build host. The
// storage, backup-phrase and UI flow are wired so that turning this on later
// is a localized change to two functions.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Assertion {
    pub hmac_secret: Vec<u8>,
}

pub fn register(_pin: Option<&str>, _nickname: Option<String>) -> Result<Fido2Slot> {
    Err(Error::Other(
        "FIDO2 hardware registration is not yet wired in this build. \
         Backup phrase fallback is available."
            .into(),
    ))
}

pub fn assert_any(_pin: Option<&str>, _config: &Fido2Config) -> Result<Assertion> {
    Err(Error::Other(
        "FIDO2 hardware assertion is not yet wired in this build.".into(),
    ))
}

/// Decode the saved credential id for display.
pub fn slot_short(slot: &Fido2Slot) -> String {
    let s = B64.encode(&slot.credential_id);
    if s.len() > 12 {
        format!("{}…", &s[..12])
    } else {
        s
    }
}
