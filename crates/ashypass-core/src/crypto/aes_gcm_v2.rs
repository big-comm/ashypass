//! AES-256-GCM authenticated encryption (crypto_version = 2).
//!
//! Ciphertext layout (stored verbatim in BLOB columns):
//!
//! ```text
//! | 1 byte version=2 | 12 bytes nonce | ciphertext | 16 bytes GCM tag |
//! ```
//!
//! Compared to Fernet (v1) this is:
//! - AEAD in a single step (no separate HMAC)
//! - AES-256 (vs AES-128)
//! - 12-byte nonce (vs 16-byte IV)
//! - smaller token, faster

use crate::{Error, Result};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};

use super::key::DerivedKey;

pub const VERSION_BYTE: u8 = 0x02;
const NONCE_LEN: usize = 12;

pub fn encrypt(key: &DerivedKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| Error::Crypto(format!("aes-gcm encrypt: {e}")))?;

    let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    out.push(VERSION_BYTE);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt(key: &DerivedKey, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 1 + NONCE_LEN + 16 {
        return Err(Error::Crypto("v2 blob too short".into()));
    }
    if blob[0] != VERSION_BYTE {
        return Err(Error::Crypto(format!(
            "unexpected version byte: {:#x}",
            blob[0]
        )));
    }
    let nonce = Nonce::from_slice(&blob[1..1 + NONCE_LEN]);
    let ct = &blob[1 + NONCE_LEN..];
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let pt = cipher
        .decrypt(nonce, ct)
        .map_err(|_| Error::Crypto("aes-gcm decrypt: authentication failed".into()))?;
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k() -> DerivedKey {
        DerivedKey::new([0x42u8; 32])
    }

    #[test]
    fn roundtrip() {
        let ct = encrypt(&k(), b"hello world").unwrap();
        let pt = decrypt(&k(), &ct).unwrap();
        assert_eq!(pt, b"hello world");
    }

    #[test]
    fn tamper_detected() {
        let mut ct = encrypt(&k(), b"hello").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(decrypt(&k(), &ct).is_err());
    }

    #[test]
    fn nonce_uniqueness() {
        let a = encrypt(&k(), b"x").unwrap();
        let b = encrypt(&k(), b"x").unwrap();
        assert_ne!(a, b, "two encrypts of same plaintext must differ (nonce)");
    }

    #[test]
    fn wrong_key_fails() {
        let ct = encrypt(&k(), b"secret").unwrap();
        let other = DerivedKey::new([0x99u8; 32]);
        assert!(decrypt(&other, &ct).is_err());
    }

    #[test]
    fn version_byte_checked() {
        let mut ct = encrypt(&k(), b"x").unwrap();
        ct[0] = 0x01;
        assert!(decrypt(&k(), &ct).is_err());
    }
}
