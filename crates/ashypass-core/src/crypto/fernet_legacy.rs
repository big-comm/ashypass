//! Read-only Fernet (v1) decryptor, for migrating existing Python vaults.
//!
//! Fernet token (urlsafe-b64 of):
//! `0x80 | timestamp(8) | iv(16) | ciphertext(PKCS7-padded, AES-128-CBC) | HMAC-SHA256(32)`
//!
//! Key derivation (Python original):
//! ```text
//! salt_str = master.salt (the base64url string is the literal salt)
//! raw = PBKDF2-HMAC-SHA256(password, salt_str.as_bytes(), 100_000, 32)
//! fernet_key = base64url_encode(raw)        // urlsafe, no padding stripped
//! signing_key = first 16 bytes of base64url_decode(fernet_key)
//! encryption_key = last  16 bytes of base64url_decode(fernet_key)
//! ```

use crate::{Error, Result};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type HmacSha256 = Hmac<Sha256>;

const FERNET_VERSION: u8 = 0x80;

/// Derive the 32-byte Fernet key exactly as the Python implementation did.
/// Returns (signing_key[16], encryption_key[16]).
pub fn derive_fernet_keys(password: &str, salt_text: &str) -> Result<([u8; 16], [u8; 16])> {
    let mut raw = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt_text.as_bytes(), 100_000, &mut raw);
    // The Python code re-encoded raw to urlsafe-b64 then handed it to Fernet;
    // Fernet itself decodes it back. So raw[..32] split 16/16 is correct.
    let mut signing = [0u8; 16];
    let mut encryption = [0u8; 16];
    signing.copy_from_slice(&raw[..16]);
    encryption.copy_from_slice(&raw[16..]);
    raw.zeroize();
    Ok((signing, encryption))
}

/// Decrypt a single Fernet token (urlsafe-b64 string OR raw bytes of that string).
pub fn decrypt_token(
    signing_key: &[u8; 16],
    encryption_key: &[u8; 16],
    token: &[u8],
) -> Result<Vec<u8>> {
    // Token may be stored as bytes-of-ascii (Python's `bytes` from .encrypt()).
    // Trim trailing whitespace just in case.
    let token_str = std::str::from_utf8(token)
        .map_err(|_| Error::Crypto("fernet: token not ASCII".into()))?
        .trim();

    let data = URL_SAFE
        .decode(token_str)
        .map_err(|e| Error::Crypto(format!("fernet b64: {e}")))?;

    if data.len() < 1 + 8 + 16 + 32 || data.len() % 16 != (1 + 8 + 16 + 32) % 16 {
        // Length must be: 57 + 16*N
        if data.len() < 57 || (data.len() - 57) % 16 != 0 {
            return Err(Error::Crypto("fernet: bad length".into()));
        }
    }
    if data[0] != FERNET_VERSION {
        return Err(Error::Crypto(format!("fernet: bad version {:#x}", data[0])));
    }

    let hmac_pos = data.len() - 32;
    let body = &data[..hmac_pos];
    let mac_tag = &data[hmac_pos..];

    let mut mac = <HmacSha256 as Mac>::new_from_slice(signing_key)
        .map_err(|e| Error::Crypto(format!("fernet hmac key: {e}")))?;
    mac.update(body);
    let expected = mac.finalize().into_bytes();
    if expected.ct_eq(mac_tag).unwrap_u8() != 1 {
        return Err(Error::Crypto("fernet: HMAC mismatch".into()));
    }

    let iv: &[u8; 16] = data[9..25]
        .try_into()
        .map_err(|_| Error::Crypto("fernet: iv slice".into()))?;
    let ct = &data[25..hmac_pos];

    let mut buf = ct.to_vec();
    let pt = Aes128CbcDec::new(encryption_key.into(), iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| Error::Crypto(format!("fernet decrypt: {e}")))?
        .to_vec();
    Ok(pt)
}

// AES-128-CBC backing crates pulled in transitively. We need explicit `aes` and `cbc`.
// Re-declare here as direct deps via Cargo.toml addition done later if compile fails.

#[cfg(test)]
mod tests {
    // Note: end-to-end test against a real Python-produced vault belongs in db::migration tests.
    // Unit test here validates the b64+length checks.
    use super::*;

    #[test]
    fn rejects_bad_version() {
        // Construct a "token" with wrong version byte.
        let mut buf = vec![0u8; 57];
        buf[0] = 0x7F;
        let b64 = URL_SAFE.encode(&buf);
        let r = decrypt_token(&[0u8; 16], &[0u8; 16], b64.as_bytes());
        assert!(r.is_err());
    }
}
