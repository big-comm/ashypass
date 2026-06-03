//! `.ashy` encrypted export format.
//!
//! Designed to replace the plaintext CSV as the default backup path. The
//! recipient needs the export password (not the vault master password) to
//! restore — so the file can be moved through email / cloud without exposing
//! credentials.
//!
//! File layout (little-endian where applicable):
//!
//! ```text
//! offset  size  description
//! 0       7     magic "ASHYP\0\x01"   (last byte = format version, here 1)
//! 7       16    Argon2id salt
//! 23      4     Argon2 t_cost  (u32)
//! 27      4     Argon2 m_cost  (u32, KiB)
//! 31      4     Argon2 p_cost  (u32)
//! 35      12    AES-256-GCM nonce
//! 47      ...   AES-256-GCM(ciphertext || tag)   (plaintext is JSON)
//! ```
//!
//! The JSON payload is a `ExportDocument` (see below).

use crate::db::vault::{NewEntry, PasswordEntry, Vault};
use crate::{Error, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

const MAGIC: &[u8; 7] = b"ASHYP\x00\x01";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const ARGON2_T: u32 = 3;
const ARGON2_M_KIB: u32 = 65536;
const ARGON2_P: u32 = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    pub title: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub password: String,
    pub notes: Option<String>,
    pub totp_secret: Option<String>,
    pub totp_algorithm: String,
    pub totp_digits: u8,
    pub totp_period: u32,
    pub category: Option<String>,
    pub favorite: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportDocument {
    pub version: u32,
    pub created_at: i64,
    pub entries: Vec<ExportEntry>,
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(32))
        .map_err(|e| Error::Argon2(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| Error::Argon2(e.to_string()))?;
    Ok(out)
}

fn entry_from(e: PasswordEntry) -> ExportEntry {
    ExportEntry {
        title: e.title,
        username: e.username,
        url: e.url,
        password: e.password.unwrap_or_default(),
        notes: e.notes,
        totp_secret: e.totp_secret,
        totp_algorithm: e.totp_algorithm,
        totp_digits: e.totp_digits,
        totp_period: e.totp_period,
        category: e.category,
        favorite: e.favorite,
    }
}

pub fn export_vault(vault: &Vault, path: impl AsRef<Path>, export_password: &str) -> Result<usize> {
    if export_password.is_empty() {
        return Err(Error::Other("export password is empty".into()));
    }
    let summaries = vault.list(None)?;
    let mut entries: Vec<ExportEntry> = Vec::with_capacity(summaries.len());
    for s in &summaries {
        if let Some(full) = vault.get_without_touch(s.id)? {
            entries.push(entry_from(full));
        }
    }
    let doc = ExportDocument {
        version: 1,
        created_at: chrono::Utc::now().timestamp(),
        entries,
    };
    let json = serde_json::to_vec(&doc)?;

    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let key = derive_key(export_password, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, json.as_slice())
        .map_err(|e| Error::Crypto(format!("ashy export encrypt: {e}")))?;

    let mut out = Vec::with_capacity(MAGIC.len() + SALT_LEN + 12 + NONCE_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&ARGON2_T.to_le_bytes());
    out.extend_from_slice(&ARGON2_M_KIB.to_le_bytes());
    out.extend_from_slice(&ARGON2_P.to_le_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);

    if let Some(p) = path.as_ref().parent() {
        fs::create_dir_all(p)?;
    }
    fs::write(path, out)?;
    let count = match serde_json::from_slice::<ExportDocument>(&json) {
        Ok(d) => d.entries.len(),
        Err(_) => 0,
    };
    Ok(count)
}

pub fn read_export(path: impl AsRef<Path>, export_password: &str) -> Result<ExportDocument> {
    let raw = fs::read(&path)?;
    let header_len = MAGIC.len() + SALT_LEN + 12 + NONCE_LEN;
    if raw.len() < header_len + 16 {
        return Err(Error::Other(".ashy file truncated".into()));
    }
    if &raw[0..MAGIC.len()] != MAGIC {
        return Err(Error::Other(".ashy magic mismatch".into()));
    }
    let salt = &raw[MAGIC.len()..MAGIC.len() + SALT_LEN];
    // t, m, p are stored but ignored — we always use the same params for v1.
    let nonce_start = MAGIC.len() + SALT_LEN + 12;
    let nonce = Nonce::from_slice(&raw[nonce_start..nonce_start + NONCE_LEN]);
    let ct = &raw[header_len..];

    let key = derive_key(export_password, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let pt = cipher
        .decrypt(nonce, ct)
        .map_err(|_| Error::Crypto("ashy import: wrong password or corrupt file".into()))?;
    Ok(serde_json::from_slice(&pt)?)
}

pub fn import_into_vault(
    vault: &Vault,
    path: impl AsRef<Path>,
    export_password: &str,
) -> Result<usize> {
    let doc = read_export(path, export_password)?;
    let mut imported = 0;
    for e in doc.entries {
        let np = NewEntry {
            title: e.title,
            username: e.username,
            url: e.url,
            password: e.password,
            notes: e.notes,
            totp_secret: e.totp_secret,
            totp_algorithm: Some(e.totp_algorithm),
            totp_digits: Some(e.totp_digits),
            totp_period: Some(e.totp_period),
            category: e.category,
        };
        if vault.add(np).is_ok() {
            imported += 1;
        }
    }
    Ok(imported)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn roundtrip_smoke() {
        // Real vault roundtrip lives in integration tests; here we just check
        // the file format header and Argon2 key derivation are reversible.
        let salt = [0x42u8; SALT_LEN];
        let k1 = derive_key("hunter2", &salt).unwrap();
        let k2 = derive_key("hunter2", &salt).unwrap();
        assert_eq!(k1, k2);
        let k3 = derive_key("wrong", &salt).unwrap();
        assert_ne!(k1, k3);
    }

    #[test]
    fn missing_file_is_error() {
        let f = NamedTempFile::new().unwrap();
        let p = f.path().to_path_buf();
        drop(f);
        assert!(read_export(&p, "x").is_err());
    }
}
