//! Bitwarden unencrypted JSON export importer.
//!
//! Expected layout (Bitwarden 2024 web export `bitwarden_export_<ts>.json`):
//!
//! ```json
//! {
//!   "encrypted": false,
//!   "folders": [ { "id": "...", "name": "..." }, ... ],
//!   "items": [ {
//!     "type": 1, "name": "...", "notes": "...",
//!     "folderId": "...",
//!     "login": {
//!       "username": "...", "password": "...",
//!       "totp": "otpauth://...",
//!       "uris": [ { "uri": "https://..." } ]
//!     }
//!   }, ... ]
//! }
//! ```
//!
//! Encrypted exports are NOT supported — the user must export with
//! "JSON" (not "JSON (encrypted)"). We reject `encrypted == true` early.

use crate::db::vault::{NewEntry, Vault};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize)]
struct BwFolder {
    id: Option<String>,
    name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct BwUri {
    uri: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    #[serde(default)]
    uris: Vec<BwUri>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct BwItem {
    #[serde(default)]
    r#type: u8,
    name: Option<String>,
    notes: Option<String>,
    #[serde(rename = "folderId")]
    folder_id: Option<String>,
    login: Option<BwLogin>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct BwExport {
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    folders: Vec<BwFolder>,
    #[serde(default)]
    items: Vec<BwItem>,
}

/// Parse a Bitwarden JSON export. Only `type == 1` (login items) carry
/// passwords; secure notes / cards / identities are skipped because we have
/// no equivalent storage.
pub fn parse_file(path: impl AsRef<Path>) -> Result<Vec<NewEntry>> {
    let text = fs::read_to_string(&path)?;
    parse_str(&text)
}

pub fn parse_str(text: &str) -> Result<Vec<NewEntry>> {
    let doc: BwExport = serde_json::from_str(text)?;
    if doc.encrypted {
        return Err(Error::Other(
            "encrypted Bitwarden exports are not supported — export as unencrypted JSON".into(),
        ));
    }
    let folder_names: HashMap<String, String> = doc
        .folders
        .iter()
        .filter_map(|f| match (f.id.clone(), f.name.clone()) {
            (Some(id), Some(name)) => Some((id, name)),
            _ => None,
        })
        .collect();

    let mut out: Vec<NewEntry> = Vec::new();
    for item in doc.items {
        if item.r#type != 1 {
            continue;
        }
        let login = match item.login {
            Some(l) => l,
            None => continue,
        };
        let password = login.password.clone().unwrap_or_default();
        if password.is_empty() {
            continue;
        }
        let url = login.uris.into_iter().find_map(|u| u.uri).filter(|s| !s.is_empty());
        let totp_secret = login.totp.as_deref().and_then(extract_totp_secret);
        let category = item
            .folder_id
            .as_ref()
            .and_then(|fid| folder_names.get(fid).cloned());
        out.push(NewEntry {
            title: item.name.unwrap_or_else(|| "Untitled".into()),
            username: login.username.filter(|s| !s.is_empty()),
            password,
            notes: item.notes.filter(|s| !s.is_empty()),
            url,
            totp_secret,
            totp_algorithm: Some("SHA1".into()),
            totp_digits: Some(6),
            totp_period: Some(30),
            category,
        });
    }
    Ok(out)
}

/// Pull the `secret` parameter out of an otpauth URI, or accept a raw base32
/// secret if the field doesn't look like a URI.
fn extract_totp_secret(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if s.starts_with("otpauth://") {
        let q = s.split_once('?').map(|x| x.1).unwrap_or("");
        for kv in q.split('&') {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            if k == "secret" {
                return Some(v.to_string());
            }
        }
        return None;
    }
    // Bare base32 string
    Some(s.to_string())
}

pub fn import_into_vault(vault: &Vault, path: impl AsRef<Path>) -> Result<usize> {
    let entries = parse_file(path)?;
    let mut imported = 0;
    for e in entries {
        if vault.add(e).is_ok() {
            imported += 1;
        }
    }
    Ok(imported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_login() {
        let json = r#"{
          "encrypted": false,
          "folders": [{"id": "f1", "name": "Work"}],
          "items": [{
            "type": 1,
            "name": "Example",
            "folderId": "f1",
            "login": {
              "username": "alice",
              "password": "hunter2",
              "totp": "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example",
              "uris": [{"uri": "https://example.com"}]
            }
          }]
        }"#;
        let v = parse_str(json).unwrap();
        assert_eq!(v.len(), 1);
        let e = &v[0];
        assert_eq!(e.title, "Example");
        assert_eq!(e.username.as_deref(), Some("alice"));
        assert_eq!(e.password, "hunter2");
        assert_eq!(e.url.as_deref(), Some("https://example.com"));
        assert_eq!(e.totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(e.category.as_deref(), Some("Work"));
    }

    #[test]
    fn rejects_encrypted() {
        let json = r#"{"encrypted": true, "items": []}"#;
        assert!(parse_str(json).is_err());
    }

    #[test]
    fn skips_non_login_types() {
        let json = r#"{
          "encrypted": false,
          "items": [
            {"type": 2, "name": "Secure note"},
            {"type": 3, "name": "Card"},
            {"type": 1, "name": "Login", "login": {"password": "p"}}
          ]
        }"#;
        let v = parse_str(json).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].title, "Login");
    }

    #[test]
    fn raw_base32_totp_accepted() {
        let json = r#"{"encrypted": false, "items": [
            {"type": 1, "name": "X", "login": {"password": "p", "totp": "JBSWY3DPEHPK3PXP"}}
        ]}"#;
        let v = parse_str(json).unwrap();
        assert_eq!(v[0].totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }
}
