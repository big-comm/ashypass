//! 1Password unencrypted 1PUX export importer.
//!
//! A `.1pux` is a zip archive containing `export.data` (JSON) plus optional
//! file attachments. We only parse `export.data` and pull login items.
//!
//! Structure (1Password 8 export format, simplified):
//!
//! ```json
//! {
//!   "accounts": [{
//!     "vaults": [{
//!       "items": [{
//!         "categoryUuid": "001",          // 001 = Login
//!         "overview": { "title": "...", "url": "..." },
//!         "details": {
//!           "loginFields": [
//!             { "designation": "username", "value": "alice" },
//!             { "designation": "password", "value": "hunter2" }
//!           ],
//!           "sections": [{
//!             "fields": [{
//!               "title": "one-time password",
//!               "value": { "totp": "otpauth://..." }
//!             }]
//!           }],
//!           "notesPlain": "..."
//!         }
//!       }]
//!     }]
//!   }]
//! }
//! ```
//!
//! The format varies slightly across 1Password versions; this parser is
//! tolerant and skips items it can't make sense of.

use crate::db::vault::{NewEntry, Vault};
use crate::{Error, Result};
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct OpExport {
    #[serde(default)]
    accounts: Vec<OpAccount>,
}

#[derive(Debug, Deserialize)]
struct OpAccount {
    #[serde(default)]
    vaults: Vec<OpVault>,
}

#[derive(Debug, Deserialize)]
struct OpVault {
    #[serde(default)]
    items: Vec<OpItem>,
    #[serde(default)]
    attrs: Option<OpVaultAttrs>,
}

#[derive(Debug, Deserialize)]
struct OpVaultAttrs {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpItem {
    #[serde(rename = "categoryUuid", default)]
    category_uuid: String,
    #[serde(default)]
    overview: Option<OpOverview>,
    #[serde(default)]
    details: Option<OpDetails>,
}

#[derive(Debug, Deserialize)]
struct OpOverview {
    title: Option<String>,
    url: Option<String>,
    #[serde(default)]
    urls: Vec<OpUrl>,
}

#[derive(Debug, Deserialize)]
struct OpUrl {
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpDetails {
    #[serde(rename = "loginFields", default)]
    login_fields: Vec<OpLoginField>,
    #[serde(default)]
    sections: Vec<OpSection>,
    #[serde(rename = "notesPlain", default)]
    notes_plain: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpLoginField {
    #[serde(default)]
    designation: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpSection {
    #[serde(default)]
    fields: Vec<OpSectionField>,
}

#[derive(Debug, Deserialize)]
struct OpSectionField {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    value: Option<OpFieldValue>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OpFieldValue {
    Object(serde_json::Map<String, serde_json::Value>),
    String(String),
}

/// Open a `.1pux` file (zip) and return the parsed login items.
pub fn parse_file(path: impl AsRef<Path>) -> Result<Vec<NewEntry>> {
    let file = File::open(&path)?;
    let mut zip = zip::ZipArchive::new(file)
        .map_err(|e| Error::Other(format!("1pux: not a valid zip: {e}")))?;
    let mut data = String::new();
    let mut found = false;
    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| Error::Other(format!("1pux: zip entry: {e}")))?;
        if entry.name().ends_with("export.data") || entry.name() == "export.data" {
            entry.read_to_string(&mut data)?;
            found = true;
            break;
        }
    }
    if !found {
        return Err(Error::Other(
            "1pux: export.data not found in archive".into(),
        ));
    }
    parse_str(&data)
}

pub fn parse_str(text: &str) -> Result<Vec<NewEntry>> {
    let doc: OpExport = serde_json::from_str(text)?;
    let mut out: Vec<NewEntry> = Vec::new();
    for acc in doc.accounts {
        for vault in acc.vaults {
            let category = vault
                .attrs
                .as_ref()
                .and_then(|a| a.name.clone())
                .filter(|s| !s.is_empty());
            for item in vault.items {
                // 001 is the well-known Login category UUID. Other categories
                // (notes, identities, etc.) don't have a stable shape for us.
                if item.category_uuid != "001" {
                    continue;
                }
                let Some(details) = item.details else {
                    continue;
                };
                let (mut username, mut password) = (None::<String>, None::<String>);
                for f in details.login_fields {
                    let designation = f.designation.unwrap_or_default();
                    let name = f.name.unwrap_or_default();
                    match designation.as_str() {
                        "username" => username = f.value,
                        "password" => password = f.value,
                        _ if name.eq_ignore_ascii_case("username") => username = f.value,
                        _ if name.eq_ignore_ascii_case("password") => password = f.value,
                        _ => {}
                    }
                }
                let Some(password) = password.filter(|s| !s.is_empty()) else {
                    continue;
                };

                let totp_secret = details
                    .sections
                    .iter()
                    .flat_map(|s| s.fields.iter())
                    .find_map(|f| {
                        let title = f.title.as_deref().unwrap_or("").to_lowercase();
                        if !title.contains("otp") && title != "one-time password" {
                            return None;
                        }
                        match &f.value {
                            Some(OpFieldValue::Object(map)) => map
                                .get("totp")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string()),
                            Some(OpFieldValue::String(s)) => Some(s.clone()),
                            None => None,
                        }
                        .and_then(|raw| extract_totp_secret(&raw))
                    });

                let overview = item.overview.unwrap_or(OpOverview {
                    title: None,
                    url: None,
                    urls: Vec::new(),
                });
                let url = overview
                    .url
                    .or_else(|| overview.urls.into_iter().find_map(|u| u.url))
                    .filter(|s| !s.is_empty());

                out.push(NewEntry {
                    title: overview.title.unwrap_or_else(|| "Untitled".into()),
                    username: username.filter(|s| !s.is_empty()),
                    password,
                    notes: details.notes_plain.filter(|s| !s.is_empty()),
                    url,
                    totp_secret,
                    totp_algorithm: Some("SHA1".into()),
                    totp_digits: Some(6),
                    totp_period: Some(30),
                    category: category.clone(),
                });
            }
        }
    }
    Ok(out)
}

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
          "accounts": [{
            "vaults": [{
              "attrs": {"name": "Personal"},
              "items": [{
                "categoryUuid": "001",
                "overview": {"title": "Example", "url": "https://example.com"},
                "details": {
                  "loginFields": [
                    {"designation": "username", "value": "alice"},
                    {"designation": "password", "value": "hunter2"}
                  ],
                  "sections": [{
                    "fields": [{
                      "title": "one-time password",
                      "value": {"totp": "otpauth://totp/Ex:alice?secret=JBSWY3DPEHPK3PXP"}
                    }]
                  }],
                  "notesPlain": "the note"
                }
              }]
            }]
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
        assert_eq!(e.notes.as_deref(), Some("the note"));
        assert_eq!(e.category.as_deref(), Some("Personal"));
    }

    #[test]
    fn skips_non_login_categories() {
        let json = r#"{
          "accounts": [{
            "vaults": [{
              "items": [
                {"categoryUuid": "003", "overview": {"title": "Note"}, "details": {}},
                {"categoryUuid": "001", "overview": {"title": "L"},
                 "details": {"loginFields": [{"designation":"password","value":"p"}]}}
              ]
            }]
          }]
        }"#;
        let v = parse_str(json).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].title, "L");
    }
}
