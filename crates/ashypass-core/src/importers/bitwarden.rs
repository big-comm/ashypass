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
//!
//! Logins map to entries. Secure notes, cards, identities and SSH keys have
//! no dedicated storage, so they are imported as entries whose (encrypted)
//! notes hold every field — nothing is dropped. Custom fields, extra URIs and
//! password history are preserved as well.

use crate::db::vault::{NewEntry, Vault};
use crate::importers::otp;
use crate::importers::report::{self, ImportCandidate, ImportPreview, ImportReport, ParsedImport};
use crate::{Error, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
struct BwFolder {
    id: Option<String>,
    name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct BwUri {
    uri: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    #[serde(default)]
    uris: Option<Vec<BwUri>>,
}

#[derive(Debug, Clone, Deserialize)]
struct BwField {
    name: Option<String>,
    value: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct BwHistory {
    password: Option<String>,
    #[serde(rename = "lastUsedDate")]
    last_used_date: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct BwItem {
    #[serde(default)]
    r#type: u8,
    name: Option<String>,
    notes: Option<String>,
    #[serde(rename = "folderId")]
    folder_id: Option<String>,
    #[serde(default)]
    favorite: bool,
    login: Option<BwLogin>,
    card: Option<serde_json::Map<String, serde_json::Value>>,
    identity: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "sshKey")]
    ssh_key: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    fields: Option<Vec<BwField>>,
    #[serde(rename = "passwordHistory", default)]
    password_history: Option<Vec<BwHistory>>,
}

#[derive(Debug, Clone, Deserialize)]
struct BwExport {
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    folders: Vec<BwFolder>,
    #[serde(default)]
    items: Vec<BwItem>,
}

/// Parse a Bitwarden JSON export without touching the vault.
pub fn parse_file(path: impl AsRef<Path>) -> Result<ParsedImport> {
    parse_str(&super::read_text_limited(path)?)
}

pub fn parse_str(text: &str) -> Result<ParsedImport> {
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

    let mut out = ParsedImport::default();
    for item in doc.items {
        let title = item
            .name
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "Untitled".into());
        let mut entry = NewEntry {
            title: title.clone(),
            notes: item.notes.clone().filter(|s| !s.is_empty()),
            category: item
                .folder_id
                .as_ref()
                .and_then(|fid| folder_names.get(fid).cloned()),
            ..NewEntry::default()
        };
        let mut history = Vec::new();
        match item.r#type {
            1 => {
                let login = item.login.clone().unwrap_or(BwLogin {
                    username: None,
                    password: None,
                    totp: None,
                    uris: None,
                });
                entry.username = login.username.filter(|s| !s.is_empty());
                entry.password = login.password.unwrap_or_default();
                let mut uris = login
                    .uris
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|u| u.uri)
                    .filter(|s| !s.trim().is_empty());
                entry.url = uris.next();
                let extra: Vec<String> = uris.collect();
                if !extra.is_empty() {
                    otp::append_note(
                        &mut entry,
                        &format!("Additional URLs:\n{}", extra.join("\n")),
                    );
                }
                let field = otp::parse_field(login.totp.as_deref().unwrap_or_default());
                otp::attach(&mut entry, field, &mut out.warnings);
                for old in item.password_history.clone().unwrap_or_default() {
                    if let Some(password) = old.password.filter(|p| !p.is_empty()) {
                        let changed_at = old
                            .last_used_date
                            .as_deref()
                            .and_then(|d| chrono::DateTime::parse_from_rfc3339(d).ok())
                            .map(|d| d.timestamp());
                        history.push((password, changed_at));
                    }
                }
            }
            2 => {}
            3 => {
                append_section(&mut entry, "Card", item.card.as_ref(), CARD_LABELS);
                out.warnings.push(report::ImportIssue::new(
                    &title,
                    "card details stored in notes",
                ));
            }
            4 => {
                append_section(&mut entry, "Identity", item.identity.as_ref(), &[]);
                out.warnings.push(report::ImportIssue::new(
                    &title,
                    "identity details stored in notes",
                ));
            }
            5 => {
                append_section(&mut entry, "SSH key", item.ssh_key.as_ref(), SSH_LABELS);
                out.warnings
                    .push(report::ImportIssue::new(&title, "SSH key stored in notes"));
            }
            other => {
                out.skip(&title, &format!("unsupported Bitwarden item type {other}"));
                continue;
            }
        }
        append_custom_fields(&mut entry, item.fields.as_deref().unwrap_or_default());
        out.push(ImportCandidate {
            entry,
            favorite: item.favorite,
            tags: Vec::new(),
            history,
            attachments: Vec::new(),
        });
    }
    Ok(out)
}

const CARD_LABELS: &[(&str, &str)] = &[
    ("cardholderName", "Cardholder"),
    ("brand", "Brand"),
    ("number", "Number"),
    ("expMonth", "Expiry month"),
    ("expYear", "Expiry year"),
    ("code", "Security code"),
];

const SSH_LABELS: &[(&str, &str)] = &[
    ("privateKey", "Private key"),
    ("publicKey", "Public key"),
    ("keyFingerprint", "Fingerprint"),
];

/// Append every non-empty field of `section` to the notes. Known keys use a
/// friendly label; unknown keys keep their JSON name so nothing is lost.
fn append_section(
    entry: &mut NewEntry,
    heading: &str,
    section: Option<&serde_json::Map<String, serde_json::Value>>,
    labels: &[(&str, &str)],
) {
    let Some(section) = section else { return };
    let mut lines = Vec::new();
    for (key, label) in labels {
        if let Some(value) = section.get(*key).and_then(value_text) {
            lines.push(format!("{label}: {value}"));
        }
    }
    for (key, value) in section {
        if labels.iter().any(|(known, _)| known == key) {
            continue;
        }
        if let Some(value) = value_text(value) {
            lines.push(format!("{key}: {value}"));
        }
    }
    if !lines.is_empty() {
        otp::append_note(entry, &format!("{heading}\n{}", lines.join("\n")));
    }
}

fn append_custom_fields(entry: &mut NewEntry, fields: &[BwField]) {
    let lines: Vec<String> = fields
        .iter()
        .filter_map(|f| {
            let name = f.name.clone().unwrap_or_default();
            let value = f.value.as_ref().and_then(value_text).unwrap_or_default();
            (!name.is_empty() || !value.is_empty()).then(|| format!("{name}: {value}"))
        })
        .collect();
    if !lines.is_empty() {
        otp::append_note(entry, &format!("Custom fields:\n{}", lines.join("\n")));
    }
}

fn value_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) if !s.trim().is_empty() => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

pub fn preview_file(vault: &Vault, path: impl AsRef<Path>) -> Result<ImportPreview> {
    report::preview(vault, &parse_file(path)?)
}

pub fn import_into_vault(vault: &Vault, path: impl AsRef<Path>) -> Result<ImportReport> {
    report::apply(vault, parse_file(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"{
      "encrypted": false,
      "folders": [{"id": "f1", "name": "Work"}],
      "items": [
        {"type": 1, "name": "Example", "folderId": "f1", "favorite": true,
         "login": {"username": "alice", "password": "hunter2",
                   "totp": "otpauth://totp/Example:alice?secret=JBSW%20Y3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60",
                   "uris": [{"uri": "https://example.com"}, {"uri": "https://login.example.com"}]},
         "fields": [{"name": "PIN", "value": "1234", "type": 1}],
         "passwordHistory": [{"password": "old-pw", "lastUsedDate": "2024-01-02T03:04:05.000Z"}]},
        {"type": 1, "name": "TOTP only", "login": {"totp": "JBSWY3DPEHPK3PXP"}},
        {"type": 1, "name": "Seven digits", "login": {"password": "p",
         "totp": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=7"}},
        {"type": 2, "name": "Secure note", "notes": "secret text"},
        {"type": 3, "name": "Visa", "card": {"cardholderName": "Alice", "number": "4111111111111111",
         "expMonth": "1", "expYear": "2030", "code": "123", "brand": "Visa"}},
        {"type": 4, "name": "Me", "identity": {"firstName": "Alice", "email": "a@example.com"}},
        {"type": 9, "name": "Future type"}
      ]
    }"#;

    #[test]
    fn parses_every_item_type() {
        let parsed = parse_str(FIXTURE).unwrap();
        assert_eq!(parsed.candidates.len(), 6);
        assert_eq!(parsed.skipped.len(), 1);
        assert_eq!(parsed.skipped[0].title, "Future type");

        let login = &parsed.candidates[0];
        assert!(login.favorite);
        assert_eq!(login.entry.username.as_deref(), Some("alice"));
        assert_eq!(login.entry.url.as_deref(), Some("https://example.com"));
        assert_eq!(login.entry.category.as_deref(), Some("Work"));
        assert_eq!(login.entry.totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(login.entry.totp_algorithm.as_deref(), Some("SHA256"));
        assert_eq!(login.entry.totp_digits, Some(8));
        assert_eq!(login.entry.totp_period, Some(60));
        let notes = login.entry.notes.as_deref().unwrap();
        assert!(notes.contains("https://login.example.com"));
        assert!(notes.contains("PIN: 1234"));
        assert_eq!(login.history.len(), 1);
        assert_eq!(login.history[0].0, "old-pw");
        assert!(login.history[0].1.is_some());

        let totp_only = &parsed.candidates[1].entry;
        assert!(totp_only.password.is_empty());
        assert_eq!(totp_only.totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));

        let seven = &parsed.candidates[2].entry;
        assert!(seven.totp_secret.is_none());
        assert!(seven.notes.as_deref().unwrap().contains("digits=7"));

        assert_eq!(
            parsed.candidates[3].entry.notes.as_deref(),
            Some("secret text")
        );
        let card = parsed.candidates[4].entry.notes.as_deref().unwrap();
        assert!(card.contains("Number: 4111111111111111"));
        assert!(card.contains("Security code: 123"));
        assert!(parsed.candidates[5]
            .entry
            .notes
            .as_deref()
            .unwrap()
            .contains("email: a@example.com"));
        // 7-digit TOTP + card + identity.
        assert_eq!(parsed.warnings.len(), 3);
    }

    #[test]
    fn rejects_encrypted() {
        let json = r#"{"encrypted": true, "items": []}"#;
        assert!(parse_str(json).is_err());
    }

    #[test]
    fn import_reports_everything() {
        let (directory, vault) = crate::importers::report::tests::test_vault();
        let path = directory.path().join("bw.json");
        std::fs::write(&path, FIXTURE).unwrap();

        let preview = preview_file(&vault, &path).unwrap();
        assert_eq!(preview.recognized, 6);
        assert_eq!(preview.unsupported.len(), 1);
        assert_eq!(preview.duplicates, 0);

        let report = import_into_vault(&vault, &path).unwrap();
        assert_eq!(report.imported, 6);
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.warnings.len(), 3);
        assert!(report.failed.is_empty());

        let example = vault
            .list(None)
            .unwrap()
            .into_iter()
            .find(|e| e.title == "Example")
            .unwrap();
        assert!(example.favorite);
        assert_eq!(example.totp_digits, 8);
        assert_eq!(example.totp_period, 60);
        assert_eq!(example.totp_algorithm, "SHA256");
        let history = vault.password_history(example.id).unwrap();
        assert_eq!(history[0].password, "old-pw");

        let again = import_into_vault(&vault, &path).unwrap();
        assert_eq!(again.imported, 0);
        assert_eq!(again.duplicates, 6);
        assert_eq!(vault.list(None).unwrap().len(), 6);
    }
}
