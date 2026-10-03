//! Aegis Authenticator importer.
//!
//! Aegis exports come in two flavors:
//!   - "plain" JSON (no encryption)
//!   - encrypted JSON (scrypt + AES-256-GCM with a vault password)
//!
//! Only plain import is supported; encrypted exports are rejected with a
//! clear error. HOTP, Steam, Yandex and mOTP tokens cannot be represented in
//! the vault and are reported as skipped.

use crate::db::vault::{NewEntry, Vault};
use crate::importers::otp::{self, TotpField};
use crate::importers::report::{self, ImportCandidate, ImportPreview, ImportReport, ParsedImport};
use crate::{Error, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Deserialize)]
struct AegisFile {
    db: serde_json::Value,
}

#[derive(Deserialize)]
struct AegisDb {
    entries: Vec<AegisRaw>,
    #[serde(default)]
    groups: Vec<AegisGroup>,
}

#[derive(Deserialize)]
struct AegisGroup {
    uuid: String,
    name: String,
}

#[derive(Deserialize)]
struct AegisRaw {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    name: String,
    issuer: Option<String>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    favorite: bool,
    #[serde(default)]
    groups: Vec<String>,
    info: AegisInfo,
}

#[derive(Deserialize)]
struct AegisInfo {
    #[serde(default)]
    secret: String,
    algo: Option<String>,
    digits: Option<u8>,
    period: Option<u32>,
}

pub fn parse_file(path: impl AsRef<Path>) -> Result<ParsedImport> {
    parse_str(&super::read_text_limited(path)?)
}

pub fn parse_str(text: &str) -> Result<ParsedImport> {
    let parsed: AegisFile =
        serde_json::from_str(text).map_err(|e| Error::Other(format!("aegis json: {e}")))?;
    if parsed.db.is_string() {
        return Err(Error::Other(
            "encrypted Aegis vaults are not supported — export without encryption".into(),
        ));
    }
    let db: AegisDb =
        serde_json::from_value(parsed.db).map_err(|e| Error::Other(format!("aegis json: {e}")))?;
    let group_names: HashMap<String, String> =
        db.groups.into_iter().map(|g| (g.uuid, g.name)).collect();

    let mut out = ParsedImport::default();
    for raw in db.entries {
        let issuer = raw.issuer.unwrap_or_default();
        let (title, username) = super::title_and_account(&issuer, &raw.name);
        match raw.kind.to_ascii_lowercase().as_str() {
            "totp" => {}
            "hotp" => {
                out.skip(&title, "HOTP counters are not supported");
                continue;
            }
            "steam" => {
                out.skip(&title, "Steam tokens are not supported");
                continue;
            }
            other => {
                out.skip(&title, &format!("unsupported token type: {other}"));
                continue;
            }
        }
        let params = match otp::from_parts(
            &raw.info.secret,
            &raw.info.secret,
            raw.info.algo.as_deref().unwrap_or("SHA1"),
            raw.info.digits.unwrap_or(6),
            raw.info.period.unwrap_or(30),
        ) {
            TotpField::Supported(params) => params,
            TotpField::Unsupported { reason, .. } => {
                out.skip(&title, &reason);
                continue;
            }
            TotpField::Absent => {
                out.skip(&title, "TOTP secret is empty");
                continue;
            }
        };
        let tags = raw
            .groups
            .iter()
            .filter_map(|uuid| group_names.get(uuid).cloned())
            .collect();
        out.push(ImportCandidate {
            entry: NewEntry {
                title,
                username,
                notes: raw.note.filter(|n| !n.trim().is_empty()),
                totp_secret: Some(params.secret),
                totp_algorithm: Some(params.algorithm),
                totp_digits: Some(params.digits),
                totp_period: Some(params.period),
                category: Some("2FA".into()),
                ..NewEntry::default()
            },
            favorite: raw.favorite,
            tags,
            history: Vec::new(),
            attachments: Vec::new(),
        });
    }
    Ok(out)
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
      "version": 1,
      "header": {"slots": null, "params": null},
      "db": {
        "version": 3,
        "groups": [{"uuid": "g1", "name": "Work"}],
        "entries": [
          {"type": "totp", "name": "alice", "issuer": "GitHub", "note": "n", "favorite": true,
           "groups": ["g1"],
           "info": {"secret": "JBSWY3DPEHPK3PXP", "algo": "SHA256", "digits": 8, "period": 60}},
          {"type": "totp", "name": "bob", "issuer": "",
           "info": {"secret": "JBSWY3DPEHPK3PXP", "algo": "SHA1", "digits": 6, "period": 30}},
          {"type": "hotp", "name": "counter", "issuer": "Bank",
           "info": {"secret": "JBSWY3DPEHPK3PXP", "algo": "SHA1", "digits": 6, "counter": 4}},
          {"type": "steam", "name": "gamer", "issuer": "Steam",
           "info": {"secret": "JBSWY3DPEHPK3PXP", "algo": "SHA1", "digits": 5, "period": 30}},
          {"type": "totp", "name": "seven", "issuer": "Odd",
           "info": {"secret": "JBSWY3DPEHPK3PXP", "algo": "SHA1", "digits": 7, "period": 30}}
        ]
      }
    }"#;

    #[test]
    fn parses_totp_and_reports_unsupported_types() {
        let parsed = parse_str(FIXTURE).unwrap();
        assert_eq!(parsed.candidates.len(), 2);
        let first = &parsed.candidates[0];
        assert_eq!(first.entry.title, "GitHub");
        assert_eq!(first.entry.username.as_deref(), Some("alice"));
        assert_eq!(first.entry.totp_algorithm.as_deref(), Some("SHA256"));
        assert_eq!(first.entry.totp_digits, Some(8));
        assert_eq!(first.entry.totp_period, Some(60));
        assert!(first.favorite);
        assert_eq!(first.tags, vec!["Work"]);
        assert_eq!(parsed.candidates[1].entry.title, "bob");
        let reasons: Vec<&str> = parsed.skipped.iter().map(|s| s.reason.as_str()).collect();
        assert_eq!(parsed.skipped.len(), 3);
        assert!(reasons[0].contains("HOTP"));
        assert!(reasons[1].contains("Steam"));
        assert!(reasons[2].contains("digit"));
    }

    #[test]
    fn rejects_encrypted_vaults() {
        let json = r#"{"version":1,"header":{"slots":[{}]},"db":"base64=="}"#;
        assert!(parse_str(json)
            .unwrap_err()
            .to_string()
            .contains("encrypted"));
    }

    #[test]
    fn import_reports_counts_and_duplicates() {
        let (directory, vault) = crate::importers::report::tests::test_vault();
        let path = directory.path().join("aegis.json");
        std::fs::write(&path, FIXTURE).unwrap();
        let preview = preview_file(&vault, &path).unwrap();
        assert_eq!(preview.recognized, 2);
        assert_eq!(preview.unsupported.len(), 3);
        let first = import_into_vault(&vault, &path).unwrap();
        assert_eq!(first.imported, 2);
        assert_eq!(first.skipped.len(), 3);
        let again = import_into_vault(&vault, &path).unwrap();
        assert_eq!(again.imported, 0);
        assert_eq!(again.duplicates, 2);
        let entry = vault
            .list(None)
            .unwrap()
            .into_iter()
            .find(|e| e.title == "GitHub")
            .unwrap();
        assert_eq!(entry.totp_digits, 8);
        assert!(entry.favorite);
    }
}
