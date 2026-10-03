//! andOTP plain JSON importer.
//!
//! HOTP, Steam and mOTP tokens cannot be represented in the vault and are
//! reported as skipped.

use crate::db::vault::{NewEntry, Vault};
use crate::importers::otp::{self, TotpField};
use crate::importers::report::{self, ImportCandidate, ImportPreview, ImportReport, ParsedImport};
use crate::{Error, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
struct Raw {
    #[serde(default)]
    issuer: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    secret: String,
    #[serde(default = "default_algo")]
    algorithm: String,
    #[serde(default = "default_digits")]
    digits: u8,
    #[serde(default = "default_period")]
    period: u32,
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    tags: Vec<String>,
}

fn default_algo() -> String {
    "SHA1".into()
}
fn default_digits() -> u8 {
    6
}
fn default_period() -> u32 {
    30
}

pub fn parse_file(path: impl AsRef<Path>) -> Result<ParsedImport> {
    parse_str(&super::read_text_limited(path)?)
}

pub fn parse_str(text: &str) -> Result<ParsedImport> {
    let raws: Vec<Raw> =
        serde_json::from_str(text).map_err(|e| Error::Other(format!("andotp json: {e}")))?;
    let mut out = ParsedImport::default();
    for raw in raws {
        let (title, username) = super::title_and_account(&raw.issuer, &raw.label);
        match raw.kind.to_ascii_uppercase().as_str() {
            "" | "TOTP" => {}
            "HOTP" => {
                out.skip(&title, "HOTP counters are not supported");
                continue;
            }
            "STEAM" => {
                out.skip(&title, "Steam tokens are not supported");
                continue;
            }
            other => {
                out.skip(&title, &format!("unsupported token type: {other}"));
                continue;
            }
        }
        let params = match otp::from_parts(
            &raw.secret,
            &raw.secret,
            &raw.algorithm,
            raw.digits,
            raw.period,
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
        out.push(ImportCandidate {
            entry: NewEntry {
                title,
                username,
                totp_secret: Some(params.secret),
                totp_algorithm: Some(params.algorithm),
                totp_digits: Some(params.digits),
                totp_period: Some(params.period),
                category: Some("2FA".into()),
                ..NewEntry::default()
            },
            favorite: false,
            tags: raw.tags,
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

    #[test]
    fn parses_totp_and_reports_unsupported_types() {
        let json = r#"[
          {"secret":"JBSWY3DPEHPK3PXP","issuer":"GitHub","label":"alice","digits":8,
           "type":"TOTP","algorithm":"SHA512","period":60,"tags":["Work"]},
          {"secret":"JBSWY3DPEHPK3PXP","issuer":"","label":"plain"},
          {"secret":"JBSWY3DPEHPK3PXP","issuer":"Bank","label":"c","type":"HOTP","counter":2},
          {"secret":"JBSWY3DPEHPK3PXP","issuer":"Steam","label":"g","type":"STEAM","digits":5},
          {"secret":"!!!","issuer":"Broken","label":"b","type":"TOTP"}
        ]"#;
        let parsed = parse_str(json).unwrap();
        assert_eq!(parsed.candidates.len(), 2);
        let first = &parsed.candidates[0].entry;
        assert_eq!(first.title, "GitHub");
        assert_eq!(first.totp_algorithm.as_deref(), Some("SHA512"));
        assert_eq!(first.totp_digits, Some(8));
        assert_eq!(first.totp_period, Some(60));
        assert_eq!(parsed.candidates[0].tags, vec!["Work"]);
        assert_eq!(parsed.candidates[1].entry.title, "plain");
        assert_eq!(parsed.skipped.len(), 3);
        assert!(parsed.skipped[0].reason.contains("HOTP"));
        assert!(parsed.skipped[1].reason.contains("Steam"));
        assert_eq!(parsed.skipped[2].title, "Broken");
    }

    #[test]
    fn import_into_vault_reports_skips() {
        let (directory, vault) = crate::importers::report::tests::test_vault();
        let path = directory.path().join("andotp.json");
        std::fs::write(
            &path,
            r#"[{"secret":"JBSWY3DPEHPK3PXP","issuer":"A","label":"a","type":"TOTP"},
                {"secret":"JBSWY3DPEHPK3PXP","issuer":"B","label":"b","type":"HOTP"}]"#,
        )
        .unwrap();
        let report = import_into_vault(&vault, &path).unwrap();
        assert_eq!(report.imported, 1);
        assert_eq!(report.skipped.len(), 1);
        assert!(!report.is_complete());
    }
}
