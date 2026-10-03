//! Importers / exporters: CSV (Chrome-compatible), Aegis, andOTP, Bitwarden,
//! 1Password, KeePass and the native `.ashy` format.
//!
//! Every importer parses into a [`ParsedImport`] without touching the vault.
//! [`preview`] reports what would happen (recognised items, duplicates,
//! unsupported items) and [`apply`] writes everything in one transaction,
//! returning an [`ImportReport`] that lists each skipped or failed item.

pub mod aegis;
pub mod andotp;
pub mod ashy;
pub mod bitwarden;
pub mod csv_io;
pub mod keepass;
pub mod onepassword;
pub(crate) mod otp;
pub mod report;
pub mod vault_import;

pub use csv_io::{export_csv, import_csv, CsvEntry};
pub use report::{
    apply, apply_with, preview, DuplicatePolicy, ImportCandidate, ImportIssue, ImportPreview,
    ImportReport, ParsedImport,
};
pub use vault_import::import_csv_entries;

use crate::db::vault::Vault;
use crate::{Error, Result};
use std::io::Read;
use std::path::Path;

/// Largest text export (CSV/JSON) accepted by the importers.
pub const MAX_IMPORT_TEXT_BYTES: u64 = 256 * 1024 * 1024;

/// An import source plus the password it needs, if any.
#[derive(Debug, Clone)]
pub enum ImportSource {
    Csv,
    Aegis,
    Andotp,
    Bitwarden,
    OnePassword,
    KeePass { password: String },
    Ashy { password: String },
}

/// Parse `path` without touching the vault. Feed the result to [`preview`]
/// and then [`apply`] so the file is read only once.
pub fn parse_source(source: &ImportSource, path: impl AsRef<Path>) -> Result<ParsedImport> {
    let path = path.as_ref();
    match source {
        ImportSource::Csv => csv_io::parse_file(path),
        ImportSource::Aegis => aegis::parse_file(path),
        ImportSource::Andotp => andotp::parse_file(path),
        ImportSource::Bitwarden => bitwarden::parse_file(path),
        ImportSource::OnePassword => onepassword::parse_file(path),
        ImportSource::KeePass { password } => keepass::parse_file(path, password),
        ImportSource::Ashy { password } => ashy::parse_file(path, password),
    }
}

/// Parse and preview in one call.
pub fn preview_source(
    vault: &Vault,
    source: &ImportSource,
    path: impl AsRef<Path>,
) -> Result<ImportPreview> {
    preview(vault, &parse_source(source, path)?)
}

/// Parse and import in one call (exact duplicates are skipped).
pub fn import_source(
    vault: &Vault,
    source: &ImportSource,
    path: impl AsRef<Path>,
) -> Result<ImportReport> {
    apply(vault, parse_source(source, path)?)
}

/// Read a text export, refusing files beyond [`MAX_IMPORT_TEXT_BYTES`].
pub(crate) fn read_text_limited(path: impl AsRef<Path>) -> Result<String> {
    let file = std::fs::File::open(path)?;
    read_to_string_limited(file, MAX_IMPORT_TEXT_BYTES)
}

pub(crate) fn read_to_string_limited(reader: impl Read, limit: u64) -> Result<String> {
    let mut text = String::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_string(&mut text)?;
    if text.len() as u64 > limit {
        return Err(Error::InvalidInput(format!(
            "import file is larger than the {} MiB limit",
            limit / (1024 * 1024)
        )));
    }
    // Spreadsheet and Windows tools often prepend a UTF-8 BOM.
    if let Some(stripped) = text.strip_prefix('\u{feff}') {
        text = stripped.to_string();
    }
    Ok(text)
}

/// Authenticator apps store "issuer" and "account": use the issuer as the
/// title when present, otherwise the account label.
pub(crate) fn title_and_account(issuer: &str, label: &str) -> (String, Option<String>) {
    let issuer = issuer.trim();
    let label = label.trim();
    if issuer.is_empty() {
        let title = if label.is_empty() { "Untitled" } else { label };
        (title.to_string(), None)
    } else {
        (
            issuer.to_string(),
            (!label.is_empty()).then(|| label.to_string()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limited_reads_reject_oversized_input() {
        assert!(read_to_string_limited(std::io::Cursor::new(vec![b'a'; 11]), 10).is_err());
        assert_eq!(
            read_to_string_limited(std::io::Cursor::new("\u{feff}ok".as_bytes()), 10).unwrap(),
            "ok"
        );
    }

    #[test]
    fn issuer_becomes_title() {
        assert_eq!(
            title_and_account("GitHub", "alice"),
            ("GitHub".into(), Some("alice".into()))
        );
        assert_eq!(title_and_account("", "alice"), ("alice".into(), None));
        assert_eq!(title_and_account(" ", " "), ("Untitled".into(), None));
    }
}
