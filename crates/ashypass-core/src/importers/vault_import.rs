//! Glue between parsed CSV rows and the live Vault, plus CSV export.

use crate::db::vault::{NewEntry, Vault};
use crate::importers::csv_io::{export_csv, CsvEntry};
use crate::importers::report::{self, ImportReport, ParsedImport};
use crate::Result;
use std::path::Path;

/// Convert CSV rows into an importable document. Rows without a password are
/// still imported (the vault accepts them) so nothing is lost.
pub fn csv_entries_to_import(entries: Vec<CsvEntry>) -> ParsedImport {
    let mut out = ParsedImport::default();
    for e in entries {
        out.push(NewEntry {
            title: e.title,
            username: opt_str(e.username),
            password: e.password,
            notes: opt_str(e.notes),
            url: opt_str(e.url),
            ..Default::default()
        });
    }
    out
}

/// Import already-parsed CSV rows in one transaction.
pub fn import_csv_entries(vault: &Vault, entries: Vec<CsvEntry>) -> Result<ImportReport> {
    report::apply(vault, csv_entries_to_import(entries))
}

fn opt_str(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Decrypt every entry and emit a Chrome-compatible CSV file.
pub fn export_vault_to_csv(vault: &Vault, path: impl AsRef<Path>) -> Result<usize> {
    let list = vault.list(None)?;
    let mut rows = Vec::with_capacity(list.len());
    for e in list {
        let full = match vault.get_without_touch(e.id)? {
            Some(v) => v,
            None => continue,
        };
        rows.push(CsvEntry {
            title: full.title,
            url: full.url.unwrap_or_default(),
            username: full.username.unwrap_or_default(),
            password: full.password.unwrap_or_default(),
            notes: full.notes.unwrap_or_default(),
        });
    }
    let n = rows.len();
    export_csv(path, &rows)?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_rows_without_password_are_imported() {
        let (_directory, vault) = crate::importers::report::tests::test_vault();
        let rows = vec![
            CsvEntry {
                title: "Login".into(),
                password: "pw".into(),
                username: "alice".into(),
                ..CsvEntry::default()
            },
            CsvEntry {
                title: "Bookmark".into(),
                url: "https://example.com".into(),
                ..CsvEntry::default()
            },
            CsvEntry {
                title: "Login".into(),
                password: "pw".into(),
                username: "alice".into(),
                ..CsvEntry::default()
            },
        ];
        let report = import_csv_entries(&vault, rows).unwrap();
        assert_eq!(report.imported, 2);
        assert_eq!(report.duplicates, 1);
        assert!(report.is_complete());
    }
}
