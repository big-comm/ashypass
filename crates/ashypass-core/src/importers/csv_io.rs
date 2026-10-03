//! CSV import/export, Google Chrome-compatible columns: name, url, username, password, note.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CsvEntry {
    pub title: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub notes: String,
}

pub fn import_csv(path: impl AsRef<Path>) -> Result<Vec<CsvEntry>> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_path(path)
        .map_err(|e| Error::Other(format!("csv open: {e}")))?;

    let headers = rdr
        .headers()
        .map_err(|e| Error::Other(format!("csv headers: {e}")))?
        .clone();
    let idx = |names: &[&str]| -> Option<usize> {
        for (i, h) in headers.iter().enumerate() {
            // Spreadsheet exports often start with a UTF-8 BOM.
            let h = h.trim_start_matches('\u{feff}').trim();
            if names.iter().any(|n| n.eq_ignore_ascii_case(h)) {
                return Some(i);
            }
        }
        None
    };

    // Chrome/Firefox use `url`/`username`/`password`; Bitwarden prefixes its
    // login fields with `login_`; 1Password uses `Website`.
    let i_name = idx(&["name", "title"]);
    let i_url = idx(&["url", "login_uri", "website", "uri"]);
    let i_user = idx(&["username", "login_username", "user", "email"]);
    let i_pw = idx(&["password", "login_password"]);
    let i_notes = idx(&["note", "notes", "comment", "extra"]);
    if i_pw.is_none() {
        // Without this every row would import with an empty password while
        // the UI reports success.
        return Err(Error::Other(
            "csv: no password column found (expected `password` or `login_password`)".into(),
        ));
    }

    let get = |row: &csv::StringRecord, i: Option<usize>| -> String {
        i.and_then(|i| row.get(i)).unwrap_or("").trim().to_string()
    };

    let mut out = Vec::new();
    for row in rdr.records() {
        let row = row.map_err(|e| Error::Other(format!("csv row: {e}")))?;
        let entry = CsvEntry {
            title: {
                let t = get(&row, i_name);
                if t.is_empty() {
                    "Untitled".into()
                } else {
                    t
                }
            },
            url: get(&row, i_url),
            username: get(&row, i_user),
            password: get(&row, i_pw),
            notes: get(&row, i_notes),
        };
        // Only fully blank rows are dropped; a row with just a URL or a
        // username is still user data.
        let has_data = entry.title != "Untitled"
            || !entry.password.is_empty()
            || !entry.url.is_empty()
            || !entry.username.is_empty()
            || !entry.notes.is_empty();
        if has_data {
            out.push(entry);
        }
    }
    Ok(out)
}

/// Parse a CSV export into an importable document.
pub fn parse_file(path: impl AsRef<Path>) -> Result<crate::importers::ParsedImport> {
    let metadata = std::fs::metadata(path.as_ref())?;
    if metadata.len() > crate::importers::MAX_IMPORT_TEXT_BYTES {
        return Err(Error::InvalidInput("CSV file is too large".into()));
    }
    Ok(crate::importers::vault_import::csv_entries_to_import(
        import_csv(path)?,
    ))
}

pub fn preview_file(
    vault: &crate::db::vault::Vault,
    path: impl AsRef<Path>,
) -> Result<crate::importers::ImportPreview> {
    crate::importers::preview(vault, &parse_file(path)?)
}

pub fn import_into_vault(
    vault: &crate::db::vault::Vault,
    path: impl AsRef<Path>,
) -> Result<crate::importers::ImportReport> {
    crate::importers::apply(vault, parse_file(path)?)
}

pub fn export_csv(path: impl AsRef<Path>, entries: &[CsvEntry]) -> Result<()> {
    let mut w = csv::WriterBuilder::new()
        .has_headers(true)
        .from_writer(Vec::new());
    w.write_record(["name", "url", "username", "password", "note"])
        .map_err(|e| Error::Other(format!("csv head: {e}")))?;
    for e in entries {
        w.write_record([&e.title, &e.url, &e.username, &e.password, &e.notes])
            .map_err(|e| Error::Other(format!("csv write: {e}")))?;
    }
    let bytes = w
        .into_inner()
        .map_err(|e| Error::Other(format!("csv flush: {e}")))?;
    write_private_replacing(path.as_ref(), &bytes)
}

/// Write `bytes` owner-only (0600) through a synced temporary file renamed
/// over `path`. The CSV holds every password in clear text: it must not be
/// world-readable under the default umask, and a failed write must not leave
/// a truncated copy behind. Replacing an existing file is intended — the
/// save dialog has already asked the user.
fn write_private_replacing(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let file_name = path
        .file_name()
        .ok_or_else(|| Error::InvalidInput("csv: export path has no file name".into()))?;
    let mut temporary_name = std::ffi::OsString::from(".");
    temporary_name.push(file_name);
    temporary_name.push(format!(".{}.tmp", std::process::id()));
    let temporary = path.with_file_name(temporary_name);

    let result: std::io::Result<()> = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ashypass-csv-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn imports_bitwarden_headers() {
        let dir = temp_dir("bw");
        let path = dir.join("bw.csv");
        std::fs::write(
            &path,
            "\u{feff}folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
             ,,login,Example,note,,0,https://example.com,alice,s3cret,\n",
        )
        .unwrap();
        let rows = import_csv(&path).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].title, "Example");
        assert_eq!(rows[0].url, "https://example.com");
        assert_eq!(rows[0].username, "alice");
        assert_eq!(rows[0].password, "s3cret");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_csv_without_password_column() {
        let dir = temp_dir("nopw");
        let path = dir.join("x.csv");
        std::fs::write(&path, "name,url\nExample,https://example.com\n").unwrap();
        assert!(import_csv(&path).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn export_is_owner_only_and_replaces() {
        let dir = temp_dir("export");
        let path = dir.join("out.csv");
        std::fs::write(&path, "old").unwrap();
        let entry = CsvEntry {
            title: "Example".into(),
            password: "s3cret".into(),
            ..Default::default()
        };
        export_csv(&path, &[entry]).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let rows = import_csv(&path).unwrap();
        assert_eq!(rows[0].password, "s3cret");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
