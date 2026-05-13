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
            let lower = h.to_ascii_lowercase();
            if names.iter().any(|n| n.eq_ignore_ascii_case(&lower)) {
                return Some(i);
            }
        }
        None
    };

    let i_name = idx(&["name", "title"]);
    let i_url = idx(&["url"]);
    let i_user = idx(&["username", "user", "email"]);
    let i_pw = idx(&["password"]);
    let i_notes = idx(&["note", "notes", "comment"]);

    let get = |row: &csv::StringRecord, i: Option<usize>| -> String {
        i.and_then(|i| row.get(i)).unwrap_or("").trim().to_string()
    };

    let mut out = Vec::new();
    for row in rdr.records() {
        let row = row.map_err(|e| Error::Other(format!("csv row: {e}")))?;
        let entry = CsvEntry {
            title: {
                let t = get(&row, i_name);
                if t.is_empty() { "Untitled".into() } else { t }
            },
            url: get(&row, i_url),
            username: get(&row, i_user),
            password: get(&row, i_pw),
            notes: get(&row, i_notes),
        };
        if !entry.password.is_empty() || entry.title != "Untitled" {
            out.push(entry);
        }
    }
    Ok(out)
}

pub fn export_csv(path: impl AsRef<Path>, entries: &[CsvEntry]) -> Result<()> {
    let mut w = csv::WriterBuilder::new()
        .has_headers(true)
        .from_path(path)
        .map_err(|e| Error::Other(format!("csv create: {e}")))?;
    w.write_record(["name", "url", "username", "password", "note"])
        .map_err(|e| Error::Other(format!("csv head: {e}")))?;
    for e in entries {
        w.write_record([&e.title, &e.url, &e.username, &e.password, &e.notes])
            .map_err(|e| Error::Other(format!("csv write: {e}")))?;
    }
    w.flush().map_err(|e| Error::Other(format!("csv flush: {e}")))?;
    Ok(())
}
