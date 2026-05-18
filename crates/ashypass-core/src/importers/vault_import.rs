//! Glue between the parsed importer entries and the live Vault.
//!
//! Each function takes an unlocked `Vault` and inserts a list of entries,
//! returning the count successfully inserted.

use crate::db::vault::{NewEntry, Vault};
use crate::importers::csv_io::{export_csv, CsvEntry};
use crate::importers::{aegis::AegisEntry, andotp::AndotpEntry};
use crate::Result;
use std::path::Path;

pub fn import_csv_entries(vault: &Vault, entries: Vec<CsvEntry>) -> Result<usize> {
    let mut n = 0;
    for e in entries {
        let new_entry = NewEntry {
            title: e.title,
            username: opt_str(e.username),
            password: e.password,
            notes: opt_str(e.notes),
            url: opt_str(e.url),
            ..Default::default()
        };
        if vault.add(new_entry).is_ok() {
            n += 1;
        }
    }
    Ok(n)
}

pub fn import_aegis_entries(vault: &Vault, entries: Vec<AegisEntry>) -> Result<usize> {
    let mut n = 0;
    for e in entries {
        let title = if e.issuer.is_empty() {
            e.label.clone()
        } else {
            e.issuer.clone()
        };
        let username = if e.issuer.is_empty() {
            None
        } else {
            Some(e.label)
        };
        let new_entry = NewEntry {
            title,
            username,
            password: String::new(),
            totp_secret: Some(e.secret),
            totp_algorithm: Some(e.algorithm.to_uppercase()),
            totp_digits: Some(e.digits),
            totp_period: Some(e.period),
            category: Some("2FA".into()),
            ..Default::default()
        };
        if vault.add(new_entry).is_ok() {
            n += 1;
        }
    }
    Ok(n)
}

pub fn import_andotp_entries(vault: &Vault, entries: Vec<AndotpEntry>) -> Result<usize> {
    let mut n = 0;
    for e in entries {
        let title = if e.issuer.is_empty() {
            e.label.clone()
        } else {
            e.issuer.clone()
        };
        let username = if e.issuer.is_empty() {
            None
        } else {
            Some(e.label)
        };
        let new_entry = NewEntry {
            title,
            username,
            password: String::new(),
            totp_secret: Some(e.secret),
            totp_algorithm: Some(e.algorithm.to_uppercase()),
            totp_digits: Some(e.digits),
            totp_period: Some(e.period),
            category: Some("2FA".into()),
            ..Default::default()
        };
        if vault.add(new_entry).is_ok() {
            n += 1;
        }
    }
    Ok(n)
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
        let full = match vault.get(e.id)? {
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
