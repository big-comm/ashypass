//! KeePass KDBX (v3/v4) import and export.
//!
//! Uses the upstream `keepass` crate which handles AES/ChaCha20 cipher,
//! Argon2/AES-KDF derivation, and gzip+XML payload. We accept master-password
//! authentication; keyfile/YubiKey are out of scope for now.
//!
//! On import: each entry's nearest parent group name becomes the category.
//! TOTP is read from the standard `otp` custom field (otpauth:// URI) or from
//! KeeWeb's "TimeOtp-Secret-Base32" field.
//!
//! On export: we emit KDBX4 with all entries flat under the root group; the
//! Ashy "category" maps to a sub-group of the root. Argon2 KDF defaults are
//! taken from `Database::new()` — the user picks the export password
//! independently of their vault master.

use crate::db::vault::{NewEntry, PasswordEntry, Vault};
use crate::{Error, Result};
use keepass::db::{fields, Database, EntryMut, GroupRef};
use keepass::DatabaseKey;
use std::fs::File;
use std::path::Path;

pub fn parse_file(path: impl AsRef<Path>, password: &str) -> Result<Vec<NewEntry>> {
    let mut file = File::open(&path)?;
    let key = DatabaseKey::new().with_password(password);
    let db = Database::open(&mut file, key).map_err(|e| Error::Other(format!("kdbx open: {e}")))?;
    Ok(collect_entries(&db))
}

fn collect_entries(db: &Database) -> Vec<NewEntry> {
    let mut out: Vec<NewEntry> = Vec::new();
    walk_group(db.root(), None, &mut out);
    out
}

fn walk_group(group: GroupRef<'_>, parent_category: Option<&str>, out: &mut Vec<NewEntry>) {
    // The KDBX root is a synthetic container; entries directly under it
    // get no category. Nested groups become the category name.
    let group_name = group.name.as_str();
    let category = if parent_category.is_none() && group_name.eq_ignore_ascii_case("Root") {
        None
    } else {
        Some(group_name.to_string())
    };

    for entry in group.entries() {
        let password = entry.get(fields::PASSWORD).unwrap_or("");
        if password.is_empty() {
            continue;
        }
        let title = entry
            .get(fields::TITLE)
            .filter(|s| !s.is_empty())
            .unwrap_or("Untitled")
            .to_string();
        let username = entry
            .get(fields::USERNAME)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        let url = entry
            .get(fields::URL)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        let notes = entry
            .get(fields::NOTES)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let totp_secret = entry
            .get("otp")
            .and_then(extract_totp_secret)
            .or_else(|| entry.get("TimeOtp-Secret-Base32").map(|s| s.to_string()))
            .filter(|s| !s.is_empty());

        out.push(NewEntry {
            title,
            username,
            password: password.to_string(),
            notes,
            url,
            totp_secret,
            totp_algorithm: Some("SHA1".into()),
            totp_digits: Some(6),
            totp_period: Some(30),
            category: category.clone(),
        });
    }

    for sub in group.groups() {
        walk_group(sub, Some(group_name), out);
    }
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

pub fn import_into_vault(vault: &Vault, path: impl AsRef<Path>, password: &str) -> Result<usize> {
    let entries = parse_file(path, password)?;
    let mut imported = 0;
    for e in entries {
        if vault.add(e).is_ok() {
            imported += 1;
        }
    }
    Ok(imported)
}

/// Export the decrypted vault to a KDBX4 file protected by `password`.
/// Groups are created lazily from the per-entry category; entries without a
/// category live directly under root.
pub fn export_vault(vault: &Vault, path: impl AsRef<Path>, password: &str) -> Result<usize> {
    let listing: Vec<PasswordEntry> = vault.list(None)?;
    let mut db = Database::new();
    db.meta.database_name = Some("Ashy Pass export".into());

    // Collect distinct category names (first-seen order) and pre-create the
    // groups so we can target them by name during the second pass.
    let mut categories: Vec<String> = Vec::new();
    for e in &listing {
        if let Some(c) = e.category.as_ref() {
            if !c.is_empty() && !categories.iter().any(|x| x == c) {
                categories.push(c.clone());
            }
        }
    }
    {
        let mut root = db.root_mut();
        for cat in &categories {
            let mut g = root.add_group();
            g.name = cat.clone();
        }
    }

    let mut exported = 0usize;
    for summary in listing {
        // Re-fetch through `get` to obtain the decrypted password and TOTP.
        let full = match vault.get(summary.id)? {
            Some(f) => f,
            None => continue,
        };
        let password_plain = full.password.clone().unwrap_or_default();
        if password_plain.is_empty() {
            continue;
        }

        let category = full.category.as_deref().filter(|s| !s.is_empty());

        let mut root = db.root_mut();
        match category.and_then(|cat| root.group_by_name_mut(cat)) {
            Some(mut g) => {
                let mut e = g.add_entry();
                fill_entry(&mut e, &full, &password_plain);
            }
            None => {
                let mut e = root.add_entry();
                fill_entry(&mut e, &full, &password_plain);
            }
        }
        exported += 1;
    }

    let mut file = File::create(&path)?;
    db.save(&mut file, DatabaseKey::new().with_password(password))
        .map_err(|e| Error::Other(format!("kdbx save: {e}")))?;
    Ok(exported)
}

fn fill_entry(entry: &mut EntryMut<'_>, full: &PasswordEntry, password_plain: &str) {
    entry.set_unprotected(fields::TITLE, full.title.as_str());
    if let Some(u) = full.username.as_deref().filter(|s| !s.is_empty()) {
        entry.set_unprotected(fields::USERNAME, u);
    }
    entry.set_protected(fields::PASSWORD, password_plain);
    if let Some(u) = full.url.as_deref().filter(|s| !s.is_empty()) {
        entry.set_unprotected(fields::URL, u);
    }
    if let Some(n) = full.notes.as_deref().filter(|s| !s.is_empty()) {
        entry.set_unprotected(fields::NOTES, n);
    }
    if let Some(secret) = full.totp_secret.as_deref().filter(|s| !s.is_empty()) {
        let otpauth = format!(
            "otpauth://totp/{title}?secret={secret}&algorithm={alg}&digits={digits}&period={period}",
            title = url_escape(&full.title),
            secret = secret,
            alg = full.totp_algorithm,
            digits = full.totp_digits,
            period = full.totp_period,
        );
        entry.set_protected("otp", otpauth.as_str());
    }
}

fn url_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~') {
            out.push(ch);
        } else {
            let mut buf = [0u8; 4];
            for b in ch.encode_utf8(&mut buf).as_bytes() {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}
