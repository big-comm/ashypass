//! KeePass KDBX (v3/v4) import and export.
//!
//! Uses the upstream `keepass` crate which handles AES/ChaCha20 cipher,
//! Argon2/AES-KDF derivation, and gzip+XML payload. We accept master-password
//! authentication; keyfile/YubiKey are out of scope for now.
//!
//! On import: the full group path below the root ("Work/Email") becomes the
//! category, so same-named groups in different branches are not merged.
//! Entries in the Recycle Bin are reported as skipped. TOTP is read from the
//! `otp` field (otpauth:// URI), KeePass 2.47+ `TimeOtp-*` fields, or the
//! legacy KeePassXC `TOTP Seed`/`TOTP Settings` pair. Custom fields go to the
//! notes, attachments and tags are kept, and earlier passwords from the entry
//! history become password history. The file is capped at
//! [`MAX_IMPORT_BINARY_BYTES`](super::MAX_IMPORT_BINARY_BYTES) and attachments
//! above [`MAX_ATTACHMENT_BYTES`] are skipped with a warning.
//!
//! On export: we emit KDBX4; a category "A/B" becomes nested groups A → B.
//! Tags, attachments (as KDBX binaries) and password history (as entry
//! history snapshots that differ only in the password) are exported. KDBX
//! has no favorite flag, so favorites are not exported.
//! Argon2 KDF defaults are taken from `Database::new()` — the user picks the
//! export password independently of their vault master.

use crate::backup::files::write_private_replacing;
use crate::db::vault::{NewEntry, PasswordEntry, PasswordHistoryEntry, Vault};
use crate::importers::otp::{self, TotpField};
use crate::importers::report::{self, ImportCandidate, ImportPreview, ImportReport, ParsedImport};
use crate::{Error, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use keepass::db::{
    fields, Database, Entry as KdbxEntry, EntryMut, EntryRef, GroupId, GroupRef, History, Value,
};
use keepass::DatabaseKey;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Largest single attachment read from a KDBX file; bigger ones are skipped
/// with a warning (same limit as the 1Password importer).
const MAX_ATTACHMENT_BYTES: usize = 64 * 1024 * 1024;

/// Fields that hold TOTP configuration and are consumed by [`entry_totp`].
const OTP_FIELDS: &[&str] = &[
    "otp",
    "TimeOtp-Secret",
    "TimeOtp-Secret-Hex",
    "TimeOtp-Secret-Base32",
    "TimeOtp-Secret-Base64",
    "TimeOtp-Length",
    "TimeOtp-Period",
    "TimeOtp-Algorithm",
    "TOTP Seed",
    "TOTP Settings",
];

pub fn parse_file(path: impl AsRef<Path>, password: &str) -> Result<ParsedImport> {
    let mut file = File::open(&path)?;
    if file.metadata()?.len() > super::MAX_IMPORT_BINARY_BYTES {
        return Err(too_large());
    }
    parse_reader(&mut file, password)
}

pub fn parse_reader(reader: &mut dyn Read, password: &str) -> Result<ParsedImport> {
    parse_reader_limited(reader, password, super::MAX_IMPORT_BINARY_BYTES)
}

fn parse_reader_limited(reader: &mut dyn Read, password: &str, limit: u64) -> Result<ParsedImport> {
    // Read through a bounded reader so a growing or special file cannot make
    // us buffer more than the limit (the keepass crate loads it all anyway).
    let mut bytes = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(too_large());
    }
    let key = DatabaseKey::new().with_password(password);
    let db = Database::open(&mut bytes.as_slice(), key)
        .map_err(|e| Error::Other(format!("kdbx open: {e}")))?;
    Ok(parse_database(&db))
}

fn too_large() -> Error {
    Error::InvalidInput(format!(
        "KeePass file is larger than the {} MiB limit",
        super::MAX_IMPORT_BINARY_BYTES / (1024 * 1024)
    ))
}

pub fn parse_database(db: &Database) -> ParsedImport {
    parse_database_with(db, MAX_ATTACHMENT_BYTES)
}

fn parse_database_with(db: &Database, attachment_limit: usize) -> ParsedImport {
    let mut out = ParsedImport::default();
    let recycle_bin = db.recycle_bin().map(|g| g.id());
    let root = db.root();
    collect_entries(&root, &[], attachment_limit, &mut out);
    for sub in root.groups() {
        walk_group(&sub, Vec::new(), recycle_bin, attachment_limit, &mut out);
    }
    out
}

fn walk_group(
    group: &GroupRef<'_>,
    mut path: Vec<String>,
    recycle_bin: Option<GroupId>,
    attachment_limit: usize,
    out: &mut ParsedImport,
) {
    if Some(group.id()) == recycle_bin {
        skip_recursively(group, out);
        return;
    }
    let name = group.name.trim();
    path.push(if name.is_empty() {
        "Untitled".to_string()
    } else {
        name.replace('/', "-")
    });
    out.folders.push(path.join("/"));
    collect_entries(group, &path, attachment_limit, out);
    for sub in group.groups() {
        walk_group(&sub, path.clone(), recycle_bin, attachment_limit, out);
    }
}

fn skip_recursively(group: &GroupRef<'_>, out: &mut ParsedImport) {
    for entry in group.entries() {
        out.skip(&entry_title(&entry), "in the KeePass recycle bin");
    }
    for sub in group.groups() {
        skip_recursively(&sub, out);
    }
}

fn entry_title(entry: &EntryRef<'_>) -> String {
    entry
        .get(fields::TITLE)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("Untitled")
        .to_string()
}

fn non_empty(entry: &EntryRef<'_>, key: &str) -> Option<String> {
    entry
        .get(key)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn collect_entries(
    group: &GroupRef<'_>,
    path: &[String],
    attachment_limit: usize,
    out: &mut ParsedImport,
) {
    let category = (!path.is_empty()).then(|| path.join("/"));
    let mut entries: Vec<EntryRef<'_>> = group.entries().collect();
    entries.sort_by_key(entry_title);
    for entry in entries {
        let password = entry.get(fields::PASSWORD).unwrap_or("").to_string();
        let mut new_entry = NewEntry {
            title: entry_title(&entry),
            username: non_empty(&entry, fields::USERNAME),
            password: password.clone(),
            notes: non_empty(&entry, fields::NOTES),
            url: non_empty(&entry, fields::URL),
            category: category.clone(),
            ..NewEntry::default()
        };
        otp::attach(&mut new_entry, entry_totp(&entry), &mut out.warnings);

        let mut custom: Vec<(&String, &str)> = entry
            .fields
            .iter()
            .filter(|(key, _)| {
                !fields::KNOWN_FIELDS.contains(&key.as_str()) && !OTP_FIELDS.contains(&key.as_str())
            })
            .map(|(key, value)| (key, value.get().as_str()))
            .filter(|(_, value)| !value.is_empty())
            .collect();
        custom.sort();
        if !custom.is_empty() {
            let lines: Vec<String> = custom.iter().map(|(k, v)| format!("{k}: {v}")).collect();
            otp::append_note(
                &mut new_entry,
                &format!("Custom fields:\n{}", lines.join("\n")),
            );
        }

        let mut history = Vec::new();
        if let Some(previous) = entry.history.as_ref() {
            for old in previous.get_entries() {
                let Some(old_password) = old.fields.get(fields::PASSWORD).map(|v| v.get()) else {
                    continue;
                };
                if old_password.is_empty()
                    || *old_password == password
                    || history.iter().any(|(p, _)| p == old_password)
                {
                    continue;
                }
                let changed_at = old.times.last_modification.map(|t| t.and_utc().timestamp());
                history.push((old_password.clone(), changed_at));
            }
        }

        let mut attachments = Vec::new();
        let mut named: Vec<_> = entry.attachments_named().collect();
        named.sort_by(|a, b| a.0.cmp(b.0));
        for (name, attachment) in named {
            let data = attachment.data.get();
            if data.len() > attachment_limit {
                out.warnings.push(report::ImportIssue::new(
                    &new_entry.title,
                    &format!("attachment too large: {name}"),
                ));
                continue;
            }
            attachments.push((name.to_string(), data.clone()));
        }

        out.push(ImportCandidate {
            entry: new_entry,
            favorite: false,
            tags: entry.tags.clone(),
            history,
            attachments,
        });
    }
}

fn entry_totp(entry: &EntryRef<'_>) -> TotpField {
    if let Some(raw) = non_empty(entry, "otp") {
        return otp::parse_field(&raw);
    }

    // KeePass 2.47+ native TOTP fields.
    let native_secret = if let Some(secret) = non_empty(entry, "TimeOtp-Secret-Base32") {
        Some(Ok(secret))
    } else if let Some(hex) = non_empty(entry, "TimeOtp-Secret-Hex") {
        Some(decode_hex(&hex).map(|bytes| base32_of(&bytes)))
    } else if let Some(b64) = non_empty(entry, "TimeOtp-Secret-Base64") {
        Some(
            STANDARD
                .decode(b64.trim())
                .map(|bytes| base32_of(&bytes))
                .map_err(|_| ()),
        )
    } else {
        non_empty(entry, "TimeOtp-Secret").map(|utf8| Ok(base32_of(utf8.as_bytes())))
    };
    if let Some(secret) = native_secret {
        let raw = describe_fields(entry, "TimeOtp-");
        let Ok(secret) = secret else {
            return TotpField::Unsupported {
                raw,
                reason: "invalid TOTP secret".into(),
            };
        };
        let digits = non_empty(entry, "TimeOtp-Length")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(6);
        let period = non_empty(entry, "TimeOtp-Period")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(30);
        let algorithm =
            non_empty(entry, "TimeOtp-Algorithm").unwrap_or_else(|| "HMAC-SHA-1".into());
        return otp::from_parts(&raw, &secret, &algorithm, digits, period);
    }

    // Legacy KeePassXC: "TOTP Seed" + "TOTP Settings" = "<period>;<digits|S>".
    if let Some(seed) = non_empty(entry, "TOTP Seed") {
        let settings = non_empty(entry, "TOTP Settings").unwrap_or_else(|| "30;6".into());
        let raw = format!("TOTP Seed: {seed}\nTOTP Settings: {settings}");
        let mut parts = settings.split(';');
        let period = parts
            .next()
            .and_then(|p| p.trim().parse().ok())
            .unwrap_or(30);
        let digits_field = parts.next().unwrap_or("6").trim();
        if digits_field.eq_ignore_ascii_case("S") {
            return TotpField::Unsupported {
                raw,
                reason: "Steam tokens are not supported".into(),
            };
        }
        let digits = digits_field.parse().unwrap_or(6);
        return otp::from_parts(&raw, &seed, "SHA1", digits, period);
    }
    TotpField::Absent
}

fn describe_fields(entry: &EntryRef<'_>, prefix: &str) -> String {
    let mut lines: Vec<String> = entry
        .fields
        .iter()
        .filter(|(key, _)| key.starts_with(prefix))
        .map(|(key, value)| format!("{key}: {}", value.get()))
        .collect();
    lines.sort();
    lines.join("\n")
}

fn base32_of(bytes: &[u8]) -> String {
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, bytes)
}

fn decode_hex(text: &str) -> std::result::Result<Vec<u8>, ()> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| (b as char).to_digit(16).map(|d| d as u8).ok_or(()))
        .collect::<std::result::Result<_, _>>()?;
    if !digits.len().is_multiple_of(2) {
        return Err(());
    }
    Ok(digits
        .chunks(2)
        .map(|pair| (pair[0] << 4) | pair[1])
        .collect())
}

pub fn preview_file(
    vault: &Vault,
    path: impl AsRef<Path>,
    password: &str,
) -> Result<ImportPreview> {
    report::preview(vault, &parse_file(path, password)?)
}

pub fn import_into_vault(
    vault: &Vault,
    path: impl AsRef<Path>,
    password: &str,
) -> Result<ImportReport> {
    report::apply(vault, parse_file(path, password)?)
}

/// Export the decrypted vault to a KDBX4 file protected by `password`.
/// A category "A/B" becomes nested groups; entries without a category live
/// directly under root. An existing file at `path` is replaced atomically
/// (the save dialog has already asked) and a failed export leaves no file.
pub fn export_vault(vault: &Vault, path: impl AsRef<Path>, password: &str) -> Result<usize> {
    if password.is_empty() {
        return Err(Error::InvalidInput("export password is empty".into()));
    }
    let db = build_export_database(vault)?;
    let exported = db.root().entries().count() + count_nested(&db.root());
    let mut bytes = Vec::new();
    db.save(&mut bytes, DatabaseKey::new().with_password(password))
        .map_err(|e| Error::Other(format!("kdbx save: {e}")))?;
    write_private_replacing(path.as_ref(), &bytes)?;
    Ok(exported)
}

fn count_nested(group: &GroupRef<'_>) -> usize {
    group
        .groups()
        .map(|g| g.entries().count() + count_nested(&g))
        .sum()
}

fn build_export_database(vault: &Vault) -> Result<Database> {
    let listing: Vec<PasswordEntry> = vault.list(None)?;
    let mut db = Database::new();
    db.meta.database_name = Some("Ashy Pass export".into());
    let root_id = db.root().id();
    let mut groups: HashMap<String, GroupId> = HashMap::new();

    let mut folders = vault.categories()?;
    folders.extend(listing.iter().filter_map(|e| e.category.clone()));
    for folder in &folders {
        group_for_path(&mut db, root_id, &mut groups, folder);
    }

    for summary in listing {
        // Re-fetch through `get_without_touch` for the decrypted fields.
        let Some(full) = vault.get_without_touch(summary.id)? else {
            continue;
        };
        let group_id = match full.category.as_deref().filter(|s| !s.trim().is_empty()) {
            Some(category) => group_for_path(&mut db, root_id, &mut groups, category),
            None => root_id,
        };
        let mut group = db
            .group_mut(group_id)
            .ok_or_else(|| Error::Other("kdbx export: missing group".into()))?;
        let history = vault.password_history(full.id)?;
        let mut attachments = Vec::new();
        for info in vault.list_attachments(full.id)? {
            if let Some((info, data)) = vault.get_attachment(info.id)? {
                attachments.push((info.filename, data));
            }
        }
        let mut entry = group.add_entry();
        fill_entry(&mut entry, &full);
        entry.tags = vault.tags_of(full.id)?;
        add_history(&mut entry, &full, &history);
        add_attachments(&mut entry, attachments);
    }
    Ok(db)
}

/// Store previous passwords as KDBX history snapshots: a copy of the entry
/// with the old password and its change time. `history` is newest first.
fn add_history(entry: &mut EntryMut<'_>, full: &PasswordEntry, history: &[PasswordHistoryEntry]) {
    let current = full.password.as_deref().unwrap_or("");
    let snapshot_base: KdbxEntry = (**entry).clone();
    let mut kdbx_history = History::default();
    // `History::add_entry` prepends, so add the oldest first to end up with
    // the newest snapshot at the front, as KeePass does.
    for old in history.iter().rev() {
        if old.password.is_empty() || old.password == current {
            continue;
        }
        let mut snapshot = snapshot_base.clone();
        snapshot.set_protected(fields::PASSWORD, old.password.as_str());
        if let Some(changed) = chrono::DateTime::from_timestamp(old.changed_at, 0) {
            snapshot.times.last_modification = Some(changed.naive_utc());
        }
        kdbx_history.add_entry(snapshot);
    }
    if !kdbx_history.get_entries().is_empty() {
        entry.history = Some(kdbx_history);
    }
}

/// Add attachments as KDBX binaries. KDBX keys attachments by name, so
/// repeated file names get a " (2)", " (3)", … suffix instead of replacing
/// each other.
fn add_attachments(entry: &mut EntryMut<'_>, attachments: Vec<(String, Vec<u8>)>) {
    let mut used: Vec<String> = Vec::new();
    for (filename, data) in attachments {
        let name = unique_attachment_name(&filename, &used);
        used.push(name.clone());
        entry.add_attachment(name, Value::protected(data));
    }
}

fn unique_attachment_name(filename: &str, used: &[String]) -> String {
    let base = if filename.trim().is_empty() {
        "attachment"
    } else {
        filename
    };
    if !used.iter().any(|u| u == base) {
        return base.to_string();
    }
    let (stem, extension) = match base.rfind('.') {
        Some(dot) if dot > 0 => (&base[..dot], &base[dot..]),
        _ => (base, ""),
    };
    (2..)
        .map(|n| format!("{stem} ({n}){extension}"))
        .find(|candidate| !used.iter().any(|u| u == candidate))
        .expect("an unused name exists")
}

/// Find or create the nested group for "A/B/C" below the root.
fn group_for_path(
    db: &mut Database,
    root_id: GroupId,
    groups: &mut HashMap<String, GroupId>,
    path: &str,
) -> GroupId {
    let mut parent = root_id;
    let mut so_far = String::new();
    for segment in path.split('/').map(str::trim).filter(|s| !s.is_empty()) {
        if !so_far.is_empty() {
            so_far.push('/');
        }
        so_far.push_str(segment);
        parent = match groups.get(&so_far) {
            Some(id) => *id,
            None => {
                let mut parent_group = db.group_mut(parent).expect("parent group exists");
                let mut child = parent_group.add_group();
                child.name = segment.to_string();
                let id = child.id();
                groups.insert(so_far.clone(), id);
                id
            }
        };
    }
    parent
}

fn fill_entry(entry: &mut EntryMut<'_>, full: &PasswordEntry) {
    entry.set_unprotected(fields::TITLE, full.title.as_str());
    if let Some(u) = full.username.as_deref().filter(|s| !s.is_empty()) {
        entry.set_unprotected(fields::USERNAME, u);
    }
    entry.set_protected(fields::PASSWORD, full.password.as_deref().unwrap_or(""));
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
            secret = url_escape(secret),
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

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "kdbx test password";

    fn fixture() -> Vec<u8> {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            let mut e = root.add_entry();
            e.set_unprotected(fields::TITLE, "Root entry");
            e.set_protected(fields::PASSWORD, "root-pw");
            e.set_protected(
                "otp",
                "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60",
            );
        }
        // Two groups named "Email" under different parents must not merge.
        for parent in ["Work", "Home"] {
            let mut root = db.root_mut();
            let mut group = root.add_group();
            group.name = parent.into();
            let mut email = group.add_group();
            email.name = "Email".into();
            let mut e = email.add_entry();
            e.set_unprotected(fields::TITLE, format!("{parent} mail"));
            e.set_unprotected(fields::USERNAME, "alice");
            e.set_protected(fields::PASSWORD, "");
            e.set_protected("Recovery code", "abc-123");
            e.set_unprotected("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP");
            e.set_unprotected("TimeOtp-Length", "8");
            e.set_unprotected("TimeOtp-Algorithm", "HMAC-SHA-512");
            e.tags = vec!["mail".into()];
            e.add_attachment("note.txt", Value::unprotected(b"attached".to_vec()));
        }
        let bin_uuid = {
            let mut root = db.root_mut();
            let mut bin = root.add_group();
            bin.name = "Recycle Bin".into();
            let mut e = bin.add_entry();
            e.set_unprotected(fields::TITLE, "Deleted");
            e.set_protected(fields::PASSWORD, "gone");
            bin.id().uuid()
        };
        db.meta.recyclebin_uuid = Some(bin_uuid);
        {
            let mut root = db.root_mut();
            let mut e = root.add_entry();
            e.set_unprotected(fields::TITLE, "Steam");
            e.set_protected(fields::PASSWORD, "s");
            e.set_unprotected("TOTP Seed", "JBSWY3DPEHPK3PXP");
            e.set_unprotected("TOTP Settings", "30;S");
        }
        let mut bytes = Vec::new();
        db.save(&mut bytes, DatabaseKey::new().with_password(PASSWORD))
            .unwrap();
        bytes
    }

    #[test]
    fn parses_groups_totp_recycle_bin_and_extras() {
        let bytes = fixture();
        let parsed = parse_reader(&mut std::io::Cursor::new(bytes), PASSWORD).unwrap();
        assert_eq!(parsed.candidates.len(), 4);
        assert_eq!(parsed.skipped.len(), 1);
        assert_eq!(parsed.skipped[0].title, "Deleted");
        assert!(!parsed.folders.iter().any(|f| f.contains("Recycle")));

        let by_title = |t: &str| {
            parsed
                .candidates
                .iter()
                .find(|c| c.entry.title == t)
                .unwrap()
        };
        let root = &by_title("Root entry").entry;
        assert_eq!(root.category, None);
        assert_eq!(root.totp_algorithm.as_deref(), Some("SHA256"));
        assert_eq!(root.totp_digits, Some(8));
        assert_eq!(root.totp_period, Some(60));

        let work = by_title("Work mail");
        assert_eq!(work.entry.category.as_deref(), Some("Work/Email"));
        assert_eq!(
            by_title("Home mail").entry.category.as_deref(),
            Some("Home/Email")
        );
        assert!(work.entry.password.is_empty());
        assert_eq!(work.entry.totp_digits, Some(8));
        assert_eq!(work.entry.totp_algorithm.as_deref(), Some("SHA512"));
        assert!(work
            .entry
            .notes
            .as_deref()
            .unwrap()
            .contains("Recovery code: abc-123"));
        assert_eq!(work.tags, vec!["mail"]);
        assert_eq!(
            work.attachments,
            vec![("note.txt".into(), b"attached".to_vec())]
        );

        let steam = &by_title("Steam").entry;
        assert!(steam.totp_secret.is_none());
        assert!(steam.notes.as_deref().unwrap().contains("TOTP Seed"));
        assert_eq!(parsed.warnings.len(), 1);
    }

    #[test]
    fn oversized_input_and_attachments_are_limited() {
        let bytes = fixture();
        let limit = bytes.len() as u64 - 1;
        assert!(matches!(
            parse_reader_limited(&mut std::io::Cursor::new(bytes.clone()), PASSWORD, limit),
            Err(Error::InvalidInput(_))
        ));

        // A small limit stands in for MAX_ATTACHMENT_BYTES to keep the test fast.
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            let mut e = root.add_entry();
            e.set_unprotected(fields::TITLE, "Big file");
            e.set_protected(fields::PASSWORD, "pw");
            e.add_attachment("huge.bin", Value::unprotected(vec![0u8; 17]));
            e.add_attachment("small.txt", Value::unprotected(b"ok".to_vec()));
        }
        let parsed = parse_database_with(&db, 16);
        assert_eq!(parsed.candidates.len(), 1, "the entry itself is kept");
        assert_eq!(
            parsed.candidates[0].attachments,
            vec![("small.txt".into(), b"ok".to_vec())]
        );
        assert_eq!(parsed.warnings.len(), 1);
        assert!(parsed.warnings[0].reason.contains("huge.bin"));
    }

    #[test]
    fn export_keeps_attachments_and_history() {
        let (directory, vault) = crate::importers::report::tests::test_vault();
        let id = vault
            .add(NewEntry {
                title: "With extras".into(),
                password: "current".into(),
                ..NewEntry::default()
            })
            .unwrap();
        vault
            .append_password_history(id, "oldest", Some(1_600_000_000))
            .unwrap();
        vault
            .append_password_history(id, "older", Some(1_700_000_000))
            .unwrap();
        vault.add_attachment(id, "a.txt", None, b"one").unwrap();
        vault.add_attachment(id, "a.txt", None, b"two").unwrap();
        vault.add_attachment(id, "b.bin", None, &[0, 1, 2]).unwrap();

        let out = directory.path().join("extras.kdbx");
        assert_eq!(export_vault(&vault, &out, "export pw").unwrap(), 1);
        let parsed = parse_file(&out, "export pw").unwrap();
        assert_eq!(parsed.candidates.len(), 1);
        let candidate = &parsed.candidates[0];
        assert_eq!(candidate.entry.password, "current");

        let mut history = candidate.history.clone();
        history.sort();
        assert_eq!(
            history,
            vec![
                ("older".to_string(), Some(1_700_000_000)),
                ("oldest".to_string(), Some(1_600_000_000)),
            ]
        );

        let mut contents: Vec<Vec<u8>> = candidate
            .attachments
            .iter()
            .map(|(_, d)| d.clone())
            .collect();
        contents.sort();
        assert_eq!(
            contents,
            vec![vec![0, 1, 2], b"one".to_vec(), b"two".to_vec()]
        );
        let mut names: Vec<&str> = candidate
            .attachments
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();
        names.sort_unstable();
        assert_eq!(names, vec!["a (2).txt", "a.txt", "b.bin"]);

        // And back into a fresh vault.
        let (_other_dir, other) = crate::importers::report::tests::test_vault();
        let report = import_into_vault(&other, &out, "export pw").unwrap();
        assert_eq!(report.imported, 1);
        let imported = other.list(None).unwrap()[0].id;
        assert_eq!(other.password_history(imported).unwrap().len(), 2);
        assert_eq!(other.list_attachments(imported).unwrap().len(), 3);
    }

    #[test]
    fn attachment_names_are_unique() {
        let used = vec!["a.txt".to_string(), "a (2).txt".to_string()];
        assert_eq!(unique_attachment_name("a.txt", &used), "a (3).txt");
        assert_eq!(unique_attachment_name("b", &used), "b");
        assert_eq!(unique_attachment_name("", &[]), "attachment");
        assert_eq!(
            unique_attachment_name(".env", &[".env".to_string()]),
            ".env (2)"
        );
    }

    #[test]
    fn wrong_password_is_an_error() {
        let bytes = fixture();
        assert!(parse_reader(&mut std::io::Cursor::new(bytes), "wrong").is_err());
    }

    #[test]
    fn import_export_roundtrip_keeps_nested_groups() {
        let (directory, vault) = crate::importers::report::tests::test_vault();
        let source = directory.path().join("in.kdbx");
        std::fs::write(&source, fixture()).unwrap();
        let report = import_into_vault(&vault, &source, PASSWORD).unwrap();
        assert_eq!(report.imported, 4);
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.warnings.len(), 1);
        let work = vault
            .list(None)
            .unwrap()
            .into_iter()
            .find(|e| e.title == "Work mail")
            .unwrap();
        assert_eq!(vault.list_attachments(work.id).unwrap().len(), 1);
        assert_eq!(vault.tags_of(work.id).unwrap(), vec!["mail"]);

        // Export replaces an existing file (overwrite confirmed by the dialog).
        let out = directory.path().join("out.kdbx");
        std::fs::write(&out, b"old").unwrap();
        assert_eq!(export_vault(&vault, &out, "export pw").unwrap(), 4);
        let reparsed = parse_file(&out, "export pw").unwrap();
        assert_eq!(reparsed.candidates.len(), 4);
        let categories: Vec<_> = reparsed
            .candidates
            .iter()
            .filter_map(|c| c.entry.category.clone())
            .collect();
        assert!(categories.contains(&"Work/Email".to_string()));
        assert!(categories.contains(&"Home/Email".to_string()));
        assert!(export_vault(&vault, &out, "").is_err());
    }
}
