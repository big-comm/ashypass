//! 1Password unencrypted 1PUX export importer.
//!
//! A `.1pux` is a zip archive containing `export.data` (JSON) plus optional
//! file attachments under `files/`.
//!
//! Structure (1Password 8 export format, simplified):
//!
//! ```json
//! {
//!   "accounts": [{
//!     "vaults": [{
//!       "attrs": { "name": "Personal" },
//!       "items": [{
//!         "categoryUuid": "001",          // 001 = Login
//!         "favIndex": 1,
//!         "overview": { "title": "...", "url": "...", "tags": ["..."] },
//!         "details": {
//!           "loginFields": [
//!             { "designation": "username", "value": "alice" },
//!             { "designation": "password", "value": "hunter2" }
//!           ],
//!           "sections": [{
//!             "fields": [{
//!               "title": "one-time password",
//!               "value": { "totp": "otpauth://..." }
//!             }]
//!           }],
//!           "notesPlain": "...",
//!           "passwordHistory": [{ "value": "old", "time": 1700000000 }]
//!         }
//!       }]
//!     }]
//!   }]
//! }
//! ```
//!
//! Logins (001) and passwords (005) map to entries. Every other category
//! (notes, cards, identities, …) is imported as an entry whose encrypted
//! notes hold all section fields, so nothing is dropped. The vault name
//! becomes the category.

use crate::db::vault::{NewEntry, Vault};
use crate::importers::otp;
use crate::importers::report::{
    self, ImportCandidate, ImportIssue, ImportPreview, ImportReport, ParsedImport,
};
use crate::{Error, Result};
use serde_json::Value;
use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;

/// Largest `export.data` accepted (decompressed) — guards against zip bombs.
const MAX_EXPORT_DATA_BYTES: u64 = 256 * 1024 * 1024;
/// Largest single attachment and total attachment volume read from the zip.
const MAX_ATTACHMENT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_ATTACHMENT_BYTES: u64 = 512 * 1024 * 1024;

/// Open a `.1pux` file (zip) and parse every item.
pub fn parse_file(path: impl AsRef<Path>) -> Result<ParsedImport> {
    parse_archive(File::open(&path)?)
}

pub fn parse_archive(reader: impl Read + Seek) -> Result<ParsedImport> {
    let mut zip = zip::ZipArchive::new(reader)
        .map_err(|e| Error::Other(format!("1pux: not a valid zip: {e}")))?;
    let data = {
        let mut entry = zip
            .by_name("export.data")
            .map_err(|_| Error::Other("1pux: export.data not found in archive".into()))?;
        if entry.size() > MAX_EXPORT_DATA_BYTES {
            return Err(Error::InvalidInput("1pux: export.data is too large".into()));
        }
        super::read_to_string_limited(&mut entry, MAX_EXPORT_DATA_BYTES)?
    };
    let (mut parsed, documents) = parse_document(&data)?;

    // Attach files referenced by documentAttributes.
    let mut total = 0u64;
    let names: Vec<String> = zip.file_names().map(str::to_string).collect();
    for (candidate, documents) in parsed.candidates.iter_mut().zip(documents) {
        for (document_id, file_name) in documents {
            let wanted = format!("{document_id}__{file_name}");
            let found = names
                .iter()
                .find(|n| n.rsplit('/').next() == Some(wanted.as_str()));
            let outcome = match found {
                Some(name) => read_attachment(&mut zip, name, &mut total),
                None => Err("attachment missing from archive".to_string()),
            };
            match outcome {
                Ok(bytes) => candidate.attachments.push((file_name, bytes)),
                Err(reason) => parsed.warnings.push(ImportIssue::new(
                    &candidate.entry.title,
                    &format!("{reason}: {file_name}"),
                )),
            }
        }
    }
    Ok(parsed)
}

fn read_attachment<R: Read + Seek>(
    zip: &mut zip::ZipArchive<R>,
    name: &str,
    total: &mut u64,
) -> std::result::Result<Vec<u8>, String> {
    let entry = zip
        .by_name(name)
        .map_err(|_| "attachment missing from archive".to_string())?;
    if entry.size() > MAX_ATTACHMENT_BYTES {
        return Err("attachment too large".into());
    }
    let mut bytes = Vec::new();
    entry
        .take(MAX_ATTACHMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "attachment unreadable".to_string())?;
    if bytes.len() as u64 > MAX_ATTACHMENT_BYTES {
        return Err("attachment too large".into());
    }
    *total += bytes.len() as u64;
    if *total > MAX_TOTAL_ATTACHMENT_BYTES {
        return Err("attachments exceed the total size limit".into());
    }
    Ok(bytes)
}

/// Parse `export.data`. Attachment references are resolved only when
/// parsing a whole archive.
pub fn parse_str(text: &str) -> Result<ParsedImport> {
    Ok(parse_document(text)?.0)
}

type DocumentRefs = Vec<Vec<(String, String)>>;

fn parse_document(text: &str) -> Result<(ParsedImport, DocumentRefs)> {
    let doc: Value = serde_json::from_str(text)?;
    let mut out = ParsedImport::default();
    let mut documents: DocumentRefs = Vec::new();
    for account in array(&doc, "accounts") {
        for vault in array(account, "vaults") {
            let category = vault
                .pointer("/attrs/name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            for item in array(vault, "items") {
                let mut docs = Vec::new();
                parse_item(item, category.clone(), &mut out, &mut docs);
                if out.candidates.len() > documents.len() {
                    documents.push(docs);
                }
            }
        }
    }
    Ok((out, documents))
}

fn array<'a>(value: &'a Value, key: &str) -> impl Iterator<Item = &'a Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn parse_item(
    item: &Value,
    category: Option<String>,
    out: &mut ParsedImport,
    documents: &mut Vec<(String, String)>,
) {
    let overview = item.get("overview").unwrap_or(&Value::Null);
    let details = item.get("details").unwrap_or(&Value::Null);
    let category_uuid = item
        .get("categoryUuid")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let title = text(overview.get("title")).unwrap_or_else(|| "Untitled".into());
    if item.get("state").and_then(Value::as_str) == Some("deleted") {
        out.skip(&title, "deleted in 1Password");
        return;
    }

    let mut entry = NewEntry {
        title: title.clone(),
        category,
        ..NewEntry::default()
    };

    // Login fields: username/password designations; the rest are kept.
    let mut extra_login = Vec::new();
    for field in array(details, "loginFields") {
        let designation = field
            .get("designation")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let name = field
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let value = text(field.get("value"));
        match (designation, value) {
            (_, None) => {}
            ("username", Some(v)) => entry.username = Some(v),
            ("password", Some(v)) => entry.password = v,
            (_, Some(v)) if name.eq_ignore_ascii_case("username") && entry.username.is_none() => {
                entry.username = Some(v)
            }
            (_, Some(v)) if name.eq_ignore_ascii_case("password") && entry.password.is_empty() => {
                entry.password = v
            }
            (_, Some(v)) => extra_login.push(format!("{name}: {v}")),
        }
    }
    if entry.password.is_empty() {
        if let Some(password) = text(details.get("password")) {
            entry.password = password;
        }
    }

    let mut urls: Vec<String> = text(overview.get("url")).into_iter().collect();
    for url in array(overview, "urls") {
        if let Some(u) = text(url.get("url")) {
            if !urls.contains(&u) {
                urls.push(u);
            }
        }
    }
    let mut urls = urls.into_iter();
    entry.url = urls.next();
    entry.notes = text(details.get("notesPlain"));

    // Sections: first TOTP becomes the entry TOTP; everything else is kept
    // as text in the notes.
    let mut totp_seen = false;
    let mut section_lines = Vec::new();
    for section in array(details, "sections") {
        let heading = text(section.get("title"));
        let mut lines = Vec::new();
        for field in array(section, "fields") {
            let label = text(field.get("title")).unwrap_or_else(|| "Field".into());
            let value = field.get("value").unwrap_or(&Value::Null);
            if let Some(raw) = value.get("totp").and_then(Value::as_str) {
                if !totp_seen && !raw.trim().is_empty() {
                    totp_seen = true;
                    otp::attach(&mut entry, otp::parse_field(raw), &mut out.warnings);
                    continue;
                }
            }
            if let Some(rendered) = render_value(value) {
                lines.push(format!("{label}: {rendered}"));
            }
        }
        if !lines.is_empty() {
            match heading {
                Some(h) => section_lines.push(format!("{h}\n{}", lines.join("\n"))),
                None => section_lines.push(lines.join("\n")),
            }
        }
    }

    let extra_urls: Vec<String> = urls.collect();
    if !extra_urls.is_empty() {
        otp::append_note(
            &mut entry,
            &format!("Additional URLs:\n{}", extra_urls.join("\n")),
        );
    }
    if !extra_login.is_empty() {
        otp::append_note(
            &mut entry,
            &format!("Other login fields:\n{}", extra_login.join("\n")),
        );
    }
    for section in section_lines {
        otp::append_note(&mut entry, &section);
    }

    match category_uuid {
        "001" | "005" | "003" => {}
        _ => out
            .warnings
            .push(ImportIssue::new(&title, "item fields stored in notes")),
    }

    let history = array(details, "passwordHistory")
        .filter_map(|h| {
            let password = text(h.get("value"))?;
            Some((password, h.get("time").and_then(Value::as_i64)))
        })
        .filter(|(p, _)| *p != entry.password)
        .collect();

    if let Some(attrs) = details.get("documentAttributes") {
        if let (Some(id), Some(name)) = (text(attrs.get("documentId")), text(attrs.get("fileName")))
        {
            documents.push((id, name));
        }
    }

    let tags = array(overview, "tags")
        .filter_map(|t| text(Some(t)))
        .collect();
    let favorite = item
        .get("favIndex")
        .and_then(Value::as_i64)
        .is_some_and(|i| i > 0);
    out.push(ImportCandidate {
        entry,
        favorite,
        tags,
        history,
        attachments: Vec::new(),
    });
}

/// Turn a 1PUX field value (`{"string": "x"}`, `{"email": {...}}`, …) into
/// display text.
fn render_value(value: &Value) -> Option<String> {
    match value {
        Value::String(s) if !s.trim().is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Object(map) => {
            let parts: Vec<String> = map.values().filter_map(render_value).collect();
            (!parts.is_empty()).then(|| parts.join(", "))
        }
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().filter_map(render_value).collect();
            (!parts.is_empty()).then(|| parts.join(", "))
        }
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
    use std::io::Write;

    const EXPORT: &str = r#"{
      "accounts": [{
        "vaults": [{
          "attrs": {"name": "Personal"},
          "items": [
            {"categoryUuid": "001", "favIndex": 1,
             "overview": {"title": "Example", "url": "https://example.com",
                          "urls": [{"url": "https://example.com"}, {"url": "https://alt.example.com"}],
                          "tags": ["work"]},
             "details": {
               "loginFields": [
                 {"designation": "username", "value": "alice"},
                 {"designation": "password", "value": "hunter2"},
                 {"name": "remember", "value": "true"}
               ],
               "sections": [{"title": "Security", "fields": [
                 {"title": "one-time password",
                  "value": {"totp": "otpauth://totp/Ex:alice?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60"}},
                 {"title": "PIN", "value": {"concealed": "4321"}}
               ]}],
               "notesPlain": "the note",
               "passwordHistory": [{"value": "old-pw", "time": 1700000000}]
             }},
            {"categoryUuid": "003", "overview": {"title": "Note"}, "details": {"notesPlain": "text"}},
            {"categoryUuid": "002", "overview": {"title": "Card"},
             "details": {"sections": [{"fields": [
               {"title": "number", "value": {"creditCardNumber": "4111111111111111"}}]}]}},
            {"categoryUuid": "006", "overview": {"title": "Document"},
             "details": {"documentAttributes": {"fileName": "doc.txt", "documentId": "d1"}}}
          ]
        }]
      }]
    }"#;

    fn archive(include_file: bool) -> Vec<u8> {
        let mut buffer = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buffer);
            let options = zip::write::SimpleFileOptions::default();
            zip.start_file("export.data", options).unwrap();
            zip.write_all(EXPORT.as_bytes()).unwrap();
            if include_file {
                zip.start_file("files/d1__doc.txt", options).unwrap();
                zip.write_all(b"document body").unwrap();
            }
            zip.finish().unwrap();
        }
        buffer.into_inner()
    }

    #[test]
    fn parses_all_categories_from_archive() {
        let parsed = parse_archive(std::io::Cursor::new(archive(true))).unwrap();
        assert_eq!(parsed.candidates.len(), 4);
        assert!(parsed.skipped.is_empty());

        let login = &parsed.candidates[0];
        assert!(login.favorite);
        assert_eq!(login.tags, vec!["work"]);
        let e = &login.entry;
        assert_eq!(e.username.as_deref(), Some("alice"));
        assert_eq!(e.password, "hunter2");
        assert_eq!(e.category.as_deref(), Some("Personal"));
        assert_eq!(e.totp_algorithm.as_deref(), Some("SHA256"));
        assert_eq!(e.totp_digits, Some(8));
        assert_eq!(e.totp_period, Some(60));
        let notes = e.notes.as_deref().unwrap();
        assert!(notes.starts_with("the note"));
        assert!(notes.contains("https://alt.example.com"));
        assert!(notes.contains("PIN: 4321"));
        assert!(notes.contains("remember: true"));
        assert_eq!(login.history, vec![("old-pw".into(), Some(1_700_000_000))]);

        assert_eq!(parsed.candidates[1].entry.notes.as_deref(), Some("text"));
        assert!(parsed.candidates[2]
            .entry
            .notes
            .as_deref()
            .unwrap()
            .contains("4111111111111111"));
        assert_eq!(
            parsed.candidates[3].attachments,
            vec![("doc.txt".into(), b"document body".to_vec())]
        );
        // Card and document categories store their fields in notes.
        assert_eq!(parsed.warnings.len(), 2);
    }

    #[test]
    fn missing_attachment_is_a_warning() {
        let parsed = parse_archive(std::io::Cursor::new(archive(false))).unwrap();
        assert!(parsed.candidates[3].attachments.is_empty());
        assert!(parsed.warnings.iter().any(|w| w.reason.contains("missing")));
    }

    #[test]
    fn rejects_archives_without_export_data() {
        let mut buffer = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buffer);
            zip.start_file("other", zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.finish().unwrap();
        }
        assert!(parse_archive(std::io::Cursor::new(buffer.into_inner())).is_err());
    }

    #[test]
    fn import_into_vault_counts_items() {
        let (directory, vault) = crate::importers::report::tests::test_vault();
        let path = directory.path().join("export.1pux");
        std::fs::write(&path, archive(true)).unwrap();
        let preview = preview_file(&vault, &path).unwrap();
        assert_eq!(preview.recognized, 4);
        let report = import_into_vault(&vault, &path).unwrap();
        assert_eq!(report.imported, 4);
        assert_eq!(report.warnings.len(), 2);
        let again = import_into_vault(&vault, &path).unwrap();
        // The document carries an attachment, so it is never an exact dup.
        assert_eq!(again.duplicates, 3);
        assert_eq!(again.imported, 1);
    }
}
