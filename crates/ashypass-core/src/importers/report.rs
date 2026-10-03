//! Shared import pipeline.
//!
//! Every source parses into a [`ParsedImport`] (no vault access), which can
//! then be previewed ([`preview`]) or written ([`apply`]). Writing happens in
//! a single vault transaction: a hard error (database, crypto, I/O) rolls the
//! whole import back, while per-item validation problems are reported in the
//! returned [`ImportReport`] instead of being dropped silently.

use crate::db::vault::{NewEntry, Vault};
use crate::importers::otp;
use crate::{Error, Result};
use std::collections::HashMap;

/// One item that was not imported (or imported with an adjustment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportIssue {
    pub title: String,
    pub reason: String,
}

impl ImportIssue {
    pub fn new(title: &str, reason: &str) -> Self {
        let title = title.trim();
        Self {
            title: if title.is_empty() {
                "Untitled".into()
            } else {
                title.to_string()
            },
            reason: reason.to_string(),
        }
    }
}

/// Outcome of an import. `imported + duplicates + skipped.len() +
/// failed.len()` equals the number of items found in the source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub imported: usize,
    /// Items the vault cannot represent (unsupported type, recycle bin, …).
    pub skipped: Vec<ImportIssue>,
    /// Items that were recognised but rejected while writing.
    pub failed: Vec<ImportIssue>,
    /// Exact duplicates of entries already in the vault (or earlier in the
    /// same file) that were not imported again.
    pub duplicates: usize,
    /// Imported items that needed an adjustment, e.g. an unsupported TOTP
    /// kept in the notes. Already counted in `imported`.
    pub warnings: Vec<ImportIssue>,
}

impl ImportReport {
    /// True when every item in the source was imported unchanged (exact
    /// duplicates excepted).
    pub fn is_complete(&self) -> bool {
        self.skipped.is_empty() && self.failed.is_empty() && self.warnings.is_empty()
    }

    /// Short English summary, e.g. "12 imported, 2 duplicates, 1 skipped".
    pub fn summary(&self) -> String {
        let mut parts = vec![format!("{} imported", self.imported)];
        if self.duplicates > 0 {
            parts.push(format!("{} duplicates", self.duplicates));
        }
        if !self.skipped.is_empty() {
            parts.push(format!("{} skipped", self.skipped.len()));
        }
        if !self.failed.is_empty() {
            parts.push(format!("{} failed", self.failed.len()));
        }
        if !self.warnings.is_empty() {
            parts.push(format!("{} with warnings", self.warnings.len()));
        }
        parts.join(", ")
    }

    /// Every skipped, failed and warning item as `title: reason` lines.
    pub fn issue_lines(&self) -> Vec<String> {
        self.skipped
            .iter()
            .chain(&self.failed)
            .chain(&self.warnings)
            .map(|issue| format!("{}: {}", issue.title, issue.reason))
            .collect()
    }
}

/// What an import would do, computed without writing anything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportPreview {
    /// Items that would be imported.
    pub recognized: usize,
    /// Exact duplicates that would be skipped.
    pub duplicates: usize,
    /// Items matching an existing entry by title, username and URL but with
    /// different content. They are imported (nothing is overwritten).
    pub similar: usize,
    /// Items that cannot be imported, with the reason.
    pub unsupported: Vec<ImportIssue>,
    /// Items that would be imported with an adjustment.
    pub warnings: Vec<ImportIssue>,
}

impl ImportPreview {
    pub fn summary(&self) -> String {
        let mut parts = vec![format!("{} items recognized", self.recognized)];
        if self.duplicates > 0 {
            parts.push(format!("{} duplicates", self.duplicates));
        }
        if self.similar > 0 {
            parts.push(format!("{} similar to existing entries", self.similar));
        }
        if !self.unsupported.is_empty() {
            parts.push(format!("{} unsupported", self.unsupported.len()));
        }
        if !self.warnings.is_empty() {
            parts.push(format!("{} with warnings", self.warnings.len()));
        }
        parts.join(", ")
    }
}

/// An entry ready to be written, plus metadata `NewEntry` does not carry.
#[derive(Debug, Clone, Default)]
pub struct ImportCandidate {
    pub entry: NewEntry,
    pub favorite: bool,
    pub tags: Vec<String>,
    /// Previous passwords as `(password, changed_at unix seconds)`.
    pub history: Vec<(String, Option<i64>)>,
    /// File attachments as `(file name, contents)`.
    pub attachments: Vec<(String, Vec<u8>)>,
}

impl From<NewEntry> for ImportCandidate {
    fn from(entry: NewEntry) -> Self {
        Self {
            entry,
            ..Self::default()
        }
    }
}

/// Parsed, not yet written, content of an import source.
#[derive(Debug, Clone, Default)]
pub struct ParsedImport {
    pub candidates: Vec<ImportCandidate>,
    /// Items found in the source that the vault cannot represent.
    pub skipped: Vec<ImportIssue>,
    /// Adjustments made while parsing (counted with the candidates).
    pub warnings: Vec<ImportIssue>,
    /// Folders to create even when empty.
    pub folders: Vec<String>,
}

impl ParsedImport {
    pub fn skip(&mut self, title: &str, reason: &str) {
        self.skipped.push(ImportIssue::new(title, reason));
    }

    pub fn push(&mut self, candidate: impl Into<ImportCandidate>) {
        self.candidates.push(candidate.into());
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DuplicatePolicy {
    /// Skip items identical to an existing entry (same title, username, URL,
    /// password, and no new notes/TOTP). Default.
    #[default]
    SkipExact,
    /// Import everything, even exact duplicates.
    ImportAll,
}

/// Preview `parsed` against the current vault contents.
pub fn preview(vault: &Vault, parsed: &ParsedImport) -> Result<ImportPreview> {
    let mut index = DuplicateIndex::load(vault)?;
    let mut out = ImportPreview {
        unsupported: parsed.skipped.clone(),
        warnings: parsed.warnings.clone(),
        ..ImportPreview::default()
    };
    for candidate in &parsed.candidates {
        let mut entry = candidate.entry.clone();
        sanitize_totp(&mut entry, &mut out.warnings);
        if let Err(reason) = validate(&entry) {
            out.unsupported
                .push(ImportIssue::new(&entry.title, &reason));
            continue;
        }
        let mut class = index.classify(vault, &entry)?;
        if class == Match::Exact && !candidate.attachments.is_empty() {
            // Attachments are not compared, so the item is imported.
            class = Match::Similar;
        }
        match class {
            Match::Exact => out.duplicates += 1,
            Match::Similar => {
                out.similar += 1;
                out.recognized += 1;
                index.remember(&entry);
            }
            Match::New => {
                out.recognized += 1;
                index.remember(&entry);
            }
        }
    }
    Ok(out)
}

/// Write `parsed` into the vault, skipping exact duplicates.
pub fn apply(vault: &Vault, parsed: ParsedImport) -> Result<ImportReport> {
    apply_with(vault, parsed, DuplicatePolicy::SkipExact)
}

/// Write `parsed` into the vault in a single transaction.
pub fn apply_with(
    vault: &Vault,
    parsed: ParsedImport,
    policy: DuplicatePolicy,
) -> Result<ImportReport> {
    let mut index = DuplicateIndex::load(vault)?;
    vault.transaction(|| {
        let mut report = ImportReport {
            skipped: parsed.skipped,
            warnings: parsed.warnings,
            ..ImportReport::default()
        };
        for folder in parsed.folders.iter().filter(|f| !f.trim().is_empty()) {
            vault.create_folder(folder)?;
        }
        for candidate in parsed.candidates {
            let mut entry = candidate.entry;
            sanitize_totp(&mut entry, &mut report.warnings);
            if let Err(reason) = validate(&entry) {
                report.failed.push(ImportIssue::new(&entry.title, &reason));
                continue;
            }
            if policy == DuplicatePolicy::SkipExact
                && candidate.attachments.is_empty()
                && index.classify(vault, &entry)? == Match::Exact
            {
                report.duplicates += 1;
                continue;
            }
            let title = entry.title.clone();
            let remembered = entry.clone();
            match vault.add(entry) {
                Ok(id) => {
                    if candidate.favorite {
                        vault.set_favorite(id, true)?;
                    }
                    if !candidate.tags.is_empty() {
                        vault.set_tags(id, &candidate.tags)?;
                    }
                    for (password, changed_at) in &candidate.history {
                        vault.append_password_history(id, password, *changed_at)?;
                    }
                    for (name, data) in &candidate.attachments {
                        vault.add_attachment(id, name, None, data)?;
                    }
                    index.remember(&remembered);
                    report.imported += 1;
                }
                // Validation problems are per-item; anything else (SQLite,
                // crypto, I/O) aborts and rolls back the whole import.
                Err(Error::InvalidInput(reason)) => {
                    report.failed.push(ImportIssue::new(&title, &reason));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(report)
    })
}

/// Move a TOTP the vault would reject into the notes instead of failing the
/// whole item.
fn sanitize_totp(entry: &mut NewEntry, warnings: &mut Vec<ImportIssue>) {
    let Some(secret) = entry.totp_secret.clone().filter(|s| !s.trim().is_empty()) else {
        entry.totp_secret = None;
        return;
    };
    let field = otp::from_parts(
        &secret,
        &secret,
        entry.totp_algorithm.as_deref().unwrap_or("SHA1"),
        entry.totp_digits.unwrap_or(6),
        entry.totp_period.unwrap_or(30),
    );
    entry.totp_secret = None;
    entry.totp_algorithm = None;
    entry.totp_digits = None;
    entry.totp_period = None;
    otp::attach(entry, field, warnings);
}

fn validate(entry: &NewEntry) -> std::result::Result<(), String> {
    let has_content = !entry.title.trim().is_empty()
        || !entry.password.is_empty()
        || entry.username.as_deref().is_some_and(|s| !s.is_empty())
        || entry.url.as_deref().is_some_and(|s| !s.is_empty())
        || entry.notes.as_deref().is_some_and(|s| !s.is_empty())
        || entry.totp_secret.is_some();
    if !has_content {
        return Err("item is empty".into());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Match {
    New,
    Similar,
    Exact,
}

type Key = (String, String, String);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Fingerprint {
    password: String,
    notes: String,
    totp: String,
}

#[derive(Default)]
struct KeyState {
    ids: Vec<i64>,
    /// Decrypted lazily, only for keys that an imported item collides with.
    loaded: Option<Vec<Fingerprint>>,
}

/// Index of existing entries by (title, username, url).
struct DuplicateIndex {
    by_key: HashMap<Key, KeyState>,
}

fn key_of(title: &str, username: Option<&str>, url: Option<&str>) -> Key {
    (
        title.trim().to_string(),
        username.unwrap_or_default().trim().to_string(),
        url.unwrap_or_default().trim().to_string(),
    )
}

fn fingerprint_of(entry: &NewEntry) -> Fingerprint {
    Fingerprint {
        password: entry.password.clone(),
        notes: entry.notes.clone().unwrap_or_default(),
        totp: entry
            .totp_secret
            .as_deref()
            .map(otp::normalize_secret)
            .unwrap_or_default(),
    }
}

impl DuplicateIndex {
    fn load(vault: &Vault) -> Result<Self> {
        let mut by_key: HashMap<Key, KeyState> = HashMap::new();
        for summary in vault.list(None)? {
            by_key
                .entry(key_of(
                    &summary.title,
                    summary.username.as_deref(),
                    summary.url.as_deref(),
                ))
                .or_default()
                .ids
                .push(summary.id);
        }
        Ok(Self { by_key })
    }

    fn loaded_state(&mut self, vault: &Vault, key: &Key) -> Result<Option<&mut Vec<Fingerprint>>> {
        let Some(state) = self.by_key.get_mut(key) else {
            return Ok(None);
        };
        if state.loaded.is_none() {
            let mut fingerprints = Vec::with_capacity(state.ids.len());
            for id in &state.ids {
                if let Some(full) = vault.get_without_touch(*id)? {
                    fingerprints.push(Fingerprint {
                        password: full.password.unwrap_or_default(),
                        notes: full.notes.unwrap_or_default(),
                        totp: full
                            .totp_secret
                            .as_deref()
                            .map(otp::normalize_secret)
                            .unwrap_or_default(),
                    });
                }
            }
            state.loaded = Some(fingerprints);
        }
        Ok(state.loaded.as_mut())
    }

    fn classify(&mut self, vault: &Vault, entry: &NewEntry) -> Result<Match> {
        let key = key_of(
            &entry.title,
            entry.username.as_deref(),
            entry.url.as_deref(),
        );
        let candidate = fingerprint_of(entry);
        let Some(existing) = self.loaded_state(vault, &key)? else {
            return Ok(Match::New);
        };
        // Exact means importing would add nothing: same password and the
        // candidate brings no notes/TOTP the existing entry lacks.
        let exact = existing.iter().any(|known| {
            known.password == candidate.password
                && (candidate.notes.is_empty() || candidate.notes == known.notes)
                && (candidate.totp.is_empty() || candidate.totp == known.totp)
        });
        Ok(if exact {
            Match::Exact
        } else if existing.is_empty() {
            Match::New
        } else {
            Match::Similar
        })
    }

    /// Record an item that is (or would be) imported so later copies in the
    /// same file are detected as duplicates.
    fn remember(&mut self, entry: &NewEntry) {
        let key = key_of(
            &entry.title,
            entry.username.as_deref(),
            entry.url.as_deref(),
        );
        let state = self.by_key.entry(key).or_default();
        state
            .loaded
            .get_or_insert_with(Vec::new)
            .push(fingerprint_of(entry));
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn test_vault() -> (tempfile::TempDir, Vault) {
        let directory = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(directory.path().join("vault.db")).unwrap();
        vault.set_master_password("correct horse battery").unwrap();
        (directory, vault)
    }

    fn login(title: &str, password: &str) -> ImportCandidate {
        NewEntry {
            title: title.into(),
            username: Some("alice".into()),
            url: Some("https://example.com".into()),
            password: password.into(),
            ..NewEntry::default()
        }
        .into()
    }

    #[test]
    fn duplicates_are_counted_not_reimported() {
        let (_dir, vault) = test_vault();
        vault.add(login("Example", "one").entry).unwrap();

        let mut parsed = ParsedImport::default();
        parsed.push(login("Example", "one")); // exact duplicate of vault entry
        parsed.push(login("Example", "two")); // similar: imported
        parsed.push(login("Example", "two")); // duplicate within the file
        parsed.push(login("Other", "x"));
        parsed.skip("Card", "unsupported");

        let preview = preview(&vault, &parsed).unwrap();
        assert_eq!(preview.recognized, 2);
        assert_eq!(preview.duplicates, 2);
        assert_eq!(preview.similar, 1);
        assert_eq!(preview.unsupported.len(), 1);
        assert_eq!(vault.list(None).unwrap().len(), 1, "preview must not write");

        let report = apply(&vault, parsed).unwrap();
        assert_eq!(report.imported, 2);
        assert_eq!(report.duplicates, 2);
        assert_eq!(report.skipped.len(), 1);
        assert!(!report.is_complete());
        assert_eq!(vault.list(None).unwrap().len(), 3);
    }

    #[test]
    fn duplicate_with_new_totp_is_not_skipped() {
        let (_dir, vault) = test_vault();
        vault.add(login("Example", "one").entry).unwrap();
        let mut candidate = login("Example", "one");
        candidate.entry.totp_secret = Some("JBSWY3DPEHPK3PXP".into());
        let parsed = ParsedImport {
            candidates: vec![candidate],
            ..ParsedImport::default()
        };
        let report = apply(&vault, parsed).unwrap();
        assert_eq!(report.imported, 1);
        assert_eq!(report.duplicates, 0);
    }

    #[test]
    fn import_all_policy_keeps_duplicates() {
        let (_dir, vault) = test_vault();
        vault.add(login("Example", "one").entry).unwrap();
        let parsed = ParsedImport {
            candidates: vec![login("Example", "one")],
            ..ParsedImport::default()
        };
        let report = apply_with(&vault, parsed, DuplicatePolicy::ImportAll).unwrap();
        assert_eq!(report.imported, 1);
        assert_eq!(vault.list(None).unwrap().len(), 2);
    }

    #[test]
    fn passwordless_and_invalid_totp_items_are_kept() {
        let (_dir, vault) = test_vault();
        let mut parsed = ParsedImport::default();
        parsed.push(NewEntry {
            title: "2FA only".into(),
            totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
            ..NewEntry::default()
        });
        parsed.push(NewEntry {
            title: "Bad TOTP".into(),
            password: "pw".into(),
            totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
            totp_digits: Some(7),
            ..NewEntry::default()
        });
        parsed.push(NewEntry::default());
        let report = apply(&vault, parsed).unwrap();
        assert_eq!(report.imported, 2);
        assert_eq!(report.failed.len(), 1, "the empty item is reported");
        assert_eq!(report.warnings.len(), 1);
        let bad = vault
            .list(None)
            .unwrap()
            .into_iter()
            .find(|e| e.title == "Bad TOTP")
            .unwrap();
        let bad = vault.get_without_touch(bad.id).unwrap().unwrap();
        assert!(bad.totp_secret.is_none());
        assert!(bad.notes.unwrap().contains("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn hard_errors_roll_back_the_whole_import() {
        let (_dir, vault) = test_vault();
        vault.add(login("Before", "x").entry).unwrap();
        let generation = vault.current_generation().unwrap();
        // A trigger makes the *second* insert fail with an SQLite error, after
        // the first one already succeeded inside the transaction.
        let side = rusqlite::Connection::open(vault.db_path()).unwrap();
        side.execute_batch(
            "CREATE TRIGGER fail_b BEFORE INSERT ON passwords
             WHEN NEW.title = 'B' BEGIN SELECT RAISE(ABORT, 'boom'); END;",
        )
        .unwrap();
        drop(side);

        let mut parsed = ParsedImport::default();
        parsed.push(login("A", "1"));
        parsed.push(login("B", "2"));
        parsed.folders.push("New folder".into());
        assert!(apply(&vault, parsed).is_err());
        let titles: Vec<String> = vault
            .list(None)
            .unwrap()
            .into_iter()
            .map(|e| e.title)
            .collect();
        assert_eq!(titles, vec!["Before"]);
        assert!(!vault
            .categories()
            .unwrap()
            .contains(&"New folder".to_string()));
        assert_eq!(vault.current_generation().unwrap(), generation);
    }

    #[test]
    fn rollback_discards_rows_written_before_the_error() {
        let (_dir, vault) = test_vault();
        let result: Result<()> = vault.transaction(|| {
            vault.add(login("A", "1").entry)?;
            Err(Error::Other("boom".into()))
        });
        assert!(result.is_err());
        assert!(vault.list(None).unwrap().is_empty());
    }

    #[test]
    fn summaries_are_readable() {
        let report = ImportReport {
            imported: 3,
            duplicates: 1,
            skipped: vec![ImportIssue::new("", "x")],
            ..ImportReport::default()
        };
        assert_eq!(report.summary(), "3 imported, 1 duplicates, 1 skipped");
        assert_eq!(report.issue_lines(), vec!["Untitled: x"]);
    }
}
