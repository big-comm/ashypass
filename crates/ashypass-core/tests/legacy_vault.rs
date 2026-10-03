//! A vault written by Ashy Pass 3.0.1 — the release before the redesign —
//! must open and read back completely with the current code.
//!
//! `tests/fixtures/v3_0_1/passwords.db` and `quick_unlock.json` were produced
//! by `make_fixture.rs.txt` (same folder) compiled against commit 9043f07.
//! Every test works on a copy: opening a vault may upgrade it in place.

use ashypass_core::db::vault::Vault;
use ashypass_core::settings::QuickUnlockPrefs;
use std::path::{Path, PathBuf};

const MASTER: &str = "old master password 123";
const PIN: &str = "123456";

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v3_0_1")
}

fn copy_of_fixture() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("passwords.db");
    std::fs::copy(fixture_dir().join("passwords.db"), &db).unwrap();
    (dir, db)
}

fn legacy_prefs() -> QuickUnlockPrefs {
    let text = std::fs::read_to_string(fixture_dir().join("quick_unlock.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn by_title(vault: &Vault, title: &str) -> ashypass_core::db::PasswordEntry {
    let summary = vault
        .list(None)
        .unwrap()
        .into_iter()
        .find(|e| e.title == title)
        .unwrap_or_else(|| panic!("entry {title} missing"));
    vault.get_without_touch(summary.id).unwrap().unwrap()
}

/// Everything the 3.0.1 fixture stored, read back field by field.
fn assert_all_data(vault: &Vault) {
    let titles: Vec<String> = vault
        .list(None)
        .unwrap()
        .into_iter()
        .map(|e| e.title)
        .collect();
    assert_eq!(titles.len(), 4, "{titles:?}");

    let bank = by_title(vault, "Banco");
    assert_eq!(bank.password.as_deref(), Some("s3nh@-banco"));
    assert_eq!(bank.notes.as_deref(), Some("agência 0001\nconta 12345"));
    assert_eq!(bank.category.as_deref(), Some("Pessoal"));
    assert!(bank.favorite);
    let mut tags = vault.tags_of(bank.id).unwrap();
    tags.sort();
    assert_eq!(tags, vec!["banco".to_string(), "importante".to_string()]);

    let github = by_title(vault, "GitHub");
    assert_eq!(github.password.as_deref(), Some("gh-pass-3"));
    assert_eq!(github.totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    let history: Vec<String> = vault
        .password_history(github.id)
        .unwrap()
        .into_iter()
        .map(|h| h.password)
        .collect();
    assert!(history.contains(&"gh-pass-1".to_string()), "{history:?}");
    assert!(history.contains(&"gh-pass-2".to_string()), "{history:?}");

    let server = by_title(vault, "Servidor");
    let attachments = vault.list_attachments(server.id).unwrap();
    assert_eq!(attachments.len(), 1);
    let (_, data) = vault.get_attachment(attachments[0].id).unwrap().unwrap();
    assert_eq!(data, b"segredo do anexo");

    let totp_only = by_title(vault, "Só TOTP");
    assert_eq!(totp_only.totp_secret.as_deref(), Some("GEZDGNBVGY3TQOJQ"));
    assert_eq!(totp_only.totp_algorithm, "SHA256");
    assert_eq!(totp_only.totp_digits, 8);
    assert_eq!(totp_only.totp_period, 60);

    let folders = vault.categories().unwrap();
    for folder in ["Pessoal", "Trabalho", "Vazia", "2FA"] {
        assert!(folders.contains(&folder.to_string()), "{folders:?}");
    }
    let trash = vault.list_trash().unwrap();
    assert!(trash.iter().any(|t| t.title == "Apagar"));
}

#[test]
fn opens_and_reads_every_field() {
    let (_dir, db) = copy_of_fixture();
    let mut vault = Vault::open(&db).unwrap();
    assert!(matches!(
        vault.unlock("wrong password"),
        Err(ashypass_core::Error::InvalidMasterPassword)
    ));
    vault.unlock(MASTER).unwrap();
    assert_all_data(&vault);

    // Reopen after the first unlock wrote its key check: still all there.
    drop(vault);
    let mut vault = Vault::open(&db).unwrap();
    vault.unlock(MASTER).unwrap();
    assert_all_data(&vault);
}

#[test]
fn background_unlock_path_matches_the_synchronous_one() {
    let (_dir, db) = copy_of_fixture();
    let mut vault = Vault::open(&db).unwrap();
    let inputs = vault.unlock_inputs().unwrap().expect("fast path available");
    assert!(ashypass_core::db::derive_unlock_key("nope", &inputs).is_err());
    let key = ashypass_core::db::derive_unlock_key(MASTER, &inputs).unwrap();
    vault.unlock_with_key(&inputs, key).unwrap();
    assert_all_data(&vault);
}

#[test]
fn old_pin_record_still_unlocks_and_is_upgraded() {
    let (_dir, db) = copy_of_fixture();
    let prefs = legacy_prefs();
    assert!(prefs.needs_upgrade(), "3.0.1 records carry a PIN hash");

    let mut vault = Vault::open(&db).unwrap();
    assert!(matches!(
        vault.quick_unlock_persistent_upgrading("000000", &prefs),
        Err(ashypass_core::Error::InvalidMasterPassword)
    ));
    let upgraded = vault
        .quick_unlock_persistent_upgrading(PIN, &prefs)
        .unwrap()
        .expect("old record is rewritten");
    assert!(upgraded.pin_hash.is_empty());
    assert!(!upgraded.needs_upgrade());
    assert_all_data(&vault);

    // The rewritten record works on its own.
    vault.full_lock();
    let mut fresh = Vault::open(&db).unwrap();
    assert!(fresh
        .quick_unlock_persistent_upgrading(PIN, &upgraded)
        .unwrap()
        .is_none());
    assert_all_data(&fresh);
}

#[test]
fn changing_the_master_password_keeps_every_field() {
    let (_dir, db) = copy_of_fixture();
    let mut vault = Vault::open(&db).unwrap();
    vault.unlock(MASTER).unwrap();
    vault
        .change_master_password(MASTER, "a brand new master password")
        .unwrap();
    drop(vault);
    let mut vault = Vault::open(&db).unwrap();
    assert!(vault.unlock(MASTER).is_err());
    vault.unlock("a brand new master password").unwrap();
    assert_all_data(&vault);
    // The old PIN record wraps the old key: it must not open the vault.
    let mut other = Vault::open(&db).unwrap();
    assert!(other
        .quick_unlock_persistent_upgrading(PIN, &legacy_prefs())
        .is_err());
}

#[test]
fn backup_and_full_restore_round_trip() {
    let (dir, db) = copy_of_fixture();
    let mut vault = Vault::open(&db).unwrap();
    vault.unlock(MASTER).unwrap();
    let backup = dir.path().join("copy.ashy");
    ashypass_core::importers::ashy::export_vault(&vault, &backup, "file password").unwrap();
    drop(vault);

    // Restore over a different, newer vault; it must be kept aside.
    let live = dir.path().join("live.db");
    let mut other = Vault::open(&live).unwrap();
    other.set_master_password("someone else's vault").unwrap();
    drop(other);
    let outcome = ashypass_core::backup::restore_db_snapshot_with(
        &live,
        &backup,
        MASTER,
        Some("file password"),
    )
    .unwrap();
    let previous = outcome.previous_copy.expect("previous vault kept");
    assert!(previous.exists());
    let mut kept = Vault::open(&previous).unwrap();
    kept.unlock("someone else's vault").unwrap();

    let mut restored = Vault::open(&live).unwrap();
    restored.unlock(MASTER).unwrap();
    assert_all_data(&restored);
}

#[test]
fn a_wrong_restore_password_changes_nothing() {
    let (dir, db) = copy_of_fixture();
    let mut vault = Vault::open(&db).unwrap();
    vault.unlock(MASTER).unwrap();
    let backup = dir.path().join("copy.ashy");
    ashypass_core::importers::ashy::export_vault(&vault, &backup, "file password").unwrap();
    drop(vault);
    let before = std::fs::read(&db).unwrap();
    assert!(ashypass_core::backup::restore_db_snapshot_with(
        &db,
        &backup,
        MASTER,
        Some("not the file password"),
    )
    .is_err());
    assert_eq!(std::fs::read(&db).unwrap(), before);
}

#[test]
fn merging_a_backup_skips_what_is_already_there() {
    let (dir, db) = copy_of_fixture();
    let mut vault = Vault::open(&db).unwrap();
    vault.unlock(MASTER).unwrap();
    let backup = dir.path().join("copy.ashy");
    ashypass_core::importers::ashy::export_vault(&vault, &backup, "pw").unwrap();

    // Into the same vault: everything is a duplicate, nothing doubles.
    let parsed = ashypass_core::importers::ashy::parse_file(&backup, "pw").unwrap();
    let report = ashypass_core::importers::apply(&vault, parsed).unwrap();
    assert_eq!(report.imported, 0, "{report:?}");
    assert_eq!(vault.list(None).unwrap().len(), 4);

    // Into an empty vault: everything arrives.
    let fresh_db = dir.path().join("fresh.db");
    let mut fresh = Vault::open(&fresh_db).unwrap();
    fresh.set_master_password("fresh master password").unwrap();
    let parsed = ashypass_core::importers::ashy::parse_file(&backup, "pw").unwrap();
    let report = ashypass_core::importers::apply(&fresh, parsed).unwrap();
    assert_eq!(report.imported, 4, "{report:?}");
    assert!(
        report.failed.is_empty() && report.skipped.is_empty(),
        "{report:?}"
    );
    let bank = by_title(&fresh, "Banco");
    assert_eq!(bank.password.as_deref(), Some("s3nh@-banco"));
}

#[test]
fn forgotten_master_password_can_be_replaced_with_the_pin() {
    let (_dir, db) = copy_of_fixture();
    let prefs = legacy_prefs();
    let mut vault = Vault::open(&db).unwrap();
    // Locked: nothing to reset.
    assert!(vault
        .reset_master_password_with_pin(PIN, &prefs, "new master after forgetting")
        .is_err());
    vault
        .quick_unlock_persistent_upgrading(PIN, &prefs)
        .unwrap();
    assert!(matches!(
        vault.reset_master_password_with_pin("000000", &prefs, "new master after forgetting"),
        Err(ashypass_core::Error::InvalidMasterPassword)
    ));
    assert!(vault
        .reset_master_password_with_pin(PIN, &prefs, "short")
        .is_err());
    vault
        .reset_master_password_with_pin(PIN, &prefs, "new master after forgetting")
        .unwrap();
    drop(vault);

    let mut vault = Vault::open(&db).unwrap();
    assert!(vault.unlock(MASTER).is_err());
    vault.unlock("new master after forgetting").unwrap();
    assert_all_data(&vault);
}

#[test]
fn a_pin_from_another_vault_cannot_reset_this_one() {
    let (dir, db) = copy_of_fixture();
    let mut other = Vault::open(dir.path().join("other.db")).unwrap();
    other.set_master_password("another vault entirely").unwrap();
    let other_prefs = other.enable_persistent_quick_unlock("654321").unwrap();

    let mut vault = Vault::open(&db).unwrap();
    vault.unlock(MASTER).unwrap();
    assert!(matches!(
        vault.reset_master_password_with_pin("654321", &other_prefs, "new master password"),
        Err(ashypass_core::Error::KeyMismatch)
    ));
    drop(vault);
    let mut vault = Vault::open(&db).unwrap();
    vault.unlock(MASTER).unwrap();
}
