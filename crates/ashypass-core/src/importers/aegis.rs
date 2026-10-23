//! Aegis Authenticator importer, and an exporter of the vault's codes in
//! Aegis's plain format.
//!
//! Aegis exports come in two flavors:
//!   - "plain" JSON (no encryption)
//!   - encrypted JSON (scrypt + AES-256-GCM with a vault password)
//!
//! Both are read (the encrypted one with its password); both can be written.
//! HOTP, Steam, Yandex and mOTP tokens cannot be represented in the vault
//! and are reported as skipped.

use crate::db::vault::{NewEntry, Vault};
use crate::importers::otp::{self, TotpField};
use crate::importers::report::{self, ImportCandidate, ImportPreview, ImportReport, ParsedImport};
use crate::{Error, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Deserialize)]
struct AegisFile {
    /// Read only to decrypt: a plain file's header does not matter.
    #[serde(default)]
    header: serde_json::Value,
    db: serde_json::Value,
}

#[derive(Deserialize)]
struct AegisHeader {
    slots: Option<Vec<AegisSlot>>,
    params: Option<AegisParams>,
}

#[derive(Deserialize)]
struct AegisSlot {
    #[serde(rename = "type")]
    kind: u8,
    key: String,
    key_params: AegisParams,
    n: Option<u64>,
    r: Option<u32>,
    p: Option<u32>,
    salt: Option<String>,
}

#[derive(Deserialize)]
struct AegisParams {
    nonce: String,
    tag: String,
}

/// Aegis's password-slot key derivation (scrypt). Costs above 2^20 are
/// refused: a crafted file must not exhaust the phone's memory.
fn slot_key(password: &str, salt: &[u8], n: u64, r: u32, p: u32) -> Result<[u8; 32]> {
    if !n.is_power_of_two() || !(2..=1 << 20).contains(&n) || r == 0 || r > 32 || p == 0 || p > 16 {
        return Err(Error::Other("unsupported Aegis key parameters".into()));
    }
    let params = scrypt::Params::new(n.trailing_zeros() as u8, r, p, 32)
        .map_err(|e| Error::Other(format!("aegis scrypt: {e}")))?;
    let mut key = [0u8; 32];
    scrypt::scrypt(password.as_bytes(), salt, &params, &mut key)
        .map_err(|e| Error::Other(format!("aegis scrypt: {e}")))?;
    Ok(key)
}

fn gcm_open(key: &[u8; 32], params: &AegisParams, data: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit};
    let nonce = hex::decode(&params.nonce).ok()?;
    let tag = hex::decode(&params.tag).ok()?;
    if nonce.len() != 12 || tag.len() != 16 {
        return None;
    }
    let mut sealed = data.to_vec();
    sealed.extend_from_slice(&tag);
    aes_gcm::Aes256Gcm::new(key.into())
        .decrypt(aes_gcm::Nonce::from_slice(&nonce), sealed.as_slice())
        .ok()
}

/// Returns (ciphertext, params) for Aegis's split nonce/tag layout.
fn gcm_seal(key: &[u8; 32], data: &[u8]) -> Result<(Vec<u8>, serde_json::Value)> {
    use aes_gcm::aead::{Aead, KeyInit};
    use rand::RngCore;
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut sealed = aes_gcm::Aes256Gcm::new(key.into())
        .encrypt(aes_gcm::Nonce::from_slice(&nonce), data)
        .map_err(|_| Error::Crypto("aegis encrypt".into()))?;
    let tag = sealed.split_off(sealed.len() - 16);
    Ok((
        sealed,
        serde_json::json!({ "nonce": hex::encode(nonce), "tag": hex::encode(tag) }),
    ))
}

/// The plain `db` of an encrypted Aegis vault, opened with `password`.
fn decrypt_db(header: &AegisHeader, db: &str, password: &str) -> Result<serde_json::Value> {
    use base64::Engine as _;
    let params = header
        .params
        .as_ref()
        .ok_or_else(|| Error::Other("the Aegis file has no encryption parameters".into()))?;
    let slots = header.slots.as_deref().unwrap_or_default();
    let mut tried = false;
    for slot in slots.iter().filter(|s| s.kind == 1) {
        tried = true;
        let salt = hex::decode(slot.salt.as_deref().unwrap_or_default())
            .map_err(|_| Error::Other("bad Aegis salt".into()))?;
        let derived = zeroize::Zeroizing::new(slot_key(
            password,
            &salt,
            slot.n.unwrap_or(32768),
            slot.r.unwrap_or(8),
            slot.p.unwrap_or(1),
        )?);
        let wrapped = hex::decode(&slot.key).map_err(|_| Error::Other("bad Aegis key".into()))?;
        let Some(master) = gcm_open(&derived, &slot.key_params, &wrapped) else {
            continue; // another password slot may match
        };
        let master: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(
            master
                .as_slice()
                .try_into()
                .map_err(|_| Error::Other("bad Aegis key".into()))?,
        );
        let sealed = base64::engine::general_purpose::STANDARD
            .decode(db.trim())
            .map_err(|_| Error::Other("bad Aegis data".into()))?;
        let plain = zeroize::Zeroizing::new(
            gcm_open(&master, params, &sealed)
                .ok_or_else(|| Error::Other("the Aegis file is damaged".into()))?,
        );
        return serde_json::from_slice(&plain)
            .map_err(|e| Error::Other(format!("aegis json: {e}")));
    }
    if !tried {
        return Err(Error::Other(
            "this Aegis vault has no password slot (biometrics only); export it with a password"
                .into(),
        ));
    }
    Err(Error::InvalidMasterPassword)
}

#[derive(Deserialize)]
struct AegisDb {
    entries: Vec<AegisRaw>,
    #[serde(default)]
    groups: Vec<AegisGroup>,
}

#[derive(Deserialize)]
struct AegisGroup {
    uuid: String,
    name: String,
}

#[derive(Deserialize)]
struct AegisRaw {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    name: String,
    issuer: Option<String>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    favorite: bool,
    #[serde(default)]
    groups: Vec<String>,
    info: AegisInfo,
}

#[derive(Deserialize)]
struct AegisInfo {
    #[serde(default)]
    secret: String,
    algo: Option<String>,
    digits: Option<u8>,
    period: Option<u32>,
}

pub fn parse_file(path: impl AsRef<Path>) -> Result<ParsedImport> {
    parse_str(&super::read_text_limited(path)?)
}

/// An encrypted Aegis vault needs its password; a plain one ignores it.
pub fn parse_file_with_password(path: impl AsRef<Path>, password: &str) -> Result<ParsedImport> {
    parse_str_with_password(&super::read_text_limited(path)?, Some(password))
}

pub fn parse_str(text: &str) -> Result<ParsedImport> {
    parse_str_with_password(text, None)
}

/// Error text for an encrypted vault read without a password; the apps
/// recognise it to ask for one.
pub const NEEDS_PASSWORD: &str = "this Aegis vault is encrypted: enter its password";

pub fn parse_str_with_password(text: &str, password: Option<&str>) -> Result<ParsedImport> {
    let parsed: AegisFile =
        serde_json::from_str(text).map_err(|e| Error::Other(format!("aegis json: {e}")))?;
    let db_value = match (&parsed.db, password.filter(|p| !p.is_empty())) {
        (serde_json::Value::String(sealed), Some(password)) => {
            let header: AegisHeader = serde_json::from_value(parsed.header.clone())
                .map_err(|e| Error::Other(format!("aegis header: {e}")))?;
            decrypt_db(&header, sealed, password)?
        }
        (serde_json::Value::String(_), None) => {
            return Err(Error::InvalidInput(NEEDS_PASSWORD.into()));
        }
        (plain, _) => plain.clone(),
    };
    let db: AegisDb =
        serde_json::from_value(db_value).map_err(|e| Error::Other(format!("aegis json: {e}")))?;
    let group_names: HashMap<String, String> =
        db.groups.into_iter().map(|g| (g.uuid, g.name)).collect();

    let mut out = ParsedImport::default();
    for raw in db.entries {
        let issuer = raw.issuer.unwrap_or_default();
        let (title, username) = super::title_and_account(&issuer, &raw.name);
        match raw.kind.to_ascii_lowercase().as_str() {
            "totp" => {}
            "hotp" => {
                out.skip(&title, "HOTP counters are not supported");
                continue;
            }
            "steam" => {
                out.skip(&title, "Steam tokens are not supported");
                continue;
            }
            other => {
                out.skip(&title, &format!("unsupported token type: {other}"));
                continue;
            }
        }
        let params = match otp::from_parts(
            &raw.info.secret,
            &raw.info.secret,
            raw.info.algo.as_deref().unwrap_or("SHA1"),
            raw.info.digits.unwrap_or(6),
            raw.info.period.unwrap_or(30),
        ) {
            TotpField::Supported(params) => params,
            TotpField::Unsupported { reason, .. } => {
                out.skip(&title, &reason);
                continue;
            }
            TotpField::Absent => {
                out.skip(&title, "TOTP secret is empty");
                continue;
            }
        };
        let tags = raw
            .groups
            .iter()
            .filter_map(|uuid| group_names.get(uuid).cloned())
            .collect();
        out.push(ImportCandidate {
            entry: NewEntry {
                title,
                username,
                notes: raw.note.filter(|n| !n.trim().is_empty()),
                totp_secret: Some(params.secret),
                totp_algorithm: Some(params.algorithm),
                totp_digits: Some(params.digits),
                totp_period: Some(params.period),
                category: Some("2FA".into()),
                ..NewEntry::default()
            },
            favorite: raw.favorite,
            tags,
            history: Vec::new(),
            attachments: Vec::new(),
        });
    }
    Ok(out)
}

pub fn preview_file(vault: &Vault, path: impl AsRef<Path>) -> Result<ImportPreview> {
    report::preview(vault, &parse_file(path)?)
}

pub fn import_into_vault(vault: &Vault, path: impl AsRef<Path>) -> Result<ImportReport> {
    report::apply(vault, parse_file(path)?)
}

/// Write every two-step verification code of the vault to `path` as an
/// unencrypted Aegis vault (Aegis, 2FAS, Ente Auth and others import it;
/// so does Ashy Pass). Returns how many codes were written. The file holds
/// the secrets in clear: it is created owner-only (0600).
pub fn export_plain(vault: &Vault, path: impl AsRef<Path>) -> Result<usize> {
    export(vault, path, None)
}

/// Like [`export_plain`], encrypted with `password` the way Aegis does it
/// (scrypt password slot, AES-256-GCM): Aegis opens it with that password.
pub fn export_encrypted(vault: &Vault, path: impl AsRef<Path>, password: &str) -> Result<usize> {
    if password.is_empty() {
        return Err(Error::InvalidInput("the export password is empty".into()));
    }
    export(vault, path, Some(password))
}

fn export(vault: &Vault, path: impl AsRef<Path>, password: Option<&str>) -> Result<usize> {
    let mut entries = Vec::new();
    for summary in vault.list(None)?.into_iter().filter(|e| e.has_totp) {
        let Some(entry) = vault.get_without_touch(summary.id)? else {
            continue;
        };
        let Some(secret) = entry.totp_secret.filter(|s| !s.trim().is_empty()) else {
            continue;
        };
        let account = entry.username.clone().unwrap_or_default();
        entries.push(serde_json::json!({
            "type": "totp",
            "uuid": random_uuid(),
            "name": if account.is_empty() { entry.title.clone() } else { account },
            "issuer": entry.title,
            "note": entry.notes.unwrap_or_default(),
            "favorite": entry.favorite,
            "icon": null,
            "groups": [],
            "info": {
                "secret": otp::normalize_secret(&secret),
                "algo": entry.totp_algorithm,
                "digits": entry.totp_digits,
                "period": entry.totp_period,
            },
        }));
    }
    let count = entries.len();
    let db = serde_json::json!({ "version": 3, "entries": entries, "groups": [] });
    let file = match password {
        None => serde_json::json!({
            "version": 1,
            "header": { "slots": null, "params": null },
            "db": db,
        }),
        Some(password) => {
            use base64::Engine as _;
            use rand::RngCore;
            let mut master = zeroize::Zeroizing::new([0u8; 32]);
            rand::rngs::OsRng.fill_bytes(master.as_mut());
            let mut salt = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut salt);
            let (n, r, p) = (32768u64, 8u32, 1u32);
            let derived = zeroize::Zeroizing::new(slot_key(password, &salt, n, r, p)?);
            let (wrapped, key_params) = gcm_seal(&derived, master.as_ref())?;
            let plain = zeroize::Zeroizing::new(serde_json::to_vec(&db)?);
            let (sealed, params) = gcm_seal(&master, &plain)?;
            serde_json::json!({
                "version": 1,
                "header": {
                    "slots": [{
                        "type": 1,
                        "uuid": random_uuid(),
                        "key": hex::encode(wrapped),
                        "key_params": key_params,
                        "n": n, "r": r, "p": p,
                        "salt": hex::encode(salt),
                        "repaired": true,
                        "is_backup": false,
                    }],
                    "params": params,
                },
                "db": base64::engine::general_purpose::STANDARD.encode(sealed),
            })
        }
    };
    let text = zeroize::Zeroizing::new(serde_json::to_string_pretty(&file)?);
    crate::config::atomic_write_private(path.as_ref(), text.as_bytes())?;
    Ok(count)
}

fn random_uuid() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"{
      "version": 1,
      "header": {"slots": null, "params": null},
      "db": {
        "version": 3,
        "groups": [{"uuid": "g1", "name": "Work"}],
        "entries": [
          {"type": "totp", "name": "alice", "issuer": "GitHub", "note": "n", "favorite": true,
           "groups": ["g1"],
           "info": {"secret": "JBSWY3DPEHPK3PXP", "algo": "SHA256", "digits": 8, "period": 60}},
          {"type": "totp", "name": "bob", "issuer": "",
           "info": {"secret": "KRSXG5CTMVRXEZLU", "algo": "SHA1", "digits": 6, "period": 30}},
          {"type": "hotp", "name": "counter", "issuer": "Bank",
           "info": {"secret": "JBSWY3DPEHPK3PXP", "algo": "SHA1", "digits": 6, "counter": 4}},
          {"type": "steam", "name": "gamer", "issuer": "Steam",
           "info": {"secret": "JBSWY3DPEHPK3PXP", "algo": "SHA1", "digits": 5, "period": 30}},
          {"type": "totp", "name": "seven", "issuer": "Odd",
           "info": {"secret": "JBSWY3DPEHPK3PXP", "algo": "SHA1", "digits": 7, "period": 30}}
        ]
      }
    }"#;

    #[test]
    fn parses_totp_and_reports_unsupported_types() {
        let parsed = parse_str(FIXTURE).unwrap();
        assert_eq!(parsed.candidates.len(), 2);
        let first = &parsed.candidates[0];
        assert_eq!(first.entry.title, "GitHub");
        assert_eq!(first.entry.username.as_deref(), Some("alice"));
        assert_eq!(first.entry.totp_algorithm.as_deref(), Some("SHA256"));
        assert_eq!(first.entry.totp_digits, Some(8));
        assert_eq!(first.entry.totp_period, Some(60));
        assert!(first.favorite);
        assert_eq!(first.tags, vec!["Work"]);
        assert_eq!(parsed.candidates[1].entry.title, "bob");
        let reasons: Vec<&str> = parsed.skipped.iter().map(|s| s.reason.as_str()).collect();
        assert_eq!(parsed.skipped.len(), 3);
        assert!(reasons[0].contains("HOTP"));
        assert!(reasons[1].contains("Steam"));
        assert!(reasons[2].contains("digit"));
    }

    #[test]
    fn encrypted_vaults_ask_for_their_password() {
        let json = r#"{"version":1,"header":{"slots":[{}]},"db":"base64=="}"#;
        assert!(parse_str(json)
            .unwrap_err()
            .to_string()
            .contains("encrypted"));
    }

    #[test]
    fn import_reports_counts_and_duplicates() {
        let (directory, vault) = crate::importers::report::tests::test_vault();
        let path = directory.path().join("aegis.json");
        std::fs::write(&path, FIXTURE).unwrap();
        let preview = preview_file(&vault, &path).unwrap();
        assert_eq!(preview.recognized, 2);
        assert_eq!(preview.unsupported.len(), 3);
        let first = import_into_vault(&vault, &path).unwrap();
        assert_eq!(first.imported, 2);
        assert_eq!(first.skipped.len(), 3);
        let again = import_into_vault(&vault, &path).unwrap();
        assert_eq!(again.imported, 0);
        assert_eq!(again.duplicates, 2);
        let entry = vault
            .list(None)
            .unwrap()
            .into_iter()
            .find(|e| e.title == "GitHub")
            .unwrap();
        assert_eq!(entry.totp_digits, 8);
        assert!(entry.favorite);
    }

    #[test]
    fn exported_codes_import_back_and_never_duplicate() {
        let (dir, vault) = crate::importers::report::tests::test_vault();
        // A login with its 2FA, as the desktop keeps it.
        vault
            .add(NewEntry {
                title: "github.com".into(),
                username: Some("ana".into()),
                password: "secret-pass".into(),
                totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
                totp_digits: Some(6),
                totp_period: Some(30),
                ..NewEntry::default()
            })
            .unwrap();
        let path = dir.path().join("codes.json");
        assert_eq!(export_plain(&vault, &path).unwrap(), 1);
        let text = std::fs::read_to_string(&path).unwrap();
        let parsed = parse_str(&text).unwrap();
        assert_eq!(parsed.candidates.len(), 1);
        assert_eq!(
            parsed.candidates[0].entry.totp_secret.as_deref(),
            Some("JBSWY3DPEHPK3PXP")
        );
        // Importing the same codes again (or the same code from Aegis under
        // another name, with spaces and lower case) adds nothing.
        let again = import_into_vault(&vault, &path).unwrap();
        assert_eq!((again.imported, again.duplicates), (0, 1));
        let aegis = r#"{"version":1,"header":{"slots":null,"params":null},"db":{"version":3,
          "entries":[
            {"type":"totp","name":"ana","issuer":"GitHub","info":{"secret":"jbsw y3dp ehpk 3pxp","algo":"SHA1","digits":6,"period":30}},
            {"type":"totp","name":"bob","issuer":"GitLab","info":{"secret":"KRSXG5CTMVRXEZLU","algo":"SHA1","digits":6,"period":30}},
            {"type":"totp","name":"bob","issuer":"GitLab copy","info":{"secret":"KRSXG5CTMVRXEZLU","algo":"SHA1","digits":6,"period":30}}
          ]}}"#;
        let file = dir.path().join("aegis.json");
        std::fs::write(&file, aegis).unwrap();
        let preview = preview_file(&vault, &file).unwrap();
        assert_eq!((preview.recognized, preview.duplicates), (1, 2));
        let report = import_into_vault(&vault, &file).unwrap();
        assert_eq!((report.imported, report.duplicates), (1, 2));
        assert_eq!(vault.list(None).unwrap().len(), 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn encrypted_vaults_round_trip_with_their_password() {
        let (dir, vault) = crate::importers::report::tests::test_vault();
        vault
            .add(NewEntry {
                title: "GitHub".into(),
                username: Some("ana".into()),
                totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
                totp_digits: Some(6),
                totp_period: Some(30),
                ..NewEntry::default()
            })
            .unwrap();
        let path = dir.path().join("enc.json");
        assert_eq!(export_encrypted(&vault, &path, "aegis pass").unwrap(), 1);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("JBSWY3DPEHPK3PXP"));
        // No password: a clear request for it; wrong one: refused.
        assert!(matches!(parse_str(&text), Err(Error::InvalidInput(m)) if m == NEEDS_PASSWORD));
        assert!(matches!(
            parse_str_with_password(&text, Some("wrong")),
            Err(Error::InvalidMasterPassword)
        ));
        let parsed = parse_str_with_password(&text, Some("aegis pass")).unwrap();
        assert_eq!(parsed.candidates.len(), 1);
        assert_eq!(
            parsed.candidates[0].entry.totp_secret.as_deref(),
            Some("JBSWY3DPEHPK3PXP")
        );
        // A plain file ignores a password.
        assert!(parse_str_with_password(FIXTURE, Some("x")).is_ok());
    }
}
