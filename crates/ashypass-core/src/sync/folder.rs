//! End-to-end encrypted sync through a plain folder (WebDAV, Dropbox, Google
//! Drive, a local or USB folder): every entry type, on every device.
//!
//! The folder only ever holds ciphertext:
//!
//! ```text
//! ashypass-sync.json          header: vault id, KDF salt, the sync key
//!                             wrapped with the master password (Argon2id +
//!                             AES-GCM)
//! changes/<device>/<seq>.bin  one encrypted batch per sync per device
//! ```
//!
//! Each device writes only its own files, so two devices never overwrite
//! each other. A batch lists the entries that changed on that device since
//! its previous batch (full content, or a deletion). Applying is per entry:
//! the newest `updated_at` wins (ties: the larger device id), deletions are
//! kept as versions so a stale copy never comes back. All devices of a vault
//! use the same master password: it unwraps the same random sync key.

use crate::crypto::{aes_gcm_v2, argon2_kdf, key::DerivedKey};
use crate::db::vault::{SyncItem, Vault};
use crate::{Error, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rand::RngCore as _;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use zeroize::Zeroizing;

const HEADER: &str = "ashypass-sync.json";
const CHANGES: &str = "changes";
const FORMAT: u32 = 1;
/// A pull that would delete more than this share of the entries (and more
/// than `MASS_DELETE_MIN` of them) needs approval.
const MASS_DELETE_SHARE: f64 = 0.5;
const MASS_DELETE_MIN: usize = 5;

/// Where the encrypted files live. Paths use `/` and are relative to the
/// sync folder.
pub trait Remote {
    /// File names in `dir` (not recursive); empty when `dir` is missing.
    fn list(&self, dir: &str) -> Result<Vec<String>>;
    fn get(&self, path: &str) -> Result<Option<Vec<u8>>>;
    /// Create or replace `path`, creating its folders.
    fn put(&self, path: &str, data: &[u8]) -> Result<()>;
}

/// A folder on this computer (tests, USB drives, folders synced by another
/// program).
pub struct LocalFolder {
    pub root: PathBuf,
}

impl Remote for LocalFolder {
    fn list(&self, dir: &str) -> Result<Vec<String>> {
        let path = self.root.join(dir);
        if !path.is_dir() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in std::fs::read_dir(path)? {
            if let Some(name) = entry?.file_name().to_str() {
                names.push(name.to_string());
            }
        }
        Ok(names)
    }

    fn get(&self, path: &str) -> Result<Option<Vec<u8>>> {
        match std::fs::read(self.root.join(path)) {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn put(&self, path: &str, data: &[u8]) -> Result<()> {
        let path = self.root.join(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Write then rename: a reader never sees half a file.
        let tmp = path.with_extension("part");
        std::fs::write(&tmp, data)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct Header {
    format: u32,
    vault_id: String,
    /// Argon2id salt (base64) for the master-password key.
    salt: String,
    /// The sync key, AES-GCM-encrypted with the master-password key.
    wrapped_key: String,
}

#[derive(Serialize, Deserialize)]
struct Batch {
    device: String,
    seq: u64,
    records: Vec<Record>,
}

#[derive(Serialize, Deserialize)]
struct Record {
    uid: String,
    updated_at: i64,
    /// `None` is a deletion.
    item: Option<SyncItem>,
}

/// What one sync did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FolderSyncReport {
    pub received: usize,
    pub deleted_here: usize,
    pub sent: usize,
    pub deleted_there: usize,
}

/// Options of one sync.
#[derive(Debug, Default, Clone, Copy)]
pub struct FolderSyncOptions {
    /// Apply a pull that deletes this many entries (after
    /// `Error::MassDelete` asked).
    pub approve_deletes: usize,
}

// ── Local bookkeeping ───────────────────────────────────────────────────────

const SETUP: &str = "
    CREATE TABLE IF NOT EXISTS folder_sync_kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS folder_sync_seen (device TEXT PRIMARY KEY, seq INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS folder_sync_versions (
        uid TEXT PRIMARY KEY,
        updated_at INTEGER NOT NULL,
        device TEXT NOT NULL,
        deleted INTEGER NOT NULL DEFAULT 0
    );";

fn kv(vault: &Vault, key: &str) -> Result<Option<String>> {
    Ok(vault
        .sync_conn()
        .query_row(
            "SELECT value FROM folder_sync_kv WHERE key = ?",
            params![key],
            |r| r.get(0),
        )
        .optional()?)
}

fn set_kv(vault: &Vault, key: &str, value: &str) -> Result<()> {
    vault.sync_conn().execute(
        "INSERT INTO folder_sync_kv (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = ?2",
        params![key, value],
    )?;
    Ok(())
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Forget the sync state of this vault (disconnecting the folder). Entries
/// stay; connecting again re-sends them and merges.
pub fn forget(vault: &Vault) -> Result<()> {
    vault.sync_conn().execute_batch(&format!(
        "{SETUP}
         DELETE FROM folder_sync_kv; DELETE FROM folder_sync_seen; DELETE FROM folder_sync_versions;"
    ))?;
    Ok(())
}

// ── Keys ────────────────────────────────────────────────────────────────────

/// The sync key, kept in the vault encrypted with the vault key, so a vault
/// opened with a PIN or biometrics syncs without the master password.
fn cached_key(vault: &Vault) -> Result<Option<DerivedKey>> {
    let Some(sealed) = kv(vault, "sync_key")? else {
        return Ok(None);
    };
    let key = Zeroizing::new(vault.sync_open(&B64.decode(sealed)?)?);
    let key: [u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| Error::Other("bad sync key".into()))?;
    Ok(Some(DerivedKey::new(key)))
}

fn wrap_header(key: &DerivedKey, vault_id: &str, master: &str) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let wrapping = argon2_kdf::derive_key_v2(master, &salt)?;
    let header = Header {
        format: FORMAT,
        vault_id: vault_id.to_string(),
        salt: B64.encode(salt),
        wrapped_key: B64.encode(aes_gcm_v2::encrypt(&wrapping, key.as_bytes())?),
    };
    Ok(serde_json::to_vec_pretty(&header)?)
}

fn unwrap_header(header: &Header, master: &str) -> Result<DerivedKey> {
    let salt = B64.decode(&header.salt)?;
    let wrapping = argon2_kdf::derive_key_v2(master, &salt)?;
    let key = Zeroizing::new(
        aes_gcm_v2::decrypt(&wrapping, &B64.decode(&header.wrapped_key)?)
            .map_err(|_| Error::InvalidMasterPassword)?,
    );
    let key: [u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| Error::Other("bad sync key".into()))?;
    Ok(DerivedKey::new(key))
}

/// Whether the next sync of this vault needs the master password (it has
/// not joined a sync folder yet, or the folder was emptied).
pub fn needs_master_password(vault: &Vault) -> Result<bool> {
    vault.sync_conn().execute_batch(SETUP)?;
    Ok(cached_key(vault)?.is_none())
}

/// The vault's sync key: the one this vault keeps, or the folder header's
/// (unwrapped with the master password), or a new one written to a new
/// header. With `master`, a header still wrapped with an older master
/// password of this vault is wrapped again with the current one.
fn sync_key(vault: &Vault, remote: &dyn Remote, master: Option<&str>) -> Result<DerivedKey> {
    let cached = cached_key(vault)?;
    let Some(raw) = remote.get(HEADER)? else {
        if kv(vault, "vault_id")?.is_some() {
            // The folder was emptied or replaced: start over, sending
            // everything again under a new header.
            forget(vault)?;
        }
        let master = master.ok_or(Error::InvalidMasterPassword)?;
        let key = cached.unwrap_or_else(|| {
            let mut key = Zeroizing::new([0u8; 32]);
            rand::rngs::OsRng.fill_bytes(key.as_mut());
            DerivedKey::new(*key)
        });
        let vault_id = random_hex(16);
        remote.put(HEADER, &wrap_header(&key, &vault_id, master)?)?;
        set_kv(vault, "vault_id", &vault_id)?;
        set_kv(
            vault,
            "sync_key",
            &B64.encode(vault.sync_seal(key.as_bytes())?),
        )?;
        return Ok(key);
    };
    let header: Header = serde_json::from_slice(&raw)
        .map_err(|_| Error::Other("the sync folder header is damaged".into()))?;
    if header.format > FORMAT {
        return Err(Error::Other(
            "the sync folder was written by a newer Ashy Pass".into(),
        ));
    }
    match kv(vault, "vault_id")? {
        Some(id) if id != header.vault_id => {
            return Err(Error::Other(
                "this folder holds another vault; choose another folder".into(),
            ))
        }
        Some(_) => {}
        None => set_kv(vault, "vault_id", &header.vault_id)?,
    }
    if let Some(key) = cached {
        if let Some(master) = master {
            let stale = matches!(
                unwrap_header(&header, master),
                Err(Error::InvalidMasterPassword)
            );
            if stale && argon2_kdf::verify_master(master, &vault.master_hash()?)? {
                remote.put(HEADER, &wrap_header(&key, &header.vault_id, master)?)?;
            }
        }
        return Ok(key);
    }
    let master = master.ok_or(Error::InvalidMasterPassword)?;
    let key = unwrap_header(&header, master)?;
    set_kv(
        vault,
        "sync_key",
        &B64.encode(vault.sync_seal(key.as_bytes())?),
    )?;
    Ok(key)
}

// ── Sync ────────────────────────────────────────────────────────────────────

/// Pull the other devices' batches, then push this device's changes. The
/// vault must be unlocked. `master` (the same on every device of the vault)
/// is needed only when [`needs_master_password`] says so.
pub fn sync(
    vault: &Vault,
    remote: &dyn Remote,
    master: Option<&str>,
    options: FolderSyncOptions,
) -> Result<FolderSyncReport> {
    vault.sync_conn().execute_batch(SETUP)?;
    let key = sync_key(vault, remote, master)?;
    let device = match kv(vault, "device")? {
        Some(d) => d,
        None => {
            let d = random_hex(8);
            set_kv(vault, "device", &d)?;
            d
        }
    };
    let mut report = FolderSyncReport::default();

    // Versions this vault already knows (entries and deletions).
    let mut versions: HashMap<String, (i64, String, bool)> = HashMap::new();
    {
        let mut stmt = vault
            .sync_conn()
            .prepare("SELECT uid, updated_at, device, deleted FROM folder_sync_versions")?;
        for row in stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get::<_, i64>(3)? != 0,
            ))
        })? {
            let (uid, at, dev, del) = row?;
            versions.insert(uid, (at, dev, del));
        }
    }
    let local: HashMap<String, i64> = vault.sync_inventory()?.into_iter().collect();

    // 1. Pull: every batch of the other devices not applied yet.
    let mut incoming: Vec<(String, Record)> = Vec::new();
    let mut seen_updates: Vec<(String, u64)> = Vec::new();
    for other in remote.list(CHANGES)? {
        if other == device || !other.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let seen: u64 = vault
            .sync_conn()
            .query_row(
                "SELECT seq FROM folder_sync_seen WHERE device = ?",
                params![other],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0);
        let mut seqs: Vec<u64> = remote
            .list(&format!("{CHANGES}/{other}"))?
            .iter()
            .filter_map(|n| n.strip_suffix(".bin")?.parse().ok())
            .filter(|s| *s > seen)
            .collect();
        seqs.sort_unstable();
        let mut last = seen;
        for seq in seqs {
            let Some(blob) = remote.get(&format!("{CHANGES}/{other}/{seq:010}.bin"))? else {
                break; // not uploaded completely yet: next sync
            };
            let plain = Zeroizing::new(aes_gcm_v2::decrypt(&key, &blob)?);
            let batch: Batch = serde_json::from_slice(&plain)?;
            if batch.device != other || batch.seq != seq {
                return Err(Error::Other(
                    "a sync batch does not match its file name".into(),
                ));
            }
            for record in batch.records {
                Vault::check_uid(&record.uid)?;
                incoming.push((other.clone(), record));
            }
            last = seq;
        }
        if last > seen {
            seen_updates.push((other, last));
        }
    }

    // Newest version of each incoming entry.
    let mut newest: HashMap<String, (String, Record)> = HashMap::new();
    for (dev, record) in incoming {
        let better = newest
            .get(&record.uid)
            .is_none_or(|(d, r)| (record.updated_at, dev.as_str()) > (r.updated_at, d.as_str()));
        if better {
            newest.insert(record.uid.clone(), (dev, record));
        }
    }
    // Keep only what beats this device's copy (and what it already knows).
    let winners: Vec<(String, Record)> = newest
        .into_values()
        .filter(|(dev, r)| {
            let known = versions.get(&r.uid).map(|(at, d, _)| (*at, d.clone()));
            let mine = local.get(&r.uid).map(|at| (*at, device.clone()));
            let best = known.into_iter().chain(mine).max();
            best.is_none_or(|(at, d)| (r.updated_at, dev.clone()) > (at, d))
        })
        .collect();

    let deletes = winners
        .iter()
        .filter(|(_, r)| r.item.is_none() && local.contains_key(&r.uid))
        .count();
    if deletes >= MASS_DELETE_MIN
        && deletes as f64 > local.len() as f64 * MASS_DELETE_SHARE
        && deletes > options.approve_deletes
    {
        return Err(Error::MassDelete {
            count: deletes,
            mapped: local.len(),
        });
    }

    // Each entry is written atomically; re-applying after an interruption
    // is harmless (the newest version still wins), so no outer transaction.
    (|| -> Result<()> {
        for (dev, r) in &winners {
            match &r.item {
                Some(item) => {
                    vault.sync_apply(&r.uid, item, r.updated_at)?;
                    report.received += 1;
                }
                None => {
                    if vault.sync_remove(&r.uid)? {
                        report.deleted_here += 1;
                    }
                }
            }
            vault.sync_conn().execute(
                "INSERT OR REPLACE INTO folder_sync_versions (uid, updated_at, device, deleted)
                 VALUES (?, ?, ?, ?)",
                params![r.uid, r.updated_at, dev, r.item.is_none() as i64],
            )?;
        }
        for (dev, seq) in &seen_updates {
            vault.sync_conn().execute(
                "INSERT OR REPLACE INTO folder_sync_seen (device, seq) VALUES (?, ?)",
                params![dev, *seq as i64],
            )?;
        }
        Ok(())
    })()?;

    // 2. Push: entries changed here since this vault last recorded them, and
    //    deletions of entries it had.
    let local: HashMap<String, i64> = vault.sync_inventory()?.into_iter().collect();
    let mut versions: HashMap<String, (i64, bool)> = HashMap::new();
    {
        let mut stmt = vault
            .sync_conn()
            .prepare("SELECT uid, updated_at, deleted FROM folder_sync_versions")?;
        for row in stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get(1)?, r.get::<_, i64>(2)? != 0))
        })? {
            let (uid, at, del) = row?;
            versions.insert(uid, (at, del));
        }
    }
    let now = chrono::Utc::now().timestamp();
    let mut records = Vec::new();
    for (uid, at) in &local {
        let changed = versions
            .get(uid)
            .is_none_or(|(known, deleted)| *deleted || at > known);
        if changed {
            if let Some(item) = vault.sync_item(uid)? {
                records.push(Record {
                    uid: uid.clone(),
                    updated_at: *at,
                    item: Some(item),
                });
            }
        }
    }
    for (uid, (at, deleted)) in &versions {
        if !deleted && !local.contains_key(uid) {
            records.push(Record {
                uid: uid.clone(),
                updated_at: now.max(*at + 1),
                item: None,
            });
        }
    }
    if !records.is_empty() {
        let seq: u64 = kv(vault, "seq")?.and_then(|s| s.parse().ok()).unwrap_or(0) + 1;
        let batch = Batch {
            device: device.clone(),
            seq,
            records,
        };
        let plain = Zeroizing::new(serde_json::to_vec(&batch)?);
        let blob = aes_gcm_v2::encrypt(&key, &plain)?;
        remote.put(&format!("{CHANGES}/{device}/{seq:010}.bin"), &blob)?;
        // Recorded only once the file is up: a failed upload is retried.
        (|| -> Result<()> {
            for r in &batch.records {
                vault.sync_conn().execute(
                    "INSERT OR REPLACE INTO folder_sync_versions (uid, updated_at, device, deleted)
                     VALUES (?, ?, ?, ?)",
                    params![r.uid, r.updated_at, device, r.item.is_none() as i64],
                )?;
                if r.item.is_some() {
                    report.sent += 1;
                } else {
                    report.deleted_there += 1;
                }
            }
            set_kv(vault, "seq", &seq.to_string())
        })()?;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::vault::{NewEntry, UpdateEntry, ITEM_CARD, ITEM_PASSKEY};

    const MASTER: &str = "correct horse battery";

    fn device(dir: &std::path::Path, name: &str) -> Vault {
        let mut v = Vault::open(dir.join(format!("{name}.db"))).unwrap();
        v.set_master_password(MASTER).unwrap();
        v
    }

    fn titles(v: &Vault) -> Vec<String> {
        let mut t: Vec<String> = v.list(None).unwrap().into_iter().map(|e| e.title).collect();
        t.sort();
        t
    }

    fn run(v: &Vault, folder: &LocalFolder) -> FolderSyncReport {
        sync(v, folder, Some(MASTER), FolderSyncOptions::default()).unwrap()
    }

    #[test]
    fn two_devices_converge() {
        let dir = tempfile::tempdir().unwrap();
        let folder = LocalFolder {
            root: dir.path().join("cloud"),
        };
        let phone = device(dir.path(), "phone");
        let desk = device(dir.path(), "desk");

        let mail = phone
            .add(NewEntry {
                title: "Mail".into(),
                password: "p1".into(),
                ..Default::default()
            })
            .unwrap();
        phone
            .add(NewEntry {
                item_type: Some(ITEM_CARD.into()),
                extra: Some(r#"{"card":{"number":"4111"}}"#.into()),
                title: "Visa".into(),
                ..Default::default()
            })
            .unwrap();
        phone
            .add(NewEntry {
                item_type: Some(ITEM_PASSKEY.into()),
                extra: Some(r#"{"passkey":{"rpId":"example.com"}}"#.into()),
                title: "Example".into(),
                ..Default::default()
            })
            .unwrap();
        desk.add(NewEntry {
            title: "Bank".into(),
            password: "b1".into(),
            ..Default::default()
        })
        .unwrap();

        assert_eq!(run(&phone, &folder).sent, 3);
        let r = run(&desk, &folder);
        assert_eq!((r.received, r.sent), (3, 1));
        run(&phone, &folder);
        assert_eq!(titles(&phone), vec!["Bank", "Example", "Mail", "Visa"]);
        assert_eq!(titles(&desk), titles(&phone));

        // Every field arrives, cards and passkeys included.
        let visa = desk.list(Some("Visa")).unwrap()[0].id;
        let got = desk.get_without_touch(visa).unwrap().unwrap();
        assert_eq!(
            (got.item_type.as_str(), got.extra.as_deref()),
            (ITEM_CARD, Some(r#"{"card":{"number":"4111"}}"#))
        );

        // Nothing changed: nothing sent, nothing received.
        assert_eq!(run(&desk, &folder), FolderSyncReport::default());

        // An edit travels, and the old password goes to the history.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        phone
            .update(
                mail,
                UpdateEntry {
                    password: Some("p2".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        run(&phone, &folder);
        run(&desk, &folder);
        let desk_mail = desk.list(Some("Mail")).unwrap()[0].id;
        assert_eq!(
            desk.get_without_touch(desk_mail)
                .unwrap()
                .unwrap()
                .password
                .as_deref(),
            Some("p2")
        );
        assert_eq!(desk.password_history(desk_mail).unwrap().len(), 1);

        // Both edit the same entry: the newest wins on both.
        phone
            .update(
                mail,
                UpdateEntry {
                    title: Some("Mail (phone)".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        // Edits within one second are stamped a second apart: wait two so the
        // desk's edit is the newer one.
        std::thread::sleep(std::time::Duration::from_millis(2100));
        desk.update(
            desk_mail,
            UpdateEntry {
                title: Some("Mail (desk)".into()),
                ..Default::default()
            },
        )
        .unwrap();
        // The version stamped later wins (as the core stamps it, not the
        // wall clock), and both devices end with it.
        let phone_at = phone.get_without_touch(mail).unwrap().unwrap().updated_at;
        let desk_at = desk
            .get_without_touch(desk_mail)
            .unwrap()
            .unwrap()
            .updated_at;
        run(&phone, &folder);
        run(&desk, &folder);
        run(&phone, &folder);
        assert_eq!(titles(&desk), titles(&phone));
        if desk_at > phone_at {
            assert!(titles(&phone).contains(&"Mail (desk)".to_string()));
        } else if phone_at > desk_at {
            assert!(titles(&desk).contains(&"Mail (phone)".to_string()));
        }

        // A deletion travels and the entry does not come back.
        let bank = phone.list(Some("Bank")).unwrap()[0].id;
        phone.delete(bank).unwrap();
        assert_eq!(run(&phone, &folder).deleted_there, 1);
        assert_eq!(run(&desk, &folder).deleted_here, 1);
        run(&phone, &folder);
        run(&desk, &folder);
        assert!(!titles(&desk).contains(&"Bank".to_string()));
        assert!(!titles(&phone).contains(&"Bank".to_string()));

        // The folder holds no plaintext.
        for entry in walk(&dir.path().join("cloud")) {
            let bytes = std::fs::read(&entry).unwrap();
            for secret in [&b"p2"[..], b"4111", b"Visa", b"example.com"] {
                assert!(
                    !bytes.windows(secret.len()).any(|w| w == secret),
                    "{entry:?} leaks"
                );
            }
        }
    }

    fn walk(dir: &std::path::Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
        out
    }

    #[test]
    fn wrong_master_password_and_other_vaults_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let folder = LocalFolder {
            root: dir.path().join("cloud"),
        };
        let a = device(dir.path(), "a");
        a.add(NewEntry {
            title: "x".into(),
            password: "y".into(),
            ..Default::default()
        })
        .unwrap();
        run(&a, &folder);
        let b = device(dir.path(), "b");
        assert!(matches!(
            sync(
                &b,
                &folder,
                Some("another master pw"),
                FolderSyncOptions::default()
            ),
            Err(Error::InvalidMasterPassword)
        ));
        // A vault already synced with one folder refuses another vault's folder.
        let other = LocalFolder {
            root: dir.path().join("cloud2"),
        };
        let c = device(dir.path(), "c");
        run(&c, &other);
        assert!(sync(&a, &other, Some(MASTER), FolderSyncOptions::default()).is_err());
    }

    #[test]
    fn mass_deletions_need_approval() {
        let dir = tempfile::tempdir().unwrap();
        let folder = LocalFolder {
            root: dir.path().join("cloud"),
        };
        let a = device(dir.path(), "a");
        let b = device(dir.path(), "b");
        let ids: Vec<i64> = (0..8)
            .map(|i| {
                a.add(NewEntry {
                    title: format!("e{i}"),
                    password: "p".into(),
                    ..Default::default()
                })
                .unwrap()
            })
            .collect();
        run(&a, &folder);
        run(&b, &folder);
        for id in ids {
            a.delete(id).unwrap();
        }
        run(&a, &folder);
        match sync(&b, &folder, Some(MASTER), FolderSyncOptions::default()) {
            Err(Error::MassDelete { count, .. }) => assert_eq!(count, 8),
            other => panic!("expected MassDelete, got {other:?}"),
        }
        assert_eq!(b.list(None).unwrap().len(), 8);
        let r = sync(
            &b,
            &folder,
            Some(MASTER),
            FolderSyncOptions { approve_deletes: 8 },
        )
        .unwrap();
        assert_eq!(r.deleted_here, 8);
    }

    #[test]
    fn master_password_only_to_join_and_after_changing_it() {
        let dir = tempfile::tempdir().unwrap();
        let folder = LocalFolder {
            root: dir.path().join("cloud"),
        };
        let mut phone = device(dir.path(), "phone");
        let opts = FolderSyncOptions::default;
        assert!(needs_master_password(&phone).unwrap());
        assert!(matches!(
            sync(&phone, &folder, None, opts()),
            Err(Error::InvalidMasterPassword)
        ));
        phone
            .add(NewEntry {
                title: "Mail".into(),
                password: "p1".into(),
                ..Default::default()
            })
            .unwrap();
        sync(&phone, &folder, Some(MASTER), opts()).unwrap();
        assert!(!needs_master_password(&phone).unwrap());
        // Later syncs (a PIN or biometric unlock) need no password.
        sync(&phone, &folder, None, opts()).unwrap();

        // A new master password: the kept key is re-encrypted with the
        // vault, and the next sync that has the password re-wraps the
        // header, so a new device joins with the new password.
        const NEW: &str = "a brand new master password";
        phone.change_master_password(MASTER, NEW).unwrap();
        sync(&phone, &folder, None, opts()).unwrap();
        sync(&phone, &folder, Some(NEW), opts()).unwrap();
        let mut tablet = Vault::open(dir.path().join("tablet.db")).unwrap();
        tablet.set_master_password(NEW).unwrap();
        assert!(matches!(
            sync(&tablet, &folder, Some(MASTER), opts()),
            Err(Error::InvalidMasterPassword)
        ));
        sync(&tablet, &folder, Some(NEW), opts()).unwrap();
        assert_eq!(titles(&tablet), ["Mail"]);
    }

    #[test]
    fn two_factor_codes_travel_with_their_item() {
        let dir = tempfile::tempdir().unwrap();
        let folder = LocalFolder {
            root: dir.path().join("cloud"),
        };
        let desk = device(dir.path(), "desk");
        let phone = device(dir.path(), "phone");
        desk.add(NewEntry {
            title: "GitHub".into(),
            password: "p".into(),
            totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
            totp_digits: Some(8),
            totp_period: Some(60),
            ..Default::default()
        })
        .unwrap();
        run(&desk, &folder);
        run(&phone, &folder);
        let id = phone.list(None).unwrap()[0].id;
        let entry = phone.get(id).unwrap().unwrap();
        assert_eq!(
            phone.totp_secret(id).unwrap().as_deref(),
            Some("JBSWY3DPEHPK3PXP")
        );
        assert_eq!((entry.totp_digits, entry.totp_period), (8, 60));
    }

    /// Runs against a real WebDAV server when `ASHYPASS_TEST_WEBDAV_URL`,
    /// `_USER` and `_PASSWORD` are set (see `scripts/webdav-test-server.sh`).
    #[test]
    #[ignore = "needs a WebDAV server"]
    fn webdav_folder_round_trip() {
        use crate::backup::webdav::{WebdavConfig, WebdavFolder};
        let var = |name: &str| std::env::var(format!("ASHYPASS_TEST_WEBDAV_{name}")).unwrap();
        let folder = format!("AshyPass Sync test {}", rand::random::<u32>());
        let remote = WebdavFolder::new(WebdavConfig {
            base_url: var("URL"),
            username: var("USER"),
            password: var("PASSWORD"),
            folder,
        })
        .unwrap();
        remote.probe().unwrap();

        assert!(remote.list("changes").unwrap().is_empty());
        assert_eq!(remote.get("missing.bin").unwrap(), None);
        remote.put("changes/dev a/0000000001.bin", b"one").unwrap();
        remote.put("changes/dev a/0000000001.bin", b"uno").unwrap();
        remote.put("top.json", b"{}").unwrap();
        assert_eq!(remote.list("changes").unwrap(), vec!["dev a".to_string()]);
        assert_eq!(
            remote.list("changes/dev a").unwrap(),
            vec!["0000000001.bin".to_string()]
        );
        assert_eq!(
            remote.get("changes/dev a/0000000001.bin").unwrap(),
            Some(b"uno".to_vec())
        );

        let dir = tempfile::tempdir().unwrap();
        let phone = device(dir.path(), "phone");
        let desk = device(dir.path(), "desk");
        phone
            .add(NewEntry {
                title: "Mail".into(),
                password: "p1".into(),
                ..Default::default()
            })
            .unwrap();
        desk.add(NewEntry {
            title: "Bank".into(),
            password: "b1".into(),
            ..Default::default()
        })
        .unwrap();
        let opts = FolderSyncOptions::default;
        sync(&phone, &remote, Some(MASTER), opts()).unwrap();
        sync(&desk, &remote, Some(MASTER), opts()).unwrap();
        sync(&phone, &remote, Some(MASTER), opts()).unwrap();
        assert_eq!(titles(&phone), ["Bank", "Mail"]);
        assert_eq!(titles(&desk), ["Bank", "Mail"]);
    }
}
