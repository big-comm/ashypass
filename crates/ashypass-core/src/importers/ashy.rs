//! Password-protected `.ashy` exports.
//!
//! Version 1 documents contain importable JSON entries. Version 2 keeps that
//! compatibility and embeds a consistent SQLite snapshot so folders, tags,
//! history, trash, attachments, and sync metadata can be restored losslessly.

use crate::db::vault::{NewEntry, PasswordEntry, Vault};
use crate::{Error, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::RngCore;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 7] = b"ASHYP\x00\x01";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const ARGON2_T: u32 = 3;
const ARGON2_M_KIB: u32 = 65_536;
const ARGON2_P: u32 = 4;
const MAX_ARGON2_T: u32 = 12;
const MAX_ARGON2_M_KIB: u32 = 1_048_576;
const MAX_ARGON2_P: u32 = 16;
const MAX_EXPORT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    pub title: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub password: String,
    pub notes: Option<String>,
    pub totp_secret: Option<String>,
    pub totp_algorithm: String,
    pub totp_digits: u8,
    pub totp_period: u32,
    pub category: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportDocument {
    pub version: u32,
    pub created_at: i64,
    pub entries: Vec<ExportEntry>,
    #[serde(default)]
    pub folders: Vec<String>,
    /// Base64 SQLite snapshot. Added in document version 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_snapshot: Option<String>,
}

fn derive_key(
    password: &str,
    salt: &[u8],
    time_cost: u32,
    memory_kib: u32,
    parallelism: u32,
) -> Result<[u8; 32]> {
    if time_cost == 0
        || time_cost > MAX_ARGON2_T
        || memory_kib < 8 * parallelism
        || memory_kib > MAX_ARGON2_M_KIB
        || parallelism == 0
        || parallelism > MAX_ARGON2_P
    {
        return Err(Error::InvalidInput("unsafe .ashy Argon2 parameters".into()));
    }
    let params = Params::new(memory_kib, time_cost, parallelism, Some(32))
        .map_err(|error| Error::Argon2(error.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|error| Error::Argon2(error.to_string()))?;
    Ok(output)
}

fn entry_from(entry: PasswordEntry, tags: Vec<String>) -> ExportEntry {
    ExportEntry {
        title: entry.title,
        username: entry.username,
        url: entry.url,
        password: entry.password.unwrap_or_default(),
        notes: entry.notes,
        totp_secret: entry.totp_secret,
        totp_algorithm: entry.totp_algorithm,
        totp_digits: entry.totp_digits,
        totp_period: entry.totp_period,
        category: entry.category,
        favorite: entry.favorite,
        tags,
    }
}

pub fn export_vault(vault: &Vault, path: impl AsRef<Path>, export_password: &str) -> Result<usize> {
    if export_password.is_empty() {
        return Err(Error::InvalidInput("export password is empty".into()));
    }

    let summaries = vault.list(None)?;
    let mut entries = Vec::with_capacity(summaries.len());
    for summary in summaries {
        if let Some(full) = vault.get_without_touch(summary.id)? {
            entries.push(entry_from(full, vault.tags_of(summary.id)?));
        }
    }

    let snapshot_path = unique_temporary_path(vault.db_path(), "ashy-snapshot");
    vault.backup_to(&snapshot_path)?;
    let snapshot_result = fs::read(&snapshot_path);
    let _ = fs::remove_file(&snapshot_path);
    let snapshot = snapshot_result?;

    let doc = ExportDocument {
        version: 2,
        created_at: chrono::Utc::now().timestamp(),
        entries,
        folders: vault.categories()?,
        database_snapshot: Some(STANDARD.encode(snapshot)),
    };
    let entry_count = doc.entries.len();
    let plaintext = serde_json::to_vec(&doc)?;

    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let key = derive_key(export_password, &salt, ARGON2_T, ARGON2_M_KIB, ARGON2_P)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_slice())
        .map_err(|error| Error::Crypto(format!("ashy export encrypt: {error}")))?;

    let mut output = Vec::with_capacity(MAGIC.len() + SALT_LEN + 12 + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&ARGON2_T.to_le_bytes());
    output.extend_from_slice(&ARGON2_M_KIB.to_le_bytes());
    output.extend_from_slice(&ARGON2_P.to_le_bytes());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    write_new_private(path.as_ref(), &output)?;
    Ok(entry_count)
}

pub fn read_export(path: impl AsRef<Path>, export_password: &str) -> Result<ExportDocument> {
    let metadata = fs::metadata(path.as_ref())?;
    if metadata.len() > MAX_EXPORT_BYTES {
        return Err(Error::InvalidInput(".ashy file is too large".into()));
    }
    let raw = fs::read(path)?;
    let header_len = MAGIC.len() + SALT_LEN + 12 + NONCE_LEN;
    if raw.len() < header_len + 16 {
        return Err(Error::InvalidInput(".ashy file is truncated".into()));
    }
    if &raw[..MAGIC.len()] != MAGIC {
        return Err(Error::InvalidInput(".ashy magic mismatch".into()));
    }

    let salt_start = MAGIC.len();
    let params_start = salt_start + SALT_LEN;
    let time_cost = read_u32(&raw[params_start..params_start + 4]);
    let memory_kib = read_u32(&raw[params_start + 4..params_start + 8]);
    let parallelism = read_u32(&raw[params_start + 8..params_start + 12]);
    let nonce_start = params_start + 12;
    let key = derive_key(
        export_password,
        &raw[salt_start..params_start],
        time_cost,
        memory_kib,
        parallelism,
    )?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&raw[nonce_start..nonce_start + NONCE_LEN]),
            &raw[header_len..],
        )
        .map_err(|_| Error::Crypto("ashy import: wrong password or corrupt file".into()))?;
    let document: ExportDocument = serde_json::from_slice(&plaintext)?;
    if !(1..=2).contains(&document.version) {
        return Err(Error::UnsupportedCryptoVersion(document.version as i64));
    }
    Ok(document)
}

/// Merge importable entries, folders, favourites, and tags atomically.
/// For a lossless whole-vault recovery use [`restore_database`].
pub fn import_into_vault(
    vault: &Vault,
    path: impl AsRef<Path>,
    export_password: &str,
) -> Result<usize> {
    let document = read_export(path, export_password)?;
    vault.transaction(|| {
        for folder in &document.folders {
            vault.create_folder(folder)?;
        }
        let mut imported = 0;
        for entry in &document.entries {
            let id = vault.add(NewEntry {
                title: entry.title.clone(),
                username: entry.username.clone(),
                url: entry.url.clone(),
                password: entry.password.clone(),
                notes: entry.notes.clone(),
                totp_secret: entry.totp_secret.clone(),
                totp_algorithm: Some(entry.totp_algorithm.clone()),
                totp_digits: Some(entry.totp_digits),
                totp_period: Some(entry.totp_period),
                category: entry.category.clone(),
            })?;
            vault.set_favorite(id, entry.favorite)?;
            vault.set_tags(id, &entry.tags)?;
            imported += 1;
        }
        Ok(imported)
    })
}

/// Restore the complete SQLite snapshot to a new path. The destination must
/// not exist and is validated before it becomes visible.
pub fn restore_database(
    export_path: impl AsRef<Path>,
    export_password: &str,
    destination: impl AsRef<Path>,
) -> Result<()> {
    let document = read_export(export_path, export_password)?;
    let encoded = document.database_snapshot.ok_or_else(|| {
        Error::InvalidInput("this legacy .ashy file has no complete database snapshot".into())
    })?;
    let snapshot = STANDARD.decode(encoded)?;
    let destination = destination.as_ref();
    let temporary = unique_temporary_path(destination, "restore");
    write_new_private(&temporary, &snapshot)?;

    let validation = (|| {
        let connection = Connection::open_with_flags(&temporary, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let integrity: String =
            connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if integrity != "ok" {
            return Err(Error::InvalidInput(format!(
                "restored database integrity check failed: {integrity}"
            )));
        }
        for table in ["master", "passwords"] {
            let exists: i64 = connection.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
                [table],
                |row| row.get(0),
            )?;
            if exists != 1 {
                return Err(Error::InvalidInput(format!(
                    "restored database is missing the {table} table"
                )));
            }
        }
        Ok(())
    })();
    if let Err(error) = validation {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }

    match fs::hard_link(&temporary, destination) {
        Ok(()) => {
            fs::remove_file(&temporary)?;
            Ok(())
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(Error::Io(error))
        }
    }
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("four-byte slice"))
}

fn unique_temporary_path(path: &Path, purpose: &str) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut random = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut random);
    parent.join(format!(
        ".ashypass-{purpose}-{:016x}.tmp",
        u64::from_ne_bytes(random)
    ))
}

fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = unique_temporary_path(path, "write");
    let result: std::io::Result<()> = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::hard_link(&temporary, path)?;
        fs::remove_file(&temporary)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::vault::UpdateEntry;

    #[test]
    fn full_roundtrip_preserves_metadata_and_database_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("source.db");
        let export_path = directory.path().join("backup.ashy");
        let restored_path = directory.path().join("restored.db");
        let imported_path = directory.path().join("imported.db");

        let mut source = Vault::open(&source_path).unwrap();
        source
            .set_master_password("source master password")
            .unwrap();
        source.create_folder("Work").unwrap();
        let id = source
            .add(NewEntry {
                title: "Example".into(),
                password: "old password".into(),
                category: Some("Work".into()),
                ..NewEntry::default()
            })
            .unwrap();
        source
            .update(
                id,
                UpdateEntry {
                    password: Some("current password".into()),
                    ..UpdateEntry::default()
                },
            )
            .unwrap();
        source.set_favorite(id, true).unwrap();
        source.set_tags(id, &["Important".into()]).unwrap();
        source
            .add_attachment(id, "proof.txt", Some("text/plain"), b"attachment")
            .unwrap();

        assert_eq!(
            export_vault(&source, &export_path, "export password").unwrap(),
            1
        );
        assert!(export_vault(&source, &export_path, "export password").is_err());
        restore_database(&export_path, "export password", &restored_path).unwrap();

        let mut restored = Vault::open(&restored_path).unwrap();
        restored.unlock("source master password").unwrap();
        assert_eq!(
            restored.password_history(id).unwrap()[0].password,
            "old password"
        );
        assert_eq!(restored.list_attachments(id).unwrap().len(), 1);
        assert_eq!(restored.tags_of(id).unwrap(), vec!["Important"]);

        let mut imported = Vault::open(&imported_path).unwrap();
        imported
            .set_master_password("import master password")
            .unwrap();
        assert_eq!(
            import_into_vault(&imported, &export_path, "export password").unwrap(),
            1
        );
        let imported_entry = imported.list(None).unwrap().remove(0);
        assert!(imported_entry.favorite);
        assert_eq!(
            imported.tags_of(imported_entry.id).unwrap(),
            vec!["Important"]
        );
        assert!(imported.categories().unwrap().contains(&"Work".into()));
    }

    #[test]
    fn rejects_unsafe_header_parameters_before_derivation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("bad.ashy");
        let mut bytes = vec![0u8; MAGIC.len() + SALT_LEN + 12 + NONCE_LEN + 16];
        bytes[..MAGIC.len()].copy_from_slice(MAGIC);
        let params = MAGIC.len() + SALT_LEN;
        bytes[params..params + 4].copy_from_slice(&(MAX_ARGON2_T + 1).to_le_bytes());
        bytes[params + 4..params + 8].copy_from_slice(&ARGON2_M_KIB.to_le_bytes());
        bytes[params + 8..params + 12].copy_from_slice(&ARGON2_P.to_le_bytes());
        write_new_private(&path, &bytes).unwrap();
        assert!(matches!(
            read_export(&path, "password"),
            Err(Error::InvalidInput(_))
        ));
    }
}
