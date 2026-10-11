//! Folder management: rename and remove a folder without touching the
//! entries' secrets.
//!
//! Folders are the `category` text on each entry plus the `folders` table for
//! empty ones. Removing a folder never removes the entries in it — they move
//! to "no folder". Both operations bump `updated_at` on the affected entries
//! so Nextcloud sync sends the new folder to the server.

use super::{normalize_folder_name, NextcloudFolderMapping, Vault};
use crate::{Error, Result};
use rusqlite::{params, Connection, OptionalExtension};

/// A local folder change waiting to be sent to Nextcloud Passwords.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextcloudFolderOp {
    /// Rename the remote folder `nc_uuid` to `label`.
    Rename { nc_uuid: String, label: String },
    /// The local folder `label` was removed; remove the remote folder
    /// `nc_uuid` once no password is left in it.
    Delete { nc_uuid: String, label: String },
}

impl NextcloudFolderOp {
    pub fn nc_uuid(&self) -> &str {
        match self {
            Self::Rename { nc_uuid, .. } | Self::Delete { nc_uuid, .. } => nc_uuid,
        }
    }
}

impl Vault {
    /// Rename `old` to `new` for every entry and the folder record. Merges
    /// into `new` if it already exists. Returns how many entries moved.
    pub fn rename_folder(&self, old: &str, new: &str) -> Result<usize> {
        let old = normalize_folder_name(old)?;
        let new = normalize_folder_name(new)?;
        if old == new {
            return Ok(0);
        }
        let ts = chrono::Utc::now().timestamp();
        let tx = self.conn.unchecked_transaction()?;
        let moved = tx.execute(
            "UPDATE passwords SET category = ?, updated_at = ? WHERE category = ?",
            params![new, ts, old],
        )?;
        let existed = tx.execute("DELETE FROM folders WHERE name = ?", params![old])? > 0;
        if existed || moved > 0 {
            tx.execute(
                "INSERT OR IGNORE INTO folders (name, created_at, updated_at) VALUES (?, ?, ?)",
                params![new, ts, ts],
            )?;
        }
        if !existed && moved == 0 {
            return Err(Error::InvalidInput(format!("folder not found: {old}")));
        }
        // Restoring a trashed entry must land in the renamed folder, not
        // bring the old name back.
        tx.execute(
            "UPDATE passwords_trash SET category = ? WHERE category = ?",
            params![new, old],
        )?;
        record_nextcloud_folder_rename(&tx, &old, &new, ts)?;
        tx.commit()?;
        self.notify_change();
        Ok(moved)
    }

    /// Remove the folder and move its entries to "no folder". The entries
    /// themselves are kept. Returns how many entries moved.
    pub fn remove_folder_keep_entries(&self, name: &str) -> Result<usize> {
        let name = normalize_folder_name(name)?;
        let ts = chrono::Utc::now().timestamp();
        let tx = self.conn.unchecked_transaction()?;
        let moved = tx.execute(
            "UPDATE passwords SET category = NULL, updated_at = ? WHERE category = ?",
            params![ts, name],
        )?;
        tx.execute("DELETE FROM folders WHERE name = ?", params![name])?;
        if let Some(uuid) = mapped_folder_uuid(&tx, &name)? {
            // Forget the mapping so sync does not pull the folder back, and
            // remember to remove it remotely once it is empty.
            tx.execute(
                "DELETE FROM nextcloud_folder_mapping WHERE nc_uuid = ?",
                params![uuid],
            )?;
            queue_folder_op(&tx, &uuid, "delete", &name, ts)?;
        }
        tx.commit()?;
        self.notify_change();
        Ok(moved)
    }

    // -----------------------------------------------------------------
    // Nextcloud Passwords folder state
    // -----------------------------------------------------------------

    /// Folder changes waiting to be sent to Nextcloud Passwords.
    pub fn nc_folder_ops(&self) -> Result<Vec<NextcloudFolderOp>> {
        let mut stmt = self.conn.prepare(
            "SELECT nc_uuid, op, label FROM nextcloud_folder_ops ORDER BY created_at, nc_uuid",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows
            .into_iter()
            .filter_map(|(nc_uuid, op, label)| match op.as_str() {
                "rename" => Some(NextcloudFolderOp::Rename { nc_uuid, label }),
                "delete" => Some(NextcloudFolderOp::Delete { nc_uuid, label }),
                // Written by a newer build: leave it alone.
                _ => None,
            })
            .collect())
    }

    pub fn nc_clear_folder_op(&self, nc_uuid: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM nextcloud_folder_ops WHERE nc_uuid = ?",
            params![nc_uuid],
        )?;
        Ok(())
    }

    pub fn nc_folder_mapping_delete(&self, nc_uuid: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM nextcloud_folder_mapping WHERE nc_uuid = ?",
            params![nc_uuid],
        )?;
        Ok(())
    }

    /// Apply a rename made on the server to the local folder mapped to it.
    /// Entries keep their `updated_at`: their remote copy is already in the
    /// renamed folder, so there is nothing to send back. Returns false (and
    /// changes nothing) when another remote folder is already mapped to the
    /// new name.
    pub fn nc_apply_remote_folder_rename(&self, mapping: &NextcloudFolderMapping) -> Result<bool> {
        let new = normalize_folder_name(&mapping.local_name)?;
        let tx = self.conn.unchecked_transaction()?;
        let taken: Option<String> = tx
            .query_row(
                "SELECT nc_uuid FROM nextcloud_folder_mapping
                 WHERE local_name = ? COLLATE NOCASE AND nc_uuid != ?",
                params![new, mapping.nc_uuid],
                |r| r.get(0),
            )
            .optional()?;
        if taken.is_some() {
            return Ok(false);
        }
        let old: Option<String> = tx
            .query_row(
                "SELECT local_name FROM nextcloud_folder_mapping WHERE nc_uuid = ?",
                params![mapping.nc_uuid],
                |r| r.get(0),
            )
            .optional()?;
        let ts = chrono::Utc::now().timestamp();
        if let Some(old) = old.as_deref() {
            tx.execute(
                "UPDATE passwords SET category = ? WHERE category = ?",
                params![new, old],
            )?;
            tx.execute(
                "UPDATE passwords_trash SET category = ? WHERE category = ?",
                params![new, old],
            )?;
            tx.execute("DELETE FROM folders WHERE name = ?", params![old])?;
        }
        tx.execute(
            "INSERT OR IGNORE INTO folders (name, created_at, updated_at) VALUES (?, ?, ?)",
            params![new, ts, ts],
        )?;
        tx.execute(
            "DELETE FROM nextcloud_folder_mapping WHERE nc_uuid = ?",
            params![mapping.nc_uuid],
        )?;
        tx.execute(
            "INSERT INTO nextcloud_folder_mapping (
                 local_name, nc_uuid, last_synced_at,
                 remote_edited_snapshot, remote_revision_snapshot)
             VALUES (?, ?, ?, ?, ?)",
            params![
                new,
                mapping.nc_uuid,
                mapping.last_synced_at,
                mapping.remote_edited_snapshot,
                mapping.remote_revision_snapshot,
            ],
        )?;
        tx.commit()?;
        self.notify_change();
        Ok(true)
    }

    /// Number of entries in each folder, for "Organize folders".
    pub fn folder_counts(&self) -> Result<Vec<(String, usize)>> {
        let mut stmt = self.conn.prepare(
            "SELECT f.name, (SELECT COUNT(*) FROM passwords p WHERE p.category = f.name)
             FROM (SELECT name FROM folders
                   UNION
                   SELECT DISTINCT category AS name FROM passwords
                   WHERE category IS NOT NULL AND category != '') f
             ORDER BY f.name COLLATE NOCASE",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as usize))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

fn mapped_folder_uuid(conn: &Connection, name: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT nc_uuid FROM nextcloud_folder_mapping WHERE local_name = ? COLLATE NOCASE",
            params![name],
            |r| r.get(0),
        )
        .optional()?)
}

fn queue_folder_op(conn: &Connection, uuid: &str, op: &str, label: &str, ts: i64) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO nextcloud_folder_ops (nc_uuid, op, label, created_at)
         VALUES (?, ?, ?, ?)",
        params![uuid, op, label, ts],
    )?;
    Ok(())
}

/// Keep the Nextcloud folder mapping in step with a local rename, so sync
/// renames the remote folder instead of creating a second one and pulling
/// the old name back.
fn record_nextcloud_folder_rename(conn: &Connection, old: &str, new: &str, ts: i64) -> Result<()> {
    let Some(uuid) = mapped_folder_uuid(conn, old)? else {
        return Ok(());
    };
    let target = mapped_folder_uuid(conn, new)?.filter(|other| *other != uuid);
    if target.is_some() {
        // Merged into a folder that already exists remotely: the old remote
        // folder is left without entries and goes away like a removal.
        conn.execute(
            "DELETE FROM nextcloud_folder_mapping WHERE nc_uuid = ?",
            params![uuid],
        )?;
        queue_folder_op(conn, &uuid, "delete", old, ts)
    } else {
        conn.execute(
            "UPDATE nextcloud_folder_mapping SET local_name = ? WHERE nc_uuid = ?",
            params![new, uuid],
        )?;
        queue_folder_op(conn, &uuid, "rename", new, ts)
    }
}

#[cfg(test)]
mod tests {
    use crate::db::vault::{NewEntry, NextcloudFolderMapping, NextcloudFolderOp, Vault};

    fn vault() -> (Vault, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "ashypass-folders-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut v = Vault::open(dir.join("v.db")).unwrap();
        v.set_master_password("correct horse battery").unwrap();
        (v, dir)
    }

    fn add(v: &Vault, title: &str, category: Option<&str>) -> i64 {
        v.add(NewEntry {
            title: title.into(),
            username: None,
            password: "pw".into(),
            url: None,
            notes: None,
            totp_secret: None,
            totp_algorithm: None,
            totp_digits: None,
            totp_period: None,
            category: category.map(str::to_string),
        })
        .unwrap()
    }

    #[test]
    fn removing_a_folder_keeps_its_entries() {
        let (v, dir) = vault();
        let a = add(&v, "A", Some("Work"));
        let b = add(&v, "B", Some("Home"));
        assert_eq!(v.remove_folder_keep_entries("Work").unwrap(), 1);
        let a = v.get(a).unwrap().expect("entry kept");
        assert_eq!(a.category, None);
        assert_eq!(a.password.as_deref(), Some("pw"));
        assert_eq!(v.get(b).unwrap().unwrap().category.as_deref(), Some("Home"));
        assert!(!v.categories().unwrap().contains(&"Work".to_string()));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn renaming_moves_entries_and_empty_folders() {
        let (v, dir) = vault();
        let a = add(&v, "A", Some("Old"));
        v.create_folder("Empty").unwrap();
        assert_eq!(v.rename_folder("Old", "New").unwrap(), 1);
        assert_eq!(v.get(a).unwrap().unwrap().category.as_deref(), Some("New"));
        assert_eq!(v.rename_folder("Empty", "Still empty").unwrap(), 0);
        let cats = v.categories().unwrap();
        assert!(cats.contains(&"New".to_string()));
        assert!(cats.contains(&"Still empty".to_string()));
        assert!(!cats.contains(&"Old".to_string()));
        assert!(v.rename_folder("Missing", "X").is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn map_folder(v: &Vault, name: &str, uuid: &str) {
        v.nc_folder_mapping_upsert(&NextcloudFolderMapping {
            local_name: name.into(),
            nc_uuid: uuid.into(),
            last_synced_at: 1,
            remote_edited_snapshot: 1,
            remote_revision_snapshot: "r1".into(),
        })
        .unwrap();
    }

    #[test]
    fn renaming_a_synced_folder_queues_a_remote_rename() {
        let (v, dir) = vault();
        let a = add(&v, "A", Some("Old"));
        let trashed = add(&v, "T", Some("Old"));
        v.delete(trashed).unwrap();
        map_folder(&v, "Old", "uuid-old");
        v.rename_folder("Old", "New").unwrap();

        let mapping = v.nc_folder_mapping_for_uuid("uuid-old").unwrap().unwrap();
        assert_eq!(mapping.local_name, "New");
        assert_eq!(
            v.nc_folder_ops().unwrap(),
            vec![NextcloudFolderOp::Rename {
                nc_uuid: "uuid-old".into(),
                label: "New".into()
            }]
        );
        assert_eq!(v.get(a).unwrap().unwrap().category.as_deref(), Some("New"));
        let trash = v.list_trash().unwrap();
        assert_eq!(trash[0].category.as_deref(), Some("New"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn merging_into_a_synced_folder_queues_a_remote_delete() {
        let (v, dir) = vault();
        add(&v, "A", Some("Old"));
        add(&v, "B", Some("Target"));
        map_folder(&v, "Old", "uuid-old");
        map_folder(&v, "Target", "uuid-target");
        v.rename_folder("Old", "Target").unwrap();
        assert!(v.nc_folder_mapping_for_uuid("uuid-old").unwrap().is_none());
        assert_eq!(
            v.nc_folder_mapping_for_name("Target")
                .unwrap()
                .unwrap()
                .nc_uuid,
            "uuid-target"
        );
        assert_eq!(
            v.nc_folder_ops().unwrap(),
            vec![NextcloudFolderOp::Delete {
                nc_uuid: "uuid-old".into(),
                label: "Old".into()
            }]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn removing_a_synced_folder_queues_a_remote_delete() {
        let (v, dir) = vault();
        add(&v, "A", Some("Work"));
        add(&v, "B", Some("Plain"));
        map_folder(&v, "Work", "uuid-work");
        v.remove_folder_keep_entries("Work").unwrap();
        v.remove_folder_keep_entries("Plain").unwrap();
        assert!(v.nc_folder_mapping_for_uuid("uuid-work").unwrap().is_none());
        assert_eq!(
            v.nc_folder_ops().unwrap(),
            vec![NextcloudFolderOp::Delete {
                nc_uuid: "uuid-work".into(),
                label: "Work".into()
            }]
        );
        v.nc_clear_folder_op("uuid-work").unwrap();
        assert!(v.nc_folder_ops().unwrap().is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn remote_folder_rename_moves_entries_without_marking_them_changed() {
        let (v, dir) = vault();
        let a = add(&v, "A", Some("Old"));
        let before = v.entry_updated_at(a).unwrap();
        map_folder(&v, "Old", "uuid-old");
        map_folder(&v, "Taken", "uuid-taken");
        let renamed = NextcloudFolderMapping {
            local_name: "Renamed".into(),
            nc_uuid: "uuid-old".into(),
            last_synced_at: 2,
            remote_edited_snapshot: 2,
            remote_revision_snapshot: "r2".into(),
        };
        assert!(v.nc_apply_remote_folder_rename(&renamed).unwrap());
        assert_eq!(
            v.get(a).unwrap().unwrap().category.as_deref(),
            Some("Renamed")
        );
        assert_eq!(v.entry_updated_at(a).unwrap(), before);
        assert!(!v.categories().unwrap().contains(&"Old".to_string()));
        assert!(v.nc_folder_ops().unwrap().is_empty());

        // A name already mapped to another remote folder is left alone.
        let clash = NextcloudFolderMapping {
            local_name: "taken".into(),
            ..renamed
        };
        assert!(!v.nc_apply_remote_folder_rename(&clash).unwrap());
        assert_eq!(
            v.get(a).unwrap().unwrap().category.as_deref(),
            Some("Renamed")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn counts_include_empty_folders() {
        let (v, dir) = vault();
        add(&v, "A", Some("Work"));
        add(&v, "B", Some("Work"));
        v.create_folder("Empty").unwrap();
        let counts = v.folder_counts().unwrap();
        assert!(counts.contains(&("Work".to_string(), 2)));
        assert!(counts.contains(&("Empty".to_string(), 0)));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
