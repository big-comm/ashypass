//! Folder management: rename and remove a folder without touching the
//! entries' secrets.
//!
//! Folders are the `category` text on each entry plus the `folders` table for
//! empty ones. Removing a folder never removes the entries in it — they move
//! to "no folder". Both operations bump `updated_at` on the affected entries
//! so Nextcloud sync sends the new folder to the server.

use super::{normalize_folder_name, Vault};
use crate::{Error, Result};
use rusqlite::params;

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
        tx.commit()?;
        self.notify_change();
        Ok(moved)
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

#[cfg(test)]
mod tests {
    use crate::db::vault::{NewEntry, Vault};

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
