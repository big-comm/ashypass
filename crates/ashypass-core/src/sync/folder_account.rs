//! The WebDAV account of the encrypted folder sync (`super::folder`): where
//! the folder is and how to sign in. Saved in `folder-sync.json` (0600) with
//! the password in the system keyring when there is one.

use crate::backup::webdav::{WebdavConfig, WebdavFolder};
use crate::{server_url, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const PASSWORD_SECRET_KIND: &str = "folder-sync-password";
const PASSWORD_SECRET_LABEL: &str = "Ashy Pass — sync folder password";

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct FolderSyncAccount {
    /// A Nextcloud address (`cloud.example.com`) when `nextcloud` is set,
    /// otherwise the full WebDAV URL.
    pub server_url: String,
    pub nextcloud: bool,
    pub user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    /// Folder on the server; empty means `AshyPass Sync`.
    pub folder: String,
}

impl std::fmt::Debug for FolderSyncAccount {
    // Never print the password, even in a debug log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FolderSyncAccount")
            .field("server_url", &self.server_url)
            .field("nextcloud", &self.nextcloud)
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .field("folder", &self.folder)
            .finish()
    }
}

impl FolderSyncAccount {
    /// The WebDAV folder of this account.
    pub fn remote(&self) -> Result<WebdavFolder> {
        let base_url = if self.nextcloud {
            // The user's files, without needing the user id (which differs
            // from the login name when signing in with an e-mail address).
            format!(
                "{}/remote.php/webdav",
                server_url::normalize_nextcloud(&self.server_url)
            )
        } else {
            server_url::normalize(&self.server_url)
        };
        WebdavFolder::new(WebdavConfig {
            base_url,
            username: self.user.trim().to_string(),
            password: self.password.trim().to_string(),
            folder: self.folder.trim().to_string(),
        })
    }

    fn path() -> PathBuf {
        crate::config::config_dir().join("folder-sync.json")
    }

    /// The saved account, if any.
    pub fn load() -> Option<Self> {
        let path = Self::path();
        let _ = crate::config::ensure_private_file(&path);
        let text = std::fs::read_to_string(&path).ok()?;
        let mut account: Self = serde_json::from_str(&text).ok()?;
        if account.password.is_empty() {
            account.password = crate::keyring::load_named_secret(PASSWORD_SECRET_KIND)
                .map_err(|e| log::warn!("sync folder password unavailable from keyring: {e}"))
                .ok()
                .flatten()?;
        }
        Some(account)
    }

    /// Save the account: the password goes to the keyring, or stays in the
    /// 0600 file on sessions without one.
    pub fn save(&self) -> Result<()> {
        let mut disk = self.clone();
        match crate::keyring::store_named_secret(
            PASSWORD_SECRET_KIND,
            PASSWORD_SECRET_LABEL,
            &self.password,
        ) {
            Ok(()) => disk.password.clear(),
            Err(e) => log::warn!("sync folder keyring save failed; keeping chmod 0600 file: {e}"),
        }
        let text = serde_json::to_string_pretty(&disk)?;
        crate::config::atomic_write_private(&Self::path(), text.as_bytes())?;
        Ok(())
    }

    pub fn delete() -> Result<()> {
        let path = Self::path();
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        let _ = crate::keyring::delete_named_secret(PASSWORD_SECRET_KIND);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nextcloud_accounts_use_the_files_endpoint() {
        let account = FolderSyncAccount {
            server_url: "cloud.example.com/".into(),
            nextcloud: true,
            user: "ana@example.com".into(),
            password: "app-password".into(),
            folder: String::new(),
        };
        assert!(account.remote().is_ok());
        assert!(!format!("{account:?}").contains("app-password"));
        let plain = FolderSyncAccount {
            server_url: "http://dav.example.com/files".into(),
            nextcloud: false,
            ..account
        };
        // Plain http only on a loopback test server.
        assert!(plain.remote().is_err());
    }
}
