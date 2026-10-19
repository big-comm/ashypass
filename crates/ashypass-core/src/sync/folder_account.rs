//! The account of the encrypted folder sync (`super::folder`): which
//! service holds the folder (Nextcloud or WebDAV, Dropbox, Google Drive, a
//! local folder) and how to sign in. Saved in `folder-sync.json` (0600)
//! with the secret in the system keyring when there is one.

use super::folder::{LocalFolder, Remote};
use super::folder_cloud::{self, DriveFolder, DropboxFolder, TokenSource};
use crate::backup::webdav::{WebdavConfig, WebdavFolder};
use crate::{server_url, Error, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const PASSWORD_SECRET_KIND: &str = "folder-sync-password";
const PASSWORD_SECRET_LABEL: &str = "Ashy Pass — sync folder password";

/// The services that can hold the sync folder (`FolderSyncAccount::provider`).
pub const PROVIDER_WEBDAV: &str = "webdav";
pub const PROVIDER_DROPBOX: &str = "dropbox";
pub const PROVIDER_GOOGLE_DRIVE: &str = "gdrive";
pub const PROVIDER_LOCAL: &str = "local";

/// pCloud's WebDAV servers, by where the account's data lives. A pCloud
/// account is a WebDAV one on either.
pub const PCLOUD_WEBDAV_US: &str = "https://webdav.pcloud.com";
pub const PCLOUD_WEBDAV_EU: &str = "https://ewebdav.pcloud.com";

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct FolderSyncAccount {
    /// `webdav` (also Nextcloud; the default, as in older files),
    /// `dropbox`, `gdrive` or `local`.
    #[serde(default)]
    pub provider: String,
    /// WebDAV: a Nextcloud address (`cloud.example.com`) when `nextcloud`
    /// is set, otherwise the full WebDAV URL. Local: the folder's path.
    pub server_url: String,
    pub nextcloud: bool,
    /// WebDAV: the login. Cloud drives: the account's e-mail (shown only).
    pub user: String,
    /// WebDAV: the password. Dropbox: the refresh token.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    /// Folder on the server; empty means `AshyPass Sync`.
    pub folder: String,
}

impl std::fmt::Debug for FolderSyncAccount {
    // Never print the password, even in a debug log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FolderSyncAccount")
            .field("provider", &self.provider)
            .field("server_url", &self.server_url)
            .field("nextcloud", &self.nextcloud)
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .field("folder", &self.folder)
            .finish()
    }
}

impl FolderSyncAccount {
    pub fn provider(&self) -> &str {
        if self.provider.is_empty() {
            PROVIDER_WEBDAV
        } else {
            &self.provider
        }
    }

    /// A WebDAV account on pCloud's servers.
    pub fn is_pcloud(&self) -> bool {
        self.provider() == PROVIDER_WEBDAV
            && !self.nextcloud
            && [PCLOUD_WEBDAV_US, PCLOUD_WEBDAV_EU]
                .contains(&server_url::normalize(&self.server_url).as_str())
    }

    /// The WebDAV folder of a WebDAV (or Nextcloud) account.
    pub fn webdav(&self) -> Result<WebdavFolder> {
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

    fn folder_name(&self) -> String {
        let folder = self.folder.trim().trim_matches('/');
        if folder.is_empty() {
            "AshyPass Sync".into()
        } else {
            folder.into()
        }
    }

    /// The folder of this account. Google Drive needs `google` (an access
    /// token source); without one the desktop's Google sign-in is used.
    pub fn remote_with(&self, google: Option<TokenSource>) -> Result<Box<dyn Remote>> {
        Ok(match self.provider() {
            PROVIDER_DROPBOX => Box::new(DropboxFolder::new(
                self.dropbox_tokens()?,
                &format!("/{}", self.folder_name()),
            )),
            PROVIDER_GOOGLE_DRIVE => Box::new(DriveFolder::new(
                match google {
                    Some(source) => source,
                    None => desktop_google_token()?,
                },
                &self.folder_name(),
            )),
            PROVIDER_LOCAL => {
                let base = self.server_url.trim();
                if base.is_empty() {
                    return Err(Error::InvalidInput("choose the local folder".into()));
                }
                Box::new(LocalFolder {
                    root: PathBuf::from(base).join(self.folder_name()),
                })
            }
            _ => Box::new(self.webdav()?),
        })
    }

    pub fn remote(&self) -> Result<Box<dyn Remote>> {
        self.remote_with(None)
    }

    /// Check the address and sign-in. Returns the account name to show
    /// (e-mail for the cloud drives), when the service tells it.
    pub fn probe_with(&self, google: Option<TokenSource>) -> Result<String> {
        match self.provider() {
            PROVIDER_DROPBOX => DropboxFolder::new(self.dropbox_tokens()?, "/").probe(),
            PROVIDER_GOOGLE_DRIVE => DriveFolder::new(
                match google {
                    Some(source) => source,
                    None => desktop_google_token()?,
                },
                "",
            )
            .probe(),
            PROVIDER_LOCAL => {
                let root = PathBuf::from(self.server_url.trim());
                if !root.is_dir() {
                    return Err(Error::InvalidInput(format!(
                        "the folder {} does not exist",
                        root.display()
                    )));
                }
                Ok(String::new())
            }
            _ => {
                self.webdav()?.probe()?;
                Ok(self.user.clone())
            }
        }
    }

    pub fn probe(&self) -> Result<String> {
        self.probe_with(None)
    }

    fn dropbox_tokens(&self) -> Result<TokenSource> {
        let key = folder_cloud::dropbox_app_key()
            .ok_or_else(|| Error::Other("this build has no Dropbox app key".into()))?;
        if self.password.trim().is_empty() {
            return Err(Error::InvalidInput("sign in to Dropbox first".into()));
        }
        Ok(folder_cloud::dropbox_token_source(
            key,
            self.password.trim().to_string(),
        ))
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

/// The desktop's Google sign-in (Settings → Backups → Google Drive),
/// refreshed when it is about to expire.
fn desktop_google_token() -> Result<TokenSource> {
    use crate::backup::oauth::{refresh, Token};
    if Token::load().is_none() {
        return Err(Error::Other(
            "sign in to Google Drive first (Backups → Google Drive)".into(),
        ));
    }
    Ok(Box::new(|| {
        let mut token = Token::load().ok_or_else(|| {
            Error::Other("sign in to Google Drive first (Backups → Google Drive)".into())
        })?;
        if token.is_expired(chrono::Utc::now().timestamp()) {
            refresh(&mut token)?;
        }
        Ok(token.access_token)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcloud_accounts_are_webdav_on_its_servers() {
        let account = |url: &str| FolderSyncAccount {
            server_url: url.into(),
            user: "ana@example.com".into(),
            password: "p".into(),
            ..Default::default()
        };
        assert!(account(PCLOUD_WEBDAV_US).is_pcloud());
        assert!(account("ewebdav.pcloud.com/").is_pcloud());
        assert!(account(PCLOUD_WEBDAV_EU).remote().is_ok());
        assert!(!account("https://dav.example.com").is_pcloud());
        let nextcloud = FolderSyncAccount {
            nextcloud: true,
            ..account(PCLOUD_WEBDAV_US)
        };
        assert!(!nextcloud.is_pcloud());
    }

    #[test]
    fn nextcloud_accounts_use_the_files_endpoint() {
        let account = FolderSyncAccount {
            provider: String::new(),
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

    #[test]
    fn older_files_are_webdav_and_other_services_check_their_setup() {
        // Saved before there was a choice of service.
        let old: FolderSyncAccount = serde_json::from_str(
            r#"{"server_url":"cloud.example.com","nextcloud":true,"user":"ana","folder":"AshyPass Sync"}"#,
        )
        .unwrap();
        assert_eq!(old.provider(), PROVIDER_WEBDAV);

        let dir = tempfile::tempdir().unwrap();
        let local = FolderSyncAccount {
            provider: PROVIDER_LOCAL.into(),
            server_url: dir.path().display().to_string(),
            ..Default::default()
        };
        local.probe().unwrap();
        let remote = local.remote().unwrap();
        remote.put("changes/a/1.bin", b"x").unwrap();
        assert!(dir.path().join("AshyPass Sync/changes/a/1.bin").exists());
        let missing = FolderSyncAccount {
            server_url: dir.path().join("nope").display().to_string(),
            ..local
        };
        assert!(missing.probe().is_err());

        // Dropbox needs its sign-in (a refresh token) first.
        let dropbox = FolderSyncAccount {
            provider: PROVIDER_DROPBOX.into(),
            ..Default::default()
        };
        assert!(dropbox.remote().is_err());
    }
}
