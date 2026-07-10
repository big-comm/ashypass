//! Google Drive REST client.
//!
//! Stays scope-minimal (`drive.file`): the app only sees files it created or
//! the user explicitly opens. Folder lookup/create + multipart upload +
//! list/download/delete is enough for vault snapshots.

use crate::backup::oauth::{self, ClientCredentials, Token};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

const DRIVE_FILES: &str = "https://www.googleapis.com/drive/v3/files";
const DRIVE_UPLOAD: &str = "https://www.googleapis.com/upload/drive/v3/files";
const FOLDER_MIME: &str = "application/vnd.google-apps.folder";

#[derive(Debug, Clone)]
pub struct BackupService {
    pub token: Option<Token>,
    pub folder_name: String,
    pub folder_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveFile {
    pub id: String,
    pub name: String,
    #[serde(rename = "modifiedTime", default)]
    pub modified_time: String,
    #[serde(default)]
    pub size: Option<String>,
}

impl BackupService {
    pub fn new() -> Self {
        Self {
            token: Token::load(),
            folder_name: "AshyPass Backups".to_string(),
            folder_id: None,
        }
    }

    pub fn is_logged_in(&self) -> bool {
        self.token.is_some()
    }

    pub fn login(&mut self, creds: &ClientCredentials) -> Result<()> {
        let tok = oauth::login(creds)?;
        self.token = Some(tok);
        self.folder_id = None;
        Ok(())
    }

    pub fn logout(&mut self) -> Result<()> {
        self.token = None;
        self.folder_id = None;
        Token::delete()?;
        Ok(())
    }

    fn refreshed_access_token(&mut self) -> Result<String> {
        let token = self
            .token
            .as_mut()
            .ok_or(Error::Other("not signed in to Google Drive".into()))?;
        let now = chrono::Utc::now().timestamp();
        if token.is_expired(now) {
            oauth::refresh(token)?;
        }
        Ok(token.access_token.clone())
    }

    fn client(&self) -> Result<&'static reqwest::blocking::Client> {
        static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
        if let Some(client) = CLIENT.get() {
            return Ok(client);
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| Error::Other(format!("drive http: {e}")))?;
        let _ = CLIENT.set(client);
        Ok(CLIENT.get().expect("client was initialized"))
    }

    /// Look up the configured folder by name. Creates it if missing.
    pub fn ensure_folder(&mut self) -> Result<String> {
        if let Some(id) = &self.folder_id {
            return Ok(id.clone());
        }
        let access = self.refreshed_access_token()?;
        let client = self.client()?;

        let q = format!(
            "mimeType='{FOLDER_MIME}' and name='{}' and trashed=false",
            escape_q(&self.folder_name)
        );
        #[derive(Deserialize)]
        struct ListResp {
            files: Vec<DriveFile>,
        }
        let resp = client
            .get(DRIVE_FILES)
            .bearer_auth(&access)
            .query(&[("q", q.as_str()), ("fields", "files(id,name)")])
            .send()
            .map_err(|e| Error::Other(format!("folder list: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::Other(format!(
                "folder list: {}",
                resp.text().unwrap_or_default()
            )));
        }
        let list: ListResp = resp
            .json()
            .map_err(|e| Error::Other(format!("folder parse: {e}")))?;
        if let Some(found) = list.files.into_iter().next() {
            self.folder_id = Some(found.id.clone());
            return Ok(found.id);
        }

        // Create
        let body = serde_json::json!({
            "name": self.folder_name,
            "mimeType": FOLDER_MIME,
        });
        let resp = client
            .post(DRIVE_FILES)
            .bearer_auth(&access)
            .json(&body)
            .send()
            .map_err(|e| Error::Other(format!("folder create: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::Other(format!(
                "folder create: {}",
                resp.text().unwrap_or_default()
            )));
        }
        let created: DriveFile = resp
            .json()
            .map_err(|e| Error::Other(format!("folder parse: {e}")))?;
        self.folder_id = Some(created.id.clone());
        Ok(created.id)
    }

    /// Resumable, streaming upload of `path` into the backup folder.
    pub fn upload(&mut self, path: impl AsRef<Path>, name: &str) -> Result<String> {
        let folder_id = self.ensure_folder()?;
        let access = self.refreshed_access_token()?;
        let client = self.client()?;
        let size = fs::metadata(path.as_ref())?.len();
        let meta = serde_json::json!({
            "name": name,
            "parents": [folder_id],
        });
        let initiate = client
            .post(DRIVE_UPLOAD)
            .bearer_auth(&access)
            .query(&[("uploadType", "resumable")])
            .header("X-Upload-Content-Type", "application/octet-stream")
            .header("X-Upload-Content-Length", size)
            .json(&meta)
            .send()
            .map_err(|e| Error::Other(format!("upload initiate: {e}")))?;
        if !initiate.status().is_success() {
            return Err(Error::Other(format!(
                "upload initiate: {}",
                initiate.text().unwrap_or_default()
            )));
        }
        let location = initiate
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| Error::Other("upload initiate: missing Location header".into()))?
            .to_string();
        let file = fs::File::open(path.as_ref())?;
        let resp = client
            .put(location)
            .header(reqwest::header::CONTENT_LENGTH, size)
            .body(reqwest::blocking::Body::new(file))
            .send()
            .map_err(|e| Error::Other(format!("upload: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::Other(format!(
                "upload: {}",
                resp.text().unwrap_or_default()
            )));
        }
        let file: DriveFile = resp
            .json()
            .map_err(|e| Error::Other(format!("upload parse: {e}")))?;
        Ok(file.id)
    }

    /// List the snapshots in the backup folder, newest first.
    pub fn list_backups(&mut self) -> Result<Vec<DriveFile>> {
        let folder_id = self.ensure_folder()?;
        let access = self.refreshed_access_token()?;
        let client = self.client()?;
        let q = format!("'{folder_id}' in parents and trashed=false");
        #[derive(Deserialize)]
        struct ListResp {
            #[serde(rename = "nextPageToken", default)]
            next_page_token: Option<String>,
            files: Vec<DriveFile>,
        }
        let mut page_token: Option<String> = None;
        let mut files = Vec::new();
        loop {
            let mut request = client.get(DRIVE_FILES).bearer_auth(&access).query(&[
                ("q", q.as_str()),
                ("orderBy", "modifiedTime desc"),
                ("fields", "nextPageToken,files(id,name,modifiedTime,size)"),
                ("pageSize", "1000"),
            ]);
            if let Some(token) = page_token.as_deref() {
                request = request.query(&[("pageToken", token)]);
            }
            let response = request
                .send()
                .map_err(|e| Error::Other(format!("list: {e}")))?;
            if !response.status().is_success() {
                return Err(Error::Other(format!(
                    "list: {}",
                    response.text().unwrap_or_default()
                )));
            }
            let mut page: ListResp = response
                .json()
                .map_err(|e| Error::Other(format!("list parse: {e}")))?;
            files.append(&mut page.files);
            page_token = page.next_page_token;
            if page_token.is_none() {
                break;
            }
        }
        Ok(files)
    }

    /// Download `file_id` to `dest`.
    pub fn download(&mut self, file_id: &str, dest: impl AsRef<Path>) -> Result<()> {
        let access = self.refreshed_access_token()?;
        let client = self.client()?;
        let url = format!("{DRIVE_FILES}/{file_id}?alt=media");
        let mut resp = client
            .get(&url)
            .bearer_auth(&access)
            .send()
            .map_err(|e| Error::Other(format!("download: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::Other(format!(
                "download: {}",
                resp.text().unwrap_or_default()
            )));
        }
        write_response_new(&mut resp, dest.as_ref())
    }

    pub fn delete(&mut self, file_id: &str) -> Result<()> {
        let access = self.refreshed_access_token()?;
        let client = self.client()?;
        let url = format!("{DRIVE_FILES}/{file_id}");
        let resp = client
            .delete(&url)
            .bearer_auth(&access)
            .send()
            .map_err(|e| Error::Other(format!("delete: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::Other(format!(
                "delete: {}",
                resp.text().unwrap_or_default()
            )));
        }
        Ok(())
    }
}

impl Default for BackupService {
    fn default() -> Self {
        Self::new()
    }
}

fn escape_q(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

fn write_response_new(response: &mut impl std::io::Read, destination: &Path) -> Result<()> {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".ashypass-drive-download-{}-{}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ));
    let result: std::io::Result<()> = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        std::io::copy(response, &mut file)?;
        file.flush()?;
        file.sync_all()?;
        fs::hard_link(&temporary, destination)?;
        fs::remove_file(&temporary)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn downloaded_files_never_overwrite_existing_data() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("backup.db");
        let mut first = std::io::Cursor::new(b"first".to_vec());
        write_response_new(&mut first, &destination).unwrap();
        let mut second = std::io::Cursor::new(b"second".to_vec());
        assert!(write_response_new(&mut second, &destination).is_err());
        assert_eq!(fs::read(destination).unwrap(), b"first");
    }
}
