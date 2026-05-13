//! Google Drive REST client.
//!
//! Stays scope-minimal (`drive.file`): the app only sees files it created or
//! the user explicitly opens. Folder lookup/create + multipart upload +
//! list/download/delete is enough for vault snapshots.

use crate::backup::oauth::{self, ClientCredentials, Token};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
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
        let token = self.token.as_mut().ok_or(Error::Other(
            "not signed in to Google Drive".into(),
        ))?;
        let now = chrono::Utc::now().timestamp();
        if token.is_expired(now) {
            oauth::refresh(token)?;
        }
        Ok(token.access_token.clone())
    }

    fn client(&self) -> Result<reqwest::blocking::Client> {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| Error::Other(format!("drive http: {e}")))
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

    /// Multipart upload of `path` into the backup folder. Returns the file id.
    pub fn upload(&mut self, path: impl AsRef<Path>, name: &str) -> Result<String> {
        let folder_id = self.ensure_folder()?;
        let access = self.refreshed_access_token()?;
        let bytes = fs::read(path.as_ref())?;
        let client = self.client()?;

        let boundary = format!(
            "ashypass{}{}",
            chrono::Utc::now().timestamp(),
            rand::random::<u32>()
        );
        let meta = serde_json::json!({
            "name": name,
            "parents": [folder_id],
        });
        let mut body: Vec<u8> = Vec::with_capacity(bytes.len() + 512);
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: application/json; charset=UTF-8\r\n\r\n");
        body.extend_from_slice(meta.to_string().as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(&bytes);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        let resp = client
            .post(DRIVE_UPLOAD)
            .bearer_auth(&access)
            .query(&[("uploadType", "multipart")])
            .header(
                "Content-Type",
                format!("multipart/related; boundary={boundary}"),
            )
            .body(body)
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
            files: Vec<DriveFile>,
        }
        let resp = client
            .get(DRIVE_FILES)
            .bearer_auth(&access)
            .query(&[
                ("q", q.as_str()),
                ("orderBy", "modifiedTime desc"),
                ("fields", "files(id,name,modifiedTime,size)"),
            ])
            .send()
            .map_err(|e| Error::Other(format!("list: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::Other(format!(
                "list: {}",
                resp.text().unwrap_or_default()
            )));
        }
        let list: ListResp = resp
            .json()
            .map_err(|e| Error::Other(format!("list parse: {e}")))?;
        Ok(list.files)
    }

    /// Download `file_id` to `dest`.
    pub fn download(&mut self, file_id: &str, dest: impl AsRef<Path>) -> Result<()> {
        let access = self.refreshed_access_token()?;
        let client = self.client()?;
        let url = format!("{DRIVE_FILES}/{file_id}?alt=media");
        let resp = client
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
        let bytes = resp
            .bytes()
            .map_err(|e| Error::Other(format!("download bytes: {e}")))?;
        if let Some(parent) = dest.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(dest.as_ref(), &bytes)?;
        Ok(())
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
