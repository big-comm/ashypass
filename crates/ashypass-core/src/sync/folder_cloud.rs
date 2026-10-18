//! Cloud drives as remotes of the encrypted folder sync (`super::folder`):
//! Dropbox and Google Drive, through their HTTP APIs. They only ever store
//! the sync's ciphertext files.
//!
//! The access token comes from the caller ([`TokenSource`]): the desktop
//! signs in through the browser, Android through the phone's Google account
//! or the browser. The API addresses can be changed so tests run against a
//! local stand-in.

use super::folder::Remote;
use crate::{Error, Result};
use reqwest::blocking::{Client, RequestBuilder, Response};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;
use std::sync::Mutex;
use std::time::Duration;

/// Gives a valid access token (refreshing it when needed).
pub type TokenSource = Box<dyn Fn() -> Result<String> + Send + Sync>;

/// Largest file read into memory (the sync's files are small batches).
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

fn client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| Error::Other(format!("cloud http: {e}")))
}

fn send(what: &str, request: RequestBuilder) -> Result<Response> {
    let again = request.try_clone();
    let first = request.send();
    let response = match (first, again) {
        // One more try when the phone dropped the connection for a moment.
        (Err(e), Some(again)) if e.is_connect() || e.is_timeout() => {
            std::thread::sleep(Duration::from_secs(2));
            again.send()
        }
        (other, _) => other,
    };
    response.map_err(|e| {
        Error::Other(format!(
            "{what}: {}",
            crate::sync::nextcloud_passwords::error_chain(&e)
        ))
    })
}

fn read_body(what: &str, mut response: Response) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    (&mut response)
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut data)?;
    if data.len() as u64 > MAX_FILE_BYTES {
        return Err(Error::InvalidInput(format!("{what}: file too large")));
    }
    Ok(data)
}

fn http_error(what: &str, response: Response) -> Error {
    let status = response.status().as_u16();
    let detail: String = response
        .text()
        .unwrap_or_default()
        .chars()
        .take(300)
        .collect();
    if status == 401 {
        return Error::Other(format!(
            "{what}: the sign-in expired or was revoked (HTTP 401); connect again"
        ));
    }
    Error::Other(format!("{what}: HTTP {status} {detail}"))
}

fn join(folder: &str, path: &str) -> String {
    let mut out = String::new();
    for part in folder.split('/').chain(path.split('/')) {
        let part = part.trim();
        if !part.is_empty() {
            out.push('/');
            out.push_str(part);
        }
    }
    out
}

// ── Dropbox ─────────────────────────────────────────────────────────────────

/// A folder in Dropbox. With an "App folder" app it lives under
/// `Apps/<app name>/`, which is all the app can see.
pub struct DropboxFolder {
    token: TokenSource,
    folder: String,
    api: String,
    content: String,
}

impl DropboxFolder {
    pub fn new(token: TokenSource, folder: &str) -> Self {
        Self::with_endpoints(
            token,
            folder,
            "https://api.dropboxapi.com",
            "https://content.dropboxapi.com",
        )
    }

    pub fn with_endpoints(token: TokenSource, folder: &str, api: &str, content: &str) -> Self {
        Self {
            token,
            folder: folder.trim().to_string(),
            api: api.trim_end_matches('/').to_string(),
            content: content.trim_end_matches('/').to_string(),
        }
    }

    /// Dropbox's `Dropbox-API-Arg` header: JSON with non-ASCII escaped.
    fn arg(value: &Value) -> String {
        let mut out = String::new();
        for ch in value.to_string().chars() {
            if ch.is_ascii() {
                out.push(ch);
            } else {
                let mut buf = [0u16; 2];
                for unit in ch.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
        out
    }

    /// Check the token works (the account's name, for the settings).
    pub fn probe(&self) -> Result<String> {
        let response = send(
            "dropbox account",
            client()?
                .post(format!("{}/2/users/get_current_account", self.api))
                .bearer_auth((self.token)()?),
        )?;
        if !response.status().is_success() {
            return Err(http_error("dropbox account", response));
        }
        let body: Value = response
            .json()
            .map_err(|e| Error::Other(format!("dropbox account: {e}")))?;
        Ok(body["email"]
            .as_str()
            .or(body["name"]["display_name"].as_str())
            .unwrap_or_default()
            .to_string())
    }
}

/// A 409 whose error says the path does not exist.
fn dropbox_not_found(status: u16, body: &str) -> bool {
    status == 409 && body.contains("not_found")
}

impl Remote for DropboxFolder {
    fn list(&self, dir: &str) -> Result<Vec<String>> {
        let client = client()?;
        let token = (self.token)()?;
        let mut names = Vec::new();
        let mut request = client
            .post(format!("{}/2/files/list_folder", self.api))
            .bearer_auth(&token)
            .json(&json!({ "path": join(&self.folder, dir) }));
        loop {
            let response = send("dropbox list", request)?;
            let status = response.status().as_u16();
            if !response.status().is_success() {
                let body = response.text().unwrap_or_default();
                if dropbox_not_found(status, &body) {
                    return Ok(Vec::new());
                }
                return Err(Error::Other(format!("dropbox list: HTTP {status} {body}")));
            }
            let body: Value = response
                .json()
                .map_err(|e| Error::Other(format!("dropbox list: {e}")))?;
            for entry in body["entries"].as_array().into_iter().flatten() {
                if let Some(name) = entry["name"].as_str() {
                    names.push(name.to_string());
                }
            }
            if body["has_more"].as_bool() != Some(true) {
                return Ok(names);
            }
            request = client
                .post(format!("{}/2/files/list_folder/continue", self.api))
                .bearer_auth(&token)
                .json(&json!({ "cursor": body["cursor"] }));
        }
    }

    fn get(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let response = send(
            "dropbox download",
            client()?
                .post(format!("{}/2/files/download", self.content))
                .bearer_auth((self.token)()?)
                .header(
                    "Dropbox-API-Arg",
                    Self::arg(&json!({ "path": join(&self.folder, path) })),
                ),
        )?;
        let status = response.status().as_u16();
        if !response.status().is_success() {
            let body = response.text().unwrap_or_default();
            if dropbox_not_found(status, &body) {
                return Ok(None);
            }
            return Err(Error::Other(format!(
                "dropbox download: HTTP {status} {body}"
            )));
        }
        Ok(Some(read_body("dropbox download", response)?))
    }

    fn put(&self, path: &str, data: &[u8]) -> Result<()> {
        // Dropbox creates the missing folders itself.
        let response = send(
            "dropbox upload",
            client()?
                .post(format!("{}/2/files/upload", self.content))
                .bearer_auth((self.token)()?)
                .header(
                    "Dropbox-API-Arg",
                    Self::arg(&json!({
                        "path": join(&self.folder, path),
                        "mode": "overwrite",
                        "mute": true,
                    })),
                )
                .header("Content-Type", "application/octet-stream")
                .body(data.to_vec()),
        )?;
        if !response.status().is_success() {
            return Err(http_error("dropbox upload", response));
        }
        Ok(())
    }
}

// ── Google Drive ────────────────────────────────────────────────────────────

const FOLDER_MIME: &str = "application/vnd.google-apps.folder";

/// A folder in Google Drive (`My Drive/<folder>`). With the `drive.file`
/// scope the app only sees the files it created.
pub struct DriveFolder {
    token: TokenSource,
    folder: String,
    api: String,
    upload: String,
    /// Path ("" = the sync folder, "changes", "changes/x/y.bin") → file id.
    ids: Mutex<HashMap<String, String>>,
}

impl DriveFolder {
    pub fn new(token: TokenSource, folder: &str) -> Self {
        Self::with_endpoints(token, folder, "https://www.googleapis.com")
    }

    pub fn with_endpoints(token: TokenSource, folder: &str, base: &str) -> Self {
        let base = base.trim_end_matches('/');
        let folder = folder.trim();
        Self {
            token,
            folder: if folder.is_empty() {
                "AshyPass Sync".into()
            } else {
                folder.into()
            },
            api: format!("{base}/drive/v3/files"),
            upload: format!("{base}/upload/drive/v3/files"),
            ids: Mutex::new(HashMap::new()),
        }
    }

    /// Check the token works (the account's e-mail, for the settings).
    pub fn probe(&self) -> Result<String> {
        let about = self.api.replace("/files", "/about");
        let response = send(
            "google drive account",
            client()?
                .get(about)
                .bearer_auth((self.token)()?)
                .query(&[("fields", "user(emailAddress,displayName)")]),
        )?;
        if !response.status().is_success() {
            return Err(http_error("google drive account", response));
        }
        let body: Value = response
            .json()
            .map_err(|e| Error::Other(format!("google drive account: {e}")))?;
        Ok(body["user"]["emailAddress"]
            .as_str()
            .unwrap_or_default()
            .to_string())
    }

    fn quote(name: &str) -> String {
        name.replace('\\', "\\\\").replace('\'', "\\'")
    }

    /// Children of folder `parent` named `name` (newest first).
    fn find(&self, token: &str, parent: &str, name: &str) -> Result<Option<String>> {
        let q = format!(
            "name = '{}' and '{}' in parents and trashed = false",
            Self::quote(name),
            Self::quote(parent)
        );
        let response = send(
            "google drive search",
            client()?.get(&self.api).bearer_auth(token).query(&[
                ("q", q.as_str()),
                ("fields", "files(id)"),
                ("orderBy", "modifiedTime desc"),
                ("spaces", "drive"),
            ]),
        )?;
        if !response.status().is_success() {
            return Err(http_error("google drive search", response));
        }
        let body: Value = response
            .json()
            .map_err(|e| Error::Other(format!("google drive search: {e}")))?;
        Ok(body["files"][0]["id"].as_str().map(str::to_string))
    }

    fn create_folder(&self, token: &str, parent: &str, name: &str) -> Result<String> {
        let response = send(
            "google drive folder",
            client()?
                .post(&self.api)
                .bearer_auth(token)
                .query(&[("fields", "id")])
                .json(&json!({ "name": name, "mimeType": FOLDER_MIME, "parents": [parent] })),
        )?;
        if !response.status().is_success() {
            return Err(http_error("google drive folder", response));
        }
        let body: Value = response
            .json()
            .map_err(|e| Error::Other(format!("google drive folder: {e}")))?;
        body["id"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| Error::Other("google drive folder: no id".into()))
    }

    /// The id of `path` (a folder or file under the sync folder); folders
    /// are created on the way when `create` is set.
    fn id_of(&self, token: &str, path: &str, create: bool) -> Result<Option<String>> {
        let mut parent = "root".to_string();
        let mut walked = String::new();
        let parts =
            std::iter::once(self.folder.as_str()).chain(path.split('/').filter(|p| !p.is_empty()));
        for (i, part) in parts.enumerate() {
            if i > 0 {
                if !walked.is_empty() {
                    walked.push('/');
                }
                walked.push_str(part);
            }
            let key = walked.clone();
            if let Some(id) = self.ids.lock().expect("lock").get(&key).cloned() {
                parent = id;
                continue;
            }
            let id = match self.find(token, &parent, part)? {
                Some(id) => id,
                None if create => self.create_folder(token, &parent, part)?,
                None => return Ok(None),
            };
            self.ids.lock().expect("lock").insert(key, id.clone());
            parent = id;
        }
        Ok(Some(parent))
    }
}

impl Remote for DriveFolder {
    fn list(&self, dir: &str) -> Result<Vec<String>> {
        let token = (self.token)()?;
        let Some(folder) = self.id_of(&token, dir, false)? else {
            return Ok(Vec::new());
        };
        let q = format!("'{}' in parents and trashed = false", Self::quote(&folder));
        let mut names = Vec::new();
        let mut page: Option<String> = None;
        loop {
            let mut query = vec![
                ("q", q.clone()),
                ("fields", "nextPageToken,files(id,name)".to_string()),
                ("pageSize", "1000".to_string()),
                ("spaces", "drive".to_string()),
            ];
            if let Some(page) = &page {
                query.push(("pageToken", page.clone()));
            }
            let response = send(
                "google drive list",
                client()?.get(&self.api).bearer_auth(&token).query(&query),
            )?;
            if !response.status().is_success() {
                return Err(http_error("google drive list", response));
            }
            let body: Value = response
                .json()
                .map_err(|e| Error::Other(format!("google drive list: {e}")))?;
            for file in body["files"].as_array().into_iter().flatten() {
                if let (Some(name), Some(id)) = (file["name"].as_str(), file["id"].as_str()) {
                    let key = if dir.trim_matches('/').is_empty() {
                        name.to_string()
                    } else {
                        format!("{}/{name}", dir.trim_matches('/'))
                    };
                    self.ids.lock().expect("lock").insert(key, id.to_string());
                    names.push(name.to_string());
                }
            }
            match body["nextPageToken"].as_str() {
                Some(next) => page = Some(next.to_string()),
                None => return Ok(names),
            }
        }
    }

    fn get(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let token = (self.token)()?;
        let Some(id) = self.id_of(&token, path, false)? else {
            return Ok(None);
        };
        let response = send(
            "google drive download",
            client()?
                .get(format!("{}/{id}", self.api))
                .bearer_auth(&token)
                .query(&[("alt", "media")]),
        )?;
        if response.status().as_u16() == 404 {
            self.ids
                .lock()
                .expect("lock")
                .remove(path.trim_matches('/'));
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(http_error("google drive download", response));
        }
        Ok(Some(read_body("google drive download", response)?))
    }

    fn put(&self, path: &str, data: &[u8]) -> Result<()> {
        let token = (self.token)()?;
        let path = path.trim_matches('/');
        let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
        if let Some(id) = self.id_of(&token, path, false)? {
            let response = send(
                "google drive upload",
                client()?
                    .patch(format!("{}/{id}", self.upload))
                    .bearer_auth(&token)
                    .query(&[("uploadType", "media")])
                    .header("Content-Type", "application/octet-stream")
                    .body(data.to_vec()),
            )?;
            if !response.status().is_success() {
                return Err(http_error("google drive upload", response));
            }
            return Ok(());
        }
        let parent = self
            .id_of(&token, dir, true)?
            .ok_or_else(|| Error::Other("google drive: no folder".into()))?;
        // multipart/related: the metadata, then the content.
        let boundary = format!("ashypass{:016x}", rand::random::<u64>());
        let mut body = Vec::with_capacity(data.len() + 512);
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{}\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n",
                json!({ "name": name, "parents": [parent] })
            )
            .as_bytes(),
        );
        body.extend_from_slice(data);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let response = send(
            "google drive upload",
            client()?
                .post(&self.upload)
                .bearer_auth(&token)
                .query(&[("uploadType", "multipart"), ("fields", "id")])
                .header(
                    "Content-Type",
                    format!("multipart/related; boundary={boundary}"),
                )
                .body(body),
        )?;
        if !response.status().is_success() {
            return Err(http_error("google drive upload", response));
        }
        let created: Value = response
            .json()
            .map_err(|e| Error::Other(format!("google drive upload: {e}")))?;
        if let Some(id) = created["id"].as_str() {
            self.ids
                .lock()
                .expect("lock")
                .insert(path.to_string(), id.to_string());
        }
        Ok(())
    }
}

// ── Dropbox sign-in (OAuth 2 PKCE, no redirect) ─────────────────────────────

/// Dropbox sign-in for a public client (no secret): the user opens
/// [`DropboxAuth::authorize_url`], allows the app, and pastes the code that
/// Dropbox shows; the refresh token then lasts until revoked.
pub struct DropboxAuth {
    pub app_key: String,
    pub verifier: String,
    challenge: String,
}

/// Tokens from a Dropbox sign-in or refresh.
#[derive(Debug, Clone)]
pub struct DropboxTokens {
    pub access_token: String,
    /// Only from the first sign-in.
    pub refresh_token: Option<String>,
    /// Unix seconds.
    pub expires_at: i64,
}

const DROPBOX_TOKEN_URL: &str = "https://api.dropboxapi.com/oauth2/token";

impl DropboxAuth {
    pub fn start(app_key: &str) -> Self {
        let (verifier, challenge) = crate::backup::oauth::pkce_pair();
        Self {
            app_key: app_key.trim().to_string(),
            verifier,
            challenge,
        }
    }

    /// Pick up a sign-in started earlier (the app went to the browser):
    /// the challenge is derived again from the kept verifier.
    pub fn resume(app_key: &str, verifier: &str) -> Self {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use sha2::{Digest, Sha256};
        Self {
            app_key: app_key.trim().to_string(),
            verifier: verifier.to_string(),
            challenge: URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
        }
    }

    pub fn authorize_url(&self) -> String {
        let mut url =
            url::Url::parse("https://www.dropbox.com/oauth2/authorize").expect("valid url");
        url.query_pairs_mut()
            .append_pair("client_id", &self.app_key)
            .append_pair("response_type", "code")
            .append_pair("code_challenge", &self.challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("token_access_type", "offline");
        url.to_string()
    }

    /// Trade the pasted code for tokens.
    pub fn finish(&self, code: &str) -> Result<DropboxTokens> {
        dropbox_token(&[
            ("grant_type", "authorization_code"),
            ("code", code.trim()),
            ("client_id", &self.app_key),
            ("code_verifier", &self.verifier),
        ])
    }
}

/// A fresh access token from the refresh token.
pub fn dropbox_refresh(app_key: &str, refresh_token: &str) -> Result<DropboxTokens> {
    dropbox_token(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", app_key),
    ])
}

fn dropbox_token(form: &[(&str, &str)]) -> Result<DropboxTokens> {
    let response = send(
        "dropbox sign-in",
        client()?.post(DROPBOX_TOKEN_URL).form(form),
    )?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body = response.text().unwrap_or_default();
        return Err(Error::Other(format!(
            "dropbox sign-in: HTTP {status} {}",
            body.chars().take(200).collect::<String>()
        )));
    }
    let body: Value = response
        .json()
        .map_err(|e| Error::Other(format!("dropbox sign-in: {e}")))?;
    let access_token = body["access_token"]
        .as_str()
        .ok_or_else(|| Error::Other("dropbox sign-in: no access token".into()))?
        .to_string();
    Ok(DropboxTokens {
        access_token,
        refresh_token: body["refresh_token"].as_str().map(str::to_string),
        expires_at: chrono::Utc::now().timestamp() + body["expires_in"].as_i64().unwrap_or(14_400),
    })
}

/// A [`TokenSource`] that refreshes a Dropbox access token when it is
/// about to expire.
pub fn dropbox_token_source(app_key: String, refresh_token: String) -> TokenSource {
    let cache: Mutex<Option<(String, i64)>> = Mutex::new(None);
    Box::new(move || {
        let now = chrono::Utc::now().timestamp();
        if let Some((token, expires)) = cache.lock().expect("lock").clone() {
            if expires > now + 120 {
                return Ok(token);
            }
        }
        let fresh = dropbox_refresh(&app_key, &refresh_token)?;
        *cache.lock().expect("lock") = Some((fresh.access_token.clone(), fresh.expires_at));
        Ok(fresh.access_token)
    })
}

/// Ashy Pass's Dropbox app ("App folder" access: it sees only
/// `Apps/Ashy Pass/`). An app key is public: sign-in uses PKCE, no secret.
const DROPBOX_APP_KEY: &str = "7vdp5694xs9jaym";

/// The Dropbox app key: `ASHYPASS_DROPBOX_APP_KEY` (at run or build time)
/// overrides Ashy Pass's own, e.g. for a fork with its own Dropbox app.
pub fn dropbox_app_key() -> Option<String> {
    std::env::var("ASHYPASS_DROPBOX_APP_KEY")
        .ok()
        .or(option_env!("ASHYPASS_DROPBOX_APP_KEY").map(str::to_string))
        .filter(|k| !k.trim().is_empty())
        .or_else(|| Some(DROPBOX_APP_KEY.to_string()))
}

#[cfg(test)]
#[path = "folder_cloud_tests.rs"]
mod tests;
