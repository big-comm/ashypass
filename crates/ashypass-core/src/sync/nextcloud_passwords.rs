//! Client for the Nextcloud Passwords app REST API (v1.0).
//!
//! Reference: <https://git.mdns.eu/nextcloud/passwords/-/wikis/Developers/Api/Index>
//!
//! Authentication is HTTPS Basic with the user's Nextcloud login plus an
//! **app password** (issued in Settings → Security → "Devices & Sessions").
//! Never feed the user's primary Nextcloud password here — the desktop app
//! does not check; the server may reject it; and rotation gets ugly. The
//! UI is responsible for explaining this to the user.
//!
//! Only the subset of endpoints the sync engine needs is implemented. The
//! v1.0 surface is stable and unencrypted-at-rest (server-side encryption
//! is transparent); v2.0 introduces client-side encryption and a session
//! handshake that is materially more complex — left for a future task.

use crate::{Error, Result};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Deserializer, Serialize};
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

/// Persisted config. Service password is stored in Secret Service when
/// available; the JSON file is still chmod 0600 and keeps legacy fallback
/// compatibility on sessions without a keyring.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NcConfig {
    /// Base URL of the Nextcloud instance, e.g.
    /// `https://cloud.example.com`. No trailing slash, no `/index.php`.
    pub base_url: String,
    pub username: String,
    /// The Nextcloud **app password** — not the account password.
    pub app_password: String,
}

const APP_PASSWORD_SECRET_KIND: &str = "nextcloud-passwords-app-password";
const APP_PASSWORD_SECRET_LABEL: &str = "Ashy Pass — Nextcloud Passwords app password";

/// A password entry as returned by the Nextcloud Passwords API. Only the
/// fields the sync engine cares about are deserialised; extras are dropped.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NcPassword {
    pub id: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub notes: String,
    /// Server-assigned revision string. Changes whenever any field changes —
    /// the sync engine uses it as a stable change marker.
    #[serde(default)]
    pub revision: String,
    /// Unix timestamp the server last edited this entry.
    #[serde(default)]
    pub edited: i64,
    #[serde(default)]
    pub trashed: bool,
    /// Folder UUID this password belongs to (used as our "category").
    #[serde(default, deserialize_with = "deserialize_folder_id")]
    pub folder: String,
}

/// Folder as returned by the Nextcloud Passwords API.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NcFolder {
    pub id: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub parent: String,
    #[serde(default)]
    pub revision: String,
    #[serde(default)]
    pub edited: i64,
    #[serde(default)]
    pub trashed: bool,
    #[serde(default)]
    pub hidden: bool,
}

/// Fields accepted on `password/create` and `password/update`. Server fills
/// in defaults for anything we omit; the API does require `password` and
/// `label` to be non-empty on create.
#[derive(Debug, Clone, Serialize, Default)]
pub struct NcCreateOrUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub label: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub folder: String,
    /// Required on create per spec — server rejects empty hash.
    pub hash: String,
}

/// Fields accepted on `folder/create`.
#[derive(Debug, Clone, Serialize, Default)]
pub struct NcFolderCreate {
    pub label: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub parent: String,
}

#[derive(Debug, Clone)]
pub struct NextcloudPasswordsClient {
    pub config: Option<NcConfig>,
}

impl NextcloudPasswordsClient {
    pub fn new() -> Self {
        Self {
            config: Self::load_config(),
        }
    }

    pub fn is_logged_in(&self) -> bool {
        self.config.is_some()
    }

    /// Probe the server and persist the config on success.
    pub fn login(&mut self, mut cfg: NcConfig) -> Result<()> {
        cfg.base_url = trim_trailing_slash(&cfg.base_url).to_string();
        validate_server_url(&cfg.base_url)?;
        if cfg.base_url.is_empty() || cfg.username.is_empty() || cfg.app_password.is_empty() {
            return Err(Error::Other(
                "base url, username and app password are required".into(),
            ));
        }
        // Smoke test: list passwords with limit=0 isn't a thing, but
        // /password/list is cheap and returns 200 even on empty vaults.
        let probe = self.request_with_cfg(&cfg, "GET", "/password/list", None)?;
        if probe.status >= 400 {
            return Err(Error::Other(format!(
                "nextcloud login failed: HTTP {}",
                probe.status
            )));
        }
        Self::save_config(&cfg)?;
        self.config = Some(cfg);
        Ok(())
    }

    pub fn logout(&mut self) -> Result<()> {
        self.config = None;
        let path = Self::config_path();
        if path.exists() {
            fs::remove_file(path)?;
        }
        let _ = crate::keyring::delete_named_secret(APP_PASSWORD_SECRET_KIND);
        Ok(())
    }

    fn require(&self) -> Result<&NcConfig> {
        self.config
            .as_ref()
            .ok_or_else(|| Error::Other("not signed in to Nextcloud Passwords".into()))
    }

    pub fn list(&self) -> Result<Vec<NcPassword>> {
        let cfg = self.require()?;
        let body = serde_json::json!({ "details": "model+folder" }).to_string();
        let r = self.request_with_cfg(cfg, "POST", "/password/list", Some(body))?;
        ensure_2xx(&r)?;
        let parsed: Vec<NcPassword> = serde_json::from_str(&r.body)
            .map_err(|e| Error::Other(format!("nextcloud list parse: {e}")))?;
        Ok(parsed)
    }

    pub fn create(&self, payload: &NcCreateOrUpdate) -> Result<NcPassword> {
        let cfg = self.require()?;
        let body = serde_json::to_string(payload)?;
        let r = self.request_with_cfg(cfg, "POST", "/password/create", Some(body))?;
        ensure_2xx(&r)?;
        parse_single(&r.body)
    }

    pub fn update(&self, payload: &NcCreateOrUpdate) -> Result<NcPassword> {
        let cfg = self.require()?;
        let body = serde_json::to_string(payload)?;
        let r = self.request_with_cfg(cfg, "PATCH", "/password/update", Some(body))?;
        ensure_2xx(&r)?;
        parse_single(&r.body)
    }

    pub fn delete(&self, id: &str) -> Result<()> {
        let cfg = self.require()?;
        let body = serde_json::json!({ "id": id }).to_string();
        let r = self.request_with_cfg(cfg, "DELETE", "/password/delete", Some(body))?;
        ensure_2xx(&r)
    }

    pub fn list_folders(&self) -> Result<Vec<NcFolder>> {
        let cfg = self.require()?;
        let r = self.request_with_cfg(cfg, "GET", "/folder/list", None)?;
        ensure_2xx(&r)?;
        let parsed: Vec<NcFolder> = serde_json::from_str(&r.body)
            .map_err(|e| Error::Other(format!("nextcloud folder list parse: {e}")))?;
        Ok(parsed)
    }

    pub fn create_folder(&self, payload: &NcFolderCreate) -> Result<NcFolder> {
        let cfg = self.require()?;
        let body = serde_json::to_string(payload)?;
        let r = self.request_with_cfg(cfg, "POST", "/folder/create", Some(body))?;
        ensure_2xx(&r)?;
        parse_single_folder(&r.body)
    }

    // -----------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------

    fn request_with_cfg(
        &self,
        cfg: &NcConfig,
        method: &str,
        path: &str,
        body: Option<String>,
    ) -> Result<Response> {
        validate_server_url(&cfg.base_url)?;
        let url = format!("{}/index.php/apps/passwords/api/1.0{}", cfg.base_url, path);
        let client = http_client()?;
        let mut req = match method {
            "GET" => client.get(&url),
            "POST" => client.post(&url),
            "PATCH" => client.patch(&url),
            "DELETE" => client.delete(&url),
            other => {
                return Err(Error::Other(format!("unsupported method {other}")));
            }
        };
        req = req
            .basic_auth(&cfg.username, Some(&cfg.app_password))
            .headers(default_headers());
        if let Some(b) = body {
            req = req.body(b);
        }
        let mut resp = req
            .send()
            .map_err(|e| Error::Other(format!("nextcloud {method} {path}: {e}")))?;
        let status = resp.status().as_u16();
        const MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;
        if resp
            .content_length()
            .is_some_and(|size| size > MAX_RESPONSE_BYTES)
        {
            return Err(Error::InvalidInput(
                "Nextcloud response is too large".into(),
            ));
        }
        let mut body = String::new();
        (&mut resp)
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_string(&mut body)?;
        if body.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(Error::InvalidInput(
                "Nextcloud response is too large".into(),
            ));
        }
        Ok(Response { status, body })
    }

    fn config_path() -> PathBuf {
        let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        base.join("ashypass").join("nextcloud_passwords.json")
    }

    fn load_config() -> Option<NcConfig> {
        let path = Self::config_path();
        let _ = crate::config::ensure_private_file(&path);
        let text = fs::read_to_string(path).ok()?;
        let mut cfg: NcConfig = serde_json::from_str(&text).ok()?;
        if cfg.app_password.is_empty() {
            cfg.app_password = crate::keyring::load_named_secret(APP_PASSWORD_SECRET_KIND)
                .map_err(|e| {
                    log::warn!("nextcloud app password unavailable from keyring: {e}");
                    e
                })
                .ok()
                .flatten()?;
        } else if crate::keyring::store_named_secret(
            APP_PASSWORD_SECRET_KIND,
            APP_PASSWORD_SECRET_LABEL,
            &cfg.app_password,
        )
        .is_ok()
        {
            let mut disk_cfg = cfg.clone();
            disk_cfg.app_password.clear();
            let _ = Self::write_config_file(&disk_cfg);
        }
        Some(cfg)
    }

    fn save_config(cfg: &NcConfig) -> Result<()> {
        let mut disk_cfg = cfg.clone();
        match crate::keyring::store_named_secret(
            APP_PASSWORD_SECRET_KIND,
            APP_PASSWORD_SECRET_LABEL,
            &cfg.app_password,
        ) {
            Ok(()) => disk_cfg.app_password.clear(),
            Err(e) => {
                log::warn!("nextcloud keyring save failed; keeping chmod 0600 fallback: {e}");
            }
        }
        Self::write_config_file(&disk_cfg)
    }

    fn write_config_file(cfg: &NcConfig) -> Result<()> {
        let path = Self::config_path();
        let text = serde_json::to_string_pretty(cfg)?;
        crate::config::atomic_write_private(&path, text.as_bytes())?;
        Ok(())
    }
}

impl Default for NextcloudPasswordsClient {
    fn default() -> Self {
        Self::new()
    }
}

struct Response {
    status: u16,
    body: String,
}

fn ensure_2xx(r: &Response) -> Result<()> {
    if (200..300).contains(&r.status) {
        Ok(())
    } else {
        let body = nextcloud_error_message(&r.body).unwrap_or_else(|| truncate_for_msg(&r.body));
        Err(Error::Other(format!("nextcloud HTTP {}: {body}", r.status)))
    }
}

fn parse_single(body: &str) -> Result<NcPassword> {
    // /password/create and /update return the new resource. Older API
    // versions wrap the result in `{ "id": "...", "revision": "..." }` only;
    // newer return the full object. Handle both.
    if let Ok(full) = serde_json::from_str::<NcPassword>(body) {
        if !full.id.is_empty() {
            return Ok(full);
        }
    }
    #[derive(Deserialize)]
    struct Shallow {
        id: String,
        revision: String,
    }
    let s: Shallow = serde_json::from_str(body)
        .map_err(|e| Error::Other(format!("nextcloud create/update parse: {e}")))?;
    Ok(NcPassword {
        id: s.id,
        revision: s.revision,
        ..Default::default()
    })
}

fn parse_single_folder(body: &str) -> Result<NcFolder> {
    if let Ok(full) = serde_json::from_str::<NcFolder>(body) {
        if !full.id.is_empty() {
            return Ok(full);
        }
    }
    #[derive(Deserialize)]
    struct Shallow {
        id: String,
        #[serde(default)]
        revision: String,
    }
    let s: Shallow = serde_json::from_str(body)
        .map_err(|e| Error::Other(format!("nextcloud folder create parse: {e}")))?;
    Ok(NcFolder {
        id: s.id,
        revision: s.revision,
        ..Default::default()
    })
}

fn deserialize_folder_id<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::String(id) => Ok(id),
        serde_json::Value::Object(obj) => Ok(obj
            .get("id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string()),
        serde_json::Value::Null => Ok(String::new()),
        other => Err(serde::de::Error::custom(format!(
            "unexpected folder value: {other}"
        ))),
    }
}

fn nextcloud_error_message(body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .get("message")?
        .as_str()
        .map(ToOwned::to_owned)
}

fn truncate_for_msg(s: &str) -> String {
    const LIMIT: usize = 240;
    if s.chars().count() <= LIMIT {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(LIMIT).collect::<String>())
    }
}

fn http_client() -> Result<&'static Client> {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client);
    }
    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| Error::Other(format!("nextcloud http: {e}")))?;
    let _ = CLIENT.set(client);
    Ok(CLIENT.get().expect("client was initialized"))
}

fn default_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(ACCEPT, HeaderValue::from_static("application/json"));
    h.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    // The Nextcloud Passwords API requires OCS-APIRequest on some endpoints.
    h.insert("OCS-APIRequest", HeaderValue::from_static("true"));
    h
}

fn trim_trailing_slash(s: &str) -> &str {
    s.trim_end_matches('/')
}

fn validate_server_url(value: &str) -> Result<()> {
    let parsed = url::Url::parse(value)
        .map_err(|error| Error::InvalidInput(format!("invalid Nextcloud URL: {error}")))?;
    let loopback = parsed
        .host_str()
        .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1"));
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback) {
        return Err(Error::InvalidInput(
            "Nextcloud requires HTTPS except for a loopback test server".into(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        return Err(Error::InvalidInput(
            "Nextcloud URL must not contain credentials or a fragment".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_list_payload() {
        let body = r#"[
            {"id":"a","label":"GH","username":"u","password":"p","url":"https://github.com","notes":"","revision":"r1","edited":1700000000,"trashed":false,"folder":""},
            {"id":"b","label":"GL","username":"u2","password":"p2","url":"","notes":"x","revision":"r2","edited":1700000001,"trashed":true,"folder":"f1"}
        ]"#;
        let v: Vec<NcPassword> = serde_json::from_str(body).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].label, "GH");
        assert!(v[1].trashed);
        assert_eq!(v[1].folder, "f1");
    }

    #[test]
    fn truncates_unicode_safely_and_requires_tls() {
        let message = "á".repeat(300);
        assert_eq!(truncate_for_msg(&message).chars().count(), 241);
        assert!(validate_server_url("http://cloud.example.com").is_err());
        assert!(validate_server_url("http://localhost:8080").is_ok());
    }

    #[test]
    fn parses_password_folder_detail_object() {
        let body = r#"[
            {"id":"a","label":"GH","username":"u","password":"p","url":"","notes":"","revision":"r1","edited":1700000000,"trashed":false,"folder":{"id":"f1","label":"Work"}},
            {"id":"b","label":"None","username":"","password":"p","url":"","notes":"","revision":"r2","edited":1700000001,"trashed":false,"folder":null}
        ]"#;
        let v: Vec<NcPassword> = serde_json::from_str(body).unwrap();
        assert_eq!(v[0].folder, "f1");
        assert!(v[1].folder.is_empty());
    }

    #[test]
    fn parse_single_supports_shallow_response() {
        let shallow = r#"{"id":"abc","revision":"rev-1"}"#;
        let p = parse_single(shallow).unwrap();
        assert_eq!(p.id, "abc");
        assert_eq!(p.revision, "rev-1");
        assert!(p.label.is_empty());
    }

    #[test]
    fn parse_single_supports_full_response() {
        let full = r#"{"id":"abc","label":"L","username":"u","password":"p","url":"","notes":"","revision":"r","edited":42,"trashed":false,"folder":""}"#;
        let p = parse_single(full).unwrap();
        assert_eq!(p.id, "abc");
        assert_eq!(p.label, "L");
        assert_eq!(p.edited, 42);
    }

    #[test]
    fn parse_single_folder_supports_full_response() {
        let full = r#"{"id":"f1","label":"Work","parent":"","revision":"r","edited":42,"trashed":false,"hidden":false}"#;
        let f = parse_single_folder(full).unwrap();
        assert_eq!(f.id, "f1");
        assert_eq!(f.label, "Work");
        assert_eq!(f.edited, 42);
    }

    #[test]
    fn password_payload_includes_folder_when_present() {
        let payload = NcCreateOrUpdate {
            label: "Example".into(),
            password: "secret".into(),
            folder: "folder-uuid".into(),
            ..Default::default()
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains(r#""folder":"folder-uuid""#));
    }

    #[test]
    fn extracts_nextcloud_error_message() {
        let body =
            r#"{"status":"error","id":"abc","message":"Field \"password\" can not be empty"}"#;
        assert_eq!(
            nextcloud_error_message(body).as_deref(),
            Some("Field \"password\" can not be empty")
        );
    }

    #[test]
    fn trim_slash_strips_one_trailing() {
        assert_eq!(trim_trailing_slash("https://x.tld/"), "https://x.tld");
        assert_eq!(trim_trailing_slash("https://x.tld"), "https://x.tld");
    }
}
