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
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

/// On-disk persisted config. Same plaintext-on-disk threat model as the
/// WebDAV backend — chmod 0600 on save.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NcConfig {
    /// Base URL of the Nextcloud instance, e.g.
    /// `https://cloud.example.com`. No trailing slash, no `/index.php`.
    pub base_url: String,
    pub username: String,
    /// The Nextcloud **app password** — not the account password.
    pub app_password: String,
}

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
    #[serde(default)]
    pub folder: String,
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
    /// Required on create per spec — server rejects empty hash.
    pub hash: String,
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
        Ok(())
    }

    fn require(&self) -> Result<&NcConfig> {
        self.config
            .as_ref()
            .ok_or_else(|| Error::Other("not signed in to Nextcloud Passwords".into()))
    }

    pub fn list(&self) -> Result<Vec<NcPassword>> {
        let cfg = self.require()?;
        let r = self.request_with_cfg(cfg, "GET", "/password/list", None)?;
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
        let url = format!(
            "{}/index.php/apps/passwords/api/1.0{}",
            cfg.base_url, path
        );
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
        let resp = req
            .send()
            .map_err(|e| Error::Other(format!("nextcloud {method} {path}: {e}")))?;
        let status = resp.status().as_u16();
        let body = resp
            .text()
            .map_err(|e| Error::Other(format!("nextcloud read body: {e}")))?;
        Ok(Response { status, body })
    }

    fn config_path() -> PathBuf {
        let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        base.join("ashypass").join("nextcloud_passwords.json")
    }

    fn load_config() -> Option<NcConfig> {
        let text = fs::read_to_string(Self::config_path()).ok()?;
        serde_json::from_str(&text).ok()
    }

    fn save_config(cfg: &NcConfig) -> Result<()> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(cfg)?;
        fs::write(&path, text)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
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
        Err(Error::Other(format!(
            "nextcloud HTTP {}: {}",
            r.status,
            truncate_for_msg(&r.body)
        )))
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

fn truncate_for_msg(s: &str) -> String {
    const LIMIT: usize = 240;
    if s.len() <= LIMIT {
        s.to_string()
    } else {
        format!("{}…", &s[..LIMIT])
    }
}

fn http_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| Error::Other(format!("nextcloud http: {e}")))
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
    s.strip_suffix('/').unwrap_or(s)
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
    fn trim_slash_strips_one_trailing() {
        assert_eq!(trim_trailing_slash("https://x.tld/"), "https://x.tld");
        assert_eq!(trim_trailing_slash("https://x.tld"), "https://x.tld");
    }
}
