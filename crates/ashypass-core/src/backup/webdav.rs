//! WebDAV / Nextcloud backup backend.
//!
//! Uses HTTP Basic auth (or an app-password) over HTTPS. Designed for the
//! Nextcloud `remote.php/dav/files/<user>/...` path layout but works against
//! any RFC 4918 server (ownCloud, FastMail Files, Apache mod_dav, etc.).
//!
//! Credentials are stored in Secret Service when available. The JSON config
//! remains chmod 0600 and is used as a legacy fallback on sessions without a
//! desktop keyring.

use crate::{Error, Result};
use reqwest::blocking::Client;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebdavConfig {
    /// Full base URL including any per-user prefix. Trailing slash optional.
    /// e.g. `https://cloud.example.com/remote.php/dav/files/alice`
    pub base_url: String,
    pub username: String,
    pub password: String,
    /// Sub-folder under `base_url` where backups go. Defaults to
    /// `AshyPass Backups`. Will be created on demand.
    pub folder: String,
}

const PASSWORD_SECRET_KIND: &str = "webdav-password";
const PASSWORD_SECRET_LABEL: &str = "Ashy Pass — WebDAV password";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebdavFile {
    pub name: String,
    pub href: String,
    pub modified: String,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct WebdavService {
    pub config: Option<WebdavConfig>,
}

impl WebdavService {
    pub fn new() -> Self {
        Self {
            config: Self::load_config(),
        }
    }

    pub fn is_logged_in(&self) -> bool {
        self.config.is_some()
    }

    /// Persist new config to disk after a successful PROPFIND check.
    pub fn login(&mut self, mut cfg: WebdavConfig) -> Result<()> {
        cfg.base_url = trim_trailing_slash(&cfg.base_url).to_string();
        validate_server_url(&cfg.base_url)?;
        if cfg.folder.trim().is_empty() {
            cfg.folder = "AshyPass Backups".into();
        }
        // Smoke-test: PROPFIND on the base URL.
        let client = http_client()?;
        let resp = client
            .request(propfind(), &cfg.base_url)
            .basic_auth(&cfg.username, Some(&cfg.password))
            .header("Depth", "0")
            .header("Content-Type", "application/xml")
            .body(PROPFIND_BODY)
            .send()
            .map_err(|e| Error::Other(format!("webdav probe: {e}")))?;
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(Error::Other(format!("webdav login failed: HTTP {status}")));
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
        let _ = crate::keyring::delete_named_secret(PASSWORD_SECRET_KIND);
        Ok(())
    }

    fn require(&self) -> Result<&WebdavConfig> {
        self.config
            .as_ref()
            .ok_or_else(|| Error::Other("not signed in to WebDAV".into()))
    }

    fn folder_url(&self) -> Result<String> {
        let cfg = self.require()?;
        Ok(format!("{}/{}", cfg.base_url, url_escape_path(&cfg.folder)))
    }

    /// Create the configured sub-folder if it doesn't already exist.
    /// Servers return 405 if it already exists, which we ignore.
    pub fn ensure_folder(&self) -> Result<()> {
        let cfg = self.require()?;
        let url = self.folder_url()?;
        let client = http_client()?;
        let resp = client
            .request(Method::from_bytes(b"MKCOL").unwrap(), &url)
            .basic_auth(&cfg.username, Some(&cfg.password))
            .send()
            .map_err(|e| Error::Other(format!("webdav mkcol: {e}")))?;
        let status = resp.status().as_u16();
        // 201 created, 405 already exists — both fine.
        if status == 201 || status == 405 {
            return Ok(());
        }
        Err(Error::Other(format!("webdav mkcol: HTTP {status}")))
    }

    pub fn upload(&self, local: impl AsRef<Path>, remote_name: &str) -> Result<()> {
        let cfg = self.require()?;
        let folder = self.folder_url()?;
        let url = format!("{folder}/{}", url_escape_path(remote_name));
        let body = reqwest::blocking::Body::new(fs::File::open(local.as_ref())?);
        let client = http_client()?;
        let resp = client
            .put(&url)
            .basic_auth(&cfg.username, Some(&cfg.password))
            .body(body)
            .send()
            .map_err(|e| Error::Other(format!("webdav put: {e}")))?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(Error::Other(format!("webdav put: HTTP {status}")));
        }
        Ok(())
    }

    pub fn list_backups(&self) -> Result<Vec<WebdavFile>> {
        let cfg = self.require()?;
        let url = self.folder_url()?;
        let client = http_client()?;
        let mut resp = client
            .request(propfind(), &url)
            .basic_auth(&cfg.username, Some(&cfg.password))
            .header("Depth", "1")
            .header("Content-Type", "application/xml")
            .body(PROPFIND_BODY)
            .send()
            .map_err(|e| Error::Other(format!("webdav propfind: {e}")))?;
        let status = resp.status().as_u16();
        // 404 = folder doesn't exist yet, treat as empty.
        if status == 404 {
            return Ok(Vec::new());
        }
        if !(200..300).contains(&status) {
            return Err(Error::Other(format!("webdav propfind: HTTP {status}")));
        }
        const MAX_PROPFIND_BYTES: u64 = 16 * 1024 * 1024;
        if resp
            .content_length()
            .is_some_and(|size| size > MAX_PROPFIND_BYTES)
        {
            return Err(Error::InvalidInput("WebDAV listing is too large".into()));
        }
        let mut body = String::new();
        (&mut resp)
            .take(MAX_PROPFIND_BYTES + 1)
            .read_to_string(&mut body)?;
        if body.len() as u64 > MAX_PROPFIND_BYTES {
            return Err(Error::InvalidInput("WebDAV listing is too large".into()));
        }
        Ok(parse_propfind(&body))
    }

    pub fn download(&self, href: &str, dest: impl AsRef<Path>) -> Result<()> {
        let cfg = self.require()?;
        let url = href_to_url(&cfg.base_url, href)?;
        let client = http_client()?;
        let mut resp = client
            .get(&url)
            .basic_auth(&cfg.username, Some(&cfg.password))
            .send()
            .map_err(|e| Error::Other(format!("webdav get: {e}")))?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(Error::Other(format!("webdav get: HTTP {status}")));
        }
        write_response_new(&mut resp, dest.as_ref())
    }

    pub fn delete(&self, href: &str) -> Result<()> {
        let cfg = self.require()?;
        let url = href_to_url(&cfg.base_url, href)?;
        let client = http_client()?;
        let resp = client
            .delete(&url)
            .basic_auth(&cfg.username, Some(&cfg.password))
            .send()
            .map_err(|e| Error::Other(format!("webdav delete: {e}")))?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(Error::Other(format!("webdav delete: HTTP {status}")));
        }
        Ok(())
    }

    fn config_path() -> PathBuf {
        let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        base.join("ashypass").join("webdav.json")
    }

    fn load_config() -> Option<WebdavConfig> {
        let path = Self::config_path();
        let _ = crate::config::ensure_private_file(&path);
        let text = fs::read_to_string(&path).ok()?;
        let mut cfg: WebdavConfig = serde_json::from_str(&text).ok()?;
        if cfg.password.is_empty() {
            cfg.password = crate::keyring::load_named_secret(PASSWORD_SECRET_KIND)
                .map_err(|e| {
                    log::warn!("webdav password unavailable from keyring: {e}");
                    e
                })
                .ok()
                .flatten()?;
        } else if crate::keyring::store_named_secret(
            PASSWORD_SECRET_KIND,
            PASSWORD_SECRET_LABEL,
            &cfg.password,
        )
        .is_ok()
        {
            let mut disk_cfg = cfg.clone();
            disk_cfg.password.clear();
            let _ = Self::write_config_file(&disk_cfg);
        }
        Some(cfg)
    }

    fn save_config(cfg: &WebdavConfig) -> Result<()> {
        let mut disk_cfg = cfg.clone();
        match crate::keyring::store_named_secret(
            PASSWORD_SECRET_KIND,
            PASSWORD_SECRET_LABEL,
            &cfg.password,
        ) {
            Ok(()) => disk_cfg.password.clear(),
            Err(e) => {
                log::warn!("webdav keyring save failed; keeping chmod 0600 fallback: {e}");
            }
        }
        Self::write_config_file(&disk_cfg)
    }

    fn write_config_file(cfg: &WebdavConfig) -> Result<()> {
        let path = Self::config_path();
        let text = serde_json::to_string_pretty(cfg)?;
        crate::config::atomic_write_private(&path, text.as_bytes())?;
        Ok(())
    }
}

impl Default for WebdavService {
    fn default() -> Self {
        Self::new()
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
        .map_err(|e| Error::Other(format!("webdav http: {e}")))?;
    let _ = CLIENT.set(client);
    Ok(CLIENT.get().expect("client was initialized"))
}

fn propfind() -> Method {
    Method::from_bytes(b"PROPFIND").expect("PROPFIND is a valid method name")
}

const PROPFIND_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:">
  <d:prop>
    <d:displayname/>
    <d:getcontentlength/>
    <d:getlastmodified/>
    <d:resourcetype/>
  </d:prop>
</d:propfind>"#;

fn trim_trailing_slash(s: &str) -> &str {
    s.trim_end_matches('/')
}

fn validate_server_url(value: &str) -> Result<url::Url> {
    let parsed = url::Url::parse(value)
        .map_err(|error| Error::InvalidInput(format!("invalid WebDAV URL: {error}")))?;
    let loopback = parsed
        .host_str()
        .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1"));
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback) {
        return Err(Error::InvalidInput(
            "WebDAV requires HTTPS except for a loopback test server".into(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        return Err(Error::InvalidInput(
            "WebDAV URL must not contain credentials or a fragment".into(),
        ));
    }
    Ok(parsed)
}

/// Percent-encode the parts of a path that aren't already safe. Splits on `/`
/// so embedded slashes are preserved as path separators.
fn url_escape_path(s: &str) -> String {
    s.split('/')
        .map(url_escape_segment)
        .collect::<Vec<_>>()
        .join("/")
}

fn url_escape_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~') {
            out.push(ch);
        } else {
            let mut buf = [0u8; 4];
            for b in ch.encode_utf8(&mut buf).as_bytes() {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

/// Build an absolute URL from a server-returned `<d:href>`. Hrefs may be
/// absolute paths (`/remote.php/dav/files/alice/foo`) or full URLs.
fn href_to_url(base: &str, href: &str) -> Result<String> {
    let base = validate_server_url(base)?;
    let resolved = base
        .join(href)
        .map_err(|error| Error::InvalidInput(format!("invalid WebDAV href: {error}")))?;
    if resolved.scheme() != base.scheme()
        || resolved.host_str() != base.host_str()
        || resolved.port_or_known_default() != base.port_or_known_default()
    {
        return Err(Error::InvalidInput(
            "WebDAV server returned a cross-origin href".into(),
        ));
    }
    Ok(resolved.to_string())
}

fn write_response_new(response: &mut impl std::io::Read, destination: &Path) -> Result<()> {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".ashypass-download-{}-{}.tmp",
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

/// Minimal PROPFIND XML parser. We pull `<d:href>`, `<d:displayname>`,
/// `<d:getcontentlength>`, `<d:getlastmodified>`, and skip any entry whose
/// `<d:resourcetype>` contains `<d:collection/>`.
fn parse_propfind(xml: &str) -> Vec<WebdavFile> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = find_tag(rest, "response") {
        let after_open = &rest[start..];
        let Some(end) = find_close_tag(after_open, "response") else {
            break;
        };
        let block = &after_open[..end];
        rest = &after_open[end..];

        let is_collection = block.contains("<d:collection")
            || block.contains("<D:collection")
            || block.contains(":collection/>");
        if is_collection {
            // Could still be the folder itself rather than a sub-collection.
            // We always skip collections in the listing.
            continue;
        }

        let href = extract_inner(block, "href").unwrap_or_default();
        let display = extract_inner(block, "displayname").unwrap_or_default();
        let size = extract_inner(block, "getcontentlength")
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let modified = extract_inner(block, "getlastmodified").unwrap_or_default();

        let name = if !display.is_empty() {
            display
        } else {
            href.rsplit('/')
                .find(|s| !s.is_empty())
                .unwrap_or("")
                .to_string()
        };
        if name.is_empty() {
            continue;
        }
        out.push(WebdavFile {
            name,
            href: href.trim().to_string(),
            modified: modified.trim().to_string(),
            size,
        });
    }
    out
}

fn find_tag(haystack: &str, local: &str) -> Option<usize> {
    // Match either `<d:tag` or `<D:tag` or `<tag` (no namespace).
    for needle in [
        format!("<d:{local}"),
        format!("<D:{local}"),
        format!("<{local}"),
    ] {
        if let Some(i) = haystack.find(&needle) {
            return Some(i);
        }
    }
    None
}

fn find_close_tag(haystack: &str, local: &str) -> Option<usize> {
    for needle in [
        format!("</d:{local}>"),
        format!("</D:{local}>"),
        format!("</{local}>"),
    ] {
        if let Some(i) = haystack.find(&needle) {
            return Some(i + needle.len());
        }
    }
    None
}

/// Return the text content of the first occurrence of `<{ns}:tag>...</{ns}:tag>`
/// inside `block`. Whitespace inside is preserved; the caller can trim.
fn extract_inner(block: &str, local: &str) -> Option<String> {
    let start = find_tag(block, local)?;
    let after_open_tag = &block[start..];
    // Move past the `>` that closes the opening tag (could have attributes).
    let gt = after_open_tag.find('>')?;
    let body_start = start + gt + 1;
    let body = &block[body_start..];
    let end = find_close_tag(body, local)?;
    let inner = &body[..end];
    // Strip the closing tag itself.
    let close_start = inner.rfind("</")?;
    Some(inner[..close_start].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn propfind_parses_two_files() {
        let xml = r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/remote.php/dav/files/alice/AshyPass%20Backups/</d:href>
    <d:propstat><d:prop>
      <d:displayname>AshyPass Backups</d:displayname>
      <d:resourcetype><d:collection/></d:resourcetype>
    </d:prop></d:propstat>
  </d:response>
  <d:response>
    <d:href>/remote.php/dav/files/alice/AshyPass%20Backups/a.ashy</d:href>
    <d:propstat><d:prop>
      <d:displayname>a.ashy</d:displayname>
      <d:getcontentlength>1024</d:getcontentlength>
      <d:getlastmodified>Mon, 01 Jan 2024 00:00:00 GMT</d:getlastmodified>
      <d:resourcetype/>
    </d:prop></d:propstat>
  </d:response>
  <d:response>
    <d:href>/remote.php/dav/files/alice/AshyPass%20Backups/b.ashy</d:href>
    <d:propstat><d:prop>
      <d:displayname>b.ashy</d:displayname>
      <d:getcontentlength>2048</d:getcontentlength>
      <d:getlastmodified>Tue, 02 Jan 2024 00:00:00 GMT</d:getlastmodified>
      <d:resourcetype/>
    </d:prop></d:propstat>
  </d:response>
</d:multistatus>"#;
        let files = parse_propfind(xml);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].name, "a.ashy");
        assert_eq!(files[0].size, 1024);
        assert_eq!(files[1].name, "b.ashy");
    }

    #[test]
    fn trim_slash() {
        assert_eq!(trim_trailing_slash("https://x/y/"), "https://x/y");
        assert_eq!(trim_trailing_slash("https://x/y"), "https://x/y");
    }

    #[test]
    fn escape_path_segments_only() {
        assert_eq!(
            url_escape_path("AshyPass Backups/foo bar.ashy"),
            "AshyPass%20Backups/foo%20bar.ashy"
        );
    }

    #[test]
    fn href_to_url_relative() {
        assert_eq!(
            href_to_url(
                "https://cloud.example.com/remote.php/dav/files/alice",
                "/remote.php/dav/files/alice/AshyPass%20Backups/a.ashy"
            )
            .unwrap(),
            "https://cloud.example.com/remote.php/dav/files/alice/AshyPass%20Backups/a.ashy"
        );
    }

    #[test]
    fn rejects_insecure_and_cross_origin_urls() {
        assert!(validate_server_url("http://cloud.example.com/dav").is_err());
        assert!(validate_server_url("http://127.0.0.1:8080/dav").is_ok());
        assert!(href_to_url(
            "https://cloud.example.com/dav",
            "https://attacker.example/backup.db"
        )
        .is_err());
    }

    #[test]
    fn downloads_do_not_replace_existing_files() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("backup.db");
        let mut first = std::io::Cursor::new(b"first".to_vec());
        write_response_new(&mut first, &destination).unwrap();
        let mut second = std::io::Cursor::new(b"second".to_vec());
        assert!(write_response_new(&mut second, &destination).is_err());
        assert_eq!(fs::read(destination).unwrap(), b"first");
    }
}
