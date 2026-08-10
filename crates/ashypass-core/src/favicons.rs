//! Favicon cache.
//!
//! Resolves `https://<host>/favicon.ico` (with an opt-in Google s2 fallback,
//! see `Settings::favicon_third_party_fallback`) and
//! stores the raw bytes under `favicons/<host>.png`. The hostname is the
//! cache key so different URLs for the same site share a single file.

use crate::config::favicons_dir;
use crate::{Error, Result};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use url::Url;

const FETCH_TIMEOUT: Duration = Duration::from_secs(6);
const MAX_BYTES: usize = 256 * 1024;
const GENERIC_USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36";

pub fn cache_path(host: &str) -> PathBuf {
    favicons_dir().join(format!("{host}.png"))
}

pub fn host_of(raw: &str) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    };
    Url::parse(&with_scheme)
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_string()))
}

/// Look up `host` in the on-disk cache. Returns `None` if not cached yet.
pub fn lookup(host: &str) -> Option<PathBuf> {
    let p = cache_path(host);
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

/// Fetch `host`'s favicon and store it under `favicons_dir()`. Blocking.
pub fn fetch_blocking(host: &str) -> Result<PathBuf> {
    let path = cache_path(host);
    if path.exists() {
        return Ok(path);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Deliberately generic: "AshyPass … favicon-fetch" would tell every site
    // the user stores credentials for that they run this password manager.
    let client = reqwest::blocking::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .user_agent(GENERIC_USER_AGENT)
        .build()
        .map_err(|e| Error::Other(format!("favicon http: {e}")))?;

    let mut candidates = vec![format!("https://{host}/favicon.ico")];
    // The third-party fallback sends the hostname to Google, i.e. leaks which
    // sites are in the vault. Opt-in only.
    if crate::settings::Settings::load().favicon_third_party_fallback {
        candidates.push(format!(
            "https://www.google.com/s2/favicons?domain={host}&sz=64"
        ));
    }

    for url in &candidates {
        let resp = match client.get(url).send() {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };
        let bytes = match resp.bytes() {
            Ok(b) if !b.is_empty() && b.len() <= MAX_BYTES => b,
            _ => continue,
        };
        if let Ok(img) = image::load_from_memory(&bytes) {
            if img.save(&path).is_ok() {
                return Ok(path);
            }
        } else {
            // not parseable; store raw bytes anyway (e.g. animated/atypical ico)
            if fs::write(&path, &bytes).is_ok() {
                return Ok(path);
            }
        }
    }

    Err(Error::Other(format!("favicon: no source for {host}")))
}
