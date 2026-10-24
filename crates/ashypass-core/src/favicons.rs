//! Favicon cache.
//!
//! Resolves `https://<host>/favicon.ico` (with an opt-in Google s2 fallback,
//! see `Settings::favicon_third_party_fallback`) and
//! stores the raw bytes under `favicons/<host>.png`. The hostname is the
//! cache key so different URLs for the same site share a single file.

use crate::config::favicons_dir;
use crate::{Error, Result};
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;
use url::Url;

const FETCH_TIMEOUT: Duration = Duration::from_secs(6);
const MAX_BYTES: usize = 256 * 1024;
const GENERIC_USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36";

/// Names that only exist on a local network.
const LOCAL_SUFFIXES: &[&str] = &[
    "localhost",
    "local",
    "lan",
    "home",
    "internal",
    "intranet",
    "corp",
    "home.arpa",
];

/// Whether `host` is on the public internet. Icons are fetched for nothing
/// else: a request to a router, a NAS or a single-label name only tells the
/// local network which sites are in the vault, and it rarely has an icon.
pub fn is_public_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => {
                let [a, b, ..] = v4.octets();
                // 100.64.0.0/10: carrier-grade NAT, also Tailscale's range.
                let shared = a == 100 && (b & 0xc0) == 64;
                !(v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.is_broadcast()
                    || v4.is_documentation()
                    || shared)
            }
            IpAddr::V6(v6) => {
                let first = v6.segments()[0];
                // fc00::/7 unique local, fe80::/10 link local.
                !(v6.is_loopback()
                    || v6.is_unspecified()
                    || (first & 0xfe00) == 0xfc00
                    || (first & 0xffc0) == 0xfe80)
            }
        };
    }
    host.contains('.')
        && !LOCAL_SUFFIXES
            .iter()
            .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
}

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
/// The Google fallback follows `Settings::favicon_third_party_fallback`.
pub fn fetch_blocking(host: &str) -> Result<PathBuf> {
    fetch_blocking_with(
        host,
        crate::settings::Settings::load().favicon_third_party_fallback,
    )
}

/// Like [`fetch_blocking`], with the Google fallback chosen by the caller
/// (apps that keep their own settings).
pub fn fetch_blocking_with(host: &str, third_party_fallback: bool) -> Result<PathBuf> {
    if !is_public_host(host) {
        return Err(Error::Other(format!(
            "favicon: {host} is not a public site"
        )));
    }
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
    if third_party_fallback {
        candidates.push(format!(
            "https://www.google.com/s2/favicons?domain={host}&sz=64"
        ));
    }

    for url in &candidates {
        let resp = match client.get(url).send() {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };
        if resp
            .content_length()
            .is_some_and(|len| len > MAX_BYTES as u64)
        {
            continue;
        }
        // Read at most one byte past the limit so a hostile server cannot
        // stream an unbounded body into memory.
        let mut bytes = Vec::new();
        if std::io::Read::read_to_end(
            &mut std::io::Read::take(resp, MAX_BYTES as u64 + 1),
            &mut bytes,
        )
        .is_err()
            || bytes.is_empty()
            || bytes.len() > MAX_BYTES
        {
            continue;
        }
        // Write to a temporary name and rename, so a crash or a concurrent
        // fetch never leaves a truncated file that looks cached.
        let tmp = path.with_extension("png.part");
        let written = if let Ok(img) = image::load_from_memory(&bytes) {
            img.save_with_format(&tmp, image::ImageFormat::Png).is_ok()
        } else if bytes.starts_with(&[0, 0, 1, 0]) {
            // An icon the decoder does not handle; GTK may still load it.
            // Anything else (often an HTML error page served with 200) is
            // not cached, so the next source is tried.
            fs::write(&tmp, &bytes).is_ok()
        } else {
            false
        };
        if written && fs::rename(&tmp, &path).is_ok() {
            return Ok(path);
        }
        let _ = fs::remove_file(&tmp);
    }

    Err(Error::Other(format!("favicon: no source for {host}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_sites_get_their_icon_fetched() {
        for host in [
            "github.com",
            "accounts.google.com",
            "8.8.8.8",
            "wiki.debian.org.",
        ] {
            assert!(is_public_host(host), "{host}");
        }
        for host in [
            "192.168.0.10",
            "10.1.2.3",
            "172.16.5.4",
            "127.0.0.1",
            "100.64.0.18",
            "169.254.1.1",
            "[::1]",
            "[fd12::1]",
            "[fe80::1]",
            "localhost",
            "router",
            "nas.local",
            "printer.lan",
            "intranet.corp",
            "box.home.arpa",
        ] {
            assert!(!is_public_host(host), "{host}");
        }
    }

    #[test]
    fn a_local_host_is_never_requested() {
        assert!(fetch_blocking_with("192.168.0.10", true).is_err());
    }
}
