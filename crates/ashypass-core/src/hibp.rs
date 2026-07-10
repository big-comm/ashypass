//! Have I Been Pwned — k-anonymity password check.
//!
//! Protocol (cf. https://haveibeenpwned.com/API/v3#PwnedPasswords):
//!
//! 1. SHA-1 the password, uppercase hex.
//! 2. Send the first 5 hex chars as `GET https://api.pwnedpasswords.com/range/{prefix}`.
//! 3. The response is a newline-separated list of `suffix:count` rows. We
//!    look for our suffix locally. The server never sees the full hash.
//!
//! All checks are bounded by a per-prefix on-disk cache so repeated audits
//! don't hammer the API. Cache TTL is 7 days.
//!
//! Networking is blocking by design — this is meant to be called from a
//! background thread, not the UI thread.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

const HIBP_RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";
const CACHE_TTL_SECS: i64 = 7 * 24 * 3600;

#[derive(Debug, Clone, Copy)]
pub enum BreachStatus {
    NotFound,
    Found { count: u64 },
}

#[derive(Serialize, Deserialize, Default)]
struct CacheEntry {
    fetched_at: i64,
    body: String,
}

#[derive(Serialize, Deserialize, Default)]
struct Cache {
    #[serde(default)]
    prefixes: HashMap<String, CacheEntry>,
}

fn cache_file() -> PathBuf {
    crate::config::data_dir().join("hibp-cache.json")
}

fn load_cache() -> Cache {
    let path = cache_file();
    let _ = crate::config::ensure_private_file(&path);
    fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_cache(c: &Cache) -> Result<()> {
    let path = cache_file();
    let serialized = serde_json::to_string(c)?;
    crate::config::atomic_write_private(&path, serialized.as_bytes())?;
    Ok(())
}

fn sha1_hex_upper(password: &str) -> String {
    let mut h = Sha1::new();
    h.update(password.as_bytes());
    let out = h.finalize();
    let mut s = String::with_capacity(40);
    for b in out.iter() {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

fn fetch_range(prefix: &str) -> Result<String> {
    let url = format!("{HIBP_RANGE_URL}{prefix}");
    let resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("AshyPass/3.0")
        .build()
        .map_err(|e| Error::Other(format!("hibp client: {e}")))?
        .get(&url)
        .header("Add-Padding", "true")
        .send()
        .map_err(|e| Error::Other(format!("hibp http: {e}")))?;
    if !resp.status().is_success() {
        return Err(Error::Other(format!(
            "hibp status {}: {}",
            resp.status(),
            resp.status().canonical_reason().unwrap_or("?")
        )));
    }
    resp.text()
        .map_err(|e| Error::Other(format!("hibp read: {e}")))
}

fn parse_body(body: &str, suffix: &str) -> BreachStatus {
    for line in body.lines() {
        let mut it = line.trim().splitn(2, ':');
        let s = match it.next() {
            Some(s) => s,
            None => continue,
        };
        if s.eq_ignore_ascii_case(suffix) {
            let count = it.next().and_then(|c| c.parse::<u64>().ok()).unwrap_or(1);
            return BreachStatus::Found { count };
        }
    }
    BreachStatus::NotFound
}

/// Check a single password. Returns `NotFound` or `Found { count }`.
/// Padded responses are honoured (rows with count=0 are skipped automatically
/// because parse() only matches the suffix — padding suffixes are random so
/// the match is statistically negligible).
pub fn check(password: &str) -> Result<BreachStatus> {
    if password.is_empty() {
        return Ok(BreachStatus::NotFound);
    }
    let hex = sha1_hex_upper(password);
    let (prefix, suffix) = hex.split_at(5);
    let mut cache = load_cache();
    let now = now_secs();
    let body = match cache.prefixes.get(prefix) {
        Some(entry) if now - entry.fetched_at < CACHE_TTL_SECS => entry.body.clone(),
        _ => {
            let body = fetch_range(prefix)?;
            cache.prefixes.insert(
                prefix.to_string(),
                CacheEntry {
                    fetched_at: now,
                    body: body.clone(),
                },
            );
            let _ = save_cache(&cache);
            body
        }
    };
    Ok(parse_body(&body, suffix))
}

/// Batch check using the same in-memory cache snapshot for the run.
/// Returns the status for each input in input order.
pub fn check_many(passwords: &[&str]) -> Result<Vec<BreachStatus>> {
    let mut cache = load_cache();
    let now = now_secs();
    let mut out = Vec::with_capacity(passwords.len());
    let mut dirty = false;
    for pw in passwords {
        if pw.is_empty() {
            out.push(BreachStatus::NotFound);
            continue;
        }
        let hex = sha1_hex_upper(pw);
        let (prefix, suffix) = hex.split_at(5);
        let body = match cache.prefixes.get(prefix) {
            Some(entry) if now - entry.fetched_at < CACHE_TTL_SECS => entry.body.clone(),
            _ => {
                let body = fetch_range(prefix)?;
                cache.prefixes.insert(
                    prefix.to_string(),
                    CacheEntry {
                        fetched_at: now,
                        body: body.clone(),
                    },
                );
                dirty = true;
                body
            }
        };
        out.push(parse_body(&body, suffix));
    }
    if dirty {
        let _ = save_cache(&cache);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_matches_known() {
        // sha1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        assert_eq!(
            sha1_hex_upper("password"),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        );
    }

    #[test]
    fn parse_finds_suffix() {
        let body =
            "ABCDE0123456789ABCDEF0123456789ABCDEF:42\n0000000000000000000000000000000000A:7\n";
        let r = parse_body(body, "ABCDE0123456789ABCDEF0123456789ABCDEF");
        assert!(matches!(r, BreachStatus::Found { count: 42 }));
    }

    #[test]
    fn parse_not_found_returns_not_found() {
        let body = "ABCDEF:1\nFFFF:2\n";
        let r = parse_body(body, "0000000000000000000000000000000000000");
        assert!(matches!(r, BreachStatus::NotFound));
    }
}
