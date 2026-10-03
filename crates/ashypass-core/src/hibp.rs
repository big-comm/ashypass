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

fn http_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("AshyPass/3.0")
        .build()
        .map_err(|e| Error::Other(format!("hibp client: {e}")))
}

fn fetch_range(client: &reqwest::blocking::Client, prefix: &str) -> Result<String> {
    let url = format!("{HIBP_RANGE_URL}{prefix}");
    let resp = client
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
    into_result(check_many_report(&[password]))?
        .pop()
        .ok_or_else(|| Error::Other("hibp: no result".into()))
}

/// Batch check using the same in-memory cache snapshot for the run.
/// Returns the status for each input in input order, or the first network
/// error if any password could not be checked. Use `check_many_report` to
/// keep the partial results instead.
pub fn check_many(passwords: &[&str]) -> Result<Vec<BreachStatus>> {
    into_result(check_many_report(passwords))
}

/// Result of `check_many_report`.
#[derive(Debug, Default)]
pub struct BatchReport {
    /// One entry per input, in input order. `None` when the password's range
    /// could not be fetched and nothing (not even a stale copy) was cached.
    pub statuses: Vec<Option<BreachStatus>>,
    /// Distinct network errors encountered. Never includes hash prefixes.
    pub errors: Vec<String>,
}

/// Batch check that keeps going after a network error. Each distinct hash
/// prefix is fetched at most once over a single HTTP client; a failed fetch
/// falls back to a stale cache entry when there is one. Whatever was fetched
/// is written to the cache even if other prefixes failed.
pub fn check_many_report(passwords: &[&str]) -> BatchReport {
    let mut cache = load_cache();
    let mut client: Option<std::result::Result<reqwest::blocking::Client, String>> = None;
    let (report, dirty) = check_with(passwords, &mut cache, now_secs(), |prefix| {
        let client = client
            .get_or_insert_with(|| http_client().map_err(|e| e.to_string()))
            .as_ref()
            .map_err(|e| Error::Other(e.clone()))?;
        fetch_range(client, prefix)
    });
    if dirty {
        if let Err(error) = save_cache(&cache) {
            log::warn!("could not save HIBP cache: {error}");
        }
    }
    report
}

fn into_result(report: BatchReport) -> Result<Vec<BreachStatus>> {
    let statuses: Option<Vec<BreachStatus>> = report.statuses.into_iter().collect();
    statuses.ok_or_else(|| {
        Error::Other(
            report
                .errors
                .into_iter()
                .next()
                .unwrap_or_else(|| "hibp: check failed".into()),
        )
    })
}

/// Core of the batch check with the network injected. Returns the report
/// and whether `cache` gained entries.
fn check_with<F>(
    passwords: &[&str],
    cache: &mut Cache,
    now: i64,
    mut fetch: F,
) -> (BatchReport, bool)
where
    F: FnMut(&str) -> Result<String>,
{
    let hashes: Vec<Option<String>> = passwords
        .iter()
        .map(|pw| (!pw.is_empty()).then(|| sha1_hex_upper(pw)))
        .collect();

    let mut errors: Vec<String> = Vec::new();
    let mut dirty = false;
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for hex in hashes.iter().flatten() {
        let prefix = &hex[..5];
        if !seen.insert(prefix) {
            continue;
        }
        let fresh = cache
            .prefixes
            .get(prefix)
            .is_some_and(|entry| now - entry.fetched_at < CACHE_TTL_SECS);
        if fresh {
            continue;
        }
        match fetch(prefix) {
            Ok(body) => {
                cache.prefixes.insert(
                    prefix.to_string(),
                    CacheEntry {
                        fetched_at: now,
                        body,
                    },
                );
                dirty = true;
            }
            Err(error) => {
                let message = error.to_string();
                if !errors.contains(&message) {
                    errors.push(message);
                }
            }
        }
    }

    let statuses = hashes
        .iter()
        .map(|hex| match hex {
            None => Some(BreachStatus::NotFound),
            Some(hex) => {
                let (prefix, suffix) = hex.split_at(5);
                cache
                    .prefixes
                    .get(prefix)
                    .map(|entry| parse_body(&entry.body, suffix))
            }
        })
        .collect();
    (BatchReport { statuses, errors }, dirty)
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
    fn batch_dedupes_prefixes_continues_on_error_and_caches() {
        // "password" and "password" share a prefix; "hunter2" has another.
        let pw_hex = sha1_hex_upper("password");
        let hunter_hex = sha1_hex_upper("hunter2");
        let mut cache = Cache::default();
        let mut calls: Vec<String> = Vec::new();
        let (report, dirty) = check_with(
            &["password", "", "hunter2", "password"],
            &mut cache,
            1_000,
            |prefix| {
                calls.push(prefix.to_string());
                if prefix == &pw_hex[..5] {
                    Ok(format!("{}:3\n", &pw_hex[5..]))
                } else {
                    Err(Error::Other("hibp http: offline".into()))
                }
            },
        );
        assert_eq!(calls.len(), 2, "each prefix fetched once");
        assert!(dirty);
        assert!(matches!(
            report.statuses[0],
            Some(BreachStatus::Found { count: 3 })
        ));
        assert!(matches!(report.statuses[1], Some(BreachStatus::NotFound)));
        assert!(report.statuses[2].is_none());
        assert!(matches!(
            report.statuses[3],
            Some(BreachStatus::Found { count: 3 })
        ));
        assert_eq!(report.errors, vec!["hibp http: offline".to_string()]);
        assert!(!report.errors[0].contains(&hunter_hex[..5]));
        assert!(cache.prefixes.contains_key(&pw_hex[..5]));
        assert!(into_result(report).is_err());

        // Second run: fresh cache hit, no fetch at all.
        let (report, dirty) = check_with(&["password"], &mut cache, 2_000, |_| {
            panic!("must not fetch a fresh prefix")
        });
        assert!(!dirty);
        assert!(into_result(report).is_ok());
    }

    #[test]
    fn stale_cache_is_used_when_refresh_fails() {
        let hex = sha1_hex_upper("password");
        let mut cache = Cache::default();
        cache.prefixes.insert(
            hex[..5].to_string(),
            CacheEntry {
                fetched_at: 0,
                body: format!("{}:9\n", &hex[5..]),
            },
        );
        let (report, dirty) = check_with(&["password"], &mut cache, CACHE_TTL_SECS + 1, |_| {
            Err(Error::Other("offline".into()))
        });
        assert!(!dirty);
        assert_eq!(report.errors.len(), 1);
        assert!(matches!(
            report.statuses[0],
            Some(BreachStatus::Found { count: 9 })
        ));
    }

    #[test]
    fn parse_not_found_returns_not_found() {
        let body = "ABCDEF:1\nFFFF:2\n";
        let r = parse_body(body, "0000000000000000000000000000000000000");
        assert!(matches!(r, BreachStatus::NotFound));
    }
}
