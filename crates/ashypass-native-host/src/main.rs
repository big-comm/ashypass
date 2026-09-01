//! Ashy Pass — native messaging host.
//!
//! Browsers (Chrome, Firefox, Edge, Brave, …) spawn this binary on demand
//! when an extension calls `browser.runtime.connectNative("com.bigcommunity.ashypass")`.
//! Communication happens over stdin/stdout with the Chrome native messaging
//! wire format:
//!
//! ```text
//! [u32 length, little-endian] [UTF-8 JSON payload]
//! ```
//!
//! Messages are JSON objects with a `cmd` field. Supported commands:
//!
//! | cmd        | request fields              | response                        |
//! |------------|------------------------------|----------------------------------|
//! | `ping`     | —                            | `{ok, version}`                  |
//! | `list`     | `query?`                     | `{ok, entries: [Summary]}`       |
//! | `search`   | `query`                      | `{ok, entries: [Summary]}`       |
//! | `match_url`| `url`                        | `{ok, entries: [Summary]}`       |
//! | `get`      | `id`                         | `{ok, entry: Full}`              |
//! | `generate` | `length?, kind?`             | `{ok, password}`                 |
//!
//! On error, every response is `{ok: false, error: string}`.
//!
//! ## Unlock policy
//!
//! There is no TTY — the host is launched by the browser. We therefore only
//! attempt to unlock the vault via the Secret Service keyring item that the
//! GUI populates (`ashypass_core::keyring::load_master`). If keyring unlock
//! fails (no item, wrong master, or D-Bus unavailable), we reply with
//! `{ok: false, error: "vault locked — open the desktop app to unlock"}`
//! and the extension surfaces that to the user.
//!
//! Unlocking is *lazy and expiring*, mirroring the desktop auto-lock:
//!
//! - The key is derived on the first request that needs vault data, not at
//!   startup. A browser port opened while the keyring was unavailable
//!   therefore recovers as soon as the user unlocks their session, instead of
//!   answering "locked" for as long as the browser keeps the port open.
//! - After `lock_timeout` seconds without a vault-touching request the key is
//!   dropped again, so a long-lived browser process does not hold the vault
//!   key in memory all day.
//! - The `browser_integration` setting gates everything: when the user turns
//!   it off, vault commands are refused without consulting the keyring.
//!
//! ## Installing the manifest
//!
//! Run `ashypass-native-host --install` once after building. That writes the
//! Chrome / Firefox manifest files pointing at the current binary into the
//! per-user directories where each browser expects them.

use anyhow::{anyhow, bail, Context, Result};
use ashypass_core::db::vault::{PasswordEntry, Vault};
use ashypass_core::generator::{
    generate_passphrase, generate_password, generate_pin, PasswordConfig,
};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

const EXTENSION_NAME: &str = "com.bigcommunity.ashypass";
const VERSION: &str = ashypass_core::config::APP_VERSION;
/// Maximum incoming payload accepted. Mirrors the Chrome limit (~1 MiB),
/// guarding against a runaway extension stream.
const MAX_MESSAGE_BYTES: u32 = 1024 * 1024;

fn main() {
    // CLI helper modes for installing or printing the manifest. These run
    // when the binary is invoked from a terminal rather than by the browser
    // wire protocol.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(first) = args.first().map(|s| s.as_str()) {
        match first {
            "--install" => {
                if let Err(e) = install_manifests(&args[1..]) {
                    eprintln!("install failed: {e}");
                    std::process::exit(1);
                }
                return;
            }
            "--print-manifest" => {
                let allowed = args.get(1).cloned().unwrap_or_default();
                println!("{}", manifest_chrome(&current_exe_path_str(), &allowed));
                return;
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            _ => {
                eprintln!("unknown argument: {first}\n");
                print_help();
                std::process::exit(2);
            }
        }
    }

    // Browser wire mode.
    if let Err(e) = serve() {
        // Best-effort: write a final error frame so the extension can show
        // something. If even that fails the browser will see EOF.
        let payload = serde_json::json!({
            "ok": false,
            "error": format!("host crashed: {e}"),
        });
        let _ = write_message(&payload);
        std::process::exit(1);
    }
}

fn print_help() {
    println!("ashypass-native-host {VERSION}");
    println!();
    println!("Browser native messaging host for the Ashy Pass extension.");
    println!();
    println!("Usage:");
    println!("  ashypass-native-host                    # browser wire mode (stdin/stdout)");
    println!("  ashypass-native-host --install <ext-id>... # write manifests into Chrome/Firefox profile dirs");
    println!(
        "  ashypass-native-host --print-manifest <ext-id>  # print Chrome-style manifest to stdout"
    );
    println!();
    println!(
        "Extension id is the Chrome/Firefox extension id that's allowed to talk to this host."
    );
    println!("You can pass multiple ids to allow several builds (dev, beta, prod).");
}

// ---------------------------------------------------------------------------
// Wire protocol
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum Request {
    Ping,
    List {
        query: Option<String>,
    },
    Search {
        query: String,
    },
    MatchUrl {
        url: String,
    },
    Get {
        id: i64,
    },
    Generate {
        length: Option<usize>,
        kind: Option<String>,
    },
}

#[derive(Debug, Serialize)]
struct EntrySummary {
    id: i64,
    title: String,
    username: Option<String>,
    url: Option<String>,
    category: Option<String>,
    has_totp: bool,
}

#[derive(Debug, Serialize)]
struct EntryFull {
    id: i64,
    title: String,
    username: Option<String>,
    url: Option<String>,
    password: Option<String>,
    notes: Option<String>,
    has_totp: bool,
    category: Option<String>,
}

impl From<&PasswordEntry> for EntrySummary {
    fn from(e: &PasswordEntry) -> Self {
        Self {
            id: e.id,
            title: e.title.clone(),
            username: e.username.clone(),
            url: e.url.clone(),
            category: e.category.clone(),
            has_totp: e.has_totp,
        }
    }
}

/// Vault handle plus the expiring-unlock bookkeeping described in the module
/// docs. `last_used` is the timestamp of the last request that needed the key.
struct HostSession {
    vault: Vault,
    last_used: Option<Instant>,
}

impl HostSession {
    fn open() -> Result<Self> {
        let db_path = ashypass_core::config::database_path();
        let vault = Vault::open(&db_path).context("opening vault")?;
        Ok(Self {
            vault,
            last_used: None,
        })
    }

    /// Idle window before the key is dropped. Follows the desktop auto-lock
    /// setting so the browser never outlives the policy the user chose, with a
    /// floor that keeps a normal fill-then-submit flow from re-deriving.
    fn idle_timeout() -> Duration {
        let seconds = ashypass_core::settings::Settings::load()
            .lock_timeout
            .max(30);
        Duration::from_secs(seconds)
    }

    /// True when the vault is usable for this request. Drops an expired key
    /// first, then unlocks from the keyring on demand.
    fn ensure_unlocked(&mut self) -> bool {
        if !ashypass_core::settings::Settings::load().browser_integration {
            self.relock();
            return false;
        }

        if let Some(last) = self.last_used {
            if last.elapsed() >= Self::idle_timeout() {
                self.relock();
            }
        }

        if !self.vault.is_unlocked() && !self.unlock_from_keyring() {
            return false;
        }

        self.last_used = Some(Instant::now());
        true
    }

    fn unlock_from_keyring(&mut self) -> bool {
        if !self.vault.has_master_password().unwrap_or(false) {
            return false;
        }
        let Ok(Some(master)) = ashypass_core::keyring::load_master() else {
            return false;
        };
        self.vault.unlock(&master).is_ok()
    }

    fn relock(&mut self) {
        self.vault.full_lock();
        self.last_used = None;
    }
}

fn serve() -> Result<()> {
    let mut session = HostSession::open()?;

    loop {
        let req = match read_message::<Request>() {
            Ok(Some(req)) => req,
            Ok(None) => return Ok(()), // EOF: browser closed the port.
            Err(e) => {
                write_error(&format!("malformed request: {e}"))?;
                continue;
            }
        };

        // Ping and generate work even when locked — they don't touch the
        // vault contents, so they must not trigger an unlock either.
        let resp = match &req {
            Request::Ping => serde_json::json!({"ok": true, "version": VERSION}),
            Request::Generate { length, kind } => match handle_generate(length, kind) {
                Ok(pw) => serde_json::json!({"ok": true, "password": pw}),
                Err(e) => error_response(&e.to_string()),
            },
            _ if !session.ensure_unlocked() => error_response(
                "vault locked — open the desktop app, enable browser integration, and store the master password in the system keyring",
            ),
            Request::List { query } => handle_list(&session.vault, query.as_deref()),
            Request::Search { query } => handle_list(&session.vault, Some(query)),
            Request::MatchUrl { url } => handle_match_url(&session.vault, url),
            Request::Get { id } => handle_get(&session.vault, *id),
        };

        write_message(&resp)?;
    }
}

fn handle_list(vault: &Vault, query: Option<&str>) -> serde_json::Value {
    match vault.list(query) {
        Ok(entries) => {
            let summaries: Vec<EntrySummary> = entries.iter().map(EntrySummary::from).collect();
            serde_json::json!({"ok": true, "entries": summaries})
        }
        Err(e) => error_response(&e.to_string()),
    }
}

fn handle_match_url(vault: &Vault, url: &str) -> serde_json::Value {
    let target = url_host(url).unwrap_or_else(|| url.to_string());
    if target.is_empty() {
        return serde_json::json!({"ok": true, "entries": Vec::<EntrySummary>::new()});
    }
    match vault.list(None) {
        Ok(entries) => {
            let matches: Vec<EntrySummary> = entries
                .iter()
                .filter(|e| match &e.url {
                    Some(u) => url_host(u)
                        .map(|h| host_match(&h, &target))
                        .unwrap_or(false),
                    None => false,
                })
                .map(EntrySummary::from)
                .collect();
            serde_json::json!({"ok": true, "entries": matches})
        }
        Err(e) => error_response(&e.to_string()),
    }
}

fn handle_get(vault: &Vault, id: i64) -> serde_json::Value {
    match vault.get(id) {
        Ok(Some(e)) => {
            let full = EntryFull {
                id: e.id,
                title: e.title,
                username: e.username,
                url: e.url,
                password: e.password,
                notes: e.notes,
                has_totp: e.has_totp,
                category: e.category,
            };
            serde_json::json!({"ok": true, "entry": full})
        }
        Ok(None) => error_response("entry not found"),
        Err(e) => error_response(&e.to_string()),
    }
}

fn handle_generate(length: &Option<usize>, kind: &Option<String>) -> Result<String> {
    match kind.as_deref() {
        Some("passphrase") => Ok(generate_passphrase(6, "-", true, true)),
        Some("pin") => Ok(generate_pin(length.unwrap_or(6))),
        Some("password") | None => {
            let cfg = PasswordConfig {
                length: length.unwrap_or(PasswordConfig::default().length),
                ..Default::default()
            };
            generate_password(&cfg).map_err(|e| anyhow!("{e}"))
        }
        Some(other) => bail!("unknown generate kind: {other}"),
    }
}

fn error_response(msg: &str) -> serde_json::Value {
    serde_json::json!({"ok": false, "error": msg})
}

fn write_error(msg: &str) -> Result<()> {
    write_message(&error_response(msg))
}

fn read_message<T: for<'de> Deserialize<'de>>() -> Result<Option<T>> {
    let mut len_buf = [0u8; 4];
    let stdin = std::io::stdin();
    let mut lock = stdin.lock();
    if let Err(e) = lock.read_exact(&mut len_buf) {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(e.into());
    }
    let len = u32::from_le_bytes(len_buf);
    if len == 0 {
        return Err(anyhow!("zero-length frame"));
    }
    if len > MAX_MESSAGE_BYTES {
        bail!("message too large: {len} bytes");
    }
    let mut buf = vec![0u8; len as usize];
    lock.read_exact(&mut buf)?;
    let v: T = serde_json::from_slice(&buf)?;
    Ok(Some(v))
}

fn write_message<T: Serialize>(value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    let len = bytes.len();
    if len > MAX_MESSAGE_BYTES as usize {
        bail!("response too large: {len} bytes");
    }
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    lock.write_all(&(len as u32).to_le_bytes())?;
    lock.write_all(&bytes)?;
    lock.flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// URL matching
// ---------------------------------------------------------------------------

/// Pull the hostname out of a URL, stripping the scheme and any path. Returns
/// `None` only if the input is empty.
fn url_host(input: &str) -> Option<String> {
    let s = input.trim();
    if s.is_empty() {
        return None;
    }
    let no_scheme = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
    let before_path = no_scheme.split('/').next().unwrap_or("");
    let before_query = before_path.split('?').next().unwrap_or("");
    let authority = before_query.split('@').next_back().unwrap_or("");
    // A bracketed IPv6 literal is full of colons, so strip the port only after
    // the closing bracket; splitting on ':' first would reduce it to "[".
    let host = match authority.strip_prefix('[') {
        Some(rest) => rest.split_once(']').map(|(h, _)| h).unwrap_or(rest),
        None => authority.split(':').next().unwrap_or(""),
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Multi-label public suffixes common enough to matter here. Without this a
/// suffix match would treat `github.io` or `com.br` as a registrable domain and
/// happily offer one tenant's credentials on another tenant's subdomain.
///
/// This is deliberately a short list rather than a bundled Public Suffix List:
/// the failure mode of a missing entry is a *refused* match (we fall back to
/// requiring more labels), never a credential offered to the wrong site.
const MULTI_LABEL_SUFFIXES: &[&str] = &[
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "co.jp",
    "com.br",
    "net.br",
    "org.br",
    "gov.br",
    "com.au",
    "com.mx",
    "com.ar",
    "co.za",
    "co.in",
    "com.tr",
    "github.io",
    "gitlab.io",
    "pages.dev",
    "workers.dev",
    "vercel.app",
    "netlify.app",
    "herokuapp.com",
    "azurewebsites.net",
    "cloudfront.net",
    "s3.amazonaws.com",
    "blogspot.com",
    "wordpress.com",
    "firebaseapp.com",
    "web.app",
    "appspot.com",
    "glitch.me",
    "onrender.com",
    "fly.dev",
    "duckdns.org",
    "ngrok.io",
];

/// Number of trailing labels that belong to the public suffix plus one, i.e.
/// the minimum label count of a registrable domain under `host`.
fn registrable_label_count(host: &str) -> usize {
    for suffix in MULTI_LABEL_SUFFIXES {
        if host == *suffix || host.ends_with(&format!(".{suffix}")) {
            return suffix.split('.').count() + 1;
        }
    }
    2
}

/// The registrable domain of `host` (`mail.corp.example.co.uk` →
/// `example.co.uk`). Returns `None` when `host` is itself a public suffix or
/// otherwise has too few labels to own credentials.
fn registrable_domain(host: &str) -> Option<String> {
    // IP literals have no registrable domain; treating the last two octets as
    // one would make 192.168.1.10 and 10.0.1.10 "the same site".
    if host.parse::<std::net::IpAddr>().is_ok() || host.contains(':') {
        return None;
    }
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    let needed = registrable_label_count(host);
    if labels.len() < needed {
        return None;
    }
    Some(labels[labels.len() - needed..].join("."))
}

/// Match `candidate` against `target`, allowing `www.` shedding and
/// subdomain-style matches within one registrable domain (so a stored
/// `example.com` entry is offered on `mail.example.com`).
///
/// Crossing a public-suffix boundary is refused: `github.io` must not match
/// `attacker.github.io`, and two hosts that merely share a public suffix
/// (`a.com.br` / `b.com.br`) are unrelated.
fn host_match(candidate: &str, target: &str) -> bool {
    let c = candidate.trim_start_matches("www.");
    let t = target.trim_start_matches("www.");
    if c == t {
        return true;
    }
    // Both sides must resolve to the same registrable domain. IP literals and
    // bare public suffixes yield `None` and so only ever match exactly.
    match (registrable_domain(c), registrable_domain(t)) {
        (Some(cd), Some(td)) => cd == td,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Manifest installation
// ---------------------------------------------------------------------------

fn current_exe_path_str() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .unwrap_or_else(|| "/usr/bin/ashypass-native-host".to_string())
}

fn manifest_chrome(exe_path: &str, allowed_extensions: &str) -> String {
    // `allowed_origins` for Chromium-family, comma-separated chrome-extension://
    // URIs. The caller passes the bare extension IDs and we wrap them.
    let origins: Vec<String> = allowed_extensions
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| format!("\"chrome-extension://{}/\"", s.trim()))
        .collect();
    format!(
        r#"{{
  "name": "{EXTENSION_NAME}",
  "description": "Ashy Pass native messaging host",
  "path": "{exe_path}",
  "type": "stdio",
  "allowed_origins": [{}]
}}
"#,
        origins.join(", ")
    )
}

fn manifest_firefox(exe_path: &str, allowed_extensions: &[String]) -> String {
    let ids: Vec<String> = allowed_extensions
        .iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| format!("\"{}\"", s.trim()))
        .collect();
    format!(
        r#"{{
  "name": "{EXTENSION_NAME}",
  "description": "Ashy Pass native messaging host",
  "path": "{exe_path}",
  "type": "stdio",
  "allowed_extensions": [{}]
}}
"#,
        ids.join(", ")
    )
}

fn install_manifests(extension_ids: &[String]) -> Result<()> {
    if extension_ids.is_empty() {
        bail!("at least one extension id is required");
    }
    let exe = current_exe_path_str();
    let chrome = manifest_chrome(&exe, &extension_ids.join(","));
    let firefox = manifest_firefox(&exe, extension_ids);

    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| anyhow!("HOME not set"))?;

    // Chromium-family per-user host manifest directories. Chrome, Chromium,
    // Brave, Edge, Vivaldi each look in their own directory; install to all
    // of them that exist so the user doesn't have to think about which fork
    // they're running.
    let chrome_targets = [
        home.join(".config/google-chrome/NativeMessagingHosts"),
        home.join(".config/chromium/NativeMessagingHosts"),
        home.join(".config/BraveSoftware/Brave-Browser/NativeMessagingHosts"),
        home.join(".config/microsoft-edge/NativeMessagingHosts"),
        home.join(".config/vivaldi/NativeMessagingHosts"),
    ];
    let firefox_target = home.join(".mozilla/native-messaging-hosts");

    let mut written = 0;
    for dir in &chrome_targets {
        if let Some(parent) = dir.parent() {
            if !parent.exists() {
                continue; // Browser not installed for this user — skip.
            }
        }
        std::fs::create_dir_all(dir)?;
        let path = dir.join(format!("{EXTENSION_NAME}.json"));
        std::fs::write(&path, chrome.as_bytes())?;
        println!("wrote {}", path.display());
        written += 1;
    }
    if firefox_target.parent().map(|p| p.exists()).unwrap_or(false) {
        std::fs::create_dir_all(&firefox_target)?;
        let path = firefox_target.join(format!("{EXTENSION_NAME}.json"));
        std::fs::write(&path, firefox.as_bytes())?;
        println!("wrote {}", path.display());
        written += 1;
    }
    if written == 0 {
        println!(
            "no supported browser config directories found under {}",
            home.display()
        );
        println!("install Chrome/Chromium/Brave/Edge/Vivaldi or Firefox first, then re-run.");
    } else {
        println!("\n{written} manifest file(s) installed.");
        println!(
            "The browser will now allow extension(s) {:?} to spawn this binary.",
            extension_ids
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_host_strips_scheme_and_path() {
        assert_eq!(
            url_host("https://example.com/login?next=/x"),
            Some("example.com".into())
        );
        assert_eq!(url_host("example.com"), Some("example.com".into()));
        assert_eq!(
            url_host("https://USER:PW@host.tld:8443/x"),
            Some("host.tld".into())
        );
        assert_eq!(url_host(""), None);
    }

    #[test]
    fn url_host_keeps_ipv6_literals_intact() {
        assert_eq!(url_host("http://[::1]:8080/x"), Some("::1".into()));
        assert_eq!(
            url_host("http://[2001:db8::5]/"),
            Some("2001:db8::5".into())
        );
    }

    #[test]
    fn host_match_handles_www_and_subdomains() {
        assert!(host_match("example.com", "example.com"));
        assert!(host_match("www.example.com", "example.com"));
        assert!(host_match("example.com", "www.example.com"));
        assert!(host_match("mail.example.com", "example.com"));
        assert!(host_match("example.com", "mail.example.com"));
        assert!(host_match("a.corp.example.com", "b.example.com"));
        assert!(!host_match("attacker.com", "example.com"));
        assert!(!host_match("example.org", "example.com"));
    }

    #[test]
    fn host_match_respects_public_suffix_boundaries() {
        // A bare public suffix must not vouch for its tenants.
        assert!(!host_match("github.io", "attacker.github.io"));
        assert!(!host_match("attacker.github.io", "victim.github.io"));
        assert!(!host_match("com.br", "banco.com.br"));
        assert!(!host_match("a.com.br", "b.com.br"));
        // …but real registrable domains under a multi-label suffix still work.
        assert!(host_match("banco.com.br", "www.banco.com.br"));
        assert!(host_match("login.banco.com.br", "banco.com.br"));
        assert!(host_match("shop.co.uk", "www.shop.co.uk"));
        assert!(!host_match("shop.co.uk", "other.co.uk"));
    }

    #[test]
    fn host_match_rejects_ip_literal_confusion() {
        assert!(host_match("192.168.1.10", "192.168.1.10"));
        assert!(!host_match("192.168.1.10", "10.0.1.10"));
        assert!(!host_match("192.168.1.10", "168.1.10"));
        assert!(!host_match("2001:db8::5", "2001:db8::6"));
    }

    #[test]
    fn manifest_chrome_lists_origins() {
        let m = manifest_chrome("/bin/host", "abc,def");
        assert!(m.contains("\"chrome-extension://abc/\""));
        assert!(m.contains("\"chrome-extension://def/\""));
        assert!(m.contains("\"path\": \"/bin/host\""));
    }

    #[test]
    fn manifest_firefox_lists_extension_ids() {
        let m = manifest_firefox("/bin/host", &["abc@example".into(), "def@example".into()]);
        assert!(m.contains("\"abc@example\""));
        assert!(m.contains("\"def@example\""));
    }
}
