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
/// Bounds for `generate` with `kind: "pin"`. Without a cap a single request
/// could ask for a multi-gigabyte string.
const PIN_MIN_LENGTH: usize = 4;
const PIN_MAX_LENGTH: usize = 64;

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
    let stdin = std::io::stdin();
    let mut input = stdin.lock();

    loop {
        let req = match read_message::<Request>(&mut input)? {
            Incoming::Message(req) => req,
            Incoming::Eof => return Ok(()), // EOF: browser closed the port.
            Incoming::Malformed(e) => {
                // The frame was consumed in full, so the stream is still in
                // sync: report and keep serving.
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
    if url_host(url).is_none() {
        return serde_json::json!({"ok": true, "entries": Vec::<EntrySummary>::new()});
    }
    match vault.list(None) {
        Ok(entries) => {
            let matches: Vec<EntrySummary> = entries
                .iter()
                .filter(|e| e.url.as_deref().is_some_and(|u| entry_matches_page(u, url)))
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
        Some("pin") => Ok(generate_pin(
            length.unwrap_or(6).clamp(PIN_MIN_LENGTH, PIN_MAX_LENGTH),
        )),
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

/// Outcome of reading one native-messaging frame.
#[derive(Debug)]
enum Incoming<T> {
    /// The browser closed the port.
    Eof,
    Message(T),
    /// The frame was read in full but its payload is not a valid request.
    /// The stream is still in sync, so the host can keep serving.
    Malformed(String),
}

/// Read one `[u32 LE length][JSON]` frame.
///
/// Framing errors (oversized length, truncated payload, I/O failure) are
/// returned as `Err`: once the length prefix cannot be trusted the stream is
/// out of sync, and reading on would interpret attacker-controlled payload
/// bytes as the next length. The caller must stop serving.
fn read_message<T: for<'de> Deserialize<'de>>(input: &mut impl Read) -> Result<Incoming<T>> {
    let mut len_buf = [0u8; 4];
    if let Err(e) = input.read_exact(&mut len_buf) {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Ok(Incoming::Eof);
        }
        return Err(e.into());
    }
    let len = u32::from_le_bytes(len_buf);
    if len == 0 {
        return Ok(Incoming::Malformed("zero-length frame".into()));
    }
    if len > MAX_MESSAGE_BYTES {
        bail!("message too large: {len} bytes");
    }
    let mut buf = vec![0u8; len as usize];
    input
        .read_exact(&mut buf)
        .context("truncated message payload")?;
    Ok(match serde_json::from_slice(&buf) {
        Ok(v) => Incoming::Message(v),
        Err(e) => Incoming::Malformed(e.to_string()),
    })
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
    // The authority ends at the first `/`, `?` or `#`. Missing `#` here let
    // `https://evil.com#@example.com` resolve to `example.com`.
    let authority_end = no_scheme
        .find(['/', '?', '#', '\\'])
        .unwrap_or(no_scheme.len());
    let authority = no_scheme[..authority_end].rsplit('@').next().unwrap_or("");
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

/// Lower-case scheme of `input` (`https`, `http`, …), or `None` when the
/// string has no `scheme://` prefix (a bare host saved by the user).
fn url_scheme(input: &str) -> Option<String> {
    let (scheme, _) = input.trim().split_once("://")?;
    let mut chars = scheme.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    valid.then(|| scheme.to_ascii_lowercase())
}

/// Whether an entry saved with `entry` scheme may be offered on a page loaded
/// with `page` scheme.
///
/// Downgrades are refused: a credential saved for `https://` (or saved as a
/// bare host, which we treat as `https`) is never offered on an `http://`
/// page, where a network attacker controls the content. An `http://` entry
/// may be offered on the `https://` version of the site. Any other scheme
/// must match exactly, and a page without a recognisable scheme only matches
/// bare-host entries.
fn scheme_compatible(entry: Option<&str>, page: Option<&str>) -> bool {
    match (entry, page) {
        (None, None) => true,
        (None | Some("https"), Some(page)) => page == "https",
        (Some("http"), Some(page)) => page == "http" || page == "https",
        (Some(entry), Some(page)) => entry == page,
        (Some(_), None) => false,
    }
}

/// Full matching rule for `match_url`: compatible scheme and same site.
fn entry_matches_page(entry_url: &str, page_url: &str) -> bool {
    let (Some(entry_host), Some(page_host)) = (url_host(entry_url), url_host(page_url)) else {
        return false;
    };
    scheme_compatible(
        url_scheme(entry_url).as_deref(),
        url_scheme(page_url).as_deref(),
    ) && host_match(&entry_host, &page_host)
}

/// Top-level domains under which registrations happen directly at the second
/// level (`example.com`), once the second-level public suffixes listed in
/// [`MULTI_LABEL_SUFFIXES`] are accounted for. Hosts under any other TLD
/// fail closed: they only ever match exactly (after `www.` shedding).
const FLAT_TLDS: &[&str] = &[
    "com", "org", "net", "edu", "gov", "mil", "int", "info", "biz", "dev", "app", "page", "xyz",
    "online", "site", "shop", "store", "tech", "cloud", "io", "me", "ai", "co", "de", "nl", "ch",
    "eu", "be", "dk", "fi", "cz", "es", "pt",
];

/// Multi-label public suffixes common enough to matter here. Without this a
/// suffix match would treat `github.io` or `com.br` as a registrable domain and
/// happily offer one tenant's credentials on another tenant's subdomain.
///
/// This is deliberately a short list rather than a bundled Public Suffix List,
/// so it must fail closed: a host whose suffix is neither listed here nor
/// under one of the [`FLAT_TLDS`] has no registrable domain and only matches
/// exactly. A missing entry therefore means a *refused* subdomain match,
/// never a credential offered to the wrong site.
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
    // Second-level registries of TLDs listed in FLAT_TLDS.
    "com.io",
    "net.io",
    "org.io",
    "edu.io",
    "gov.io",
    "mil.io",
    "co.me",
    "net.me",
    "org.me",
    "edu.me",
    "ac.me",
    "gov.me",
    "its.me",
    "priv.me",
    "com.ai",
    "net.ai",
    "off.ai",
    "org.ai",
    "com.co",
    "net.co",
    "org.co",
    "edu.co",
    "gov.co",
    "mil.co",
    "nom.co",
    "com.es",
    "nom.es",
    "org.es",
    "gob.es",
    "edu.es",
    "com.pt",
    "edu.pt",
    "gov.pt",
    "int.pt",
    "net.pt",
    "nome.pt",
    "org.pt",
    "publ.pt",
    "ac.be",
    "bv.nl",
    "aland.fi",
    // Common second-level registries of other ccTLDs.
    "co.nz",
    "org.nz",
    "net.nz",
    "ac.nz",
    "govt.nz",
    "ne.jp",
    "or.jp",
    "ac.jp",
    "go.jp",
    "co.kr",
    "com.cn",
    "net.cn",
    "org.cn",
    "com.hk",
    "com.sg",
    "com.tw",
    "co.il",
    "edu.au",
    "net.au",
    "org.au",
    "gov.au",
    "org.mx",
    "gob.mx",
    "edu.br",
    "art.br",
    // Shared hosting under flat TLDs.
    "readthedocs.io",
    "ngrok.app",
    "ngrok-free.app",
    "trycloudflare.com",
    "r2.dev",
    "azurestaticapps.net",
    "cloudapp.azure.com",
    "elasticbeanstalk.com",
    "github.dev",
    "dyndns.org",
];

/// Number of trailing labels that belong to the public suffix plus one, i.e.
/// the minimum label count of a registrable domain under `host`. `None` when
/// the suffix is unknown — the caller must then require an exact match.
fn registrable_label_count(host: &str) -> Option<usize> {
    // Longest listed suffix wins (`s3.amazonaws.com` before a shorter entry).
    let listed = MULTI_LABEL_SUFFIXES
        .iter()
        .filter(|suffix| host == **suffix || host.ends_with(&format!(".{suffix}")))
        .map(|suffix| suffix.split('.').count())
        .max();
    if let Some(labels) = listed {
        return Some(labels + 1);
    }
    let tld = host.rsplit('.').next()?;
    FLAT_TLDS.contains(&tld).then_some(2)
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
    let needed = registrable_label_count(host)?;
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
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| format!("chrome-extension://{s}/"))
        .collect();
    render_manifest(exe_path, "allowed_origins", origins)
}

fn manifest_firefox(exe_path: &str, allowed_extensions: &[String]) -> String {
    let ids: Vec<String> = allowed_extensions
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    render_manifest(exe_path, "allowed_extensions", ids)
}

/// Serialise a host manifest with serde_json, so a path or extension id
/// containing quotes or backslashes cannot break (or inject into) the JSON.
fn render_manifest(exe_path: &str, allow_key: &str, allowed: Vec<String>) -> String {
    let mut manifest = serde_json::json!({
        "name": EXTENSION_NAME,
        "description": "Ashy Pass native messaging host",
        "path": exe_path,
        "type": "stdio",
    });
    manifest[allow_key] = serde_json::Value::from(allowed);
    let mut out = serde_json::to_string_pretty(&manifest).expect("manifest is valid JSON");
    out.push('\n');
    out
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
    fn url_host_ignores_userinfo_lookalikes_after_the_authority() {
        assert_eq!(
            url_host("https://evil.com#@example.com/"),
            Some("evil.com".into())
        );
        assert_eq!(
            url_host("https://evil.com?@example.com"),
            Some("evil.com".into())
        );
        assert_eq!(
            url_host("https://evil.com\\@example.com"),
            Some("evil.com".into())
        );
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
        let m: serde_json::Value =
            serde_json::from_str(&manifest_chrome("/bin/host", "abc, def,")).unwrap();
        assert_eq!(m["name"], EXTENSION_NAME);
        assert_eq!(m["path"], "/bin/host");
        assert_eq!(m["type"], "stdio");
        assert_eq!(
            m["allowed_origins"],
            serde_json::json!(["chrome-extension://abc/", "chrome-extension://def/"])
        );
    }

    #[test]
    fn manifest_firefox_lists_extension_ids() {
        let m: serde_json::Value = serde_json::from_str(&manifest_firefox(
            "/bin/host",
            &["abc@example".into(), " ".into(), "def@example".into()],
        ))
        .unwrap();
        assert_eq!(
            m["allowed_extensions"],
            serde_json::json!(["abc@example", "def@example"])
        );
    }

    #[test]
    fn manifest_escapes_hostile_input() {
        let path = r#"/opt/we"ird\path"#;
        let m: serde_json::Value =
            serde_json::from_str(&manifest_chrome(path, r#"x"]}{"evil":["#)).unwrap();
        assert_eq!(m["path"], path);
        assert_eq!(m["allowed_origins"].as_array().unwrap().len(), 1);
        assert!(m.get("evil").is_none());
        let m: serde_json::Value =
            serde_json::from_str(&manifest_firefox(path, &[r#"a"]}"#.into()])).unwrap();
        assert_eq!(m["allowed_extensions"][0], r#"a"]}"#);
    }

    #[test]
    fn unknown_public_suffixes_fail_closed() {
        // `school.nz` is not in the built-in list and `nz` is not flat: the
        // old two-label fallback made these "the same site".
        assert!(!host_match("a.school.nz", "evil.school.nz"));
        assert!(!host_match("login.example.zz", "example.zz"));
        assert!(!host_match("a.example.zz", "b.example.zz"));
        assert!(!host_match("a.gov.pl", "evil.gov.pl"));
        // …but exact matches (and `www.`) still work there.
        assert!(host_match("example.zz", "example.zz"));
        assert!(host_match("www.example.zz", "example.zz"));
        assert!(host_match("bank.school.nz", "bank.school.nz"));
        // Listed second-level registries behave like a public suffix.
        assert!(!host_match("a.co.nz", "evil.co.nz"));
        assert!(host_match("shop.co.nz", "login.shop.co.nz"));
        assert!(!host_match("a.com.io", "b.com.io"));
        assert!(!host_match("a.edu.br", "b.edu.br"));
        // Flat TLDs keep subdomain matching.
        assert!(host_match("accounts.example.de", "example.de"));
        assert_eq!(
            registrable_domain("x.y.example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(registrable_domain("x.example.zz"), None);
        assert_eq!(registrable_domain("com"), None);
    }

    #[test]
    fn longest_listed_suffix_wins() {
        assert_eq!(
            registrable_domain("bucket.s3.amazonaws.com").as_deref(),
            Some("bucket.s3.amazonaws.com")
        );
        assert!(!host_match("a.s3.amazonaws.com", "b.s3.amazonaws.com"));
    }

    #[test]
    fn scheme_rules() {
        assert_eq!(url_scheme("HTTPS://example.com").as_deref(), Some("https"));
        assert_eq!(url_scheme("example.com"), None);
        assert_eq!(url_scheme("1x://example.com"), None);
        // No downgrade.
        assert!(!scheme_compatible(Some("https"), Some("http")));
        assert!(!scheme_compatible(None, Some("http")));
        // Same scheme or upgrade.
        assert!(scheme_compatible(Some("https"), Some("https")));
        assert!(scheme_compatible(None, Some("https")));
        assert!(scheme_compatible(Some("http"), Some("http")));
        assert!(scheme_compatible(Some("http"), Some("https")));
        // Other schemes match exactly only.
        assert!(scheme_compatible(Some("ftp"), Some("ftp")));
        assert!(!scheme_compatible(Some("ftp"), Some("https")));
        assert!(!scheme_compatible(None, Some("chrome-extension")));
        assert!(!scheme_compatible(Some("https"), None));
    }

    #[test]
    fn entry_matching_combines_scheme_and_host() {
        assert!(entry_matches_page(
            "https://example.com",
            "https://login.example.com/x"
        ));
        assert!(entry_matches_page("example.com", "https://example.com/"));
        assert!(!entry_matches_page(
            "https://example.com",
            "http://example.com/"
        ));
        assert!(!entry_matches_page("example.com", "http://example.com/"));
        assert!(entry_matches_page(
            "http://intranet.example.com",
            "http://intranet.example.com/"
        ));
        assert!(entry_matches_page(
            "http://example.com",
            "https://example.com/"
        ));
        assert!(!entry_matches_page(
            "https://example.com",
            "https://evil.com#@example.com"
        ));
        assert!(!entry_matches_page("", "https://example.com"));
    }

    #[test]
    fn pin_length_is_clamped() {
        let pin = handle_generate(&Some(10_000_000), &Some("pin".into())).unwrap();
        assert_eq!(pin.len(), PIN_MAX_LENGTH);
        let pin = handle_generate(&Some(0), &Some("pin".into())).unwrap();
        assert_eq!(pin.len(), PIN_MIN_LENGTH);
        let pin = handle_generate(&None, &Some("pin".into())).unwrap();
        assert_eq!(pin.len(), 6);
        assert!(pin.chars().all(|c| c.is_ascii_digit()));
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut out = (payload.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn frames_are_read_in_sequence() {
        let mut bytes = frame(br#"{"cmd":"ping"}"#);
        bytes.extend(frame(br#"{"cmd":"get","id":7}"#));
        let mut input = std::io::Cursor::new(bytes);
        assert!(matches!(
            read_message::<Request>(&mut input).unwrap(),
            Incoming::Message(Request::Ping)
        ));
        assert!(matches!(
            read_message::<Request>(&mut input).unwrap(),
            Incoming::Message(Request::Get { id: 7 })
        ));
        assert!(matches!(
            read_message::<Request>(&mut input).unwrap(),
            Incoming::Eof
        ));
    }

    #[test]
    fn malformed_payload_keeps_the_stream_in_sync() {
        let mut bytes = frame(b"not json");
        bytes.extend(frame(br#"{"cmd":"ping"}"#));
        let mut input = std::io::Cursor::new(bytes);
        assert!(matches!(
            read_message::<Request>(&mut input).unwrap(),
            Incoming::Malformed(_)
        ));
        assert!(matches!(
            read_message::<Request>(&mut input).unwrap(),
            Incoming::Message(Request::Ping)
        ));
    }

    #[test]
    fn oversized_or_truncated_frames_are_fatal() {
        // An oversized length prefix followed by bytes that would parse as a
        // valid frame if the reader resynchronised on them.
        let mut bytes = (MAX_MESSAGE_BYTES + 1).to_le_bytes().to_vec();
        bytes.extend(frame(br#"{"cmd":"ping"}"#));
        let mut input = std::io::Cursor::new(bytes);
        assert!(read_message::<Request>(&mut input).is_err());

        let mut truncated = 100u32.to_le_bytes().to_vec();
        truncated.extend_from_slice(b"{\"cmd\"");
        let mut input = std::io::Cursor::new(truncated);
        assert!(read_message::<Request>(&mut input).is_err());

        let mut input = std::io::Cursor::new(0u32.to_le_bytes().to_vec());
        assert!(matches!(
            read_message::<Request>(&mut input).unwrap(),
            Incoming::Malformed(_)
        ));
    }
}
