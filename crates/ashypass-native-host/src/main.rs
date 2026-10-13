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
//! Messages are JSON objects with a `cmd` field and an optional `rid` that
//! the response echoes. The full protocol (commands, fields, error codes) is
//! in `browser-extension/PROTOCOL.md`.
//!
//! ## Unlock policy
//!
//! There is no TTY — the host is launched by the browser. The vault opens
//! either with the master password the user types in the extension
//! (`unlock`), or by itself when the GUI stored the master password in the
//! Secret Service keyring ("Open automatically at login"). Wrong passwords
//! pause `unlock` for a while after a few attempts.
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
//! - The `browser_extension` setting (off by default) gates everything:
//!   while it is off, vault commands are refused without consulting the
//!   keyring.
//! - With `lock_on_screen_lock` on, vault commands are refused (and the key
//!   dropped) while logind reports the session's screen as locked.
//!
//! ## Installing the manifest
//!
//! The package installs system-wide manifests (Firefox, Chrome, Chromium,
//! Edge). `ashypass-native-host --install` (Settings → Browser → Connect
//! browsers) writes per-user manifests for every installed browser, which
//! also covers Brave, Vivaldi, LibreWolf and Waterfox.

use anyhow::{anyhow, bail, Context, Result};
use ashypass_core::db::vault::{PasswordEntry, Vault};
use ashypass_core::generator::{
    generate_passphrase, generate_password, generate_pin, PasswordConfig,
};
use ashypass_core::settings::Settings;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

const EXTENSION_NAME: &str = "com.bigcommunity.ashypass";
/// Firefox id of the extension (`browser_specific_settings.gecko.id`).
const FIREFOX_EXTENSION_ID: &str = "ashypass@big-comm.github.io";
/// Chrome-family ids allowed to connect: the development build (fixed by the
/// `key` in its manifest). Add the Chrome Web Store id here once published.
const CHROME_EXTENSION_IDS: &[&str] = &["opelfkfheadglgamfephkfejfpcnlbck"];
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
    if let Some(first) = args
        .first()
        .map(|s| s.as_str())
        .filter(|a| is_cli_command(a))
    {
        match first {
            "--install" => {
                if let Err(e) = install_manifests(&args[1..]) {
                    eprintln!("install failed: {e}");
                    std::process::exit(1);
                }
                return;
            }
            "--print-manifest" => {
                // --print-manifest <chrome|firefox> [host path]: for packaging
                // the system-wide manifests.
                let path = args.get(2).cloned().unwrap_or_else(current_exe_path_str);
                match args.get(1).map(String::as_str) {
                    Some("chrome") => print!("{}", manifest_chrome(&path, &default_chrome_ids())),
                    Some("firefox") => {
                        print!("{}", manifest_firefox(&path, &default_firefox_ids()))
                    }
                    _ => {
                        eprintln!("usage: --print-manifest <chrome|firefox> [host path]");
                        std::process::exit(2);
                    }
                }
                return;
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            _ => unreachable!("is_cli_command"),
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

/// Terminal commands. Anything else is what a browser passes when it starts
/// the host — Chrome the caller's origin (`chrome-extension://…/`), Firefox
/// the manifest path and the extension id — and means: serve.
fn is_cli_command(arg: &str) -> bool {
    matches!(arg, "--install" | "--print-manifest" | "--help" | "-h")
}

fn print_help() {
    println!("ashypass-native-host {VERSION}");
    println!();
    println!("Browser native messaging host for the Ashy Pass extension.");
    println!();
    println!("Usage:");
    println!("  ashypass-native-host                         # browser wire mode (stdin/stdout)");
    println!("  ashypass-native-host --install [--chrome-id ID]... [--firefox-id ID]...");
    println!("        write the host manifests for this user into every installed browser");
    println!("        (built-in extension ids are always included)");
    println!("  ashypass-native-host --print-manifest <chrome|firefox> [host path]");
    println!("        print a manifest, e.g. for system-wide packaging");
}

fn default_chrome_ids() -> Vec<String> {
    CHROME_EXTENSION_IDS.iter().map(|s| s.to_string()).collect()
}

fn default_firefox_ids() -> Vec<String> {
    vec![FIREFOX_EXTENSION_ID.to_string()]
}

// ---------------------------------------------------------------------------
// Wire protocol
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum Request {
    Ping,
    Status,
    Unlock {
        password: Secret,
    },
    Lock,
    List {
        query: Option<String>,
    },
    Search {
        query: String,
    },
    MatchUrl {
        url: String,
    },
    Fill {
        id: i64,
        url: String,
    },
    Get {
        id: i64,
    },
    Totp {
        id: i64,
    },
    Generate {
        length: Option<usize>,
        kind: Option<String>,
    },
}

/// A password received from the extension: wiped from memory when dropped
/// and never printed by `Debug`.
#[derive(Deserialize)]
#[serde(transparent)]
struct Secret(String);

impl Drop for Secret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// Version of the request/response format (see browser-extension/PROTOCOL.md).
const PROTOCOL_VERSION: u32 = 2;

/// Machine-readable error kinds, so the extension can show its own
/// translated messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorCode {
    Disabled,
    NoVault,
    Locked,
    BadPassword,
    RateLimited,
    NotFound,
    NoMatch,
    NoTotp,
    Invalid,
    Internal,
}

impl ErrorCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::NoVault => "no_vault",
            Self::Locked => "locked",
            Self::BadPassword => "bad_password",
            Self::RateLimited => "rate_limited",
            Self::NotFound => "not_found",
            Self::NoMatch => "no_match",
            Self::NoTotp => "no_totp",
            Self::Invalid => "invalid",
            Self::Internal => "internal",
        }
    }
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

/// What `get` returns. Notes are not sent: the extension has no use for
/// them, and they often hold recovery codes.
#[derive(Serialize)]
struct EntryFull {
    id: i64,
    title: String,
    username: Option<String>,
    url: Option<String>,
    password: Option<String>,
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

/// Wrong master passwords accepted in a row before `unlock` pauses.
const UNLOCK_ATTEMPTS: u32 = 5;
/// How long `unlock` refuses after too many wrong passwords.
const UNLOCK_PAUSE: Duration = Duration::from_secs(30);

/// Vault handle plus the expiring-unlock bookkeeping described in the module
/// docs. `last_used` is the timestamp of the last request that needed the key.
///
/// Settings and the keyring are reached through the two functions below,
/// so tests run against a throwaway vault without touching the user's real
/// configuration or keyring.
struct HostSession {
    vault: Vault,
    last_used: Option<Instant>,
    screen_lock: ScreenLockProbe,
    load_settings: fn() -> Settings,
    keyring_master: fn() -> Option<zeroize::Zeroizing<String>>,
    failed_unlocks: u32,
    paused_until: Option<Instant>,
}

fn keyring_master_password() -> Option<zeroize::Zeroizing<String>> {
    match ashypass_core::keyring::load_master() {
        Ok(Some(master)) => Some(zeroize::Zeroizing::new(master)),
        _ => None,
    }
}

impl HostSession {
    fn open() -> Result<Self> {
        let db_path = ashypass_core::config::database_path();
        let vault = Vault::open(&db_path).context("opening vault")?;
        Ok(Self::with_vault(
            vault,
            Settings::load,
            keyring_master_password,
        ))
    }

    fn with_vault(
        vault: Vault,
        load_settings: fn() -> Settings,
        keyring_master: fn() -> Option<zeroize::Zeroizing<String>>,
    ) -> Self {
        Self {
            vault,
            last_used: None,
            screen_lock: ScreenLockProbe::default(),
            load_settings,
            keyring_master,
            failed_unlocks: 0,
            paused_until: None,
        }
    }

    /// Idle window before the key is dropped. Follows the desktop auto-lock
    /// setting so the browser never outlives the policy the user chose, with a
    /// floor that keeps a normal fill-then-submit flow from re-deriving.
    fn idle_timeout(settings: &Settings) -> Duration {
        Duration::from_secs(settings.lock_timeout.max(30))
    }

    /// Why vault data cannot be served right now, if it cannot. Applies the
    /// policy first (integration switch, screen lock, idle expiry), then
    /// tries the keyring copy of the master password.
    fn access(&mut self) -> std::result::Result<(), ErrorCode> {
        let settings = (self.load_settings)();
        if !settings.browser_extension {
            self.relock();
            return Err(ErrorCode::Disabled);
        }
        if !self.vault.has_master_password().unwrap_or(false) {
            return Err(ErrorCode::NoVault);
        }

        // Mirror the desktop "lock when the screen locks" policy. The host
        // cannot listen for signals between requests, so it asks logind on
        // each vault request instead; sleep is covered by the idle timeout.
        if settings.lock_on_screen_lock && self.screen_lock.is_locked() {
            self.relock();
            return Err(ErrorCode::Locked);
        }

        if let Some(last) = self.last_used {
            if last.elapsed() >= Self::idle_timeout(&settings) {
                self.relock();
            }
        }

        if !self.vault.is_unlocked() && !self.unlock_from_keyring() {
            return Err(ErrorCode::Locked);
        }

        self.last_used = Some(Instant::now());
        Ok(())
    }

    fn unlock_from_keyring(&mut self) -> bool {
        let Some(master) = (self.keyring_master)() else {
            return false;
        };
        self.vault.unlock(&master).is_ok()
    }

    /// Unlock with a master password typed in the extension.
    fn unlock_with_password(&mut self, password: &str) -> std::result::Result<(), ErrorCode> {
        let settings = (self.load_settings)();
        if !settings.browser_extension {
            return Err(ErrorCode::Disabled);
        }
        if !self.vault.has_master_password().unwrap_or(false) {
            return Err(ErrorCode::NoVault);
        }
        if let Some(until) = self.paused_until {
            if Instant::now() < until {
                return Err(ErrorCode::RateLimited);
            }
            self.paused_until = None;
            self.failed_unlocks = 0;
        }
        match self.vault.unlock(password) {
            Ok(()) => {
                self.failed_unlocks = 0;
                self.last_used = Some(Instant::now());
                Ok(())
            }
            Err(ashypass_core::Error::InvalidMasterPassword) => {
                self.failed_unlocks += 1;
                if self.failed_unlocks >= UNLOCK_ATTEMPTS {
                    self.paused_until = Some(Instant::now() + UNLOCK_PAUSE);
                }
                Err(ErrorCode::BadPassword)
            }
            Err(_) => Err(ErrorCode::Internal),
        }
    }

    fn relock(&mut self) {
        self.vault.full_lock();
        self.last_used = None;
    }

    /// Answer one request.
    fn respond(&mut self, request: Request) -> serde_json::Value {
        use serde_json::json;
        // Ping, status and generate never need the key, so they must not
        // trigger a keyring unlock either.
        match request {
            Request::Ping => {
                return json!({"ok": true, "version": VERSION, "protocol": PROTOCOL_VERSION})
            }
            Request::Status => {
                let settings = (self.load_settings)();
                return json!({
                    "ok": true,
                    "enabled": settings.browser_extension,
                    "has_vault": self.vault.has_master_password().unwrap_or(false),
                    "unlocked": settings.browser_extension && self.access().is_ok(),
                });
            }
            Request::Generate { length, kind } => {
                return match handle_generate(&length, &kind) {
                    Ok(pw) => json!({"ok": true, "password": pw}),
                    Err(e) => error_response(ErrorCode::Invalid, &e.to_string()),
                }
            }
            Request::Lock => {
                self.relock();
                return json!({"ok": true});
            }
            Request::Unlock { password } => {
                return match self.unlock_with_password(&password.0) {
                    Ok(()) => json!({"ok": true}),
                    Err(code) => error_for(code),
                }
            }
            _ => {}
        }
        if let Err(code) = self.access() {
            return error_for(code);
        }
        match request {
            Request::List { query } => handle_list(&self.vault, query.as_deref()),
            Request::Search { query } => handle_list(&self.vault, Some(&query)),
            Request::MatchUrl { url } => handle_match_url(&self.vault, &url),
            Request::Fill { id, url } => handle_fill(&self.vault, id, &url),
            Request::Get { id } => handle_get(&self.vault, id),
            Request::Totp { id } => handle_totp(&self.vault, id),
            Request::Ping
            | Request::Status
            | Request::Generate { .. }
            | Request::Lock
            | Request::Unlock { .. } => unreachable!("answered above"),
        }
    }
}

/// How long to wait for the system bus (connect, or one property read)
/// before treating the screen-lock state as unknown.
const SCREEN_LOCK_TIMEOUT: Duration = Duration::from_secs(2);

/// Reads logind's `LockedHint` for the caller's session over the system bus.
///
/// Desktop environments (GNOME, KDE, …) set the hint while the screen is
/// locked. When the bus or logind is unreachable the state is reported as
/// unlocked, matching the desktop app, which also has nothing to react to
/// then; the idle timeout still applies.
#[derive(Default)]
struct ScreenLockProbe {
    connection: Option<zbus::blocking::Connection>,
    /// When connecting or a call last failed. Until [`SCREEN_LOCK_RETRY`]
    /// has passed, requests skip the probe instead of waiting again for a
    /// bus that is not there; after that it is tried again.
    failed_at: Option<Instant>,
}

/// How long to wait after a failed probe before trying the bus again.
const SCREEN_LOCK_RETRY: Duration = Duration::from_secs(30);

impl ScreenLockProbe {
    fn is_locked(&mut self) -> bool {
        if !self.should_probe(Instant::now()) {
            return false;
        }
        if self.connection.is_none() {
            self.connection = Self::connect();
        }
        let Some(connection) = &self.connection else {
            self.failed_at = Some(Instant::now());
            return false;
        };
        match Self::locked_hint(connection) {
            Ok(locked) => {
                self.failed_at = None;
                locked
            }
            Err(HintError::Call) => {
                // The connection may be dead (bus restarted, timed out):
                // drop it and reconnect on the next probe after the backoff.
                self.connection = None;
                self.failed_at = Some(Instant::now());
                false
            }
            Err(HintError::Reply) => {
                self.failed_at = None;
                false
            }
        }
    }

    /// Whether to query the bus now, given the last failure.
    fn should_probe(&self, now: Instant) -> bool {
        self.failed_at
            .is_none_or(|failed| now.saturating_duration_since(failed) >= SCREEN_LOCK_RETRY)
    }

    fn connect() -> Option<zbus::blocking::Connection> {
        // Connecting performs an authentication handshake with no timeout of
        // its own, so run it on a helper thread and give up after a while.
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let connection = zbus::blocking::connection::Builder::system()
                .map(|b| b.method_timeout(SCREEN_LOCK_TIMEOUT))
                .and_then(|b| b.build());
            let _ = sender.send(connection);
        });
        receiver.recv_timeout(SCREEN_LOCK_TIMEOUT).ok()?.ok()
    }

    fn locked_hint(connection: &zbus::blocking::Connection) -> Result<bool, HintError> {
        let reply = connection
            .call_method(
                Some("org.freedesktop.login1"),
                "/org/freedesktop/login1/session/auto",
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &("org.freedesktop.login1.Session", "LockedHint"),
            )
            .map_err(|_| HintError::Call)?;
        let value: zbus::zvariant::OwnedValue =
            reply.body().deserialize().map_err(|_| HintError::Reply)?;
        bool::try_from(value).map_err(|_| HintError::Reply)
    }
}

/// Why `LockedHint` could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HintError {
    /// The call itself failed (timeout, bus gone, no session): back off and
    /// reconnect.
    Call,
    /// logind answered with something unexpected.
    Reply,
}

fn serve() -> Result<()> {
    let mut session = HostSession::open()?;
    let stdin = std::io::stdin();
    let mut input = stdin.lock();

    loop {
        let raw = match read_message::<serde_json::Value>(&mut input)? {
            Incoming::Message(raw) => raw,
            Incoming::Eof => return Ok(()), // EOF: browser closed the port.
            Incoming::Malformed(e) => {
                // The frame was consumed in full, so the stream is still in
                // sync: report and keep serving.
                write_message(&error_response(
                    ErrorCode::Invalid,
                    &format!("malformed request: {e}"),
                ))?;
                continue;
            }
        };
        let response = answer(&mut session, raw);
        write_message(&response)?;
    }
}

/// Decode one request (keeping its `rid`), answer it, and tag the response
/// with the same `rid` so the extension can match replies to requests.
fn answer(session: &mut HostSession, raw: serde_json::Value) -> serde_json::Value {
    let rid = raw.get("rid").filter(|r| r.is_number()).cloned();
    let mut response = match serde_json::from_value::<Request>(raw) {
        Ok(request) => session.respond(request),
        Err(e) => error_response(ErrorCode::Invalid, &format!("malformed request: {e}")),
    };
    if let (Some(rid), Some(object)) = (rid, response.as_object_mut()) {
        object.insert("rid".into(), rid);
    }
    response
}

fn handle_list(vault: &Vault, query: Option<&str>) -> serde_json::Value {
    match vault.list(query) {
        Ok(entries) => {
            let summaries: Vec<EntrySummary> = entries.iter().map(EntrySummary::from).collect();
            serde_json::json!({"ok": true, "entries": summaries})
        }
        Err(e) => error_response(ErrorCode::Internal, &e.to_string()),
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
        Err(e) => error_response(ErrorCode::Internal, &e.to_string()),
    }
}

fn handle_get(vault: &Vault, id: i64) -> serde_json::Value {
    // Browser reads must not bump `last_accessed`: that would write to the
    // vault on every autofill and skew the desktop app's "recently used".
    match vault.get_without_touch(id) {
        Ok(Some(e)) => {
            let full = EntryFull {
                id: e.id,
                title: e.title,
                username: e.username,
                url: e.url,
                password: e.password,
                has_totp: e.has_totp,
                category: e.category,
            };
            serde_json::json!({"ok": true, "entry": full})
        }
        Ok(None) => error_for(ErrorCode::NotFound),
        Err(e) => error_response(ErrorCode::Internal, &e.to_string()),
    }
}

/// Credentials for filling the page at `url`, only when the entry belongs
/// to that site: a page can never obtain another site's password, even if
/// the extension were asked to.
fn handle_fill(vault: &Vault, id: i64, url: &str) -> serde_json::Value {
    match vault.get_without_touch(id) {
        Ok(Some(e)) => {
            let belongs = e
                .url
                .as_deref()
                .is_some_and(|entry_url| entry_matches_page(entry_url, url));
            if !belongs {
                return error_for(ErrorCode::NoMatch);
            }
            serde_json::json!({
                "ok": true,
                "username": e.username.unwrap_or_default(),
                "password": e.password.unwrap_or_default(),
            })
        }
        Ok(None) => error_for(ErrorCode::NotFound),
        Err(e) => error_response(ErrorCode::Internal, &e.to_string()),
    }
}

/// The current verification code of an entry.
fn handle_totp(vault: &Vault, id: i64) -> serde_json::Value {
    let entry = match vault.get_without_touch(id) {
        Ok(Some(e)) => e,
        Ok(None) => return error_for(ErrorCode::NotFound),
        Err(e) => return error_response(ErrorCode::Internal, &e.to_string()),
    };
    let Some(secret) = entry.totp_secret.filter(|s| !s.is_empty()) else {
        return error_for(ErrorCode::NoTotp);
    };
    let secret = zeroize::Zeroizing::new(secret);
    let algorithm = ashypass_core::totp::Algorithm::parse(&entry.totp_algorithm)
        .unwrap_or(ashypass_core::totp::Algorithm::Sha1);
    let period = entry.totp_period.max(1);
    let now = chrono_now_secs();
    match ashypass_core::totp::generate_totp(&secret, algorithm, entry.totp_digits, period, now) {
        Ok(code) => serde_json::json!({
            "ok": true,
            "code": code,
            "remaining": ashypass_core::totp::remaining_seconds(period, now),
            "period": period,
        }),
        Err(e) => error_response(ErrorCode::Internal, &e.to_string()),
    }
}

fn chrono_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

fn error_response(code: ErrorCode, msg: &str) -> serde_json::Value {
    serde_json::json!({"ok": false, "error": msg, "code": code.as_str()})
}

/// The standard English text for `code`.
fn error_for(code: ErrorCode) -> serde_json::Value {
    let message = match code {
        ErrorCode::Disabled => {
            "browser integration is off — turn it on in Ashy Pass → Settings → Browser"
        }
        ErrorCode::NoVault => "no vault yet — create it in Ashy Pass first",
        ErrorCode::Locked => "vault locked — enter the master password",
        ErrorCode::BadPassword => "wrong master password",
        ErrorCode::RateLimited => "too many wrong passwords — wait 30 seconds and try again",
        ErrorCode::NotFound => "entry not found",
        ErrorCode::NoMatch => "this entry does not belong to the page",
        ErrorCode::NoTotp => "this entry has no verification code",
        ErrorCode::Invalid => "invalid request",
        ErrorCode::Internal => "internal error",
    };
    error_response(code, message)
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
    let authority = url_authority(s);
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

/// Split `input` into the text before `://` and the rest, but only when that
/// `://` comes before the first `/`, `?`, `#` or `\`: in
/// `example.com/login?next=https://other.com` the `://` belongs to the query,
/// and the string has no scheme.
fn split_scheme(input: &str) -> (Option<&str>, &str) {
    let Some(separator) = input.find("://") else {
        return (None, input);
    };
    let path_start = input.find(['/', '?', '#', '\\']).unwrap_or(input.len());
    if separator <= path_start {
        (Some(&input[..separator]), &input[separator + 3..])
    } else {
        (None, input)
    }
}

/// The `host[:port]` part of a URL, without scheme, userinfo or path.
fn url_authority(input: &str) -> &str {
    let (_, no_scheme) = split_scheme(input);
    // The authority ends at the first `/`, `?` or `#`. Missing `#` here let
    // `https://evil.com#@example.com` resolve to `example.com`.
    let authority_end = no_scheme
        .find(['/', '?', '#', '\\'])
        .unwrap_or(no_scheme.len());
    no_scheme[..authority_end].rsplit('@').next().unwrap_or("")
}

/// Port component of a URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UrlPort {
    /// No port, or an empty one (`host:`): the scheme's default port.
    Default,
    Explicit(u16),
    /// Not a number in `0..=65535`. Never matches anything.
    Invalid,
}

fn url_port(input: &str) -> UrlPort {
    let authority = url_authority(input.trim());
    let after_host = match authority.strip_prefix('[') {
        Some(rest) => rest.split_once(']').map_or("", |(_, r)| r),
        None => authority.split_once(':').map_or("", |(_, p)| p),
    };
    let port = after_host.strip_prefix(':').unwrap_or(after_host);
    if port.is_empty() {
        UrlPort::Default
    } else if port.bytes().all(|b| b.is_ascii_digit()) {
        port.parse().map_or(UrlPort::Invalid, UrlPort::Explicit)
    } else {
        UrlPort::Invalid
    }
}

/// Well-known default port of `scheme`, if any.
fn default_port(scheme: Option<&str>) -> Option<u16> {
    match scheme? {
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        "ftp" => Some(21),
        _ => None,
    }
}

/// Whether an entry saved with `entry_url` may be offered on `page_url` as
/// far as the port goes. An entry with an explicit port (`https://nas:5001`)
/// only matches a page on that same port; an entry without one only matches
/// pages on the default port of their scheme, so a credential for
/// `https://example.com` is not offered to a service on `example.com:8443`.
fn port_compatible(entry_url: &str, page_url: &str) -> bool {
    let page_default = default_port(url_scheme(page_url).as_deref());
    let page_port = match url_port(page_url) {
        UrlPort::Invalid => return false,
        UrlPort::Default => None,
        UrlPort::Explicit(port) => Some(port),
    };
    match url_port(entry_url) {
        UrlPort::Invalid => false,
        UrlPort::Default => page_port.is_none() || page_port == page_default,
        UrlPort::Explicit(port) => page_port.or(page_default) == Some(port),
    }
}

/// Lower-case scheme of `input` (`https`, `http`, …), or `None` when the
/// string has no `scheme://` prefix (a bare host saved by the user).
fn url_scheme(input: &str) -> Option<String> {
    let scheme = split_scheme(input.trim()).0?;
    let mut chars = scheme.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    valid.then(|| scheme.to_ascii_lowercase())
}

/// Whether an entry saved with `entry` scheme may be offered on a page loaded
/// with `page` scheme.
///
/// Downgrades are refused: a credential saved for `https://` is never offered
/// on an `http://` page, where a network attacker controls the content. An
/// `http://` entry may be offered on the `https://` version of the site. A
/// bare host saved without a scheme (`192.168.1.1`, `nas.local`) says
/// nothing about it, so it matches both `http://` and `https://` pages (the
/// port rule still limits it to their default ports unless it names one).
/// Any other scheme must match exactly, and a page without a recognisable
/// scheme only matches bare-host entries.
fn scheme_compatible(entry: Option<&str>, page: Option<&str>) -> bool {
    match (entry, page) {
        (None, None) => true,
        (Some("https"), Some(page)) => page == "https",
        (None | Some("http"), Some(page)) => page == "http" || page == "https",
        (Some(entry), Some(page)) => entry == page,
        (Some(_), None) => false,
    }
}

/// Full matching rule for `match_url`: compatible scheme, compatible port and
/// same site.
fn entry_matches_page(entry_url: &str, page_url: &str) -> bool {
    let (Some(entry_host), Some(page_host)) = (url_host(entry_url), url_host(page_url)) else {
        return false;
    };
    scheme_compatible(
        url_scheme(entry_url).as_deref(),
        url_scheme(page_url).as_deref(),
    ) && port_compatible(entry_url, page_url)
        && host_match(&entry_host, &page_host)
}

/// The registrable domain of `host` (`mail.corp.example.co.uk` →
/// `example.co.uk`), per the Public Suffix List including its private section
/// (`github.io`, `myshopify.com`, `s3.amazonaws.com`, …). Returns `None` when
/// `host` is itself a public suffix, an IP literal, or sits under a suffix the
/// list does not know: such hosts only ever match exactly.
fn registrable_domain(host: &str) -> Option<String> {
    // IP literals have no registrable domain; treating the last two octets as
    // one would make 192.168.1.10 and 10.0.1.10 "the same site".
    if host.parse::<std::net::IpAddr>().is_ok() || host.contains(':') {
        return None;
    }
    let host = host.trim_end_matches('.');
    if host.is_empty() || host.split('.').any(str::is_empty) {
        return None;
    }
    let domain = psl::domain(host.as_bytes())?;
    // The PSL's implicit `*` rule makes any unknown TLD a suffix. Fail closed
    // there instead of guessing that registrations happen at the second level.
    if !domain.suffix().is_known() {
        return None;
    }
    std::str::from_utf8(domain.as_bytes())
        .ok()
        .map(str::to_string)
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

fn manifest_chrome(exe_path: &str, allowed_extensions: &[String]) -> String {
    // `allowed_origins` for Chromium-family: chrome-extension:// URIs. The
    // caller passes the bare extension ids and we wrap them.
    let origins: Vec<String> = allowed_extensions
        .iter()
        .map(|s| s.trim())
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

/// Extension ids from `--install` arguments, on top of the built-in ones.
/// Bare ids (the old form) are allowed for both browser families.
fn parse_install_args(args: &[String]) -> Result<(Vec<String>, Vec<String>)> {
    let mut chrome = default_chrome_ids();
    let mut firefox = default_firefox_ids();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--chrome-id" => chrome.push(
                iter.next()
                    .ok_or_else(|| anyhow!("--chrome-id needs a value"))?
                    .clone(),
            ),
            "--firefox-id" => firefox.push(
                iter.next()
                    .ok_or_else(|| anyhow!("--firefox-id needs a value"))?
                    .clone(),
            ),
            other if other.starts_with("--") => bail!("unknown option: {other}"),
            id => {
                chrome.push(id.to_string());
                firefox.push(id.to_string());
            }
        }
    }
    for ids in [&mut chrome, &mut firefox] {
        ids.retain(|id| !id.trim().is_empty());
        ids.sort();
        ids.dedup();
    }
    Ok((chrome, firefox))
}

fn install_manifests(args: &[String]) -> Result<()> {
    let (chrome_ids, firefox_ids) = parse_install_args(args)?;
    let exe = current_exe_path_str();
    let chrome = manifest_chrome(&exe, &chrome_ids);
    let firefox = manifest_firefox(&exe, &firefox_ids);

    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| anyhow!("HOME not set"))?;

    // Per-user host manifest directories. Each browser looks in its own;
    // install into every one whose browser is set up for this user, so the
    // user does not have to know which fork they run.
    let chrome_targets = [
        home.join(".config/google-chrome/NativeMessagingHosts"),
        home.join(".config/chromium/NativeMessagingHosts"),
        home.join(".config/BraveSoftware/Brave-Browser/NativeMessagingHosts"),
        home.join(".config/microsoft-edge/NativeMessagingHosts"),
        home.join(".config/vivaldi/NativeMessagingHosts"),
    ];
    let firefox_targets = [
        home.join(".mozilla/native-messaging-hosts"),
        home.join(".librewolf/native-messaging-hosts"),
        home.join(".waterfox/native-messaging-hosts"),
    ];

    let mut written = 0;
    let targets = chrome_targets
        .iter()
        .map(|dir| (dir, &chrome))
        .chain(firefox_targets.iter().map(|dir| (dir, &firefox)));
    for (dir, manifest) in targets {
        if !dir.parent().is_some_and(|parent| parent.exists()) {
            continue; // Browser not set up for this user — skip.
        }
        std::fs::create_dir_all(dir)?;
        let path = dir.join(format!("{EXTENSION_NAME}.json"));
        std::fs::write(&path, manifest.as_bytes())?;
        println!("wrote {}", path.display());
        written += 1;
    }
    if written == 0 {
        println!(
            "no supported browser config directories found under {}",
            home.display()
        );
        println!("open Chrome, Chromium, Brave, Edge, Vivaldi, Firefox, LibreWolf or Waterfox once, then re-run.");
    } else {
        println!("\n{written} manifest file(s) installed.");
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
        let m: serde_json::Value = serde_json::from_str(&manifest_chrome(
            "/bin/host",
            &["abc".into(), " def".into(), "".into()],
        ))
        .unwrap();
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
            serde_json::from_str(&manifest_chrome(path, &[r#"x"]}{"evil":["#.into()])).unwrap();
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
    fn public_suffix_list_private_section_is_honoured() {
        // Shared hosts under a flat TLD: each tenant is its own site.
        assert!(!host_match("shop.myshopify.com", "evil.myshopify.com"));
        assert!(host_match("shop.myshopify.com", "www.shop.myshopify.com"));
        assert!(host_match("admin.shop.myshopify.com", "shop.myshopify.com"));
        assert_eq!(
            registrable_domain("admin.shop.myshopify.com").as_deref(),
            Some("shop.myshopify.com")
        );
        assert_eq!(registrable_domain("myshopify.com"), None);
        assert!(!host_match("victim.github.io", "attacker.github.io"));
        assert!(host_match("victim.github.io", "docs.victim.github.io"));
        assert_eq!(registrable_domain("github.io"), None);
    }

    #[test]
    fn public_suffix_list_icann_section_is_honoured() {
        assert_eq!(
            registrable_domain("mail.corp.example.co.uk").as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(registrable_domain("co.uk"), None);
        assert!(host_match("login.example.co.uk", "example.co.uk"));
        assert!(!host_match("example.co.uk", "attacker.co.uk"));
        // A plain second-level registration.
        assert_eq!(
            registrable_domain("a.b.example.com").as_deref(),
            Some("example.com")
        );
        assert!(host_match("accounts.example.com", "example.com"));
        assert!(!host_match("example.com", "example.com.evil.net"));
        // Trailing dots and empty labels.
        assert_eq!(
            registrable_domain("www.example.com.").as_deref(),
            Some("example.com")
        );
        assert_eq!(registrable_domain("a..example.com"), None);
    }

    #[test]
    fn url_port_parsing() {
        assert_eq!(url_port("https://example.com/x"), UrlPort::Default);
        assert_eq!(url_port("https://example.com:/x"), UrlPort::Default);
        assert_eq!(url_port("example.com:8443"), UrlPort::Explicit(8443));
        assert_eq!(
            url_port("https://u:p@example.com:8443/x"),
            UrlPort::Explicit(8443)
        );
        assert_eq!(url_port("http://[::1]:8080/"), UrlPort::Explicit(8080));
        assert_eq!(url_port("http://[::1]/"), UrlPort::Default);
        assert_eq!(url_port("https://example.com:99999"), UrlPort::Invalid);
        assert_eq!(url_port("https://example.com:80x"), UrlPort::Invalid);
    }

    #[test]
    fn entry_matching_respects_ports() {
        // An entry without a port only matches the default port.
        assert!(entry_matches_page(
            "https://example.com",
            "https://example.com/"
        ));
        assert!(entry_matches_page(
            "https://example.com",
            "https://example.com:443/"
        ));
        assert!(!entry_matches_page(
            "https://example.com",
            "https://example.com:8443/"
        ));
        assert!(!entry_matches_page(
            "example.com",
            "https://example.com:8443/"
        ));
        assert!(entry_matches_page(
            "http://example.com",
            "https://example.com/"
        ));
        // An explicit port only matches that port.
        assert!(entry_matches_page(
            "https://nas.example.com:5001",
            "https://nas.example.com:5001/login"
        ));
        assert!(!entry_matches_page(
            "https://nas.example.com:5001",
            "https://nas.example.com/"
        ));
        assert!(!entry_matches_page(
            "https://nas.example.com:5001",
            "https://nas.example.com:5002/"
        ));
        assert!(entry_matches_page(
            "example.com:8443",
            "https://example.com:8443/"
        ));
        // An explicit default port behaves like no port.
        assert!(entry_matches_page(
            "https://example.com:443",
            "https://example.com/"
        ));
        assert!(entry_matches_page(
            "http://192.168.1.10:8080",
            "http://192.168.1.10:8080/"
        ));
        assert!(!entry_matches_page(
            "http://192.168.1.10:8080",
            "http://192.168.1.10/"
        ));
        // Malformed ports never match.
        assert!(!entry_matches_page(
            "https://example.com:abc",
            "https://example.com/"
        ));
        assert!(!entry_matches_page(
            "https://example.com",
            "https://example.com:abc/"
        ));
    }

    #[test]
    fn scheme_rules() {
        assert_eq!(url_scheme("HTTPS://example.com").as_deref(), Some("https"));
        assert_eq!(url_scheme("example.com"), None);
        assert_eq!(url_scheme("1x://example.com"), None);
        // No downgrade.
        assert!(!scheme_compatible(Some("https"), Some("http")));
        // A bare host carries no scheme to downgrade from.
        assert!(scheme_compatible(None, Some("http")));
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
        assert!(entry_matches_page("example.com", "http://example.com/"));
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
    fn bare_host_entries_match_http_and_https_on_default_ports() {
        for entry in ["192.168.1.1", "nas.local"] {
            for scheme in ["http", "https"] {
                assert!(
                    entry_matches_page(entry, &format!("{scheme}://{entry}/login")),
                    "{entry} on {scheme}"
                );
            }
            assert!(entry_matches_page(entry, &format!("http://{entry}:80/")));
            assert!(entry_matches_page(entry, &format!("https://{entry}:443/")));
            // Not on another port, and not on other schemes.
            assert!(!entry_matches_page(entry, &format!("http://{entry}:8080/")));
            assert!(!entry_matches_page(
                entry,
                &format!("https://{entry}:8443/")
            ));
            assert!(!entry_matches_page(entry, &format!("ftp://{entry}/")));
        }
        // A bare host with a port matches that port on either scheme.
        assert!(entry_matches_page(
            "nas.local:5000",
            "http://nas.local:5000/"
        ));
        assert!(entry_matches_page(
            "nas.local:5000",
            "https://nas.local:5000/"
        ));
        assert!(!entry_matches_page("nas.local:5000", "http://nas.local/"));
        // A different IP is still a different site.
        assert!(!entry_matches_page("192.168.1.1", "http://192.168.1.2/"));
        // An explicit https entry is still never offered over http.
        assert!(!entry_matches_page(
            "https://nas.local",
            "http://nas.local/"
        ));
    }

    #[test]
    fn scheme_separator_inside_the_path_or_query_is_not_a_scheme() {
        let entry = "example.com/login?next=https://other.com";
        assert_eq!(split_scheme(entry), (None, entry));
        assert_eq!(url_scheme(entry), None);
        assert_eq!(url_authority(entry), "example.com");
        assert_eq!(url_host(entry), Some("example.com".into()));
        assert_eq!(url_port(entry), UrlPort::Default);
        assert!(entry_matches_page(entry, "https://example.com/"));
        assert!(!entry_matches_page(entry, "https://other.com/"));
        for input in [
            "example.com#https://other.com",
            "example.com?x=ftp://other.com",
        ] {
            assert_eq!(url_host(input), Some("example.com".into()), "{input}");
            assert_eq!(url_scheme(input), None, "{input}");
        }
        // A real scheme is still recognised.
        assert_eq!(
            split_scheme("https://example.com/a?b=http://c"),
            (Some("https"), "example.com/a?b=http://c")
        );
        assert_eq!(
            url_host("https://example.com/?next=https://other.com"),
            Some("example.com".into())
        );
    }

    #[test]
    fn screen_lock_probe_retries_after_a_backoff() {
        let start = Instant::now();
        let mut probe = ScreenLockProbe::default();
        assert!(probe.should_probe(start));
        probe.failed_at = Some(start);
        assert!(!probe.should_probe(start));
        assert!(!probe.should_probe(start + SCREEN_LOCK_RETRY - Duration::from_secs(1)));
        assert!(probe.should_probe(start + SCREEN_LOCK_RETRY));
        assert!(probe.should_probe(start + SCREEN_LOCK_RETRY * 3));
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

    // --- Protocol, against a throwaway vault (never the real settings or
    // keyring).

    const MASTER: &str = "correct horse battery";

    fn enabled() -> Settings {
        Settings {
            browser_extension: true,
            lock_on_screen_lock: false,
            ..Settings::default()
        }
    }

    fn disabled() -> Settings {
        Settings {
            browser_extension: false,
            ..Settings::default()
        }
    }

    fn no_keyring() -> Option<zeroize::Zeroizing<String>> {
        None
    }

    fn session_with(settings: fn() -> Settings) -> (tempfile::TempDir, HostSession, i64, i64) {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(dir.path().join("vault.db")).unwrap();
        vault.set_master_password(MASTER).unwrap();
        let mail = vault
            .add(ashypass_core::db::vault::NewEntry {
                title: "Mail".into(),
                username: Some("ana".into()),
                password: "mail-secret".into(),
                url: Some("https://mail.example.com/login".into()),
                notes: Some("recovery codes".into()),
                totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
                ..Default::default()
            })
            .unwrap();
        let bank = vault
            .add(ashypass_core::db::vault::NewEntry {
                title: "Bank".into(),
                password: "bank-secret".into(),
                url: Some("https://bank.example.org".into()),
                ..Default::default()
            })
            .unwrap();
        vault.full_lock();
        (
            dir,
            HostSession::with_vault(vault, settings, no_keyring),
            mail,
            bank,
        )
    }

    fn call(session: &mut HostSession, request: serde_json::Value) -> serde_json::Value {
        answer(session, request)
    }

    #[test]
    fn locked_until_the_master_password_is_sent() {
        let (_dir, mut s, _, _) = session_with(enabled);
        let status = call(&mut s, serde_json::json!({"cmd": "status"}));
        assert_eq!(status["enabled"], true);
        assert_eq!(status["has_vault"], true);
        assert_eq!(status["unlocked"], false);
        let listed = call(&mut s, serde_json::json!({"cmd": "list"}));
        assert_eq!(listed["code"], "locked");
        let wrong = call(
            &mut s,
            serde_json::json!({"cmd": "unlock", "password": "nope"}),
        );
        assert_eq!(wrong["code"], "bad_password");
        let right = call(
            &mut s,
            serde_json::json!({"cmd": "unlock", "password": MASTER}),
        );
        assert_eq!(right["ok"], true);
        let listed = call(&mut s, serde_json::json!({"cmd": "list"}));
        assert_eq!(listed["entries"].as_array().unwrap().len(), 2);
        let locked = call(&mut s, serde_json::json!({"cmd": "lock"}));
        assert_eq!(locked["ok"], true);
        let listed = call(&mut s, serde_json::json!({"cmd": "list"}));
        assert_eq!(listed["code"], "locked");
    }

    #[test]
    fn repeated_wrong_passwords_pause_unlocking() {
        let (_dir, mut s, _, _) = session_with(enabled);
        for _ in 0..UNLOCK_ATTEMPTS {
            let r = call(
                &mut s,
                serde_json::json!({"cmd": "unlock", "password": "x"}),
            );
            assert_eq!(r["code"], "bad_password");
        }
        // Even the right password waits now.
        let r = call(
            &mut s,
            serde_json::json!({"cmd": "unlock", "password": MASTER}),
        );
        assert_eq!(r["code"], "rate_limited");
    }

    #[test]
    fn disabled_integration_refuses_everything_but_ping() {
        let (_dir, mut s, _, _) = session_with(disabled);
        assert_eq!(
            call(&mut s, serde_json::json!({"cmd": "ping"}))["protocol"],
            2
        );
        let r = call(
            &mut s,
            serde_json::json!({"cmd": "unlock", "password": MASTER}),
        );
        assert_eq!(r["code"], "disabled");
        let r = call(&mut s, serde_json::json!({"cmd": "list"}));
        assert_eq!(r["code"], "disabled");
    }

    #[test]
    fn fill_only_answers_for_the_entry_site() {
        let (_dir, mut s, mail, bank) = session_with(enabled);
        call(
            &mut s,
            serde_json::json!({"cmd": "unlock", "password": MASTER}),
        );
        let page = "https://mail.example.com/inbox";
        let matched = call(&mut s, serde_json::json!({"cmd": "match_url", "url": page}));
        let ids: Vec<i64> = matched["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_i64().unwrap())
            .collect();
        assert_eq!(ids, vec![mail]);
        let fill = call(
            &mut s,
            serde_json::json!({"cmd": "fill", "id": mail, "url": page}),
        );
        assert_eq!(fill["username"], "ana");
        assert_eq!(fill["password"], "mail-secret");
        // Another site's password is never handed to this page.
        let other = call(
            &mut s,
            serde_json::json!({"cmd": "fill", "id": bank, "url": page}),
        );
        assert_eq!(other["code"], "no_match");
        assert!(other.get("password").is_none());
    }

    #[test]
    fn get_leaves_notes_out_and_totp_gives_a_code() {
        let (_dir, mut s, mail, bank) = session_with(enabled);
        call(
            &mut s,
            serde_json::json!({"cmd": "unlock", "password": MASTER}),
        );
        let got = call(&mut s, serde_json::json!({"cmd": "get", "id": mail}));
        assert_eq!(got["entry"]["password"], "mail-secret");
        assert!(got["entry"].get("notes").is_none());
        let code = call(&mut s, serde_json::json!({"cmd": "totp", "id": mail}));
        assert_eq!(code["code"].as_str().unwrap().len(), 6);
        assert!(code["remaining"].as_u64().unwrap() <= 30);
        let none = call(&mut s, serde_json::json!({"cmd": "totp", "id": bank}));
        assert_eq!(none["code"], "no_totp");
        let missing = call(&mut s, serde_json::json!({"cmd": "get", "id": 9999}));
        assert_eq!(missing["code"], "not_found");
    }

    #[test]
    fn responses_carry_the_request_id() {
        let (_dir, mut s, _, _) = session_with(enabled);
        let r = call(&mut s, serde_json::json!({"cmd": "ping", "rid": 41}));
        assert_eq!(r["rid"], 41);
        let r = call(&mut s, serde_json::json!({"cmd": "nonsense", "rid": 42}));
        assert_eq!(r["rid"], 42);
        assert_eq!(r["code"], "invalid");
    }

    #[test]
    fn install_arguments_keep_the_built_in_ids() {
        let (chrome, firefox) = parse_install_args(&[
            "--chrome-id".into(),
            "storeid".into(),
            "--firefox-id".into(),
            "other@example.org".into(),
        ])
        .unwrap();
        assert!(chrome.contains(&"storeid".to_string()));
        assert!(chrome.contains(&CHROME_EXTENSION_IDS[0].to_string()));
        assert!(firefox.contains(&FIREFOX_EXTENSION_ID.to_string()));
        assert!(firefox.contains(&"other@example.org".to_string()));
        assert!(parse_install_args(&["--chrome-id".into()]).is_err());
    }

    #[test]
    fn browser_launch_arguments_are_not_cli_commands() {
        // What Chrome and Firefox pass as argv[1]: none of them is a CLI mode.
        for arg in [
            "chrome-extension://opelfkfheadglgamfephkfejfpcnlbck/",
            "/usr/lib/mozilla/native-messaging-hosts/com.bigcommunity.ashypass.json",
            "ashypass@big-comm.github.io",
        ] {
            assert!(!is_cli_command(arg), "{arg}");
        }
        assert!(is_cli_command("--install"));
    }
}
