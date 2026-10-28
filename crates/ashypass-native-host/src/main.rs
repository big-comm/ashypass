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
//! - With `lock_on_screen_lock` on, the key is dropped when logind reports
//!   that the session's screen locked after it had been seen unlocked: the
//!   change, as the desktop app hears it from the screensaver, not the
//!   state, which some compositors leave set while the session is in use.
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
use ashypass_core::url_match::{entry_matches_page, url_host};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

const EXTENSION_NAME: &str = "com.bigcommunity.ashypass";
/// Firefox id of the extension (`browser_specific_settings.gecko.id`).
const FIREFOX_EXTENSION_ID: &str = "ashypass@big-comm.github.io";
/// Chrome-family ids allowed to connect: the Chrome Web Store's (Chrome,
/// Brave, Vivaldi, Opera; Edge too when installed from the Chrome store).
const CHROME_EXTENSION_IDS: &[&str] = &["aaffaajejkomddnihpblnkolkhcgaoom"];
/// The development build's id, fixed by the public `key` in its manifest.
/// Anyone can make an extension with that key, so release builds don't
/// allow it; `--install --chrome-id` adds it for testing an unpacked build.
const CHROME_DEV_EXTENSION_ID: &str = "opelfkfheadglgamfephkfejfpcnlbck";
const VERSION: &str = ashypass_core::config::APP_VERSION;
/// Profile folders of the Chromium-family browsers, under ~/.config.
const CHROME_PROFILE_DIRS: &[&str] = &[
    "google-chrome",
    "google-chrome-beta",
    "google-chrome-unstable",
    "chromium",
    "BraveSoftware/Brave-Browser",
    "BraveSoftware/Brave-Origin",
    "BraveSoftware/Brave-Browser-Beta",
    "BraveSoftware/Brave-Browser-Nightly",
    "microsoft-edge",
    "microsoft-edge-beta",
    "microsoft-edge-dev",
    "vivaldi",
    "vivaldi-snapshot",
];
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
    println!("        (built-in extension ids are always included; for an unpacked");
    println!("        development build add --chrome-id {CHROME_DEV_EXTENSION_ID})");
    println!("  ashypass-native-host --print-manifest <chrome|firefox> [host path]");
    println!("        print a manifest, e.g. for system-wide packaging");
}

fn default_chrome_ids() -> Vec<String> {
    let mut ids: Vec<String> = CHROME_EXTENSION_IDS.iter().map(|s| s.to_string()).collect();
    if cfg!(debug_assertions) {
        ids.push(CHROME_DEV_EXTENSION_ID.to_string());
    }
    ids
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
    UnlockPin {
        pin: Secret,
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
        /// Also send the notes (only the edit form asks for them).
        #[serde(default)]
        notes: bool,
    },
    Totp {
        id: i64,
    },
    Generate(GenerateOptions),
    Folders,
    Favicons {
        hosts: Vec<String>,
    },
    Add(NewLogin),
    Update(EditedLogin),
    Delete {
        id: i64,
    },
    ToggleFavorite {
        id: i64,
    },
    OpenApp,
}

/// Options for `generate`. Every field is optional; the defaults match the
/// desktop generator.
#[derive(Debug, Default, Deserialize)]
struct GenerateOptions {
    kind: Option<String>,
    length: Option<usize>,
    words: Option<usize>,
    separator: Option<String>,
    capitalize: Option<bool>,
    number: Option<bool>,
    uppercase: Option<bool>,
    lowercase: Option<bool>,
    digits: Option<bool>,
    symbols: Option<bool>,
    avoid_ambiguous: Option<bool>,
}

/// A login saved from the browser.
#[derive(Debug, Deserialize)]
struct NewLogin {
    title: String,
    username: Option<String>,
    password: Secret,
    url: Option<String>,
    category: Option<String>,
    notes: Option<String>,
}

/// A login edited in the browser. Every editable field is sent: an absent
/// username, address or folder clears it. `notes` is kept when absent and
/// replaced when present (blank clears it). `updated_at` is the value `get`
/// returned, so an edit made meanwhile (desktop app, sync) is never
/// overwritten.
#[derive(Debug, Deserialize)]
struct EditedLogin {
    id: i64,
    updated_at: i64,
    title: String,
    username: Option<String>,
    password: Secret,
    url: Option<String>,
    category: Option<String>,
    notes: Option<String>,
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
const PROTOCOL_VERSION: u32 = 4;

/// Machine-readable error kinds, so the extension can show its own
/// translated messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorCode {
    Disabled,
    NoVault,
    Locked,
    BadPassword,
    BadPin,
    PinDisabled,
    PinUnavailable,
    RateLimited,
    NotFound,
    NoMatch,
    NoTotp,
    Changed,
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
            Self::BadPin => "bad_pin",
            Self::PinDisabled => "pin_disabled",
            Self::PinUnavailable => "pin_unavailable",
            Self::RateLimited => "rate_limited",
            Self::NotFound => "not_found",
            Self::NoMatch => "no_match",
            Self::NoTotp => "no_totp",
            Self::Changed => "changed",
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
    favorite: bool,
}

/// What `get` returns. Notes often hold recovery codes, so they are only
/// sent when asked for (the edit form), never for copying or filling.
#[derive(Serialize)]
struct EntryFull {
    id: i64,
    title: String,
    username: Option<String>,
    url: Option<String>,
    password: Option<String>,
    has_totp: bool,
    category: Option<String>,
    favorite: bool,
    updated_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
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
            favorite: e.favorite,
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
    screen_edge: ScreenLockEdge,
    load_settings: fn() -> Settings,
    keyring_master: fn() -> Option<zeroize::Zeroizing<String>>,
    stored_pin: fn(&Settings) -> Option<ashypass_core::quick_unlock::StoredPin>,
    save_settings: SaveSettings,
    failed_unlocks: u32,
    paused_until: Option<Instant>,
}

/// Writes a change to the settings file.
type SaveSettings = fn(&dyn Fn(&mut Settings));

/// Apply a change to the settings file (the PIN record of older versions
/// lives there).
fn save_settings_file(change: &dyn Fn(&mut Settings)) {
    let mut settings = Settings::load();
    change(&mut settings);
    if let Err(error) = settings.save() {
        log::warn!("could not save settings: {error}");
    }
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
        let mut session = Self::with_vault(vault, Settings::load, keyring_master_password);
        session.stored_pin = ashypass_core::quick_unlock::stored_pin;
        session.save_settings = save_settings_file;
        Ok(session)
    }

    /// A session with no PIN record and no settings writes; `open` swaps in
    /// the real keyring and settings file.
    fn with_vault(
        vault: Vault,
        load_settings: fn() -> Settings,
        keyring_master: fn() -> Option<zeroize::Zeroizing<String>>,
    ) -> Self {
        Self {
            vault,
            last_used: None,
            screen_lock: ScreenLockProbe::default(),
            screen_edge: ScreenLockEdge::default(),
            load_settings,
            keyring_master,
            stored_pin: |_| None,
            save_settings: |_| {},
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
        if settings.lock_on_screen_lock && self.screen_locked() {
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

    /// Unlock with the PIN set up in Ashy Pass, under the same rules as the
    /// desktop app (attempts counted in the stored record, turned off at the
    /// limit): see `ashypass_core::quick_unlock`.
    fn unlock_with_pin(&mut self, pin: &str) -> std::result::Result<(), (ErrorCode, Option<u32>)> {
        let settings = (self.load_settings)();
        if !settings.browser_extension {
            return Err((ErrorCode::Disabled, None));
        }
        if !self.vault.has_master_password().unwrap_or(false) {
            return Err((ErrorCode::NoVault, None));
        }
        let Some(stored) = (self.stored_pin)(&settings) else {
            return Err((ErrorCode::PinUnavailable, None));
        };
        let derived = ashypass_core::db::derive_quick_unlock_key(pin, &stored.prefs);
        let save = self.save_settings;
        let mut update = |change: &dyn Fn(&mut Settings)| save(change);
        use ashypass_core::quick_unlock::PinOutcome;
        match ashypass_core::quick_unlock::finish_pin_attempt(
            &mut self.vault,
            stored,
            derived,
            &mut update,
        ) {
            PinOutcome::Unlocked => {
                self.last_used = Some(Instant::now());
                Ok(())
            }
            PinOutcome::Wrong { remaining } => Err((ErrorCode::BadPin, Some(remaining))),
            PinOutcome::TurnedOff | PinOutcome::Stale => Err((ErrorCode::PinDisabled, None)),
            PinOutcome::Unusable => Err((ErrorCode::PinUnavailable, None)),
        }
    }

    fn relock(&mut self) {
        self.vault.full_lock();
        self.last_used = None;
        self.screen_edge = ScreenLockEdge::default();
    }

    /// Whether the screen locked (see [`ScreenLockEdge`]).
    fn screen_locked(&mut self) -> bool {
        let locked = self.screen_lock.is_locked();
        self.screen_edge.observe(locked)
    }

    /// Between requests: drop the key once the vault has been idle for the
    /// auto-lock delay, or when the screen locks (if that option is on), so
    /// it does not stay in memory while the browser keeps the port open.
    fn lock_if_idle(&mut self) {
        if !self.vault.is_unlocked() {
            return;
        }
        let settings = (self.load_settings)();
        let idle = self
            .last_used
            .is_none_or(|last| last.elapsed() >= Self::idle_timeout(&settings));
        if !settings.browser_extension
            || idle
            || (settings.lock_on_screen_lock && self.screen_locked())
        {
            self.relock();
        }
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
                    "pin_available": settings.browser_extension
                        && (self.stored_pin)(&settings).is_some(),
                });
            }
            Request::Generate(options) => {
                return match handle_generate(&options) {
                    Ok(pw) => json!({"ok": true, "password": pw}),
                    Err(e) => error_response(ErrorCode::Invalid, &e.to_string()),
                }
            }
            Request::OpenApp => return handle_open_app(),
            Request::UnlockPin { pin } => {
                return match self.unlock_with_pin(&pin.0) {
                    Ok(()) => json!({"ok": true}),
                    Err((code, remaining)) => {
                        let mut reply = error_for(code);
                        if let Some(remaining) = remaining {
                            reply["attempts_left"] = json!(remaining);
                        }
                        reply
                    }
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
            Request::Get { id, notes } => handle_get(&self.vault, id, notes),
            Request::Totp { id } => handle_totp(&self.vault, id),
            Request::Folders => match self.vault.categories() {
                Ok(folders) => json!({"ok": true, "folders": folders}),
                Err(e) => error_response(ErrorCode::Internal, &e.to_string()),
            },
            Request::Favicons { hosts } => handle_favicons(&hosts),
            Request::Add(login) => handle_add(&self.vault, login),
            Request::Update(login) => handle_update(&self.vault, login),
            Request::Delete { id } => handle_delete(&self.vault, id),
            Request::ToggleFavorite { id } => match self.vault.toggle_favorite(id) {
                Ok(Some(favorite)) => json!({"ok": true, "favorite": favorite}),
                Ok(None) => error_for(ErrorCode::NotFound),
                Err(e) => error_response(ErrorCode::Internal, &e.to_string()),
            },
            Request::Ping
            | Request::Status
            | Request::Generate(_)
            | Request::OpenApp
            | Request::Lock
            | Request::Unlock { .. }
            | Request::UnlockPin { .. } => unreachable!("answered above"),
        }
    }
}

/// Turns logind's `LockedHint` into "the screen locked": true only once the
/// hint has been seen false and then reads true. Some compositors leave the
/// hint set while the session is in use (it read true on a desktop someone
/// was typing on), and reacting to the state then dropped the key right
/// after every unlock. Someone who just typed the master password in the
/// extension is looking at an unlocked screen; the desktop app, too,
/// reacts to the screensaver's change, not to a state.
#[derive(Debug, Default, Clone, Copy)]
struct ScreenLockEdge {
    seen_unlocked: bool,
}

impl ScreenLockEdge {
    fn observe(&mut self, locked: bool) -> bool {
        if !locked {
            self.seen_unlocked = true;
        }
        locked && self.seen_unlocked
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

/// How often the idle and screen-lock policy is checked between requests.
const IDLE_CHECK: Duration = Duration::from_secs(15);

fn serve() -> Result<()> {
    let mut session = HostSession::open()?;
    // Requests arrive on a thread of their own, so the auto-lock also runs
    // while the browser sends nothing.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut input = stdin.lock();
        loop {
            let message = read_message::<serde_json::Value>(&mut input);
            let last = !matches!(message, Ok(Incoming::Message(_) | Incoming::Malformed(_)));
            if tx.send(message).is_err() || last {
                return;
            }
        }
    });

    loop {
        let message = match rx.recv_timeout(IDLE_CHECK) {
            Ok(message) => message?,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                session.lock_if_idle();
                continue;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        };
        let raw = match message {
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
        if let Err(e) = write_message(&response) {
            // Too big for the browser: say so instead of ending the session.
            let mut error = error_response(ErrorCode::Internal, &e.to_string());
            if let (Some(rid), Some(object)) = (response.get("rid"), error.as_object_mut()) {
                object.insert("rid".into(), rid.clone());
            }
            write_message(&error)?;
        }
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

/// Room for the entries of one reply: browsers take at most 1 MiB from the
/// host, and the reply carries a little more than the entries.
const ENTRIES_BUDGET_BYTES: usize = 900 * 1024;

/// `{ok, entries}` with as many entries as fit in a message; `truncated`
/// tells the rest were left out (a vault of several thousand logins).
fn entries_reply(summaries: Vec<EntrySummary>) -> serde_json::Value {
    let mut used = 0;
    let mut kept = Vec::with_capacity(summaries.len());
    let total = summaries.len();
    for summary in summaries {
        let size = serde_json::to_vec(&summary)
            .map(|b| b.len() + 1)
            .unwrap_or(usize::MAX);
        if used + size > ENTRIES_BUDGET_BYTES {
            break;
        }
        used += size;
        kept.push(summary);
    }
    let truncated = kept.len() < total;
    serde_json::json!({"ok": true, "entries": kept, "truncated": truncated})
}

fn handle_list(vault: &Vault, query: Option<&str>) -> serde_json::Value {
    match vault.list(query) {
        Ok(entries) => entries_reply(entries.iter().map(EntrySummary::from).collect()),
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
            entries_reply(matches)
        }
        Err(e) => error_response(ErrorCode::Internal, &e.to_string()),
    }
}

fn handle_get(vault: &Vault, id: i64, with_notes: bool) -> serde_json::Value {
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
                favorite: e.favorite,
                updated_at: e.updated_at,
                notes: if with_notes {
                    Some(e.notes.unwrap_or_default())
                } else {
                    None
                },
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

/// Bounds that keep a request from asking for absurd values.
const PASSWORD_MAX_LENGTH: usize = 128;
const WORDS_MIN: usize = 3;
const WORDS_MAX: usize = 12;

fn handle_generate(options: &GenerateOptions) -> Result<String> {
    match options.kind.as_deref() {
        Some("passphrase") => {
            let separator: String = options
                .separator
                .as_deref()
                .unwrap_or("-")
                .chars()
                .take(3)
                .collect();
            Ok(generate_passphrase(
                options.words.unwrap_or(6).clamp(WORDS_MIN, WORDS_MAX),
                &separator,
                options.capitalize.unwrap_or(true),
                options.number.unwrap_or(true),
            ))
        }
        Some("pin") => Ok(generate_pin(
            options
                .length
                .unwrap_or(6)
                .clamp(PIN_MIN_LENGTH, PIN_MAX_LENGTH),
        )),
        Some("password") | None => {
            let defaults = PasswordConfig::default();
            let cfg = PasswordConfig {
                length: options
                    .length
                    .unwrap_or(defaults.length)
                    .min(PASSWORD_MAX_LENGTH),
                use_uppercase: options.uppercase.unwrap_or(defaults.use_uppercase),
                use_lowercase: options.lowercase.unwrap_or(defaults.use_lowercase),
                use_digits: options.digits.unwrap_or(defaults.use_digits),
                use_symbols: options.symbols.unwrap_or(defaults.use_symbols),
                exclude_ambiguous: options
                    .avoid_ambiguous
                    .unwrap_or(defaults.exclude_ambiguous),
                ..defaults
            };
            generate_password(&cfg).map_err(|e| anyhow!("{e}"))
        }
        Some(other) => bail!("unknown generate kind: {other}"),
    }
}

/// Most icons answered by one `favicons` request.
const FAVICONS_PER_REQUEST: usize = 40;
/// Larger cached files are skipped (keeps replies far below the 1 MiB limit).
const FAVICON_MAX_BYTES: u64 = 24 * 1024;

/// Whether `host` is a plain host name, so it cannot reach outside the icon
/// cache when turned into a file name.
fn is_plain_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('.')
        && !host.contains("..")
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Site icons from the desktop app's cache, as data URLs. Never fetches
/// anything: sites the app has not shown yet simply have no icon.
fn handle_favicons(hosts: &[String]) -> serde_json::Value {
    use base64::Engine as _;
    let mut icons = serde_json::Map::new();
    for host in hosts.iter().take(FAVICONS_PER_REQUEST) {
        if !is_plain_host(host) {
            continue;
        }
        let Some(path) = ashypass_core::favicons::lookup(host) else {
            continue;
        };
        if !std::fs::metadata(&path).is_ok_and(|m| m.len() <= FAVICON_MAX_BYTES) {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let mime = if bytes.starts_with(&[0, 0, 1, 0]) {
            "image/x-icon"
        } else {
            "image/png"
        };
        icons.insert(
            host.clone(),
            serde_json::Value::String(format!(
                "data:{mime};base64,{}",
                base64::engine::general_purpose::STANDARD.encode(&bytes)
            )),
        );
    }
    serde_json::json!({"ok": true, "icons": icons})
}

/// Save a login created in the browser.
fn handle_add(vault: &Vault, login: NewLogin) -> serde_json::Value {
    let title = login.title.trim().to_string();
    if title.is_empty() || login.password.0.is_empty() {
        return error_response(ErrorCode::Invalid, "a name and a password are required");
    }
    let clean = |value: Option<String>| {
        value
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let entry = ashypass_core::db::vault::NewEntry {
        title,
        username: clean(login.username),
        password: login.password.0.clone(),
        url: clean(login.url),
        category: clean(login.category),
        notes: login.notes.filter(|n| !n.trim().is_empty()),
        ..Default::default()
    };
    match vault.add(entry) {
        Ok(id) => serde_json::json!({"ok": true, "id": id}),
        Err(e) => error_response(ErrorCode::Internal, &e.to_string()),
    }
}

/// A trimmed optional field: blank means none.
fn clean_field(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Save a login edited in the browser. Only the fields that differ are
/// written, so an unchanged password adds no history entry.
fn handle_update(vault: &Vault, login: EditedLogin) -> serde_json::Value {
    let title = login.title.trim().to_string();
    if title.is_empty() || login.password.0.is_empty() {
        return error_response(ErrorCode::Invalid, "a name and a password are required");
    }
    let current = match vault.get_without_touch(login.id) {
        Ok(Some(e)) => e,
        Ok(None) => return error_for(ErrorCode::NotFound),
        Err(e) => return error_response(ErrorCode::Internal, &e.to_string()),
    };
    if current.updated_at != login.updated_at {
        return error_for(ErrorCode::Changed);
    }
    let username = clean_field(login.username);
    let url = clean_field(login.url);
    let category = clean_field(login.category);
    let mut change = ashypass_core::db::vault::UpdateEntry::default();
    if title != current.title {
        change.title = Some(title);
    }
    if username != clean_field(current.username.clone()) {
        change.username = Some(username.unwrap_or_default());
    }
    if current.password.as_deref() != Some(login.password.0.as_str()) {
        change.password = Some(login.password.0.clone());
    }
    if url != clean_field(current.url.clone()) {
        change.url = Some(url);
    }
    if category != clean_field(current.category.clone()) {
        change.category = Some(category);
    }
    // Notes keep their own spacing; only an all-blank text means none.
    if let Some(notes) = login.notes {
        let notes = Some(notes).filter(|n| !n.trim().is_empty());
        if notes != current.notes.clone().filter(|n| !n.is_empty()) {
            change.notes = Some(notes);
        }
    }
    let unchanged = change.title.is_none()
        && change.username.is_none()
        && change.password.is_none()
        && change.url.is_none()
        && change.category.is_none()
        && change.notes.is_none();
    if unchanged {
        return serde_json::json!({"ok": true, "id": login.id});
    }
    match vault.update_if_unchanged(login.id, login.updated_at, change) {
        Ok(Some(_)) => serde_json::json!({"ok": true, "id": login.id}),
        // Changed or deleted between the read above and the write.
        Ok(None) => match vault.get_without_touch(login.id) {
            Ok(Some(_)) => error_for(ErrorCode::Changed),
            Ok(None) => error_for(ErrorCode::NotFound),
            Err(e) => error_response(ErrorCode::Internal, &e.to_string()),
        },
        Err(e) => error_response(ErrorCode::Internal, &e.to_string()),
    }
}

/// Delete a login the way the desktop app does: to the trash when it is on
/// (Settings → Protection), for good otherwise. A synced login is also
/// deleted from Nextcloud on the next sync.
fn handle_delete(vault: &Vault, id: i64) -> serde_json::Value {
    let trashed = ashypass_core::settings::Settings::load().trash_retention_days > 0;
    match vault.delete(id) {
        Ok(true) => serde_json::json!({"ok": true, "trashed": trashed}),
        Ok(false) => error_for(ErrorCode::NotFound),
        Err(e) => error_response(ErrorCode::Internal, &e.to_string()),
    }
}

/// Bring up the desktop app (a second launch just presents the open window).
fn handle_open_app() -> serde_json::Value {
    let candidates = [
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join("ashypass"))),
        Some(std::path::PathBuf::from("/usr/bin/ashypass")),
    ];
    let Some(app) = candidates.into_iter().flatten().find(|p| p.is_file()) else {
        return error_response(ErrorCode::Internal, "the Ashy Pass app was not found");
    };
    match std::process::Command::new(app)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(_) => serde_json::json!({"ok": true}),
        Err(e) => error_response(ErrorCode::Internal, &e.to_string()),
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
        ErrorCode::BadPin => "wrong PIN",
        ErrorCode::PinDisabled => "the PIN was turned off — use the master password",
        ErrorCode::PinUnavailable => "no PIN is set up on this computer",
        ErrorCode::RateLimited => "too many wrong passwords — wait 30 seconds and try again",
        ErrorCode::NotFound => "entry not found",
        ErrorCode::NoMatch => "this entry does not belong to the page",
        ErrorCode::NoTotp => "this entry has no verification code",
        ErrorCode::Changed => "the entry was changed meanwhile — open it again",
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

/// The Chromium extension ids an existing manifest allows: well-formed ids
/// only (32 letters a–p), so a damaged file cannot carry junk forward.
fn kept_chrome_ids(manifest: &str) -> Vec<String> {
    allowed_list(manifest, "allowed_origins")
        .filter_map(|origin| {
            origin
                .strip_prefix("chrome-extension://")
                .map(|id| id.trim_end_matches('/').to_string())
        })
        .filter(|id| id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b)))
        .collect()
}

/// The Firefox extension ids an existing manifest allows (no spaces or
/// control characters, of a sane length).
fn kept_firefox_ids(manifest: &str) -> Vec<String> {
    allowed_list(manifest, "allowed_extensions")
        .filter(|id| {
            !id.is_empty()
                && id.len() <= 255
                && !id.chars().any(|c| c.is_whitespace() || c.is_control())
        })
        .collect()
}

fn allowed_list(manifest: &str, key: &str) -> impl Iterator<Item = String> {
    serde_json::from_str::<serde_json::Value>(manifest)
        .ok()
        .and_then(|value| value.get(key).and_then(|list| list.as_array().cloned()))
        .unwrap_or_default()
        .into_iter()
        .filter_map(|item| item.as_str().map(str::to_string))
}

fn merged_ids(ours: &[String], kept: Vec<String>) -> Vec<String> {
    let mut ids: Vec<String> = ours.iter().cloned().chain(kept).collect();
    ids.sort();
    ids.dedup();
    ids
}

fn install_manifests(args: &[String]) -> Result<()> {
    let (chrome_ids, firefox_ids) = parse_install_args(args)?;
    let exe = current_exe_path_str();

    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| anyhow!("HOME not set"))?;

    // Per-user host manifest directories. Each browser looks in its own;
    // install into every one whose browser is set up for this user, so the
    // user does not have to know which fork they run.
    // Each channel and edition keeps its own profile folder (Brave Origin,
    // Beta and Nightly; Chrome Beta and Dev): a manifest in Brave-Browser is
    // never read by Brave Origin.
    let chrome_targets = CHROME_PROFILE_DIRS
        .iter()
        .map(|dir| home.join(".config").join(dir).join("NativeMessagingHosts"))
        .collect::<Vec<_>>();
    // Firefox-family browsers read user manifests from ~/.<name>/ even when
    // they keep the profile in the XDG folder (~/.config/<name>), as recent
    // Firefox does; ~/.mozilla may then not exist yet. Checked with Firefox
    // 157: ~/.config/mozilla/native-messaging-hosts is not read.
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(".config"));
    let firefox_family: Vec<(std::path::PathBuf, bool)> = [
        (".mozilla", "mozilla"),
        (".librewolf", "librewolf"),
        (".waterfox", "waterfox"),
    ]
    .iter()
    .map(|(legacy, xdg)| {
        let installed = home.join(legacy).exists() || config.join(xdg).exists();
        (home.join(legacy).join("native-messaging-hosts"), installed)
    })
    .collect();

    let mut written = 0;
    let targets = chrome_targets
        .iter()
        .map(|dir| (dir, true, dir.parent().is_some_and(|p| p.exists())))
        .chain(
            firefox_family
                .iter()
                .map(|(dir, installed)| (dir, false, *installed)),
        );
    for (dir, is_chrome, installed) in targets {
        if !installed {
            continue; // Browser not set up for this user — skip.
        }
        std::fs::create_dir_all(dir)?;
        let path = dir.join(format!("{EXTENSION_NAME}.json"));
        // Connecting again (the app's Connect button) must not drop an id
        // added before, such as an unpacked test build's.
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        let manifest = if is_chrome {
            manifest_chrome(&exe, &merged_ids(&chrome_ids, kept_chrome_ids(&existing)))
        } else {
            manifest_firefox(&exe, &merged_ids(&firefox_ids, kept_firefox_ids(&existing)))
        };
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
    fn screen_lock_counts_the_change_not_a_stuck_hint() {
        // A hint stuck on "locked" while the session is in use never locks.
        let mut stuck = ScreenLockEdge::default();
        assert!(!stuck.observe(true));
        assert!(!stuck.observe(true));
        // A working hint: unlocked, then locked — that is a screen lock.
        let mut working = ScreenLockEdge::default();
        assert!(!working.observe(false));
        assert!(working.observe(true));
        // After the vault relocks, the next change has to be seen again.
        let mut after_relock = ScreenLockEdge::default();
        assert!(!after_relock.observe(true));
        assert!(!after_relock.observe(false));
        assert!(after_relock.observe(true));
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
        let pin = handle_generate(&GenerateOptions {
            kind: Some("pin".into()),
            length: Some(10_000_000),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(pin.len(), PIN_MAX_LENGTH);
        let pin = handle_generate(&GenerateOptions {
            kind: Some("pin".into()),
            length: Some(0),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(pin.len(), PIN_MIN_LENGTH);
        let pin = handle_generate(&GenerateOptions {
            kind: Some("pin".into()),
            length: None,
            ..Default::default()
        })
        .unwrap();
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
            Incoming::Message(Request::Get {
                id: 7,
                notes: false
            })
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
            PROTOCOL_VERSION
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
    fn an_idle_vault_locks_between_requests() {
        let (_dir, mut s, _, _) = session_with(enabled);
        let reply = call(
            &mut s,
            serde_json::json!({"cmd": "unlock", "password": MASTER}),
        );
        assert_eq!(reply["ok"], true);
        s.lock_if_idle();
        assert!(s.vault.is_unlocked(), "just used");
        s.last_used = Instant::now().checked_sub(Duration::from_secs(3600));
        s.lock_if_idle();
        assert!(!s.vault.is_unlocked(), "idle past the auto-lock delay");
    }

    #[test]
    fn long_lists_are_cut_to_fit_a_message() {
        let summary = |i: i64| EntrySummary {
            id: i,
            title: format!("Login {i} {}", "x".repeat(200)),
            username: Some("user@example.com".into()),
            url: Some("https://example.com/login".into()),
            category: None,
            has_totp: false,
            favorite: false,
        };
        let small = entries_reply((0..10).map(summary).collect());
        assert_eq!(small["entries"].as_array().unwrap().len(), 10);
        assert_eq!(small["truncated"], false);
        let big = entries_reply((0..20_000).map(summary).collect());
        let kept = big["entries"].as_array().unwrap().len();
        assert!(kept > 1000 && kept < 20_000, "{kept}");
        assert_eq!(big["truncated"], true);
        assert!(serde_json::to_vec(&big).unwrap().len() < MAX_MESSAGE_BYTES as usize);
    }

    #[test]
    fn connecting_again_keeps_ids_added_before() {
        let dev = "opelfkfheadglgamfephkfejfpcnlbck";
        let before = manifest_chrome(
            "/usr/lib/ashypass/ashypass-native-host",
            &[
                "aaffaajejkomddnihpblnkolkhcgaoom".to_string(),
                dev.to_string(),
            ],
        );
        let kept = kept_chrome_ids(&before);
        assert!(kept.contains(&dev.to_string()));
        let ids = merged_ids(&default_chrome_ids(), kept);
        assert_eq!(ids.iter().filter(|id| id.as_str() == dev).count(), 1);
        assert!(ids.contains(&"aaffaajejkomddnihpblnkolkhcgaoom".to_string()));
        // Junk in a damaged or edited file is not carried forward.
        let junk = r#"{"allowed_origins": ["chrome-extension://NOT-AN-ID/", "https://evil/", 3]}"#;
        assert!(kept_chrome_ids(junk).is_empty());
        assert!(kept_chrome_ids("not json").is_empty());
        let firefox = manifest_firefox("/x", &["ashypass@big-comm.github.io".to_string()]);
        assert_eq!(kept_firefox_ids(&firefox), ["ashypass@big-comm.github.io"]);
        assert!(kept_firefox_ids(r#"{"allowed_extensions": ["a b", ""]}"#).is_empty());
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
        assert!(CHROME_EXTENSION_IDS
            .iter()
            .all(|id| chrome.contains(&id.to_string())));
        // Only debug builds allow the development extension; release builds
        // (the package runs its tests with --release) never do.
        assert_eq!(
            chrome.contains(&CHROME_DEV_EXTENSION_ID.to_string()),
            cfg!(debug_assertions)
        );
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

    #[test]
    fn protocol_3_commands() {
        let (_dir, mut s, mail, _) = session_with(enabled);
        let status = call(&mut s, serde_json::json!({"cmd": "status"}));
        assert_eq!(status["pin_available"], false);
        let pin = call(
            &mut s,
            serde_json::json!({"cmd": "unlock_pin", "pin": "1234"}),
        );
        assert_eq!(pin["code"], "pin_unavailable");
        call(
            &mut s,
            serde_json::json!({"cmd": "unlock", "password": MASTER}),
        );

        let added = call(
            &mut s,
            serde_json::json!({"cmd": "add", "title": "Shop", "username": "ana",
                "password": "s3cret!", "url": "https://shop.example.net", "category": "Personal"}),
        );
        let id = added["id"].as_i64().unwrap();
        let fill = call(
            &mut s,
            serde_json::json!({"cmd": "fill", "id": id, "url": "https://shop.example.net/login"}),
        );
        assert_eq!(fill["password"], "s3cret!");
        let empty = call(
            &mut s,
            serde_json::json!({"cmd": "add", "title": " ", "password": "x"}),
        );
        assert_eq!(empty["code"], "invalid");

        let folders = call(&mut s, serde_json::json!({"cmd": "folders"}));
        assert!(folders["folders"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "Personal"));

        let fav = call(
            &mut s,
            serde_json::json!({"cmd": "toggle_favorite", "id": mail}),
        );
        assert_eq!(fav["favorite"], true);
        let listed = call(&mut s, serde_json::json!({"cmd": "list"}));
        let mail_row = listed["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["id"] == mail)
            .unwrap()
            .clone();
        assert_eq!(mail_row["favorite"], true);

        let words = call(
            &mut s,
            serde_json::json!({"cmd": "generate", "kind": "passphrase", "words": 4, "separator": ".", "number": false}),
        );
        assert_eq!(words["password"].as_str().unwrap().split('.').count(), 4);
        let digits_only = call(
            &mut s,
            serde_json::json!({"cmd": "generate", "length": 30, "uppercase": false,
                "lowercase": false, "symbols": false, "digits": true}),
        );
        let value = digits_only["password"].as_str().unwrap();
        assert_eq!(value.len(), 30);
        assert!(value.chars().all(|c| c.is_ascii_digit()));
        let huge = call(
            &mut s,
            serde_json::json!({"cmd": "generate", "length": 100000}),
        );
        assert_eq!(
            huge["password"].as_str().unwrap().len(),
            PASSWORD_MAX_LENGTH
        );
    }

    #[test]
    fn protocol_4_update_and_delete() {
        let (_dir, mut s, mail, bank) = session_with(enabled);
        call(
            &mut s,
            serde_json::json!({"cmd": "unlock", "password": MASTER}),
        );
        let get = |s: &mut HostSession, id: i64| {
            call(s, serde_json::json!({"cmd": "get", "id": id}))["entry"].clone()
        };
        let before = get(&mut s, mail);
        let stamp = before["updated_at"].as_i64().unwrap();
        let old_password = before["password"].as_str().unwrap().to_string();

        // Changing only the folder keeps the password out of the history.
        let moved = call(
            &mut s,
            serde_json::json!({"cmd": "update", "id": mail, "updated_at": stamp,
                "title": before["title"], "username": before["username"],
                "password": old_password, "url": before["url"], "category": "Work"}),
        );
        assert_eq!(moved["ok"], true, "{moved}");
        assert!(s.vault.password_history(mail).unwrap().is_empty());

        // A stale `updated_at` (an edit made meanwhile) is refused.
        let after_move = get(&mut s, mail);
        assert_eq!(after_move["category"], "Work");
        let stale = call(
            &mut s,
            serde_json::json!({"cmd": "update", "id": mail, "updated_at": stamp - 10,
                "title": "Other", "password": "x"}),
        );
        assert_eq!(stale["code"], "changed");
        assert_eq!(get(&mut s, mail)["title"], after_move["title"]);

        // A full edit: a new password goes to the history, absent fields clear.
        let stamp = after_move["updated_at"].as_i64().unwrap();
        let edited = call(
            &mut s,
            serde_json::json!({"cmd": "update", "id": mail, "updated_at": stamp,
                "title": "  Mail (work) ", "password": "n3w-pass"}),
        );
        assert_eq!(edited["ok"], true, "{edited}");
        let now = get(&mut s, mail);
        assert_eq!(now["title"], "Mail (work)");
        assert_eq!(now["password"], "n3w-pass");
        assert!(now["username"].is_null() || now["username"] == "");
        assert!(now["url"].is_null());
        assert!(now["category"].is_null());
        assert_eq!(s.vault.password_history(mail).unwrap().len(), 1);

        let blank = call(
            &mut s,
            serde_json::json!({"cmd": "update", "id": mail,
                "updated_at": now["updated_at"], "title": " ", "password": "x"}),
        );
        assert_eq!(blank["code"], "invalid");
        let gone = call(
            &mut s,
            serde_json::json!({"cmd": "update", "id": 9999, "updated_at": 0,
                "title": "x", "password": "x"}),
        );
        assert_eq!(gone["code"], "not_found");

        // Notes: only sent when asked for; absent keeps them, blank clears.
        assert!(now.get("notes").is_none());
        let with_notes = |s: &mut HostSession| {
            call(
                s,
                serde_json::json!({"cmd": "get", "id": mail, "notes": true}),
            )["entry"]
                .clone()
        };
        let noted = call(
            &mut s,
            serde_json::json!({"cmd": "update", "id": mail, "updated_at": now["updated_at"],
                "title": "Mail (work)", "password": "n3w-pass", "notes": "Recovery:\n  1234-5678"}),
        );
        assert_eq!(noted["ok"], true, "{noted}");
        let read = with_notes(&mut s);
        assert_eq!(read["notes"], "Recovery:\n  1234-5678");
        let kept = call(
            &mut s,
            serde_json::json!({"cmd": "update", "id": mail, "updated_at": read["updated_at"],
                "title": "Mail", "password": "n3w-pass"}),
        );
        assert_eq!(kept["ok"], true, "{kept}");
        let read = with_notes(&mut s);
        assert_eq!(read["notes"], "Recovery:\n  1234-5678");
        call(
            &mut s,
            serde_json::json!({"cmd": "update", "id": mail, "updated_at": read["updated_at"],
                "title": "Mail", "password": "n3w-pass", "notes": "  "}),
        );
        assert_eq!(with_notes(&mut s)["notes"], "");
        let added = call(
            &mut s,
            serde_json::json!({"cmd": "add", "title": "Noted", "password": "x", "notes": "hello"}),
        );
        let added_notes = call(
            &mut s,
            serde_json::json!({"cmd": "get", "id": added["id"], "notes": true}),
        );
        assert_eq!(added_notes["entry"]["notes"], "hello");

        let deleted = call(&mut s, serde_json::json!({"cmd": "delete", "id": bank}));
        assert_eq!(deleted["ok"], true, "{deleted}");
        assert!(deleted["trashed"].is_boolean());
        assert_eq!(get_code(&mut s, bank), "not_found");
        let again = call(&mut s, serde_json::json!({"cmd": "delete", "id": bank}));
        assert_eq!(again["code"], "not_found");

        // Both need an unlocked vault.
        call(&mut s, serde_json::json!({"cmd": "lock"}));
        let locked = call(&mut s, serde_json::json!({"cmd": "delete", "id": mail}));
        assert_eq!(locked["code"], "locked");
    }

    fn get_code(s: &mut HostSession, id: i64) -> serde_json::Value {
        call(s, serde_json::json!({"cmd": "get", "id": id}))["code"].clone()
    }

    #[test]
    fn favicon_hosts_cannot_leave_the_cache() {
        assert!(is_plain_host("github.com"));
        assert!(is_plain_host("mail.example-site.org"));
        for bad in [
            "",
            "../etc/passwd",
            "a/b",
            ".hidden",
            "a..b",
            "x y",
            "host\\x",
        ] {
            assert!(!is_plain_host(bad), "{bad}");
        }
    }
}
