//! OAuth 2.0 PKCE (S256) loopback flow for Google APIs.
//!
//! The flow is blocking and synchronous on a worker thread:
//!  1. Generate a random `code_verifier` and its S256 `code_challenge`.
//!  2. Bind a loopback TCP listener on a free port.
//!  3. Open the auth URL in the default browser.
//!  4. Block on the listener until Google redirects back with `?code=...`.
//!  5. Exchange the code for an access + refresh token at the token endpoint.
//!
//! The refresh token and the OAuth client secret are kept in the system
//! keyring (Secret Service) when one is available; the JSON files then only
//! hold non-secret metadata. Without a keyring the 0600 JSON files keep the
//! secrets as before, so a sign-in is never lost. Files written by older
//! versions are migrated on load: the secrets are copied to the keyring,
//! read back, and only then removed from the JSON.

use crate::config::{atomic_write_private, config_dir, ensure_private_file, token_file};
use crate::{Error, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

pub const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub const DRIVE_SCOPE: &str = "https://www.googleapis.com/auth/drive.file";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_uri: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub expires_at: i64,
}

impl Token {
    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at <= now + 60
    }

    pub fn load() -> Option<Self> {
        load_token(&token_file(), &SystemKeyring)
    }

    pub fn save(&self) -> Result<()> {
        save_token(&token_file(), self, &SystemKeyring)
    }

    pub fn delete() -> Result<()> {
        delete_token(&token_file(), &SystemKeyring)
    }
}

const TOKEN_SECRET_KIND: &str = "google-oauth-token";
const TOKEN_SECRET_LABEL: &str = "Ashy Pass — Google Drive sign-in";
const CLIENT_SECRET_KIND: &str = "google-oauth-client-secret";
const CLIENT_SECRET_LABEL: &str = "Ashy Pass — Google OAuth client secret";

/// Minimal secret storage interface so the migration logic can be tested
/// without touching the user's real keyring.
pub(crate) trait SecretStore {
    fn load(&self, kind: &'static str) -> Result<Option<String>>;
    fn store(&self, kind: &'static str, label: &str, secret: &str) -> Result<()>;
    fn delete(&self, kind: &'static str) -> Result<()>;
}

struct SystemKeyring;

impl SecretStore for SystemKeyring {
    fn load(&self, kind: &'static str) -> Result<Option<String>> {
        crate::keyring::load_named_secret(kind)
    }
    fn store(&self, kind: &'static str, label: &str, secret: &str) -> Result<()> {
        crate::keyring::store_named_secret(kind, label, secret)
    }
    fn delete(&self, kind: &'static str) -> Result<()> {
        crate::keyring::delete_named_secret(kind)
    }
}

/// Write `secret` to the store unless it is already there, then read it back:
/// callers only drop the plaintext copy after this succeeds.
fn persist_secret(
    store: &dyn SecretStore,
    kind: &'static str,
    label: &str,
    secret: &str,
) -> Result<()> {
    if store.load(kind).ok().flatten().as_deref() == Some(secret) {
        return Ok(());
    }
    store.store(kind, label, secret)?;
    match store.load(kind)? {
        Some(stored) if stored == secret => Ok(()),
        _ => Err(Error::Other("keyring did not keep the secret".into())),
    }
}

/// On-disk token layout. Secrets are `None` when `secrets_in_keyring`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredToken {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    token_uri: String,
    client_id: String,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
    expires_at: i64,
    #[serde(default)]
    secrets_in_keyring: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct TokenSecrets {
    refresh_token: Option<String>,
    client_secret: Option<String>,
}

impl TokenSecrets {
    fn is_empty(&self) -> bool {
        self.refresh_token.is_none() && self.client_secret.is_none()
    }
}

fn write_stored_token(path: &Path, stored: &StoredToken) -> Result<()> {
    let json = serde_json::to_string_pretty(stored)?;
    atomic_write_private(path, json.as_bytes())?;
    Ok(())
}

pub(crate) fn load_token(path: &Path, store: &dyn SecretStore) -> Option<Token> {
    let _ = ensure_private_file(path);
    let text = fs::read_to_string(path).ok()?;
    let stored: StoredToken = serde_json::from_str(&text).ok()?;
    let mut token = Token {
        access_token: stored.access_token.clone(),
        refresh_token: stored.refresh_token.clone(),
        token_uri: GOOGLE_TOKEN_URL.to_string(),
        client_id: stored.client_id.clone(),
        client_secret: stored.client_secret.clone(),
        scopes: stored.scopes.clone(),
        expires_at: stored.expires_at,
    };
    if stored.secrets_in_keyring {
        match store.load(TOKEN_SECRET_KIND) {
            Ok(Some(json)) => match serde_json::from_str::<TokenSecrets>(&json) {
                Ok(secrets) => {
                    token.refresh_token = token.refresh_token.or(secrets.refresh_token);
                    token.client_secret = token.client_secret.or(secrets.client_secret);
                }
                Err(error) => log::warn!("google sign-in secrets in keyring are invalid: {error}"),
            },
            Ok(None) => log::warn!("google sign-in secrets are missing from the keyring"),
            Err(error) => log::warn!("google sign-in secrets unavailable from keyring: {error}"),
        }
        return Some(token);
    }

    // Legacy plaintext file: move the secrets to the keyring, verify, and
    // only then rewrite the file without them. Any failure keeps the file
    // untouched so the sign-in keeps working.
    let secrets = TokenSecrets {
        refresh_token: stored.refresh_token.clone(),
        client_secret: stored.client_secret.clone(),
    };
    if !secrets.is_empty() {
        let migrated = serde_json::to_string(&secrets)
            .map_err(Error::from)
            .and_then(|json| persist_secret(store, TOKEN_SECRET_KIND, TOKEN_SECRET_LABEL, &json));
        match migrated {
            Ok(()) => {
                let stripped = StoredToken {
                    refresh_token: None,
                    client_secret: None,
                    secrets_in_keyring: true,
                    ..stored
                };
                if let Err(error) = write_stored_token(path, &stripped) {
                    log::warn!("could not remove google secrets from {path:?}: {error}");
                }
            }
            Err(error) => log::warn!("keeping google sign-in in the 0600 file: {error}"),
        }
    }
    Some(token)
}

pub(crate) fn save_token(path: &Path, token: &Token, store: &dyn SecretStore) -> Result<()> {
    let secrets = TokenSecrets {
        refresh_token: token.refresh_token.clone(),
        client_secret: token.client_secret.clone(),
    };
    let in_keyring = !secrets.is_empty()
        && serde_json::to_string(&secrets)
            .map_err(Error::from)
            .and_then(|json| persist_secret(store, TOKEN_SECRET_KIND, TOKEN_SECRET_LABEL, &json))
            .map_err(|error| {
                log::warn!("google keyring save failed; keeping chmod 0600 fallback: {error}")
            })
            .is_ok();
    let stored = StoredToken {
        access_token: token.access_token.clone(),
        refresh_token: if in_keyring {
            None
        } else {
            token.refresh_token.clone()
        },
        token_uri: GOOGLE_TOKEN_URL.to_string(),
        client_id: token.client_id.clone(),
        client_secret: if in_keyring {
            None
        } else {
            token.client_secret.clone()
        },
        scopes: token.scopes.clone(),
        expires_at: token.expires_at,
        secrets_in_keyring: in_keyring,
    };
    write_stored_token(path, &stored)
}

pub(crate) fn delete_token(path: &Path, store: &dyn SecretStore) -> Result<()> {
    if path.exists() {
        fs::remove_file(path)?;
    }
    let _ = store.delete(TOKEN_SECRET_KIND);
    Ok(())
}

/// Per-installation OAuth client identity. For a desktop loopback client,
/// only `client_id` is mandatory; `client_secret` is included if present.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCredentials {
    pub client_id: String,
    pub client_secret: Option<String>,
}

impl ClientCredentials {
    /// Load runtime credentials saved through the UI, falling back to
    /// compile-time environment values for distro builds.
    pub fn load() -> Option<Self> {
        Self::from_file().or_else(Self::from_env)
    }

    /// Pulls the client id/secret from compile-time env vars so the binary can
    /// be shipped without secrets in source. Returns `None` if unset.
    pub fn from_env() -> Option<Self> {
        let id = option_env!("ASHYPASS_GOOGLE_CLIENT_ID")?;
        if id.is_empty() {
            return None;
        }
        let secret = option_env!("ASHYPASS_GOOGLE_CLIENT_SECRET")
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        Some(Self {
            client_id: id.to_string(),
            client_secret: secret,
        })
    }

    pub fn save(&self) -> Result<()> {
        save_credentials(&credentials_file(), self, &SystemKeyring)
    }

    fn from_file() -> Option<Self> {
        load_credentials(&credentials_file(), &SystemKeyring)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredCredentials {
    client_id: String,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    secret_in_keyring: bool,
}

fn write_stored_credentials(path: &Path, stored: &StoredCredentials) -> Result<()> {
    let json = serde_json::to_string_pretty(stored)?;
    atomic_write_private(path, json.as_bytes())?;
    Ok(())
}

pub(crate) fn load_credentials(path: &Path, store: &dyn SecretStore) -> Option<ClientCredentials> {
    let _ = ensure_private_file(path);
    let text = fs::read_to_string(path).ok()?;
    let stored: StoredCredentials = serde_json::from_str(&text).ok()?;
    if stored.client_id.trim().is_empty() {
        return None;
    }
    let mut creds = ClientCredentials {
        client_id: stored.client_id.clone(),
        client_secret: stored.client_secret.clone(),
    };
    if stored.secret_in_keyring {
        if creds.client_secret.is_none() {
            match store.load(CLIENT_SECRET_KIND) {
                Ok(secret) => creds.client_secret = secret,
                Err(error) => log::warn!("google client secret unavailable from keyring: {error}"),
            }
        }
    } else if let Some(secret) = stored.client_secret.as_deref() {
        match persist_secret(store, CLIENT_SECRET_KIND, CLIENT_SECRET_LABEL, secret) {
            Ok(()) => {
                let stripped = StoredCredentials {
                    client_secret: None,
                    secret_in_keyring: true,
                    ..stored
                };
                if let Err(error) = write_stored_credentials(path, &stripped) {
                    log::warn!("could not remove google client secret from {path:?}: {error}");
                }
            }
            Err(error) => log::warn!("keeping google client secret in the 0600 file: {error}"),
        }
    }
    Some(creds)
}

pub(crate) fn save_credentials(
    path: &Path,
    creds: &ClientCredentials,
    store: &dyn SecretStore,
) -> Result<()> {
    let in_keyring = match creds.client_secret.as_deref().filter(|s| !s.is_empty()) {
        Some(secret) => persist_secret(store, CLIENT_SECRET_KIND, CLIENT_SECRET_LABEL, secret)
            .map_err(|error| {
                log::warn!("google keyring save failed; keeping chmod 0600 fallback: {error}")
            })
            .is_ok(),
        None => {
            let _ = store.delete(CLIENT_SECRET_KIND);
            false
        }
    };
    let stored = StoredCredentials {
        client_id: creds.client_id.clone(),
        client_secret: if in_keyring {
            None
        } else {
            creds.client_secret.clone()
        },
        secret_in_keyring: in_keyring,
    };
    write_stored_credentials(path, &stored)
}

fn credentials_file() -> std::path::PathBuf {
    config_dir().join("google_oauth.json")
}

/// Generates `(code_verifier, code_challenge_S256)`.
pub fn pkce_pair() -> (String, String) {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    let verifier = URL_SAFE_NO_PAD.encode(buf);
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(digest);
    (verifier, challenge)
}

/// Run the loopback OAuth2 PKCE flow. Blocks until the user finishes (or
/// timeout). On success, the resulting `Token` is persisted to disk before
/// being returned.
pub fn login(creds: &ClientCredentials) -> Result<Token> {
    let (verifier, challenge) = pkce_pair();
    let mut state_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut state_bytes);
    let state = URL_SAFE_NO_PAD.encode(state_bytes);

    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|e| Error::Other(format!("oauth bind: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| Error::Other(format!("oauth addr: {e}")))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/");

    let auth_url = format!(
        "{GOOGLE_AUTH_URL}?response_type=code\
         &client_id={cid}\
         &redirect_uri={redirect}\
         &scope={scope}\
         &code_challenge={ch}\
         &code_challenge_method=S256\
         &access_type=offline\
         &prompt=consent",
        cid = url::form_urlencoded::byte_serialize(creds.client_id.as_bytes()).collect::<String>(),
        redirect =
            url::form_urlencoded::byte_serialize(redirect_uri.as_bytes()).collect::<String>(),
        scope = url::form_urlencoded::byte_serialize(DRIVE_SCOPE.as_bytes()).collect::<String>(),
        ch = challenge,
    );
    let auth_url = format!(
        "{auth_url}&state={}",
        url::form_urlencoded::byte_serialize(state.as_bytes()).collect::<String>()
    );

    open_browser(&auth_url)?;

    listener
        .set_nonblocking(true)
        .map_err(|e| Error::Other(format!("oauth nonblock: {e}")))?;

    let code = wait_for_code(&listener, &state)?;

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| Error::Other(format!("token http build: {e}")))?;

    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", creds.client_id.clone()),
        ("code_verifier", verifier),
    ];
    if let Some(secret) = &creds.client_secret {
        form.push(("client_secret", secret.clone()));
    }

    let resp = client
        .post(GOOGLE_TOKEN_URL)
        .form(&form)
        .send()
        .map_err(|e| Error::Other(format!("token exchange: {e}")))?;
    if !resp.status().is_success() {
        let body = resp.text().unwrap_or_default();
        return Err(Error::Other(format!("token exchange failed: {body}")));
    }

    #[derive(Deserialize)]
    struct TokenResp {
        access_token: String,
        refresh_token: Option<String>,
        expires_in: i64,
    }
    let parsed: TokenResp = resp
        .json()
        .map_err(|e| Error::Other(format!("token parse: {e}")))?;

    let now = chrono::Utc::now().timestamp();
    let token = Token {
        access_token: parsed.access_token,
        refresh_token: parsed.refresh_token,
        token_uri: GOOGLE_TOKEN_URL.to_string(),
        client_id: creds.client_id.clone(),
        client_secret: creds.client_secret.clone(),
        scopes: vec![DRIVE_SCOPE.to_string()],
        expires_at: now + parsed.expires_in,
    };
    token.save()?;
    Ok(token)
}

/// Renew `access_token` using the persisted refresh token, if available.
pub fn refresh(token: &mut Token) -> Result<()> {
    let refresh_token = token
        .refresh_token
        .clone()
        .ok_or_else(|| Error::Other("no refresh token available".into()))?;

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| Error::Other(format!("refresh http build: {e}")))?;

    let mut form = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token),
        ("client_id", token.client_id.clone()),
    ];
    if let Some(secret) = &token.client_secret {
        form.push(("client_secret", secret.clone()));
    }

    let resp = client
        .post(GOOGLE_TOKEN_URL)
        .form(&form)
        .send()
        .map_err(|e| Error::Other(format!("refresh: {e}")))?;
    if !resp.status().is_success() {
        let body = resp.text().unwrap_or_default();
        return Err(Error::Other(format!("refresh failed: {body}")));
    }

    #[derive(Deserialize)]
    struct RefreshResp {
        access_token: String,
        expires_in: i64,
    }
    let parsed: RefreshResp = resp
        .json()
        .map_err(|e| Error::Other(format!("refresh parse: {e}")))?;
    token.access_token = parsed.access_token;
    token.expires_at = chrono::Utc::now().timestamp() + parsed.expires_in;
    token.save()?;
    Ok(())
}

/// Wait for the browser redirect. Stray connections (favicon requests,
/// port scanners, a request with a wrong `state`) are answered and ignored;
/// only a request carrying the expected `state` ends the wait.
fn wait_for_code(listener: &TcpListener, expected_state: &str) -> Result<String> {
    wait_for_code_until(
        listener,
        expected_state,
        Instant::now() + Duration::from_secs(120),
    )
}

fn wait_for_code_until(
    listener: &TcpListener,
    expected_state: &str,
    deadline: Instant,
) -> Result<String> {
    loop {
        match listener.accept() {
            Ok((stream, _)) => match handle_callback(stream, expected_state) {
                Callback::Code(code) => return Ok(code),
                Callback::Denied(error) => {
                    return Err(Error::Other(format!("oauth callback: {error}")))
                }
                Callback::Ignored => {}
            },
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(Error::Other("oauth callback timed out".into()));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(Error::Other(format!("accept: {error}"))),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Callback {
    Code(String),
    Denied(String),
    Ignored,
}

fn handle_callback(mut stream: TcpStream, expected_state: &str) -> Callback {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let outcome = (|| {
        let mut reader = BufReader::new(stream.try_clone().ok()?);
        let first_line = read_bounded_line(&mut reader, 8_192).ok()?;
        // Drain headers
        loop {
            let line = read_bounded_line(&mut reader, 8_192).ok()?;
            if line.is_empty() || line == "\r\n" || line == "\n" {
                break;
            }
        }
        Some(parse_callback_line(&first_line, expected_state))
    })()
    .unwrap_or(Callback::Ignored);

    let response: &[u8] = match outcome {
        Callback::Code(_) => {
            b"HTTP/1.1 200 OK\r\n\
            Content-Type: text/html; charset=utf-8\r\n\
            Connection: close\r\n\r\n\
            <!doctype html><html><body style='font-family:sans-serif;text-align:center;padding:3em'>\
            <h2>Ashy Pass</h2><p>You can close this window and return to the app.</p>\
            </body></html>"
        }
        Callback::Denied(_) => {
            b"HTTP/1.1 200 OK\r\n\
            Content-Type: text/html; charset=utf-8\r\n\
            Connection: close\r\n\r\n\
            <!doctype html><html><body style='font-family:sans-serif;text-align:center;padding:3em'>\
            <h2>Ashy Pass</h2><p>Sign-in was cancelled. You can close this window.</p>\
            </body></html>"
        }
        Callback::Ignored => {
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        }
    };
    let _ = stream.write_all(response);
    let _ = stream.flush();
    outcome
}

/// Interpret `GET /?code=...&state=... HTTP/1.1`. Anything without the
/// expected state is ignored, including error responses.
fn parse_callback_line(first_line: &str, expected_state: &str) -> Callback {
    let Some(path) = first_line.split_whitespace().nth(1) else {
        return Callback::Ignored;
    };
    let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
    let mut code = None;
    let mut error = None;
    let mut state = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "code" => code = Some(value.into_owned()),
            "error" => error = Some(value.into_owned()),
            "state" => state = Some(value.into_owned()),
            _ => {}
        }
    }
    if state.as_deref() != Some(expected_state) {
        return Callback::Ignored;
    }
    if let Some(error) = error {
        return Callback::Denied(error);
    }
    match code.filter(|c| !c.is_empty()) {
        Some(code) => Callback::Code(code),
        None => Callback::Ignored,
    }
}

fn read_bounded_line(reader: &mut impl BufRead, maximum: usize) -> Result<String> {
    let mut bytes = Vec::new();
    let read = {
        let mut limited = std::io::Read::take(&mut *reader, (maximum + 1) as u64);
        limited.read_until(b'\n', &mut bytes)?
    };
    if bytes.len() > maximum {
        return Err(Error::InvalidInput(
            "oauth callback request is too large".into(),
        ));
    }
    if read == 0 {
        return Ok(String::new());
    }
    String::from_utf8(bytes)
        .map_err(|_| Error::InvalidInput("oauth callback request is not UTF-8".into()))
}

fn open_browser(url: &str) -> Result<()> {
    let opener = if cfg!(target_os = "linux") {
        "xdg-open"
    } else if cfg!(target_os = "macos") {
        "open"
    } else {
        "explorer"
    };
    std::process::Command::new(opener)
        .arg(url)
        .spawn()
        .map_err(|e| Error::Other(format!("open browser: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_values_are_random_and_url_safe() {
        let first = pkce_pair();
        let second = pkce_pair();
        assert_ne!(first, second);
        assert_eq!(first.0.len(), 43);
        assert!(first
            .0
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')));
    }

    #[derive(Default)]
    struct FakeStore {
        items: std::cell::RefCell<std::collections::HashMap<&'static str, String>>,
        unavailable: bool,
    }

    impl SecretStore for FakeStore {
        fn load(&self, kind: &'static str) -> Result<Option<String>> {
            if self.unavailable {
                return Err(Error::Other("no keyring".into()));
            }
            Ok(self.items.borrow().get(kind).cloned())
        }
        fn store(&self, kind: &'static str, _label: &str, secret: &str) -> Result<()> {
            if self.unavailable {
                return Err(Error::Other("no keyring".into()));
            }
            self.items.borrow_mut().insert(kind, secret.to_string());
            Ok(())
        }
        fn delete(&self, kind: &'static str) -> Result<()> {
            self.items.borrow_mut().remove(kind);
            Ok(())
        }
    }

    const LEGACY_TOKEN: &str = r#"{
      "access_token": "access",
      "refresh_token": "refresh-secret",
      "token_uri": "https://oauth2.googleapis.com/token",
      "client_id": "client-id",
      "client_secret": "client-secret",
      "scopes": ["https://www.googleapis.com/auth/drive.file"],
      "expires_at": 1700000000
    }"#;

    #[test]
    fn legacy_token_migrates_to_keyring() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("token.json");
        fs::write(&path, LEGACY_TOKEN).unwrap();
        let store = FakeStore::default();

        let token = load_token(&path, &store).unwrap();
        assert_eq!(token.refresh_token.as_deref(), Some("refresh-secret"));
        assert_eq!(token.client_secret.as_deref(), Some("client-secret"));
        let on_disk = fs::read_to_string(&path).unwrap();
        assert!(!on_disk.contains("refresh-secret"));
        assert!(!on_disk.contains("client-secret"));
        assert!(on_disk.contains("\"secrets_in_keyring\": true"));

        // Reloading reads the secrets back from the keyring.
        let again = load_token(&path, &store).unwrap();
        assert_eq!(again.refresh_token.as_deref(), Some("refresh-secret"));
        assert_eq!(again.client_secret.as_deref(), Some("client-secret"));
        assert_eq!(again.access_token, "access");

        delete_token(&path, &store).unwrap();
        assert!(!path.exists());
        assert!(store.items.borrow().is_empty());
    }

    #[test]
    fn legacy_token_without_keyring_keeps_working() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("token.json");
        fs::write(&path, LEGACY_TOKEN).unwrap();
        let store = FakeStore {
            unavailable: true,
            ..FakeStore::default()
        };
        let token = load_token(&path, &store).unwrap();
        assert_eq!(token.refresh_token.as_deref(), Some("refresh-secret"));
        // The file is left untouched so the sign-in survives.
        assert_eq!(fs::read_to_string(&path).unwrap(), LEGACY_TOKEN);

        // Saving without a keyring falls back to the 0600 file.
        save_token(&path, &token, &store).unwrap();
        let reloaded = load_token(&path, &store).unwrap();
        assert_eq!(reloaded.refresh_token.as_deref(), Some("refresh-secret"));
    }

    #[test]
    fn save_token_strips_secrets_when_keyring_works() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("token.json");
        let store = FakeStore::default();
        let token = Token {
            access_token: "a".into(),
            refresh_token: Some("r".into()),
            token_uri: GOOGLE_TOKEN_URL.into(),
            client_id: "id".into(),
            client_secret: None,
            scopes: vec![],
            expires_at: 1,
        };
        save_token(&path, &token, &store).unwrap();
        assert!(!fs::read_to_string(&path).unwrap().contains("\"r\""));
        assert_eq!(
            load_token(&path, &store).unwrap().refresh_token.as_deref(),
            Some("r")
        );
    }

    #[test]
    fn client_secret_migrates_and_falls_back() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("google_oauth.json");
        fs::write(&path, r#"{"client_id": "id", "client_secret": "shh"}"#).unwrap();
        let broken = FakeStore {
            unavailable: true,
            ..FakeStore::default()
        };
        let creds = load_credentials(&path, &broken).unwrap();
        assert_eq!(creds.client_secret.as_deref(), Some("shh"));
        assert!(fs::read_to_string(&path).unwrap().contains("shh"));

        let store = FakeStore::default();
        let creds = load_credentials(&path, &store).unwrap();
        assert_eq!(creds.client_secret.as_deref(), Some("shh"));
        assert!(!fs::read_to_string(&path).unwrap().contains("shh"));
        let creds = load_credentials(&path, &store).unwrap();
        assert_eq!(creds.client_secret.as_deref(), Some("shh"));

        save_credentials(&path, &creds, &broken).unwrap();
        assert!(fs::read_to_string(&path).unwrap().contains("shh"));
    }

    #[test]
    fn callback_requires_matching_state() {
        assert_eq!(
            parse_callback_line("GET /?code=abc&state=s1 HTTP/1.1\r\n", "s1"),
            Callback::Code("abc".into())
        );
        assert_eq!(
            parse_callback_line("GET /?code=abc&state=other HTTP/1.1\r\n", "s1"),
            Callback::Ignored
        );
        assert_eq!(
            parse_callback_line("GET /favicon.ico HTTP/1.1\r\n", "s1"),
            Callback::Ignored
        );
        assert_eq!(
            parse_callback_line("GET /?error=access_denied&state=s1 HTTP/1.1\r\n", "s1"),
            Callback::Denied("access_denied".into())
        );
        assert_eq!(
            parse_callback_line("GET /?error=access_denied HTTP/1.1\r\n", "s1"),
            Callback::Ignored
        );
        assert_eq!(
            parse_callback_line("GET /?code=a%2Fb&state=s%201 HTTP/1.1\r\n", "s 1"),
            Callback::Code("a/b".into())
        );
    }

    #[test]
    fn listener_survives_stray_connections() {
        use std::io::Read;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let send = |request: &str| {
                let mut stream = TcpStream::connect(address).unwrap();
                stream.write_all(request.as_bytes()).unwrap();
                let mut response = String::new();
                let _ = stream.read_to_string(&mut response);
                response
            };
            // A connection that sends nothing and closes.
            drop(TcpStream::connect(address).unwrap());
            let stray = send("GET /favicon.ico HTTP/1.1\r\nHost: x\r\n\r\n");
            let forged = send("GET /?code=evil&state=wrong HTTP/1.1\r\n\r\n");
            let real = send("GET /?code=good&state=expected HTTP/1.1\r\n\r\n");
            (stray, forged, real)
        });
        let code = wait_for_code_until(
            &listener,
            "expected",
            Instant::now() + Duration::from_secs(20),
        )
        .unwrap();
        assert_eq!(code, "good");
        let (stray, forged, real) = client.join().unwrap();
        assert!(stray.starts_with("HTTP/1.1 400"));
        assert!(forged.starts_with("HTTP/1.1 400"));
        assert!(real.starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn listener_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        assert!(wait_for_code_until(&listener, "s", Instant::now()).is_err());
    }

    #[test]
    fn callback_lines_are_bounded() {
        let mut valid = std::io::Cursor::new(b"GET / HTTP/1.1\r\n".to_vec());
        assert_eq!(
            read_bounded_line(&mut valid, 64).unwrap(),
            "GET / HTTP/1.1\r\n"
        );
        let mut oversized = std::io::Cursor::new(vec![b'a'; 65]);
        assert!(read_bounded_line(&mut oversized, 64).is_err());
    }
}
