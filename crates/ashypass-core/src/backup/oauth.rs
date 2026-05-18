//! OAuth 2.0 PKCE (S256) loopback flow for Google APIs.
//!
//! The flow is blocking and synchronous on a worker thread:
//!  1. Generate a random `code_verifier` and its S256 `code_challenge`.
//!  2. Bind a loopback TCP listener on a free port.
//!  3. Open the auth URL in the default browser.
//!  4. Block on the listener until Google redirects back with `?code=...`.
//!  5. Exchange the code for an access + refresh token at the token endpoint.

use crate::config::{config_dir, token_file};
use crate::{Error, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::time::Duration;

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
        let path = token_file();
        let text = fs::read_to_string(&path).ok()?;
        serde_json::from_str(&text).ok()
    }

    pub fn save(&self) -> Result<()> {
        let path = token_file();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn delete() -> Result<()> {
        let path = token_file();
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }
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
        let path = credentials_file();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    fn from_file() -> Option<Self> {
        let text = fs::read_to_string(credentials_file()).ok()?;
        let creds: Self = serde_json::from_str(&text).ok()?;
        if creds.client_id.trim().is_empty() {
            None
        } else {
            Some(creds)
        }
    }
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

    let _ = open_browser(&auth_url);

    listener
        .set_nonblocking(false)
        .map_err(|e| Error::Other(format!("oauth nonblock: {e}")))?;

    let code = wait_for_code(&listener)?;

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
        .post(&token.token_uri)
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

fn wait_for_code(listener: &TcpListener) -> Result<String> {
    listener
        .set_nonblocking(false)
        .map_err(|e| Error::Other(format!("set_nonblock: {e}")))?;
    let (mut stream, _) = listener
        .accept()
        .map_err(|e| Error::Other(format!("accept: {e}")))?;
    stream.set_read_timeout(Some(Duration::from_secs(120))).ok();

    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| Error::Other(format!("clone: {e}")))?,
    );
    let mut first_line = String::new();
    reader
        .read_line(&mut first_line)
        .map_err(|e| Error::Other(format!("read: {e}")))?;

    // Drain headers
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).unwrap_or(0);
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }

    let body = b"HTTP/1.1 200 OK\r\n\
        Content-Type: text/html; charset=utf-8\r\n\
        Connection: close\r\n\r\n\
        <!doctype html><html><body style='font-family:sans-serif;text-align:center;padding:3em'>\
        <h2>Ashy Pass</h2><p>You can close this window and return to the app.</p>\
        </body></html>";
    let _ = stream.write_all(body);
    let _ = stream.flush();

    // first_line: "GET /?code=...&state=... HTTP/1.1"
    let path = first_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| Error::Other("oauth callback: malformed request".into()))?;
    let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");

    let mut code = None;
    let mut err = None;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let decoded = url::form_urlencoded::parse(format!("x={v}").as_bytes())
                .next()
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();
            match k {
                "code" => code = Some(decoded),
                "error" => err = Some(decoded),
                _ => {}
            }
        }
    }
    if let Some(e) = err {
        return Err(Error::Other(format!("oauth callback: {e}")));
    }
    code.ok_or_else(|| Error::Other("oauth callback: no code".into()))
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
