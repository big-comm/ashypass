use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const APP_ID: &str = "com.bigcommunity.ashypass";
pub const APP_NAME: &str = "Ashy Pass";

/// User-visible version, and the single place it is written.
///
/// This is a literal rather than `env!("CARGO_PKG_VERSION")` because the
/// packaging tooling (`gitrepo`) bumps the version by rewriting an
/// `APP_VERSION = "x.y.z"` constant in the tree, and it cannot see through the
/// macro. Every place that shows a version — the About dialog, `--version`,
/// the native host handshake — reads this constant so they can never disagree.
///
/// `version` in the workspace `Cargo.toml` is the *crate* version and is not
/// what users see; the package's own `pkgver` is date-based (see
/// `pkgbuild/PKGBUILD`). Keep it aligned with this constant when it matters,
/// but nothing breaks if it lags behind a patch bump.
pub const APP_VERSION: &str = "3.0.1";

pub const SESSION_TIMEOUT_SECONDS: u64 = 30;
pub const CLIPBOARD_CLEAR_SECONDS: u64 = 60;
pub const MIN_MASTER_PASSWORD_LENGTH: usize = 8;

pub const DEFAULT_PASSWORD_LENGTH: usize = 16;
pub const MIN_PASSWORD_LENGTH: usize = 8;
pub const MAX_PASSWORD_LENGTH: usize = 128;
pub const DEFAULT_PASSPHRASE_WORDS: usize = 6;
pub const MIN_PASSPHRASE_WORDS: usize = 5;
pub const MAX_PASSPHRASE_WORDS: usize = 10;
pub const DEFAULT_PIN_LENGTH: usize = 6;
pub const MIN_PIN_LENGTH: usize = 4;
pub const MAX_PIN_LENGTH: usize = 12;

pub const AMBIGUOUS_CHARS: &str = "il1Lo0O";
pub const DEFAULT_SYMBOLS: &str = "!@#$%&*()-_=+[]{}|;:,.<>?/";

pub const WINDOW_DEFAULT_WIDTH: i32 = 870;
pub const WINDOW_DEFAULT_HEIGHT: i32 = 650;
pub const WINDOW_MIN_WIDTH: i32 = 700;
pub const WINDOW_MIN_HEIGHT: i32 = 570;

pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ashypass")
}

pub fn data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ashypass")
}

pub fn database_path() -> PathBuf {
    data_dir().join("passwords.db")
}

pub fn settings_file() -> PathBuf {
    config_dir().join("settings.json")
}

pub fn favicons_dir() -> PathBuf {
    data_dir().join("favicons")
}

pub fn token_file() -> PathBuf {
    data_dir().join("token.json")
}

pub fn fido2_file() -> PathBuf {
    config_dir().join("fido2.json")
}

pub fn ensure_directories() -> std::io::Result<()> {
    ensure_private_dir(&config_dir())?;
    ensure_private_dir(&data_dir())?;
    ensure_private_dir(&favicons_dir())?;
    Ok(())
}

pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

pub fn ensure_private_file(path: &Path) -> io::Result<()> {
    if path.exists() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Replace a private file atomically without following an attacker-controlled
/// temporary symlink. Existing contents remain intact if any step fails.
pub fn atomic_write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    ensure_private_dir(parent)?;

    let mut random = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut random);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid file name"))?;
    let temporary = parent.join(format!(".{name}.{:016x}.tmp", u64::from_ne_bytes(random)));

    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(data)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        ensure_private_file(path)?;
        let directory = OpenOptions::new().read(true).open(parent)?;
        directory.sync_all()
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
