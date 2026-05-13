use std::path::PathBuf;

pub const APP_ID: &str = "com.bigcommunity.ashypass";
pub const APP_NAME: &str = "Ashy Pass";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

pub const SESSION_TIMEOUT_SECONDS: u64 = 30;
pub const CLIPBOARD_CLEAR_SECONDS: u64 = 60;
pub const MIN_MASTER_PASSWORD_LENGTH: usize = 8;

pub const DEFAULT_PASSWORD_LENGTH: usize = 16;
pub const MIN_PASSWORD_LENGTH: usize = 8;
pub const MAX_PASSWORD_LENGTH: usize = 128;
pub const DEFAULT_PASSPHRASE_WORDS: usize = 4;
pub const MIN_PASSPHRASE_WORDS: usize = 3;
pub const MAX_PASSPHRASE_WORDS: usize = 8;
pub const DEFAULT_PIN_LENGTH: usize = 6;
pub const MIN_PIN_LENGTH: usize = 4;
pub const MAX_PIN_LENGTH: usize = 12;

pub const AMBIGUOUS_CHARS: &str = "il1Lo0O";
pub const DEFAULT_SYMBOLS: &str = "!@#$%&*()-_=+[]{}|;:,.<>?/";

pub const WINDOW_DEFAULT_WIDTH: i32 = 800;
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
    std::fs::create_dir_all(config_dir())?;
    std::fs::create_dir_all(data_dir())?;
    Ok(())
}
