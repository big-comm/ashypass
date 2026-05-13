use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("database not unlocked")]
    Locked,

    #[error("invalid master password")]
    InvalidMasterPassword,

    #[error("master password already set")]
    MasterAlreadySet,

    #[error("crypto: {0}")]
    Crypto(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("argon2: {0}")]
    Argon2(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("unsupported crypto version: {0}")]
    UnsupportedCryptoVersion(i64),

    #[error("{0}")]
    Other(String),
}

impl From<argon2::password_hash::Error> for Error {
    fn from(e: argon2::password_hash::Error) -> Self {
        Error::Argon2(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
