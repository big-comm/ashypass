use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse lsblk output: {0}")]
    LsblkParse(#[from] serde_json::Error),

    #[error("required tool not found in PATH: {0}")]
    MissingTool(String),

    #[error("command `{cmd}` failed (exit {status}): {stderr}")]
    CommandFailed {
        cmd: String,
        status: i32,
        stderr: String,
    },

    #[error("refused destructive operation: {0}")]
    Refused(String),

    #[error("not implemented yet")]
    NotImplemented,
}

pub type Result<T> = std::result::Result<T, Error>;
