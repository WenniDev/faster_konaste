use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid pattern {0}")]
    InvalidPattern(&'static str),
    #[error("Failed to find {0}, unsupported updater version")]
    PatternNotFound(&'static str),
    #[error("Failed to resolve {0}")]
    MissingSymbol(&'static str),
    #[error("Checksum mismatch for {path}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("{0}")]
    InternalError(String),
    #[error("{0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}
