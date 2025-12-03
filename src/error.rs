use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("QRZ API error: {0}")]
    Qrz(String),

    #[error("ADIF parse error: {0}")]
    AdifParse(String),

    #[error("File watcher error: {0}")]
    Watcher(#[from] notify::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Ntfy notification error: {0}")]
    Ntfy(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
