use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("Unsupported file format (path: {0})")]
    FileFormatNotSupported(String),

    #[error("Failed to open file (path: {1}): {0}")]
    FileOpen(std::io::Error, String),
}
