use thiserror::Error;

#[derive(Error, Debug)]
pub enum WirdigenError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),

    #[error("Failed to compile JSON schema")]
    JSONSchemaCompilation(String),

    #[error(transparent)]
    RegexError(#[from] regex::Error),
}
