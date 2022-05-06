//! Enum of possible error returned by modules

use thiserror::Error;

#[derive(Error, Debug)]
pub enum WirdigenError {
    /// Error inherited from std::io::Error
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    /// Error inherited from serde_json::Error
    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),

    /// Error inherited from regex::Error
    #[error(transparent)]
    RegexError(#[from] regex::Error),

    /// String descripton of error returned by jsonschema::ValidationError
    #[error("Failed to compile JSON schema")]
    JSONSchemaCompilation(String),
}
