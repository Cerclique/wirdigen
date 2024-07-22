use thiserror::Error;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Dissector description is not valid.")]
    InvalidDissector,

    #[error("Failed to deserialize JSON schema ({0})")]
    SchemaDeserialization(serde_json::Error),

    #[error("Failed to deserialize JSON dissector ({0})")]
    DissectorDeserialization(serde_json::Error),
}
