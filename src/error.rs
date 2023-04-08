pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// Failed to deserialize value
    DeserializationFailed(serde_json::Error),

    /// Failed to validate dissector
    InvalidDissector(String),

    /// Failed to create Regex
    InvalidRegex(regex::Error),

    /// Failed to create output file
    FileCreation(std::io::Error),

    /// Failed to write into output file
    FileWrite(std::io::Error),
}
