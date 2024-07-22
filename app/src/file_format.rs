use std::ffi::OsStr;

/// List of file formats
pub(crate) enum FileFormat {
    Unknown,
    Json,
}

impl From<Option<&OsStr>> for FileFormat {
    fn from(value: Option<&OsStr>) -> Self {
        if value.is_none() {
            return FileFormat::Unknown;
        }

        match value.unwrap().to_str().unwrap() {
            "json" => FileFormat::Json,
            _ => FileFormat::Unknown,
        }
    }
}
