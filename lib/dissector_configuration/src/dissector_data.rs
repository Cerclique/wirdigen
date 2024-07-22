use crate::base::Base;
use crate::format::Format;

/// Data chunk description inside the payload
#[derive(Debug)]
pub struct Data {
    /// Name
    name: String,
    /// Format
    format: Format,
    /// Display base
    base: Base,
}

impl Data {
    pub fn new(name: String, format: Format, base: Base) -> Self {
        Self { name, format, base }
    }
}
