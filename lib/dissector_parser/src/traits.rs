use std::io::BufRead;

use dissector_configuration::dissector_configuration::DissectorConfiguration;

use crate::error::Result;

#[derive(Debug)]
pub struct CheckReport {
    pub status: bool,
    pub message: Option<String>,
}

impl CheckReport {
    pub fn success() -> Self {
        Self {
            status: true,
            message: None,
        }
    }

    pub fn failure(message: &str) -> Self {
        Self {
            status: false,
            message: Some(message.to_string()),
        }
    }
}
pub trait DissectorParsing {
    fn parse<R: BufRead>(rdr: &mut R) -> Result<DissectorConfiguration>;

    fn check<R: BufRead>(rdr: &mut R) -> Result<CheckReport>;
}
