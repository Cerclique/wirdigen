use std::io::BufRead;

use dissector_configuration::dissector_configuration::DissectorConfiguration;

use crate::error::Result;

pub trait DissectorParsing {
    fn parse<R: BufRead>(rdr: &mut R) -> Result<DissectorConfiguration>;

    fn check<R: BufRead>(rdr: &mut R) -> Result<bool>;
}
