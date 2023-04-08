use regex::Regex;

use crate::error::{Error, Result};

/// Return the size in bytes for the current format.
pub(crate) fn get_chunk_size(chunk_format: &str) -> Option<u32> {
    match chunk_format {
        "bool" | "char" | "uint8" | "int8" | "bytes" | "unused" => Some(1),
        "uint16" | "int16" => Some(2),
        "uint24" | "int24" => Some(3),
        "uint32" | "int32" | "float" | "ipv4" => Some(4),
        "ether" => Some(6),
        "uint64" | "int64" | "double" | "absolute_time" | "relative_time" => Some(8),
        "ipv6" | "guid" | "oid" => Some(16),
        _ => None,
    }
}

pub(crate) fn get_default_base(chunk_format: &str) -> Option<String> {
    match chunk_format {
        "bool" | "float" | "double" | "relative_time" | "bytes" | "ipv4" | "ipv6" | "ether"
        | "guid" | "oid" | "none" => Some(String::from("NONE")),
        "char" => Some(String::from("HEX")),
        "uint8" | "uint16" | "uint24" | "uint32" | "uint63" | "int8" | "int16" | "int24"
        | "int32" | "int63" => Some(String::from("DEC")),
        "absolute_time" => Some(String::from("UTC")),
        _ => None,
    }
}

/// Replace all occurence of `to_replace` by `replace_by` into `buffer`
pub(crate) fn find_and_replace_all<'a>(
    buffer: &'a str,
    to_replace: &'a str,
    replace_by: &'a str,
) -> Result<String> {
    let re = Regex::new(to_replace).map_err(Error::InvalidRegex)?;
    Ok(re.replace_all(buffer, replace_by).to_string())
}
