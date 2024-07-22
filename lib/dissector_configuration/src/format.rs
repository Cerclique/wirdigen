use strum::{Display, EnumIter, IntoEnumIterator};

#[derive(Debug, EnumIter, Display)]
pub enum Format {
    None,
    Bool,
    Char,
    Uint8,
    Uint16,
    Uint24,
    Uint32,
    Uint64,
    Int8,
    Int16,
    Int24,
    Int32,
    Int64,
    Float,
    Double,
    AbsoluteTime,
    RelativeTime,
    Ether,
    Bytes,
    Ipv4,
    Ipv6,
    Guid,
    Oid,
}

impl From<String> for Format {
    fn from(value: String) -> Self {
        match value.to_lowercase().as_str() {
            "none" => Format::None,
            "bool" => Format::Bool,
            "char" => Format::Char,
            "uint8" => Format::Uint8,
            "uint16" => Format::Uint16,
            "uint24" => Format::Uint24,
            "uint32" => Format::Uint32,
            "uint64" => Format::Uint64,
            "int8" => Format::Int8,
            "int16" => Format::Int16,
            "int32" => Format::Int32,
            "int64" => Format::Int64,
            "float" => Format::Float,
            "double" => Format::Double,
            "absolute_time" => Format::AbsoluteTime,
            "relative_time" => Format::RelativeTime,
            "ether" => Format::Ether,
            "bytes" => Format::Bytes,
            "ipv4" => Format::Ipv4,
            "ipv6" => Format::Ipv6,
            "guid" => Format::Guid,
            "oid" => Format::Oid,
            _ => unreachable!(),
        }
    }
}

impl Format {
    pub fn get_values_as_string() -> Vec<String> {
        Self::iter().map(|x| format!("{}", x)).collect()
    }
}
