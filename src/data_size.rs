pub(crate) fn get_data_size(data_str: &str) -> Option<u32> {
    match data_str {
        "bool" | "char" | "uint8" | "int8" => Some(1),
        "uint16" | "int16" => Some(2),
        "uint24" | "int24" => Some(3),
        "uint32" | "int32" | "float" | "ipv4" => Some(4),
        "ether" => Some(6),
        "uint64" | "int64" | "double" | "absolute_time" | "relative_time" => Some(8),
        "ipv6" | "guid" | "oid" => Some(16),
        _ => None 
    }
}