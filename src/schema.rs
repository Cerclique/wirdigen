pub const JSON_SCHEMA: &str = r#"
{
    "id": "schemaTemplate",
    "type" : "object",
    "properties" : {
        "name" : { 
            "type" : "string",
            "minLength" : 1,
            "maxLength" : 32
        },
        "endianness" : {
            "type" : "string",
            "enum" : ["little", "big"]
        },
        "connection" : { 
            "type" : "object",
            "properties" : {
                "protocol" : { 
                    "type" : "string", 
                    "enum" : [ "udp", "tcp" ] 
                },
                "ports" : { 
                    "type" : "array",
                    "UniqueItems" : true,
                    "minItems" : 1,
                    "items" : {
                        "type" : "number",
                        "minimum" : 1,
                        "maximum" : 65535
                    }
                }
            },
            "required" : ["protocol", "ports"]
        },
        "data" : {
            "type" : "array",
            "minItems" : 1,
            "items" : {
                "type" : "object",
                "properties" : {
                    "name" : {
                        "type" : "string",
                        "minLength" : 1,
                        "maxLength" : 32
                    },
                    "format" : {
                        "type" : "string",
                        "enum" : ["bool", "char", "uint8", "uint16", "uint24", "uint32", "uint64", "int8", "int16", "int24", "int32", "int64", "float", "double", "absolute_time", "relative_time", "ether", "bytes", "ipv4", "ipv6", "guid", "oid", "none"] 
                    },
                    "base" : { 
                        "type" : "string",
                        "enum" : ["NONE", "DEC", "HEX", "OCT", "DEC_HEX", "HEX_DEC", "UTC", "LOCAL", "DOY_UTC", "DOT", "DASH", "COLON", "SPACE"]
                    },
                    "offset" : {
                        "type" : "number"
                    },
                    "size" : {
                        "type" : "number"
                    }
                },
                "required" : ["name", "format", "base", "offset", "size"]
            }
        }
    },
    "required" : ["name", "endianness", "connection", "data"]
}
"#;
