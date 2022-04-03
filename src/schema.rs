pub const JSON_SCHEMA: &str = r#"
{
    "id": "schemaTemplate",
    "type" : "object",
    "properties" : {
        "name:" : { 
            "type" : "string",
            "minLength" : 1,
            "maxLength" : 20
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
                        "maxLength" : 20
                    },
                    "format" : {
                        "type" : "string",
                        "enum" : ["none", "uint8", "uint16", "uint24", "uint32", "uint64", "int8", "int16", "int24", "int32", "int64", "framenum", "bool", "absolute_time", "relative_time", "float", "double", "string", "stringz", "bytes", "ubytes", "ipv4", "ipv6", "ether", "guid", "oid", "protocol", "rel_oid", "systemid", "eui64"] 
                    },
                    "filter_name" : { 
                        "type" : "string", 
                        "maxLength" : 20
                    },
                    "description" : { 
                        "type" : "string",
                        "maxLength" : 50 
                    },
                    "base" : { 
                        "type" : "string",
                        "enum" : ["NONE", "DEC", "HEX", "OCT", "DEC_HEX", "HEX_DEC", "UNIT_STRING", "RANGE_STRING"]
                    },
                    "offset" : {
                        "type" : "number"
                    },
                    "size" : {
                        "type" : "number"
                    }
                },
                "required" : ["name", "format", "filter_name", "description", "base", "offset", "size"]
            }
        }
    },
    "required" : ["name", "connection", "data"]
}
"#;
