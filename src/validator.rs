//! Module to validate a dissector JSON description

use jsonschema::JSONSchema;
use serde_json::Value;

use crate::error::WirdigenError;

const JSON_SCHEMA: &str = include_str!("../res/schema.json");

pub struct Validator {
    schema_value: JSONSchema,
}

impl Validator {
    /// Create a new validator object.
    pub fn new() -> Result<Validator, WirdigenError> {
        let json_schema: Value = serde_json::from_str(JSON_SCHEMA)?;

        let data = Self::compile_schema(json_schema)?;
        Ok(Validator { schema_value: data })
    }

    /// Validate a dissector in serde_json format against predefined schema.
    pub fn validate(self, json_raw: &Value) -> bool {
        match self.schema_value.validate(json_raw) {
            Err(errors) => {
                for err in errors {
                    eprintln!("{:#?}", err);
                }
                false
            }
            Ok(_) => true,
        }
    }
}

impl Validator {
    fn compile_schema(value: Value) -> Result<JSONSchema, WirdigenError> {
        match JSONSchema::compile(&value) {
            Err(e) => Err(WirdigenError::JSONSchemaCompilation(e.to_string())),
            Ok(data) => Ok(data),
        }
    }
}

#[cfg(test)]
mod unit_test {
    use super::*;

    use std::fs::File;
    use std::io::BufReader;

    #[test]
    fn validator_new() -> Result<(), WirdigenError> {
        let _ = Validator::new()?;
        Ok(())
    }

    #[test]
    fn validator_compile_schema_valid() -> Result<(), WirdigenError> {
        let valid_schema = r#"
        {
            "properties" : {
                "test": {
                    "type": "string"
                }
            }
        }"#;

        let value = serde_json::from_str(valid_schema)?;

        if let Err(_) = Validator::compile_schema(value) {
            panic!("The schema should have compiled")
        }
        Ok(())
    }

    #[test]
    fn validator_compile_schema_invalid() -> Result<(), WirdigenError> {
        // "any" is no longer a valid type keyword for a schema
        let invalid_schema = r#"
        {
            "properties" : {
                "test": {
                    "type": "any"
                }
            }
        }"#;

        let value = serde_json::from_str(invalid_schema)?;

        if let Ok(_) = Validator::compile_schema(value) {
            panic!("The schema should not have compiled")
        }
        Ok(())
    }

    #[test]
    fn validator_validate_true() -> Result<(), WirdigenError> {
        let file = File::open("./example/example_dissector.json")?;
        let rdr = BufReader::new(file);
        let value: Value = serde_json::from_reader(rdr)?;
        let mgr = Validator::new()?;

        assert_eq!(mgr.validate(&value), true);
        Ok(())
    }

    #[test]
    fn validator_validate_false() -> Result<(), WirdigenError> {
        // Invalid dissector
        let json_raw = r#"
        {
        }"#;

        let value = serde_json::from_str(json_raw)?;

        let mgr = Validator::new()?;

        assert_eq!(mgr.validate(&value), false);
        Ok(())
    }
}
