use serde_json::Value;
use jsonschema::JSONSchema;

use thiserror::Error;

use crate::schema::JSON_SCHEMA;

pub struct Validator {
    schema_value: JSONSchema
}

#[derive(Error, Debug)]
pub enum ValidatorError {
    #[error(transparent)]
    SerdeJsonError (#[from] serde_json::Error),

    #[error("Failed to compile JSON schema")]
    JSONSchemaCompilation(String)
}

impl Validator {
    pub fn new() -> Result<Validator, ValidatorError> {
        let json_schema: Value = serde_json::from_str(JSON_SCHEMA)?;

        match JSONSchema::compile(&json_schema) {
            Err(e) => Err(ValidatorError::JSONSchemaCompilation(e.to_string())),
            Ok(data) => Ok(Validator { schema_value:  data })
        }
    } 
}

impl Validator {
    pub fn validate(self, json_raw: &Value) -> bool {
        if let Err(errors) = self.schema_value.validate(json_raw) {
            for err in errors {
                println!("{:#?}", err);
            }
            return false
        }
        true
    }
}

#[cfg(test)]
mod unit_test {
    use super::*;

    use std::fs::File;
    use std::io::BufReader;

    #[test]
    fn validator_new() -> Result<(), ValidatorError> {
        let _ = Validator::new()?;
        Ok(())
    }

    #[test]
    fn validator_validate() -> Result<(), ValidatorError> {
        let mgr = Validator::new()?;
        
        let file = File::open("./test/example_dissector.json").expect("A valid file");
        let rdr = BufReader::new(file);
        let value: Value = serde_json::from_reader(rdr)?;

        assert_eq!(mgr.validate(&value), true);

        Ok(())
    }
}