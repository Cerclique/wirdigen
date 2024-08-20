use std::io::BufRead;

use jsonschema::JSONSchema;

use dissector_configuration::dissector_configuration::DissectorConfiguration;
use dissector_configuration::dissector_data::Data;
use dissector_configuration::network_information::NetworkInformation;

use crate::error::{Error, Result};
use crate::parsers::json::description::Dissector;
use crate::traits::{CheckReport, DissectorParsing};

mod description;

pub struct JSONParser;

fn validation_error_to_string(error: jsonschema::ValidationError) -> String {
    format!("\n{}: {}\n", error.schema_path, error.instance)
}

fn iterator_error_to_string(errors: jsonschema::ErrorIterator) -> String {
    let mut str = String::new();

    for error in errors {
        str.push_str(&validation_error_to_string(error));
    }

    str
}

impl DissectorParsing for JSONParser {
    fn parse<R: BufRead>(rdr: &mut R) -> Result<DissectorConfiguration> {
        Self::check(rdr)?;

        let dissector: Dissector =
            serde_json::from_reader(rdr).map_err(Error::DissectorDeserialization)?;

        let mut data = Vec::<Data>::with_capacity(dissector.payload.len());
        for attribute in dissector.payload {
            data.push(Data::new(
                attribute.name,
                attribute.format.into(),
                attribute.base.into(),
            ));
        }

        Ok(DissectorConfiguration::new(
            &dissector.name,
            dissector.endianness.into(),
            NetworkInformation::new(
                dissector.connection.protocol.into(),
                dissector.connection.ports,
            ),
            data,
        ))
    }

    fn check<R: BufRead>(rdr: &mut R) -> Result<CheckReport> {
        const JSON_SCHEMA: &str = include_str!("../../../res/schema.json");

        let schema_value: serde_json::Value =
            serde_json::from_str(JSON_SCHEMA).map_err(Error::SchemaDeserialization)?;

        let dissector_value: serde_json::Value =
            serde_json::from_reader(rdr).map_err(Error::DissectorDeserialization)?;

        let schema = JSONSchema::options()
            .compile(&schema_value)
            .map_err(|e| Error::SchemaCompilation(validation_error_to_string(e)))?;

        let res = schema.validate(&dissector_value);
        match res {
            Ok(_) => Ok(CheckReport::success()),
            Err(e) => Ok(CheckReport::failure(&iterator_error_to_string(e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufReader;

    use crate::parsers::json::JSONParser;
    use crate::traits::DissectorParsing;

    #[test]
    fn test_empty_json() {
        let data = r#""#;

        let mut rdr = BufReader::new(data.as_bytes());
        let res = JSONParser::check(&mut rdr);
        assert!(res.is_err());
    }

    #[test]
    fn test_invalid_json() {
        let data = r#"
        {
          "name" : "test",
          "endianness" : "little",
          "connection" : {
            "protocol" : "udp",
            "ports" : [
              60001,
              60002
            ]
          }
        }"#;

        let mut rdr = BufReader::new(data.as_bytes());
        let res = JSONParser::check(&mut rdr);
        assert!(res.is_ok());

        let res = res.unwrap();
        assert_eq!(res.status, false);
        assert_ne!(res.message, None);
    }

    #[test]
    fn test_valid_json() {
        let data = r#"
        {
          "name" : "test",
          "endianness" : "little",
          "connection" : {
            "protocol" : "udp",
            "ports" : [
              60001,
              60002
            ]
          },
          "data" : [
            {
              "name" : "bool_NONE",
              "format" : "bool"
            }
          ]
        }"#;

        let mut rdr = BufReader::new(data.as_bytes());
        let res = JSONParser::check(&mut rdr);
        assert!(res.is_ok());

        let res = res.unwrap();
        assert_eq!(res.status, true);
        assert_eq!(res.message, None);
    }
}
