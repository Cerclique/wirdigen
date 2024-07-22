use std::io::BufRead;

use dissector_configuration::dissector_configuration::DissectorConfiguration;
use dissector_configuration::dissector_data::Data;
use dissector_configuration::network_information::NetworkInformation;

use crate::error::{Error, Result};
use crate::parsers::json::description::Dissector;
use crate::traits::DissectorParsing;

mod description;

pub struct JSONParser;

impl DissectorParsing for JSONParser {
    fn parse<R: BufRead>(rdr: &mut R) -> Result<DissectorConfiguration> {
        if !(Self::check(rdr)?) {
            return Err(Error::InvalidDissector);
        }

        let dissector: Dissector = match serde_json::from_reader(rdr) {
            Ok(value) => value,
            Err(e) => return Err(Error::DissectorDeserialization(e)),
        };

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

    fn check<R: BufRead>(rdr: &mut R) -> Result<bool> {
        const JSON_SCHEMA: &str = include_str!("../../../res/schema.json");

        let schema_value: serde_json::Value = match serde_json::from_str(JSON_SCHEMA) {
            Ok(value) => value,
            Err(e) => return Err(Error::SchemaDeserialization(e)),
        };

        let dissector_value: serde_json::Value = match serde_json::from_reader(rdr) {
            Ok(value) => value,
            Err(e) => return Err(Error::DissectorDeserialization(e)),
        };

        Ok(jsonschema::is_valid(&schema_value, &dissector_value))
    }
}
