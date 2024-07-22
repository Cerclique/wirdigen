use crate::dissector_data::Data;
use crate::endianness::Endianness;
use crate::network_information::NetworkInformation;

/// Configuration of the dissector
#[derive(Debug)]
pub struct DissectorConfiguration {
    /// Name
    pub name: String,
    /// Endianness
    pub endianness: Endianness,
    /// Network information
    pub network_information: NetworkInformation,
    /// Data payload
    pub payload: Vec<Data>,
}

impl DissectorConfiguration {
    pub fn new(
        name: &str,
        endianness: Endianness,
        network_information: NetworkInformation,
        payload: Vec<Data>,
    ) -> Self {
        Self {
            name: String::from(name),
            endianness,
            network_information,
            payload,
        }
    }
}
