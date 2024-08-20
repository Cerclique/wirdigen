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

#[cfg(test)]
mod tests {
    use crate::base::Base;
    use crate::dissector_configuration::DissectorConfiguration;
    use crate::dissector_data::Data;
    use crate::endianness::Endianness;
    use crate::format::Format;
    use crate::network_information::NetworkInformation;
    use crate::protocol::Protocol;

    #[test]
    fn test_configuration_new() {
        let conf = DissectorConfiguration::new(
            "test_conf",
            Endianness::BigEndian,
            NetworkInformation::new(Protocol::Tcp, vec![42, 1337]),
            vec![Data::new(
                "test_data".to_string(),
                Format::Char,
                Base::DecHex,
            )],
        );

        assert_eq!(conf.name, "test_conf");
        assert_eq!(conf.endianness, Endianness::BigEndian);
        assert_eq!(
            conf.network_information,
            NetworkInformation::new(Protocol::Tcp, vec![42, 1337])
        );
        assert_eq!(conf.payload.len(), 1);
        assert_eq!(
            conf.payload[0],
            Data::new("test_data".to_string(), Format::Char, Base::DecHex,)
        )
    }
}
