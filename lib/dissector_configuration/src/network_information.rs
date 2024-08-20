use crate::protocol::Protocol;

/// Network information of the dissector
#[derive(Debug, Eq, PartialEq)]
pub struct NetworkInformation {
    /// Communication protocol
    pub protocol: Protocol,
    /// List of ports
    pub ports: Vec<u16>,
}

impl NetworkInformation {
    pub fn new(protocol: Protocol, ports: Vec<u16>) -> Self {
        Self { protocol, ports }
    }
}

#[cfg(test)]
mod tests {
    use crate::network_information::NetworkInformation;
    use crate::protocol::Protocol;

    #[test]
    fn test_network_information_new() {
        let protocol = Protocol::Udp;
        let ports = vec![42, 1337];

        let net_info = NetworkInformation::new(protocol, ports);

        assert_eq!(net_info.protocol, Protocol::Udp);
        assert_eq!(net_info.ports, vec![42, 1337]);
    }
}
