use crate::protocol::Protocol;

/// Network information of the dissector
#[derive(Debug)]
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
