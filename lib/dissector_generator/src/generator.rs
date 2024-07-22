use std::fmt::Write;

use dissector_configuration::dissector_configuration::DissectorConfiguration;

use crate::error::Result;

pub struct DissectorGenerator;

impl DissectorGenerator {
    pub fn generate(
        dissector: DissectorConfiguration,
        _output_dir: Option<String>,
    ) -> Result<String> {
        const DISSECTOR_TEMPLATE: &str = include_str!("../res/template.lua");
        let mut output_buffer = String::from(DISSECTOR_TEMPLATE);

        // TODO Create object for keywords

        output_buffer = output_buffer.replace("%DISSECTOR_NAME%", &dissector.name);

        let protocol_str: &str = &dissector
            .network_information
            .protocol
            .to_string()
            .to_lowercase();

        output_buffer = output_buffer.replace("%PROTOCOL%", protocol_str);

        let mut ports_buffer: String = String::new();
        for port in dissector.network_information.ports {
            let _ = writeln!(
                ports_buffer,
                "{}_port:add({}, {})",
                &protocol_str, port, dissector.name
            );
        }

        output_buffer = output_buffer.replace("%PORTS%", &ports_buffer);

        todo!()
    }
}
