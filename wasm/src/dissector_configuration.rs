use wasm_bindgen::prelude::wasm_bindgen;

use dissector_configuration::base::Base;
use dissector_configuration::endianness::Endianness;
use dissector_configuration::format::Format;
use dissector_configuration::protocol::Protocol;

/// Returns list of supported protocols for a dissector
#[wasm_bindgen]
pub fn dissector_get_protocol_list() -> Vec<String> {
    Protocol::get_values_as_string()
}

/// Returns list of supported endianness for a dissector
#[wasm_bindgen]
pub fn dissector_get_endianness_list() -> Vec<String> {
    Endianness::get_values_as_string()
}

/// Returns list of supported data type for a dissector attribute
#[wasm_bindgen]
pub fn dissector_get_base_list() -> Vec<String> {
    Base::get_values_as_string()
}

/// Returns list of supported data display format for a dissector attribute
#[wasm_bindgen]
pub fn dissector_get_format_list() -> Vec<String> {
    Format::get_values_as_string()
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::dissector_configuration::{
        dissector_get_base_list, dissector_get_endianness_list, dissector_get_format_list,
        dissector_get_protocol_list,
    };

    #[wasm_bindgen_test]
    fn test_protocol_list_not_empty() {
        let list = dissector_get_protocol_list();
        assert!(list.len() > 0);
        list.iter().for_each(|value| assert!(value.len() > 0))
    }

    #[wasm_bindgen_test]
    fn test_endianness_list_not_empty() {
        let list = dissector_get_endianness_list();
        assert!(list.len() > 0);
        list.iter().for_each(|value| assert!(value.len() > 0))
    }

    #[wasm_bindgen_test]
    fn test_base_list_not_empty() {
        let list = dissector_get_base_list();
        assert!(list.len() > 0);
        list.iter().for_each(|value| assert!(value.len() > 0))
    }

    #[wasm_bindgen_test]
    fn test_format_list_not_empty() {
        let list = dissector_get_format_list();
        assert!(list.len() > 0);
        list.iter().for_each(|value| assert!(value.len() > 0))
    }
}
