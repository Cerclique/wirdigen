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
