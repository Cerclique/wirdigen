use std::io::BufReader;

use wasm_bindgen::prelude::*;

use dissector_parser::parsers::json::JSONParser;
use dissector_parser::traits::DissectorParsing;

mod dissector_configuration;

#[wasm_bindgen]
pub struct CheckResult {
    pub status: bool,
    #[wasm_bindgen(getter_with_clone)]
    pub message: Option<String>,
}

impl CheckResult {
    fn success() -> Self {
        Self {
            status: true,
            message: None,
        }
    }

    fn failure(message: &str) -> Self {
        Self {
            status: false,
            message: Some(message.to_string()),
        }
    }
}

#[wasm_bindgen]
pub fn check_json(buffer: &str) -> Result<CheckResult, JsError> {
    let mut rdr = BufReader::new(buffer.as_bytes());

    match JSONParser::check(&mut rdr).map_err(|err| JsError::new(&err.to_string()))? {
        true => Ok(CheckResult::success()),
        false => Ok(CheckResult::failure("Placeholder message. To edit later.")),
    }
}
