use std::io::BufReader;

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsError;

use dissector_parser::parsers::json::JSONParser;
use dissector_parser::traits::DissectorParsing;

#[wasm_bindgen]
#[allow(dead_code)]
pub(crate) struct CheckResult {
    pub(crate) status: bool,

    // #[wasm_bindgen(getter_with_clone)]
    pub(crate) message: Option<String>,
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
pub fn dissector_check_json(buffer: &str) -> Result<CheckResult, JsError> {
    let mut rdr = BufReader::new(buffer.as_bytes());

    JSONParser::check(&mut rdr)
        .map(|res| match res.status {
            true => CheckResult::success(),
            false => CheckResult::failure(&res.message.unwrap()),
        })
        .or_else(|e| Err(JsError::new(&e.to_string())))
}

#[cfg(test)]
mod tests {
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::dissector_parser_json::dissector_check_json;

    #[wasm_bindgen_test]
    fn test_empty_json() {
        let res = dissector_check_json("");
        assert!(res.is_err());
    }

    #[wasm_bindgen_test]
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
              "format" : "bool",
              "base" : "NONE"
            }
          ]
        }"#;

        let res = dissector_check_json(data);
        assert!(res.is_ok());
        let res = res.map_err(JsValue::from).unwrap();
        assert_eq!(res.status, true);
        assert!(res.message.is_none());
    }

    #[wasm_bindgen_test]
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

        let res = dissector_check_json(data);
        assert!(res.is_ok());
        let res = res.map_err(JsValue::from).unwrap();
        assert_eq!(res.status, false);
        assert!(res.message.is_some());
    }
}
