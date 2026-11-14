//! Public API shape (ADR 0012).

use wirdigen::{Diagnostic, Diagnostics, Note, RenderOptions, Severity, Source, ValidDescription};

fn assert_owned<T: Send + Sync + 'static>() {}

#[test]
fn public_types_are_owned_send_and_sync() {
    assert_owned::<Source>();
    assert_owned::<ValidDescription>();
    assert_owned::<Diagnostics>();
    assert_owned::<Diagnostic>();
    assert_owned::<Note>();
    assert_owned::<Severity>();
    assert_owned::<RenderOptions>();
}

#[test]
fn minimum_description_validates_and_generates() {
    let source = Source::new("min.wirdigen.yaml", "name: demo\nfields:\n  - { name: a, type: uint8 }\n");
    let valid = wirdigen::validate(&source).expect("valid");
    assert_eq!(valid.warnings(), []);
    assert_ne!(valid.generate(), "");
}

#[test]
fn diagnostics_work_with_question_mark() {
    fn run(text: &str) -> Result<String, Box<dyn std::error::Error>> {
        Ok(wirdigen::validate(&Source::new("x", text))?.generate())
    }
    let err = run("name: Demo\nfields: [ {name: a, type: uint8} ]\n").unwrap_err();
    assert!(err.to_string().contains("1 error"), "{err}");
}

#[test]
fn diagnostic_accessors() {
    let source = Source::new("x", "name: Demo\nfields: [ {name: a, type: uint8} ]\n");
    let diagnostics = wirdigen::validate(&source).unwrap_err();
    assert!(diagnostics.has_errors());
    let d = &diagnostics.iter().next().expect("one");
    assert_eq!(d.name(), "invalid-protocol-name");
    assert_eq!(d.severity(), Severity::Error);
    assert_eq!(d.span(), 6..10);
    assert_ne!(d.message(), "");
    assert_eq!(d.notes().len(), 1);
    assert_eq!(d.notes()[0].span(), None);
    assert_ne!(d.notes()[0].message(), "");
}

#[test]
fn json_schema_is_pretty_deterministic_json_listing_top_level_keys_in_documentation_order() {
    let schema = wirdigen::json_schema();
    assert_eq!(schema, wirdigen::json_schema());
    assert!(schema.starts_with("{\n  \"$schema\": \"http://json-schema.org/draft-07/schema#\",\n"), "{schema}");
    assert!(schema.ends_with("}\n"));
    let parsed: serde_json::Value = serde_json::from_str(&schema).expect("JSON");
    let top: Vec<&String> = parsed["properties"].as_object().expect("properties").keys().collect();
    assert_eq!(
        top,
        ["name", "title", "registration", "framing", "endian", "info", "fields", "types", "enums", "allow"]
    );
}

#[test]
fn source_line_column_counts_characters_from_one() {
    let source = Source::new("x", "é: x\nab");
    assert_eq!(source.line_column(0), (1, 1));
    assert_eq!(source.line_column(4), (1, 4));
    assert_eq!(source.line_column(7), (2, 2));
}

#[test]
fn source_line_column_after_a_trailing_newline_starts_the_next_line() {
    assert_eq!(Source::new("x", "a\n").line_column(2), (2, 1));
}

#[test]
fn severity_tokens_are_error_and_warning() {
    assert_eq!(Severity::Error.as_str(), "error");
    assert_eq!(Severity::Warning.as_str(), "warning");
}

#[test]
fn diagnostics_expose_len_is_empty_as_slice_and_an_owning_iterator() {
    let source = Source::new("x", "name: Demo\nfields: [ {name: A, type: uint8}, {name: B, type: uint8} ]\n");
    let diagnostics = wirdigen::validate(&source).unwrap_err();
    let borrowed: Vec<Diagnostic> = diagnostics.iter().cloned().collect();
    assert!(borrowed.len() > 1, "the test needs several Diagnostics: {borrowed:?}");

    assert_eq!(diagnostics.len(), borrowed.len());
    assert!(!diagnostics.is_empty());
    assert_eq!(diagnostics.as_slice(), borrowed.as_slice());

    let owned: Vec<Diagnostic> = diagnostics.into_iter().collect();
    assert_eq!(owned, borrowed);
}
