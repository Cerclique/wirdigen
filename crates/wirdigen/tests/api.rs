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
