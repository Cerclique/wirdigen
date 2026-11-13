//! Deep Expressions never overflow the stack (ADR 0018): past depth 64 they are
//! `expression-too-deep`, however deep they go. These are the inputs of #191.

use wirdigen::Source;

/// The names of the Diagnostics a description with `size: <expression>` reports.
fn names_for_size(expression: &str) -> Vec<String> {
    let text = format!("name: demo\nfields:\n  - {{ name: data, type: bytes, size: \"{expression}\" }}\n");
    match wirdigen::validate(&Source::new("deep", text)) {
        Ok(valid) => valid.warnings().iter().map(|d| d.name().to_owned()).collect(),
        Err(diagnostics) => diagnostics.iter().map(|d| d.name().to_owned()).collect(),
    }
}

#[test]
fn deeply_nested_parentheses_are_too_deep() {
    let expression = format!("{}1{}", "(".repeat(30_000), ")".repeat(30_000));
    assert_eq!(names_for_size(&expression), ["expression-too-deep"]);
}

#[test]
fn a_long_unary_chain_is_too_deep() {
    assert_eq!(names_for_size(&format!("{}1", "-".repeat(30_000))), ["expression-too-deep"]);
}

#[test]
fn a_long_flat_chain_is_too_deep() {
    assert_eq!(names_for_size(&format!("1{} > 0", "+1".repeat(99_999))), ["expression-too-deep"]);
}
