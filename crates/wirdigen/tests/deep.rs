//! Deep descriptions never overflow the stack. Expressions past depth 64 are
//! `expression-too-deep` (ADR 0018, the inputs of #191); Fields past depth 64 are
//! `field-too-deep`, and YAML past 256 levels `yaml-too-deep` (ADR 0020, #207).

use std::fmt::Write as _;

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

/// The stack of a thread Rust spawns by default, where a library caller or `cargo test` runs.
const STACK: usize = 2 * 1024 * 1024;

/// The Diagnostics of validating `text`, each as `name message`, on a thread with a 2 MB stack.
fn diagnostics_on_a_small_stack(text: String) -> Vec<String> {
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(move || {
            let diagnostics = match wirdigen::validate(&Source::new("deep", text)) {
                Ok(valid) => valid.warnings().to_vec(),
                Err(diagnostics) => diagnostics.iter().cloned().collect(),
            };
            diagnostics.iter().map(|d| format!("{} {}", d.name(), d.message())).collect()
        })
        .expect("a thread can be spawned")
        .join()
        .expect("validation does not panic")
}

/// A chain of `n` Types used by the top-level Field `t`: each holds a Field `next` of the next,
/// then a `uint8` `x`, which makes the read-to-end check walk the rest of the chain.
fn chain_of_types(n: usize) -> String {
    let mut text = "name: demo\nfields:\n  - { name: t, type: T0 }\ntypes:\n".to_owned();
    for i in 0..n - 1 {
        writeln!(text, "  T{i}:\n    fields:\n      - {{ name: next, type: T{} }}", i + 1)
            .expect("writing to a String");
        text.push_str("      - { name: x, type: uint8 }\n");
    }
    writeln!(text, "  T{}:\n    fields:\n      - {{ name: x, type: uint8 }}", n - 1).expect("writing to a String");
    text
}

/// The filter name of `x` in the last of a chain of `n` Types used by `t`.
fn chain_filter_name(n: usize) -> String {
    format!("demo.t{}.x", ".next".repeat(n - 1))
}

/// `n` levels of inline structures named `s` under the top level, the innermost holding a
/// `uint8` `x`, in flow style.
fn nested_structures(n: usize) -> String {
    format!("name: demo\nfields: [{}{{ name: x, type: uint8 }}{}]\n", "{ name: s, fields: [".repeat(n), "] }".repeat(n))
}

/// `field-too-deep` as reported at the Field of filter name `filter_name`.
fn too_deep(filter_name: &str) -> String {
    format!("field-too-deep `{filter_name}` is 65 Fields deep; the limit is 64")
}

#[test]
fn a_chain_of_ten_thousand_types_is_too_deep() {
    let diagnostics = diagnostics_on_a_small_stack(chain_of_types(10_000));
    // `next` and `x` of the Type whose Fields are 65 deep, and nothing under them.
    let next = format!("demo.t{}", ".next".repeat(65));
    assert_eq!(diagnostics, [too_deep(&next), too_deep(&chain_filter_name(65))]);
}

#[test]
fn ten_thousand_nested_inline_structures_are_too_deep_yaml() {
    let diagnostics = diagnostics_on_a_small_stack(nested_structures(10_000));
    assert_eq!(diagnostics, ["yaml-too-deep the YAML is nested more than 256 levels deep"]);
}

#[test]
fn the_deepest_inline_structures_the_yaml_limit_allows_are_too_deep() {
    // Each level is a mapping and its `fields:` list: at 126 levels the scalars of `x` are the
    // 256th level.
    let diagnostics = diagnostics_on_a_small_stack(nested_structures(126));
    assert_eq!(diagnostics, [too_deep(&format!("demo{}", ".s".repeat(66)))]);
}

#[test]
fn a_field_64_deep_is_accepted_and_one_65_deep_is_too_deep() {
    assert_eq!(diagnostics_on_a_small_stack(chain_of_types(64)), Vec::<String>::new());
    assert_eq!(diagnostics_on_a_small_stack(chain_of_types(65)), [too_deep(&chain_filter_name(65))]);
    assert_eq!(diagnostics_on_a_small_stack(nested_structures(64)), Vec::<String>::new());
    assert_eq!(diagnostics_on_a_small_stack(nested_structures(65)), [too_deep(&format!("demo{}.x", ".s".repeat(65)))]);
}

#[test]
fn a_type_reached_too_deep_by_several_uses_is_reported_once_with_the_first_filter_name() {
    let mut text =
        "name: demo\nfields:\n  - { name: leaf, type: Leaf }\n  - { name: t, type: T0 }\ntypes:\n".to_owned();
    text.push_str("  Leaf:\n    fields:\n      - { name: x, type: uint8 }\n");
    for i in 0..63 {
        writeln!(text, "  T{i}:\n    fields:\n      - {{ name: next, type: T{} }}", i + 1)
            .expect("writing to a String");
    }
    text.push_str("  T63:\n    fields:\n      - { name: a, type: Leaf }\n      - { name: b, type: Leaf }\n");
    let filter_name = format!("demo.t{}.a.x", ".next".repeat(63));
    assert_eq!(diagnostics_on_a_small_stack(text), [too_deep(&filter_name)]);
}

/// A description whose deepest YAML node, a scalar in lists under `info:`, is at level `n`: the
/// root mapping is level 1.
fn yaml_levels_deep(n: usize) -> String {
    format!("name: demo\ninfo: {}x{}\nfields: [{{ name: x, type: uint8 }}]\n", "[".repeat(n - 2), "]".repeat(n - 2))
}

#[test]
fn yaml_256_levels_deep_is_read_and_257_is_too_deep() {
    let names = |text| -> Vec<String> {
        diagnostics_on_a_small_stack(text).iter().map(|d| d.split(' ').next().unwrap_or_default().to_owned()).collect()
    };
    assert_eq!(names(yaml_levels_deep(256)), ["wrong-value-type"]);
    assert_eq!(names(yaml_levels_deep(257)), ["yaml-too-deep"]);
}
