//! Large descriptions (#199, ADR 0019): however many Fields or Types a description has, and
//! however deep it nests up to the depth limit of 64 (ADR 0020), its Dissector stays within
//! Lua's per-function limits (200 locals, 255 upvalues, 255 registers, and about 200 levels of
//! nesting in the parser), so tshark loads it and dissects with it.
//!
//! The descriptions are generated here rather than checked in. Each packet holds one byte per
//! `uint8`, and the test checks the last Field read, deepest in the tree, with tshark's `-T
//! fields` output rather than its JSON, too deeply nested for `serde_json` here. Success is
//! judged as for the corpus: nothing on stderr, and no `_ws.lua.error` or `_ws.malformed.expert`.

use std::fmt::Write as _;
use std::fs;

use wirdigen::Source;

use super::bad_input::text2pcap;
use super::{PORT, Scratch, enabled, path_str};

/// Generates the Dissector of `description`, dissects one packet of `bytes` with it, and checks
/// that the item at the filter name `deepest` shows `expected`.
fn check(name: &str, description: &str, bytes: &[u8], deepest: &str, expected: &str) {
    if !enabled() {
        return;
    }
    let file = format!("{name}.wirdigen.yaml");
    let lua = wirdigen::validate(&Source::new(&file, description))
        .unwrap_or_else(|d| panic!("{name} is invalid: {d}"))
        .generate();
    let scratch = Scratch::new(&format!("large-{name}"));
    let script = scratch.path("dissector.lua");
    fs::write(&script, lua).expect("the scratch directory is writable");
    let packets = scratch.path("packets.txt");
    fs::write(&packets, text2pcap(bytes)).expect("the scratch directory is writable");
    let pcap = scratch.capture(&packets);
    let decode_as = format!("udp.port=={PORT},demo");
    let script = format!("lua_script:{}", path_str(&script));
    let fields = [deepest, "_ws.lua.error", "_ws.malformed.expert"];
    let mut args = vec!["-r", path_str(&pcap), "-X", &script, "-d", &decode_as, "-T", "fields"];
    args.extend(fields.iter().flat_map(|field| ["-e", field]));
    let output = scratch.run("tshark", &args);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.trim().is_empty(), "{name}: tshark wrote to stderr ({}):\n{stderr}", output.status);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, format!("{expected}\t\t\n"), "{name}: `{deepest}`, then the errors, of the one packet");
}

/// Appends `line` and a line break to the description being built.
fn line(description: &mut String, line: &str) {
    writeln!(description, "{line}").expect("writing to a String");
}

/// Appends `levels` nested inline structures named `s` at `indent`, each an array of one element
/// with the `if:` condition `condition(level)`, and holding a `uint8` named `v` and the next level.
fn nested_structures(description: &mut String, indent: &str, levels: usize, condition: impl Fn(usize) -> String) {
    let mut indent = indent.to_owned();
    for level in 0..levels {
        line(description, &format!("{indent}- name: s\n{indent}  if: {}\n{indent}  count: 1", condition(level)));
        line(description, &format!("{indent}  fields:"));
        indent.push_str("    ");
        line(description, &format!("{indent}- {{ name: v, type: uint8 }}"));
    }
}

/// 1,000 Fields at the top level: 500 lengths, each the size of the `bytes` Field after it, so
/// half of them are also kept for an Expression.
#[test]
fn a_thousand_fields() {
    let mut description = "name: demo\nfields:\n".to_owned();
    for i in 0..500 {
        line(&mut description, &format!("  - {{ name: len{i}, type: uint8 }}"));
        line(&mut description, &format!("  - {{ name: data{i}, type: bytes, size: len{i} }}"));
    }
    let bytes: Vec<u8> = (0..=u8::MAX).cycle().take(500).flat_map(|byte| [1, byte]).collect();
    check("thousand-fields", &description, &bytes, "demo.data499", "f3");
}

/// 64 Types in a chain: each holds a `uint8` and a Field of the next, so the `uint8` of the last
/// is 64 deep, as deep as a Field may be.
#[test]
fn sixty_four_chained_types() {
    let mut description = "name: demo\nfields:\n  - { name: t, type: T0 }\ntypes:\n".to_owned();
    for i in 0..64 {
        line(&mut description, &format!("  T{i}:\n    fields:\n      - {{ name: a, type: uint8 }}"));
        if i < 63 {
            line(&mut description, &format!("      - {{ name: next, type: T{} }}", i + 1));
        }
    }
    let deepest = format!("demo.t{}.a", ".next".repeat(63));
    check("chained-types", &description, &[7; 64], &deepest, "7");
}

/// 500 Types, each used by one top-level Field.
#[test]
fn five_hundred_types_used_at_the_top_level() {
    let mut description = "name: demo\nfields:\n".to_owned();
    for i in 0..500 {
        line(&mut description, &format!("  - {{ name: f{i}, type: T{i} }}"));
    }
    description.push_str("types:\n");
    for i in 0..500 {
        line(&mut description, &format!("  T{i}:\n    fields:\n      - {{ name: a, type: uint8 }}"));
    }
    check("flat-types", &description, &[9; 500], "demo.f499.a", "9");
}

/// 64 levels of inline structures, each conditional on the `uint8` before it and an array of one
/// element, holding a `uint8` and the next level: the last `uint8` is 64 deep, as deep as a Field
/// may be. The last condition is an Expression nearly as deep as ADR 0018 allows, which must load
/// however deep it is in the description.
#[test]
fn sixty_four_nested_inline_structures() {
    let mut description = "name: demo\nfields:\n  - { name: v, type: uint8 }\n".to_owned();
    nested_structures(&mut description, "  ", 64, |level| {
        if level == 63 { format!("\"v{}\"", "+0".repeat(60)) } else { "v".to_owned() }
    });
    let deepest = format!("demo{}.v", ".s".repeat(64));
    check("nested-structures", &description, &[1; 65], &deepest, "1");
}

/// 50 levels of inline structures inside a Type, the first conditional on a value of its caller's.
#[test]
fn fifty_nested_inline_structures_in_a_type() {
    let mut description =
        "name: demo\nfields:\n  - { name: n, type: uint8 }\n  - { name: t, type: T }\ntypes:\n  T:\n    fields:\n"
            .to_owned();
    nested_structures(&mut description, "      ", 50, |level| if level == 0 { "n" } else { "v" }.to_owned());
    let deepest = format!("demo.t{}.v", ".s".repeat(50));
    check("nested-structures-in-a-type", &description, &[1; 51], &deepest, "1");
}

/// 63 levels of inline structures inside a Type, whose caller reads the deepest value, 64 deep,
/// as deep as a Field may be: the Type returns it in a table nested as deep.
#[test]
fn a_value_read_64_fields_deep_in_a_type() {
    let mut description = "name: demo\nfields:\n  - { name: t, type: T }\n".to_owned();
    let path = format!("t{}.v", ".s".repeat(63));
    line(&mut description, &format!("  - {{ name: data, type: bytes, size: \"{path}\" }}"));
    description.push_str("types:\n  T:\n    fields:\n");
    let mut indent = "      ".to_owned();
    for _ in 0..63 {
        line(&mut description, &format!("{indent}- name: s\n{indent}  fields:"));
        indent.push_str("  ");
    }
    line(&mut description, &format!("{indent}- {{ name: v, type: uint8 }}"));
    check("deep-export", &description, &[1, 0xab], "demo.data", "ab");
}
