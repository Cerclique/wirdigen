//! Large descriptions (#199): however many Fields or Types a description has, and however deep
//! it nests, its Dissector stays within Lua's per-function limits (200 locals, 255 upvalues, 255
//! registers), so tshark loads it and dissects with it.
//!
//! The descriptions are generated here rather than checked in. Each packet holds one byte per
//! `uint8`, and the test checks the last Field read, deepest in the tree, with tshark's `-T
//! fields` output rather than its JSON, too deeply nested for `serde_json` here. Success is
//! judged as for the corpus: nothing on stderr, and no `_ws.lua.error` or `_ws.malformed.expert`.
//! A chain of 500 Types is a tree deeper than Wireshark's default limit of 500 levels, a limit
//! of Wireshark's rather than of the Dissector, so tshark runs with a higher one.

use std::fmt::Write as _;
use std::fs;

use wirdigen::Source;

use super::{PORT, Scratch, enabled, path_str};

/// The tree depth tshark allows, above the 500 levels of the chain of Types and the layers
/// under it.
const MAX_TREE_DEPTH: &str = "gui.max_tree_depth:1000";

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
    fs::write(&packets, hex(bytes)).expect("the scratch directory is writable");
    let pcap = scratch.capture(&packets);
    let decode_as = format!("udp.port=={PORT},demo");
    let script = format!("lua_script:{}", path_str(&script));
    let output = scratch.run(
        "tshark",
        &[
            "-r",
            path_str(&pcap),
            "-X",
            &script,
            "-d",
            &decode_as,
            "-o",
            MAX_TREE_DEPTH,
            "-T",
            "fields",
            "-e",
            deepest,
            "-e",
            "_ws.lua.error",
            "-e",
            "_ws.malformed.expert",
        ],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.trim().is_empty(), "{name}: tshark wrote to stderr ({}):\n{stderr}", output.status);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, format!("{expected}\t\t\n"), "{name}: `{deepest}`, then the errors, of the one packet");
}

/// One packet of `bytes` as text2pcap hex, 16 bytes a line.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (line, chunk) in bytes.chunks(16).enumerate() {
        write!(out, "{:06x} ", line * 16).expect("writing to a String");
        for byte in chunk {
            write!(out, " {byte:02x}").expect("writing to a String");
        }
        out.push('\n');
    }
    out
}

/// 1,000 Fields at the top level: 500 lengths, each the size of the `bytes` Field after it, so
/// half of them are also kept for an Expression.
#[test]
fn a_thousand_fields() {
    let mut description = "name: demo\nfields:\n".to_owned();
    for i in 0..500 {
        writeln!(description, "  - {{ name: len{i}, type: uint8 }}").expect("writing to a String");
        writeln!(description, "  - {{ name: data{i}, type: bytes, size: len{i} }}").expect("writing to a String");
    }
    let bytes: Vec<u8> = (0..=u8::MAX).cycle().take(500).flat_map(|byte| [1, byte]).collect();
    check("thousand-fields", &description, &bytes, "demo.data499", "f3");
}

/// 500 Types in a chain: each holds a `uint8` and a Field of the next.
#[test]
fn five_hundred_chained_types() {
    let mut description = "name: demo\nfields:\n  - { name: t, type: T0 }\ntypes:\n".to_owned();
    for i in 0..500 {
        writeln!(description, "  T{i}:\n    fields:\n      - {{ name: a, type: uint8 }}").expect("writing to a String");
        if i < 499 {
            writeln!(description, "      - {{ name: next, type: T{} }}", i + 1).expect("writing to a String");
        }
    }
    let deepest = format!("demo.t{}.a", ".next".repeat(499));
    check("chained-types", &description, &[7; 500], &deepest, "7");
}

/// 500 Types, each used by one top-level Field.
#[test]
fn five_hundred_types_used_at_the_top_level() {
    let mut description = "name: demo\nfields:\n".to_owned();
    for i in 0..500 {
        writeln!(description, "  - {{ name: f{i}, type: T{i} }}").expect("writing to a String");
    }
    description.push_str("types:\n");
    for i in 0..500 {
        writeln!(description, "  T{i}:\n    fields:\n      - {{ name: a, type: uint8 }}").expect("writing to a String");
    }
    check("flat-types", &description, &[9; 500], "demo.f499.a", "9");
}

/// 50 levels of inline structures, each conditional on the `uint8` before it and an array of one
/// element, holding a `uint8` and the next level. The last condition is an Expression nearly as
/// deep as ADR 0018 allows, which must load however deep it is in the description.
#[test]
fn fifty_nested_inline_structures() {
    let mut description = "name: demo\nfields:\n  - { name: v, type: uint8 }\n".to_owned();
    let mut indent = "  ".to_owned();
    for level in 0..50 {
        let condition = if level == 49 { format!("\"v{}\"", "+0".repeat(60)) } else { "v".to_owned() };
        writeln!(description, "{indent}- name: s\n{indent}  if: {condition}\n{indent}  count: 1\n{indent}  fields:")
            .expect("writing to a String");
        indent.push_str("    ");
        writeln!(description, "{indent}- {{ name: v, type: uint8 }}").expect("writing to a String");
    }
    let deepest = format!("demo{}.v", ".s".repeat(50));
    check("nested-structures", &description, &[1; 51], &deepest, "1");
}

/// The same 50 levels inside a Type, the first conditional on a value of its caller's.
#[test]
fn fifty_nested_inline_structures_in_a_type() {
    let mut description =
        "name: demo\nfields:\n  - { name: n, type: uint8 }\n  - { name: t, type: T }\ntypes:\n  T:\n    fields:\n"
            .to_owned();
    let mut indent = "      ".to_owned();
    for level in 0..50 {
        let condition = if level == 0 { "n" } else { "v" };
        writeln!(description, "{indent}- name: s\n{indent}  if: {condition}\n{indent}  count: 1\n{indent}  fields:")
            .expect("writing to a String");
        indent.push_str("    ");
        writeln!(description, "{indent}- {{ name: v, type: uint8 }}").expect("writing to a String");
    }
    let deepest = format!("demo.t{}.v", ".s".repeat(50));
    check("nested-structures-in-a-type", &description, &[1; 51], &deepest, "1");
}
