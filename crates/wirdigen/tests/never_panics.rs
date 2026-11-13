//! `validate` never panics (spec §10.7): arbitrary bytes and mutations of the corpus descriptions
//! go through `validate`, and every resulting Diagnostic is rendered in each mode.
//!
//! `PROPTEST_CASES` sets the number of cases. Nothing is persisted between runs: a shrunk failure
//! becomes a corpus case instead, under `tests/diagnostics/<name>/` for the Diagnostic it should
//! report, or `tests/valid/` when it is valid.

use std::fs;
use std::path::{Path, PathBuf};

use proptest::prelude::*;
use proptest::sample::Index;
use proptest::test_runner::Config;
use wirdigen::{RenderOptions, Source};

/// Validates `text` and renders whatever Diagnostics come out, with and without colour and
/// denied warnings, so a panic anywhere on that path fails the case.
fn validate_and_render(text: String) {
    let source = Source::new("fuzz.wirdigen.yaml", text);
    match wirdigen::validate(&source) {
        Ok(valid) => {
            for warning in valid.warnings() {
                for options in render_modes() {
                    let _ = warning.render(&source, &options);
                }
            }
        }
        Err(diagnostics) => {
            let _ = diagnostics.to_string();
            for options in render_modes() {
                let _ = diagnostics.render(&source, &options);
            }
        }
    }
}

/// Every combination of the render options.
fn render_modes() -> impl Iterator<Item = RenderOptions> {
    [(false, false), (false, true), (true, false), (true, true)].into_iter().map(|(color, deny_warnings)| {
        // `RenderOptions` is non-exhaustive, so it is built from its default.
        let mut options = RenderOptions::default();
        options.color = color;
        options.deny_warnings = deny_warnings;
        options
    })
}

/// The text of every `.wirdigen.yaml` under `tests/`, in a stable order.
fn corpus() -> Vec<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut paths = Vec::new();
    collect(&root, &mut paths);
    paths.sort();
    paths.iter().map(|path| fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))).collect()
}

fn collect(dir: &Path, paths: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.unwrap_or_else(|e| panic!("{}: {e}", dir.display())).path();
        if path.is_dir() {
            collect(&path, paths);
        } else if path.to_str().is_some_and(|p| p.ends_with(".wirdigen.yaml")) {
            paths.push(path);
        }
    }
}

/// Fragments worth splicing into a description: YAML syntax, the description's keys and type
/// names, Expression operators, and numbers and characters at the edges.
#[rustfmt::skip]
const TOKENS: &[&str] = &[
    "\n", "\r\n", "\t", " ", "  ", "- ", ": ", ":", "{", "}", "[", "]", ",", "#", "&a ", "*a", "!!str ", "<<: ",
    "---\n", "...\n", "|\n", ">-\n", "'", "\"", "\\", "~", "null", "true", "false", "name", "title", "type",
    "fields", "types", "enums", "values", "registration", "framing", "endian", "info", "allow", "size", "count",
    "repeat", "until", "bits", "padding", "switch", "on", "cases", "default", "when", "expect", "handoff",
    "hidden", "display", "unit", "length", "terminator", "uint8", "uint64", "int32", "bytes", "string",
    "bool", "abs_time", "float64", "big", "little", "0", "-1", "0x", "0xffffffffffffffff",
    "18446744073709551616", "-9223372036854775809", "1e400", ".nan", "+", "-", "*", "/", "%", "<<", ">>", "&",
    "|", "^", "!", "==", "!=", "<=", "&&", "||", "(", ")", "$", ".", "é", "\u{200b}", "\u{1F600}", "\0",
];

/// One edit of a description's bytes; offsets wrap onto its current length.
#[derive(Debug, Clone, Copy)]
enum Mutation {
    Delete(Index, Index),
    Insert(Index, &'static str),
    Copy { from: Index, to: Index, at: Index },
    Byte(Index, u8),
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        (any::<Index>(), any::<Index>()).prop_map(|(a, b)| Mutation::Delete(a, b)),
        (any::<Index>(), prop::sample::select(TOKENS)).prop_map(|(at, token)| Mutation::Insert(at, token)),
        (any::<Index>(), any::<Index>(), any::<Index>()).prop_map(|(from, to, at)| Mutation::Copy { from, to, at }),
        (any::<Index>(), any::<u8>()).prop_map(|(at, byte)| Mutation::Byte(at, byte)),
    ]
}

/// A position in a description of `len` bytes, in `0..=len`.
fn offset(index: Index, len: usize) -> usize {
    index.index(len + 1)
}

/// A range of a description of `len` bytes, from two positions in either order.
fn range(a: Index, b: Index, len: usize) -> std::ops::Range<usize> {
    let (a, b) = (offset(a, len), offset(b, len));
    a.min(b)..a.max(b)
}

fn apply(bytes: &mut Vec<u8>, mutation: Mutation) {
    let len = bytes.len();
    match mutation {
        Mutation::Delete(a, b) => {
            bytes.drain(range(a, b, len));
        }
        Mutation::Insert(at, token) => {
            let at = offset(at, len);
            bytes.splice(at..at, token.bytes());
        }
        Mutation::Copy { from, to, at } => {
            let copied = bytes[range(from, to, len)].to_vec();
            let at = offset(at, len);
            bytes.splice(at..at, copied);
        }
        Mutation::Byte(at, byte) => {
            if len > 0 {
                bytes[at.index(len)] = byte;
            }
        }
    }
}

/// A corpus description under a few mutations.
fn mutated_description() -> impl Strategy<Value = String> {
    (prop::sample::select(corpus()), prop::collection::vec(mutation(), 1..8)).prop_map(|(text, mutations)| {
        let mut bytes = text.into_bytes();
        for mutation in mutations {
            apply(&mut bytes, mutation);
        }
        String::from_utf8_lossy(&bytes).into_owned()
    })
}

/// One level of a deep Expression, wrapped around what is inside it.
#[derive(Debug, Clone, Copy)]
enum Level {
    Parenthesis,
    Unary(&'static str),
    /// A binary operator after what is inside, as in a flat chain `a+a+…+a`.
    Right(&'static str),
    /// A binary operator before what is inside, nesting to the right.
    Left(&'static str),
}

fn level() -> impl Strategy<Value = Level> {
    let binary = prop::sample::select(&["+", "-", "*", "<<", "&", "==", "&&", "||"][..]);
    prop_oneof![
        Just(Level::Parenthesis),
        prop::sample::select(&["-", "!", "~"][..]).prop_map(Level::Unary),
        binary.clone().prop_map(Level::Right),
        binary.prop_map(Level::Left),
    ]
}

/// A description reading a Field `x`, then bytes sized by an Expression around depth 64
/// (ADR 0018) or far deeper: runs of parentheses, unary and binary operators around `x`.
fn deep_expression() -> impl Strategy<Value = String> {
    let run = (level(), prop_oneof![1..40_usize, 60..70_usize, 1_000..20_000_usize]);
    prop::collection::vec(run, 1..6).prop_map(|runs| {
        // What goes before `x`, innermost first, and what goes after it.
        let (mut before, mut after) = (Vec::new(), String::new());
        for (level, count) in runs {
            for _ in 0..count {
                match level {
                    Level::Parenthesis => {
                        before.push("(".to_owned());
                        after.push(')');
                    }
                    Level::Unary(op) => before.push(op.to_owned()),
                    Level::Right(op) => {
                        after.push_str(op);
                        after.push('1');
                    }
                    Level::Left(op) => before.push(format!("1{op}")),
                }
            }
        }
        before.reverse();
        let expression = format!("{}x{after}", before.concat());
        format!("name: demo\nfields:\n  - {{ name: x, type: uint8 }}\n  - {{ name: data, type: bytes, size: \"{expression}\" }}\n")
    })
}

/// No regression files: shrunk failures become corpus cases (see the module docs). The case count
/// stays the default, which `PROPTEST_CASES` overrides.
fn config() -> Config {
    Config { failure_persistence: None, ..Config::default() }
}

proptest! {
    #![proptest_config(config())]

    /// Any bytes, decoded the lossy way, as a description.
    #[test]
    fn arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        validate_and_render(String::from_utf8_lossy(&bytes).into_owned());
    }

    /// Any text, so multi-byte characters land where spans and columns are computed.
    #[test]
    fn arbitrary_text(text in any::<String>()) {
        validate_and_render(text);
    }

    /// A corpus description with a few bytes deleted, inserted, copied or overwritten.
    #[test]
    fn mutated_corpus(text in mutated_description()) {
        validate_and_render(text);
    }

    /// An Expression nested near the depth limit or far past it.
    #[test]
    fn deep_expressions(text in deep_expression()) {
        validate_and_render(text);
    }
}

#[test]
fn corpus_is_found() {
    // `cases/`, `diagnostics/`, `render/` and `valid/` hold well over a hundred.
    assert!(corpus().len() > 100);
}
