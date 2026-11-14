//! The coverage stress Description uses every feature at least once (#216).
//!
//! `tests/stress/coverage.wirdigen.yaml` is walked through the private model. Each module records
//! the variants of its enums with [`variants!`], whose `match` has no `_` arm: a new variant does
//! not compile until it is given a name, and then this test fails until the file uses it.

use std::collections::{BTreeMap, BTreeSet};

use crate::description;
use crate::registration::Transport;
use crate::yaml;

/// Records the variant `$value` is, after registering every variant of `$enum`, each given by a
/// pattern and its name. The `match` has no `_` arm, so every variant must be listed.
macro_rules! variants {
    ($coverage:expr, $enum:literal, $value:expr, { $($pattern:pat => $name:literal),+ $(,)? }) => {{
        let coverage: &mut $crate::coverage::Coverage = $coverage;
        coverage.expect($enum, &[$($name),+]);
        let seen = match $value { $($pattern => $name),+ };
        coverage.saw($enum, seen);
    }};
}
pub(crate) use variants;

/// What a walk over a Protocol Description saw.
#[derive(Debug, Default)]
pub(crate) struct Coverage<'s> {
    /// The source, for the text of each Expression.
    pub(crate) source: &'s str,
    /// Every variant of each enum met, by enum.
    expected: BTreeMap<&'static str, BTreeSet<&'static str>>,
    /// The variants seen, by enum.
    seen: BTreeMap<&'static str, BTreeSet<&'static str>>,
    /// The names in the `type:` of Fields: built-in types and Types.
    pub(crate) types: BTreeSet<String>,
    /// The dissectors named by `dissector:`.
    pub(crate) dissectors: BTreeSet<String>,
}

impl Coverage<'_> {
    /// Registers `variants` as every variant of the enum `name`.
    pub(crate) fn expect(&mut self, name: &'static str, variants: &[&'static str]) {
        self.expected.entry(name).or_default().extend(variants);
    }

    /// Records that the walk met `variant` of the enum `name`.
    pub(crate) fn saw(&mut self, name: &'static str, variant: &'static str) {
        self.seen.entry(name).or_default().insert(variant);
    }
}

/// The enums whose [`variants!`] the walk must reach, by the name each passes: an enum never
/// reached would hide all its variants.
const ENUMS: [&str; 20] = [
    "RawEntry",
    "RawKind",
    "RawLength",
    "RawAmount",
    "RawArray",
    "RawBody",
    "RawValues",
    "RawUnit",
    "RawBit",
    "Endian",
    "Display",
    "Encoding",
    "ExprKind",
    "Builtin",
    "UnaryOp",
    "BinaryOp",
    "TokenKind",
    "Piece",
    "Place",
    "Transport",
];

#[test]
fn the_coverage_description_uses_every_feature() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/stress/coverage.wirdigen.yaml");
    let text = std::fs::read_to_string(path).expect("the coverage stress Description is committed");
    let root = yaml::parse(&text).expect("the coverage Description is YAML");
    let raw = description::deserialize(root.as_ref()).expect("the coverage Description deserializes");
    let raw = raw.parsed().expect("the coverage Description's Expressions parse");
    let (protocol, diagnostics) = description::check(&raw);
    let protocol = protocol.unwrap_or_else(|| panic!("the coverage Description is invalid: {diagnostics:?}"));
    assert!(diagnostics.is_empty(), "the coverage Description has warnings: {diagnostics:?}");

    let mut coverage = Coverage { source: &text, ..Coverage::default() };
    raw.cover(&mut coverage);
    crate::framing::cover_places(&protocol, &mut coverage);

    for name in ENUMS {
        assert!(coverage.expected.contains_key(name), "the walk never met a `{name}`");
    }
    let missing: Vec<String> = coverage
        .expected
        .iter()
        .flat_map(|(name, all)| {
            let seen = coverage.seen.get(name).cloned().unwrap_or_default();
            all.difference(&seen).map(move |variant| format!("{name}::{variant}")).collect::<Vec<_>>()
        })
        .collect();
    assert!(missing.is_empty(), "the coverage Description uses none of: {missing:?}");

    let unused: Vec<&str> = crate::field::builtin_names().filter(|n| !coverage.types.contains(*n)).collect();
    assert!(unused.is_empty(), "the coverage Description has no Field of type: {unused:?}");

    let builtin = crate::builtin::filter_names();
    for transport in Transport::ALL {
        assert!(builtin.contains(transport.key()), "`{}` is not a built-in protocol", transport.key());
    }
    assert!(!coverage.dissectors.is_empty(), "the coverage Description hands off to no dissector");
    for dissector in &coverage.dissectors {
        assert!(builtin.contains(dissector.as_str()), "`{dissector}` is not a built-in protocol");
    }
}
