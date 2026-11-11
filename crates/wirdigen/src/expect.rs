//! `expect:` (spec §3.10): the values a Field should hold, read in stage 2 and checked in
//! stage 4.
//!
//! An `expect:` is a value, a `"low-high"` range, or a list mixing both, read like the keys of a
//! values table. A value outside it is not an error in the packet: the Dissector adds an expert
//! info warning and goes on (§5.3).

use std::ops::{Range, RangeInclusive};

use crate::diagnostic::{Diagnostic, Name};
use crate::keys::wrong_type;
use crate::mapping::{self, Key};
use crate::yaml::{Node, Value};

/// An `expect:` as written, after stage 2: its keys are integers or ranges, not yet checked
/// against the type of the Field.
#[derive(Debug, Clone)]
pub(crate) struct RawExpect {
    /// Where the `expect` key is written, where a Field that takes none is reported.
    key: Range<usize>,
    /// Where the value is written, where an `expect:` that can never match is reported.
    span: Range<usize>,
    keys: Vec<Key>,
    /// The values as written, for the expert info: `0xcafe, "5-7"` shows as `0xcafe, 5-7`.
    text: String,
}

/// The values a validated Field should hold: a value matching none of the keys is reported when
/// the packet is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Expect {
    pub(crate) keys: Vec<Key>,
    /// The values as written, as the expert info shows them: `1, 5-7`.
    pub(crate) text: String,
}

/// Stage 2: reads the value of the `expect` key `key`: one key, or a non-empty list of keys.
pub(crate) fn read(key: &Node, node: &Node) -> Result<RawExpect, Diagnostic> {
    let read_one = |item: &Node| match &item.value {
        Value::Scalar { .. } => mapping::read_key(item),
        _ => Err(wrong_type(item.span.clone(), "an expected value must be an integer or a range")
            .with_note("write `expect: 1`, `expect: \"5-7\"` or `expect: [1, \"5-7\"]`", None)),
    };
    let items = match &node.value {
        Value::Sequence(items) if items.is_empty() => {
            return Err(wrong_type(node.span.clone(), "`expect` must list at least one value")
                .with_note("remove `expect`, or write the values the Field should hold", None));
        }
        Value::Sequence(items) => items.iter().collect(),
        _ => vec![node],
    };
    let keys = items.iter().map(|item| read_one(item)).collect::<Result<_, _>>()?;
    let texts: Vec<&str> = items
        .iter()
        .filter_map(|item| match &item.value {
            Value::Scalar { text, .. } => Some(text.trim()),
            _ => None,
        })
        .collect();
    Ok(RawExpect { key: key.span.clone(), span: node.span.clone(), keys, text: texts.join(", ") })
}

/// Stage 4: the `expect:` of a Field holding `range`, which messages call `what` and which is
/// written at `subject`. An `expect:` no value of `range` matches is the warning
/// `unreachable-expect`; it is kept, so the Dissector reports every value.
pub(crate) fn check(
    raw: &RawExpect,
    what: &str,
    subject: &Range<usize>,
    range: &RangeInclusive<i128>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Expect {
    if raw.keys.iter().all(|k| k.high < *range.start() || k.low > *range.end()) {
        diagnostics.push(
            Diagnostic::new(
                Name::UnreachableExpect,
                raw.span.clone(),
                format!("this `expect` never matches a value of {what}"),
            )
            .with_note(format!("{what} holds {} to {}", range.start(), range.end()), Some(subject.clone())),
        );
    }
    Expect { keys: raw.keys.clone(), text: raw.text.clone() }
}

/// `expect:` on a Field of a type that is not an integer or a `bool`, written `what`.
pub(crate) fn misplaced(raw: &RawExpect, what: &str) -> Diagnostic {
    Diagnostic::new(Name::IncompatibleDisplay, raw.key.clone(), format!("{what} takes no `expect`"))
        .with_note("only integer types, `bool` and sub-Fields take `expect`", None)
}
