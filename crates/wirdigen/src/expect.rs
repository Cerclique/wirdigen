//! `expect:` (spec §3.10): the values a Field should hold, read in stage 2 and checked in
//! stage 4.
//!
//! An `expect:` is a value, a `"low-high"` range, or a list mixing both, read like the keys of a
//! values table. A value outside it is not an error in the packet: the Dissector adds an expert
//! info warning and goes on (§5.3).

use std::ops::{Range, RangeInclusive};

use crate::diagnostic::{Diagnostic, Name, record};
use crate::field::Builtin;
use crate::keys::{Keys, Spanned, wrong_type};
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
    /// The values expected, each one value or a range.
    keys: Vec<Key>,
    /// The values as written, for the expert info: `0xcafe, "5-7"` shows as `0xcafe, 5-7`.
    text: String,
}

/// The values a validated Field should hold: a value matching none of the keys is reported when
/// the packet is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Expect {
    /// The values expected, each one value or a range.
    pub(crate) keys: Vec<Key>,
    /// The values as written, as the expert info shows them: `1, 5-7`.
    pub(crate) text: String,
}

/// What a Field whose `expect:` is checked holds.
pub(crate) struct Subject {
    /// How messages name it: "`uint8`", "a 3-bit sub-Field".
    what: String,
    /// Where it is written, which the note of `unreachable-expect` points at.
    span: Range<usize>,
    /// The values it can hold, as Expressions read them (§4.4).
    range: RangeInclusive<i128>,
}

impl Subject {
    /// A Field of the built-in type `builtin`, written `ty`: an integer, or a `bool`, which holds
    /// 0 or 1. `Err` with the `incompatible-display` error for any other type, which takes no
    /// `expect:`.
    pub(crate) fn builtin(raw: &RawExpect, ty: &Spanned<String>, builtin: Builtin) -> Result<Self, Diagnostic> {
        let what = format!("`{}`", ty.value);
        let range = match builtin {
            Builtin::Bool => Some(0..=1),
            _ => builtin.int_range(),
        };
        match range {
            Some(range) => Ok(Self { what, span: ty.span.clone(), range }),
            None => {
                Err(Diagnostic::new(Name::IncompatibleDisplay, raw.key.clone(), format!("{what} takes no `expect`"))
                    .with_note("only integer types, `bool` and sub-Fields take `expect`", None))
            }
        }
    }

    /// A bitfield sub-Field `width` bits wide whose name is at `name` (spec §3.8).
    pub(crate) fn sub_field(name: &Range<usize>, width: u32) -> Self {
        Self { what: format!("a {width}-bit sub-Field"), span: name.clone(), range: 0..=(1_i128 << width) - 1 }
    }
}

/// Stage 2: reads the `expect:` of a Field or a sub-Field, if it has one, pushing its error.
pub(crate) fn read(keys: &Keys<'_>, errors: &mut Vec<Diagnostic>) -> Option<RawExpect> {
    let (key, value) = keys.key_of("expect").zip(keys.get("expect"))?;
    record(read_value(key, value), errors)
}

/// Reads the value `node` of the `expect` key `key`: one key, or a non-empty list of keys.
fn read_value(key: &Node, node: &Node) -> Result<RawExpect, Diagnostic> {
    let items: Vec<&Node> = match &node.value {
        Value::Sequence(items) if items.is_empty() => {
            return Err(wrong_type(node.span.clone(), "`expect` must list at least one value")
                .with_note("remove `expect`, or write the values the Field should hold", None));
        }
        Value::Sequence(items) => items.iter().collect(),
        _ => vec![node],
    };
    let mut keys = Vec::new();
    let mut texts = Vec::new();
    for item in items {
        let Value::Scalar { text, .. } = &item.value else {
            return Err(wrong_type(item.span.clone(), "an expected value must be an integer or a range")
                .with_note("write `expect: 1`, `expect: \"5-7\"` or `expect: [1, \"5-7\"]`", None));
        };
        keys.push(mapping::read_key(item)?);
        texts.push(text.trim());
    }
    Ok(RawExpect { key: key.span.clone(), span: node.span.clone(), keys, text: texts.join(", ") })
}

/// Stage 4: the `expect:` of a Field holding `subject`. An `expect:` no value of the subject
/// matches is the warning `unreachable-expect`; it is kept, so the Dissector reports every value.
pub(crate) fn check(raw: &RawExpect, subject: &Subject, diagnostics: &mut Vec<Diagnostic>) -> Expect {
    let Subject { what, span, range } = subject;
    if raw.keys.iter().all(|k| k.high < *range.start() || k.low > *range.end()) {
        diagnostics.push(
            Diagnostic::new(
                Name::UnreachableExpect,
                raw.span.clone(),
                format!("this `expect` never matches a value of {what}"),
            )
            .with_note(format!("{what} holds {} to {}", range.start(), range.end()), Some(span.clone())),
        );
    }
    Expect { keys: raw.keys.clone(), text: raw.text.clone() }
}
