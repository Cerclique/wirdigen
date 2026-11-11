//! Bitfields (spec §3.8): the `bits:` of an unsigned integer Field, read in stage 2 and checked
//! in stage 4.
//!
//! A bitfield declares its sub-Fields by width, most significant bit first, with
//! `{ padding: n }` entries for the bits nothing names. Wirdigen computes each sub-Field's shift
//! and mask from the widths, which must add up to the container.

use std::ops::Range;

use crate::diagnostic::{Diagnostic, Name, Severity, record};
use crate::expect::{self, Expect, RawExpect};
use crate::field::{self, Builtin, Display};
use crate::keys::{Spanned, expect_bool, expect_integer, expect_string, read_keys, wrong_type};
use crate::mapping::{self, Enums, Mapping, Subject};
use crate::yaml::{Node, Value};

/// The keys of a sub-Field, in documentation order (spec §3.8).
const KEYS: [&str; 11] =
    ["name", "width", "display", "values", "unit", "true", "false", "hidden", "expect", "label", "description"];

/// The `bits:` of a Field as written, after stage 2.
#[derive(Debug, Clone)]
pub(crate) struct RawBits {
    /// The span of the `bits` key, where a container that takes none or a mismatch of widths
    /// is reported.
    key: Range<usize>,
    /// The entries, most significant bits first.
    entries: Vec<RawBit>,
}

/// One entry of `bits:` as written.
#[derive(Debug, Clone)]
enum RawBit {
    /// A named sub-Field.
    SubField(Box<RawSubField>),
    /// `{ padding: n }`: `n` bits nothing names.
    Padding(Spanned<i64>),
}

/// A sub-Field as written, after stage 2: its keys are known and of the right kinds.
#[derive(Debug, Clone)]
struct RawSubField {
    /// The name, not yet checked against the naming rule.
    name: Spanned<String>,
    /// The number of bits, not yet checked to be at least 1.
    width: Spanned<i64>,
    /// The `display:` value, not yet checked against the displays of an unsigned integer.
    display: Option<Spanned<String>>,
    /// `hidden:`, which leaves the sub-Field out of the tree.
    hidden: Option<Spanned<bool>>,
    /// The tree text, not yet checked to be a non-empty single line.
    label: Option<Spanned<String>>,
    /// The `ProtoField` blurb, not yet checked to be a single line.
    description: Option<Spanned<String>>,
    /// `values:`, `unit:`, `true:` and `false:`, as written.
    mappings: mapping::RawMappings,
    /// `expect:`, the values the sub-Field should hold (spec §3.10).
    expect: Option<RawExpect>,
}

impl RawBit {
    /// The number of bits the entry takes, as written.
    fn width(&self) -> &Spanned<i64> {
        match self {
            Self::SubField(sub) => &sub.width,
            Self::Padding(width) => width,
        }
    }
}

/// What a path finds when it names a sub-Field of a bitfield.
pub(crate) enum Lookup {
    /// The bitfield has no sub-Field of that name.
    Missing,
    /// The sub-Field, at `shift` bits from the least significant bit.
    Found { shift: u32, width: u32 },
    /// The sub-Field exists, but the bitfield is in error (its widths, its container), which is
    /// reported already.
    Invalid,
}

impl RawBits {
    /// The span of the `bits` key.
    pub(crate) fn key(&self) -> &Range<usize> {
        &self.key
    }

    /// The named entries, in order, without the padding.
    fn sub_fields(&self) -> impl Iterator<Item = &RawSubField> {
        self.entries.iter().filter_map(|e| match e {
            RawBit::SubField(sub) => Some(sub.as_ref()),
            RawBit::Padding(_) => None,
        })
    }

    /// The names of the sub-Fields, in order.
    pub(crate) fn names(&self) -> Vec<String> {
        self.sub_fields().map(|s| s.name.value.clone()).collect()
    }

    /// Where the sub-Field `name` is in a bitfield of type `container`.
    pub(crate) fn lookup(&self, name: &str, container: Builtin) -> Lookup {
        let Some(index) = self.entries.iter().position(|e| matches!(e, RawBit::SubField(s) if s.name.value == name))
        else {
            return Lookup::Missing;
        };
        let Builtin::Int { signed: false, bytes } = container else {
            return Lookup::Invalid;
        };
        match self.shifts(bytes) {
            Some(shifts) => Lookup::Found { shift: shifts[index].0, width: shifts[index].1 },
            None => Lookup::Invalid,
        }
    }

    /// The shift and width of each entry in a container of `bytes` bytes, or `None` when a width
    /// is below 1 or the widths do not add up to the container.
    fn shifts(&self, bytes: usize) -> Option<Vec<(u32, u32)>> {
        let mut position = u32::try_from(8 * bytes).ok()?;
        let mut shifts = Vec::new();
        for entry in &self.entries {
            let width = u32::try_from(entry.width().value).ok().filter(|w| *w >= 1)?;
            position = position.checked_sub(width)?;
            shifts.push((position, width));
        }
        (position == 0).then_some(shifts)
    }
}

/// A validated sub-Field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Bit {
    pub(crate) name: String,
    /// The tree text, when `label:` gives one (spec §3.4.8).
    pub(crate) label: Option<String>,
    /// The `ProtoField` blurb, when `description:` gives one.
    pub(crate) description: Option<String>,
    /// Whether the tree leaves it out (`hidden: true`); it is still filtered.
    pub(crate) hidden: bool,
    /// The bits below it, by which its value is shifted.
    pub(crate) shift: u32,
    /// Its number of bits, from 1 to 64.
    pub(crate) width: u32,
    /// How an unsigned integer sub-Field is shown, `None` for a boolean one.
    pub(crate) display: Option<Display>,
    /// Its labels, when it has any (spec §3.4.7).
    pub(crate) mapping: Option<Mapping>,
    /// The values it should hold, when it has `expect:` (spec §3.10).
    pub(crate) expect: Option<Expect>,
}

impl Bit {
    /// The bits of the container it holds.
    pub(crate) fn mask(&self) -> u64 {
        let ones = (1_u128 << self.width) - 1;
        u64::try_from(ones << self.shift).expect("a sub-Field lies within 64 bits")
    }
}

/// Stage 2: reads the value of the `bits` key `key`, pushing its errors. `None` when it has any.
pub(crate) fn read(key: &Node, node: &Node, errors: &mut Vec<Diagnostic>) -> Option<RawBits> {
    let Value::Sequence(items) = &node.value else {
        errors.push(
            wrong_type(node.span.clone(), "`bits` must be a list of sub-Fields")
                .with_note("write `bits: [ { name: ext, width: 1 }, { padding: 7 } ]`", None),
        );
        return None;
    };
    let before = errors.len();
    let entries = items.iter().filter_map(|item| read_entry(item, errors)).collect();
    (errors.len() == before).then_some(RawBits { key: key.span.clone(), entries })
}

/// Reads one entry of `bits:`: a sub-Field, or `{ padding: n }`.
fn read_entry(node: &Node, errors: &mut Vec<Diagnostic>) -> Option<RawBit> {
    let Value::Mapping(entries) = &node.value else {
        errors.push(wrong_type(node.span.clone(), "a sub-Field is a mapping with a `name` and a `width`"));
        return None;
    };
    let is_padding = entries.iter().any(|(k, _)| matches!(&k.value, Value::Scalar { text, .. } if text == "padding"));
    if is_padding {
        let keys = read_keys(entries, &["padding"], errors);
        let value = keys.get("padding")?;
        let width = record(expect_integer(value, "padding"), errors)?;
        return Some(RawBit::Padding(Spanned { value: width, span: value.span.clone() }));
    }

    let before = errors.len();
    let keys = read_keys(entries, &KEYS, errors);
    for required in ["name", "width"] {
        if keys.get(required).is_none() && !keys.misspelt(required) {
            errors.push(Diagnostic::new(
                Name::MissingKey,
                node.span.clone(),
                format!("missing required key `{required}`"),
            ));
        }
    }
    let width = keys.get("width").and_then(|value| {
        let width = record(expect_integer(value, "width"), errors)?;
        Some(Spanned { value: width, span: value.span.clone() })
    });
    let hidden = keys.get("hidden").and_then(|value| record(expect_bool(value, "hidden"), errors));
    let expect = keys.key_of("expect").zip(keys.get("expect")).and_then(|(k, v)| record(expect::read(k, v), errors));
    let mappings = mapping::read(&keys, errors);
    let mut string_value =
        |key: &str, invalid: Name| keys.get(key).and_then(|value| record(expect_string(value, key, invalid), errors));
    let name = string_value("name", Name::InvalidFieldName);
    let display = string_value("display", Name::IncompatibleDisplay);
    let label = string_value("label", Name::InvalidLabel);
    let description = string_value("description", Name::InvalidDescription);
    match (name, width) {
        (Some(name), Some(width)) if errors.len() == before => {
            let sub = RawSubField { name, width, display, hidden, label, description, mappings, expect };
            Some(RawBit::SubField(Box::new(sub)))
        }
        _ => None,
    }
}

/// Stage 4: checks the `bits:` of a Field of the unsigned integer type `ty`, `bytes` bytes wide.
/// Returns the sub-Fields when nothing is wrong with them.
pub(crate) fn check(
    raw: &RawBits,
    ty: &Spanned<String>,
    bytes: usize,
    enums: &mut Enums<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Vec<Bit>> {
    let start = diagnostics.len();
    let mut widths_valid = true;
    for entry in &raw.entries {
        let width = entry.width();
        if width.value < 1 {
            widths_valid = false;
            diagnostics.push(
                Diagnostic::new(
                    Name::InvalidBitWidth,
                    width.span.clone(),
                    format!("a width is at least 1 bit, found `{}`", width.value),
                )
                .with_note("remove an entry that takes no bits", None),
            );
        }
    }
    let total = 8 * bytes;
    if widths_valid && raw.shifts(bytes).is_none() {
        let sum: i128 = raw.entries.iter().map(|e| i128::from(e.width().value)).sum();
        diagnostics.push(
            Diagnostic::new(
                Name::MismatchedBitWidths,
                raw.key.clone(),
                format!("these widths add up to {sum} bits, but `{}` has {total}", ty.value),
            )
            .with_note("name every bit, or cover the gaps with `{ padding: <bits> }` entries", None),
        );
    }

    let container = Builtin::Int { signed: false, bytes };
    let subs: Vec<&RawSubField> = raw.sub_fields().collect();
    let mut checked = Vec::new();
    for (index, sub) in subs.iter().enumerate() {
        field::check_name(&sub.name, subs[..index].iter().map(|s| &s.name), diagnostics);
        // A sub-Field naming an Enum uses it, whatever else is wrong with it (spec §3.4.7).
        enums.mark_used(&sub.mappings);
        let boolean = sub.width.value == 1 && sub.display.is_none() && !sub.mappings.makes_integer();
        let display = match (&sub.display, boolean) {
            (_, true) => Some(None),
            (Some(value), false) => record(Display::check(value, ty, container), diagnostics).map(Some),
            (None, false) => Some(container.displays().first().copied()),
        };
        let width = u32::try_from(sub.width.value).ok().filter(|w| (1..=64).contains(w));
        let mapping = width.and_then(|width| {
            let subject = Subject::sub_field(&sub.name.span, width, boolean);
            mapping::check(&sub.mappings, &subject, enums, diagnostics).ok()
        });
        let expect = width.map(|width| {
            sub.expect.as_ref().map(|raw| {
                let what = format!("a {width}-bit sub-Field");
                expect::check(raw, &what, &sub.name.span, &(0..=(1_i128 << width) - 1), diagnostics)
            })
        });
        field::check_text(sub.label.as_ref(), sub.description.as_ref(), diagnostics);
        checked.push((display, mapping, expect));
    }
    if diagnostics[start..].iter().any(|d| d.severity() == Severity::Error) {
        return None;
    }

    let shifts = raw.shifts(bytes).expect("the widths were checked");
    let located = raw.entries.iter().zip(shifts).filter(|(e, _)| matches!(e, RawBit::SubField(_)));
    let bits = subs
        .iter()
        .zip(checked)
        .zip(located)
        .map(|((sub, (display, mapping, expect)), (_, (shift, width)))| Bit {
            name: sub.name.value.clone(),
            label: sub.label.as_ref().map(|l| l.value.clone()),
            description: sub.description.as_ref().map(|d| d.value.clone()),
            hidden: sub.hidden.as_ref().is_some_and(|h| h.value),
            shift,
            width,
            display: display.expect("a sub-Field without errors has a display"),
            mapping: mapping.expect("a sub-Field without errors has its mappings"),
            expect: expect.expect("a sub-Field without errors has a width"),
        })
        .collect();
    Some(bits)
}
