//! `framing:` (spec §3.13): how a Dissector finds each Message in a TCP stream, from a constant
//! header size and a length Expression over the Fields of that header.
//!
//! Read in stage 2, its Expression parsed then; its references are checked in stage 4 against
//! the checked top-level layout, where every Field's place is known.

use std::collections::BTreeMap;
use std::ops::Range;

use crate::diagnostic::{Diagnostic, Name, record};
use crate::expr::{Expr, ExprKind, Fault};
use crate::field::{Amount, Array, Builtin, Entry, Field, FieldKind, Length, Parse, RawAmount, read_amount};
use crate::index::FieldId;
use crate::keys::{Spanned, expect_integer, read_keys, wrong_type};
use crate::scope::{self, Reference};
use crate::types::{NamedTypes, TypeUse};
use crate::yaml::{Node, Value};

/// The keys of `framing:`, both required.
pub(crate) const KEYS: [&str; 2] = ["header", "length"];

/// A `framing:` as written, after stage 2.
#[derive(Debug, Clone)]
pub(crate) struct RawFraming<E = Expr> {
    /// `header:`, the bytes `length` is computed from.
    header: Spanned<i64>,
    /// `length:`, the whole Message's length.
    length: Spanned<RawAmount<E>>,
}

/// Where a top-level Field lies in every Message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Extent {
    /// Its offset from the start of the Message.
    pub(crate) offset: usize,
    /// The bytes it reads.
    pub(crate) size: usize,
}

impl Extent {
    /// The offset just after it. Placing checked that it does not overflow.
    fn end(self) -> usize {
        self.offset + self.size
    }
}

/// A checked `framing:`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Framing {
    /// The bytes needed to compute the length, at least 1.
    pub(crate) header: usize,
    /// The whole Message's length. A constant one is at least `header`; an Expression reads
    /// only top-level Fields, and their sub-Fields, inside the header.
    pub(crate) length: Amount,
    /// Each top-level Field the length reads, by name.
    pub(crate) reads: BTreeMap<String, HeaderField>,
}

/// A top-level Field of the header the length reads, itself or through a sub-Field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeaderField {
    /// The Field's declaration, an integer or a `bool`, or a bitfield.
    pub(crate) target: FieldId,
    /// Where it lies in every Message.
    pub(crate) extent: Extent,
}

/// Stage 2: reads `framing:`, pushing its errors.
pub(crate) fn read(node: &Node, errors: &mut Vec<Diagnostic>) -> Option<RawFraming<Parse>> {
    let Value::Mapping(entries) = &node.value else {
        errors.push(
            wrong_type(node.span.clone(), "`framing` must be a mapping")
                .with_note("write `framing: { header: 2, length: \"len + 2\" }`", None),
        );
        return None;
    };
    let keys = read_keys(entries, &KEYS, errors);
    for key in KEYS {
        if keys.get(key).is_none() && !keys.misspelt(key) {
            errors.push(Diagnostic::new(Name::MissingKey, node.span.clone(), format!("`framing` needs `{key}`")));
        }
    }
    let header = keys.get("header").and_then(|value| {
        let header = record(expect_integer(value, "header"), errors)?;
        Some(Spanned { value: header, span: value.span.clone() })
    });
    let length = keys.get("length").and_then(|value| {
        let length = record(read_amount(value, "length"), errors)?;
        Some(Spanned { value: length, span: value.span.clone() })
    });
    Some(RawFraming { header: header?, length: length? })
}

impl RawFraming<Parse> {
    /// Stage 3: the framing with its `length` Expression parsed, `None` after pushing its
    /// syntax error.
    pub(crate) fn parsed(self, errors: &mut Vec<Diagnostic>) -> Option<RawFraming> {
        Some(RawFraming { header: self.header, length: self.length.parsed(errors)? })
    }
}

/// Stage 4: checks `framing:` against the checked top-level layout `top`.
pub(crate) fn check(
    raw: &RawFraming,
    top: &[Entry],
    types: &NamedTypes,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Framing> {
    let header = match usize::try_from(raw.header.value) {
        Ok(header) if header > 0 => header,
        _ => {
            diagnostics.push(
                Diagnostic::new(Name::InvalidFraming, raw.header.span.clone(), "a framing `header` is at least 1 byte")
                    .with_note("`header` is the number of bytes `length` is computed from", None),
            );
            return None;
        }
    };
    let span = raw.length.span.clone();
    let expression = match &raw.length.value {
        RawAmount::Constant(value) => {
            return check_constant(*value, header, span, diagnostics).map(|length| Framing {
                header,
                length: Amount::Constant(length),
                reads: BTreeMap::new(),
            });
        }
        RawAmount::Expression(expression) => expression,
    };
    if let Some(value) = expression.constant() {
        let value = match value {
            Ok(value) => value,
            Err(fault) => {
                let message = match fault.value {
                    Fault::DivisionByZero => "this length divides by zero".to_owned(),
                    Fault::ShiftOutOfRange(count) => format!("this length shifts by {count}, outside 0 to 63"),
                };
                diagnostics.push(Diagnostic::new(Name::InvalidFraming, fault.span, message));
                return None;
            }
        };
        check_constant(value, header, span, diagnostics)?;
        let length = Amount::Expression { expr: expression.clone(), references: BTreeMap::new() };
        return Some(Framing { header, length, reads: BTreeMap::new() });
    }
    let places = places(top, types);
    let mut references = BTreeMap::new();
    let mut reads = BTreeMap::new();
    let mut ok = true;
    for reference in expression.references() {
        match resolve(reference, header, top, &places) {
            Ok((segments, resolved, place)) => {
                reads.insert(segments[0].clone(), place);
                references.insert(segments.clone(), resolved);
            }
            Err(diagnostic) => {
                diagnostics.push(diagnostic);
                ok = false;
            }
        }
    }
    ok.then(|| Framing { header, length: Amount::Expression { expr: expression.clone(), references }, reads })
}

/// A constant length, which must cover the header.
fn check_constant(value: i64, header: usize, span: Range<usize>, diagnostics: &mut Vec<Diagnostic>) -> Option<usize> {
    match usize::try_from(value) {
        Ok(length) if length >= header => Some(length),
        _ => {
            diagnostics.push(
                Diagnostic::new(
                    Name::InvalidFraming,
                    span,
                    format!("a Message of {value} bytes is shorter than its {header}-byte header"),
                )
                .with_note("`length` is the whole Message's length, its header included", None),
            );
            None
        }
    }
}

/// What resolving a reference of the length gives: its path, what it reads, and the top-level
/// Field it reads.
type Resolved<'e> = (&'e Vec<String>, Reference, HeaderField);

/// Resolves one reference of the length: a top-level Field or one of its sub-Fields, lying
/// entirely inside the first `header` bytes (spec §3.13).
fn resolve<'e>(
    reference: &'e Expr,
    header: usize,
    top: &[Entry],
    places: &BTreeMap<&str, Place>,
) -> Result<Resolved<'e>, Diagnostic> {
    let span = reference.span.clone();
    let segments = match &reference.kind {
        ExprKind::Path(segments) => segments,
        ExprKind::Builtin(builtin) => {
            return Err(Diagnostic::new(
                Name::InvalidFraming,
                span,
                format!("a framing `length` cannot read `{}`", builtin.as_str()),
            )
            .with_note("the length is computed from the header alone, before the Message is read", None));
        }
        _ => unreachable!("references are paths and built-ins"),
    };
    let key = segments.join(".");
    let fields: Vec<&Field> = top.iter().filter_map(Entry::field).collect();
    let Some(field) = fields.iter().find(|f| f.name == segments[0]) else {
        let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
        let otherwise = "a framing `length` reads the top-level Fields of the header";
        return Err(scope::unknown_top_level(&segments[0], &names, otherwise, span));
    };
    let nested = || {
        Diagnostic::new(
            Name::InvalidFraming,
            span.clone(),
            format!("a framing `length` reads only top-level Fields and their sub-Fields, not `{key}`"),
        )
    };
    let FieldKind::Builtin(builtin) = &field.kind else {
        if segments.len() > 1 {
            return Err(nested());
        }
        return Err(Diagnostic::new(
            Name::NonNumericReference,
            span,
            format!("`{key}` is a structure, not an integer, a bitfield sub-Field or a `bool`"),
        )
        .with_note(format!("`{}` is declared here", field.name), Some(field.span.clone())));
    };
    let resolved = match &segments[1..] {
        [] if matches!(builtin.kind.builtin(), Builtin::Int { .. } | Builtin::Bool) => {
            Reference::Field { path: segments.clone(), target: field.id }
        }
        [] => {
            return Err(Diagnostic::new(
                Name::NonNumericReference,
                span,
                format!(
                    "`{key}` is a `{}`, not an integer, a bitfield sub-Field or a `bool`",
                    builtin.kind.builtin().name()
                ),
            )
            .with_note(format!("`{key}` is declared here"), Some(field.span.clone())));
        }
        [sub] => match builtin.kind.sub_fields().iter().find(|b| &b.name == sub) {
            Some(bit) => Reference::Bits { path: segments[..1].to_vec(), target: bit.id },
            None => {
                return Err(Diagnostic::new(
                    Name::UnknownField,
                    span,
                    format!("`{}` has no sub-Field named `{sub}`", field.name),
                ));
            }
        },
        _ => return Err(nested()),
    };
    let outside = |why: String| {
        Diagnostic::new(
            Name::InvalidFraming,
            span.clone(),
            format!("`{key}` does not lie within the {header}-byte header"),
        )
        .with_note(why, Some(field.span.clone()))
    };
    match places[field.name.as_str()] {
        Place::At(extent) if extent.end() <= header => {
            Ok((segments, resolved, HeaderField { target: field.id, extent }))
        }
        Place::At(extent) => {
            Err(outside(format!("`{}` is bytes {} to {} of the Message", field.name, extent.offset, extent.end())))
        }
        Place::Conditional => Err(outside(format!("`{}` is read only when its `if:` holds", field.name))),
        Place::Unknown => {
            Err(outside(format!("`{}` comes after a Field whose size is known only once it is read", field.name)))
        }
    }
}

/// Where a top-level Field lies, if it lies at the same place in every Message.
#[derive(Debug, Clone, Copy)]
enum Place {
    /// Always there.
    At(Extent),
    /// Read only when its `if:` holds.
    Conditional,
    /// After an entry whose size is known only when the Message is read, or of such a size.
    Unknown,
}

/// The place of each top-level Field, by name.
fn places<'t>(top: &'t [Entry], types: &NamedTypes) -> BTreeMap<&'t str, Place> {
    let mut places = BTreeMap::new();
    let mut offset = Some(0_usize);
    for entry in top {
        let size = entry_size(entry, types);
        if let Entry::Field(field) = entry {
            let place = match (field.condition.is_some(), offset, size) {
                (true, ..) => Place::Conditional,
                (false, Some(offset), Some(size)) if offset.checked_add(size).is_some() => {
                    Place::At(Extent { offset, size })
                }
                _ => Place::Unknown,
            };
            places.insert(field.name.as_str(), place);
        }
        offset = offset.zip(size).and_then(|(offset, size)| offset.checked_add(size));
    }
    places
}

/// The bytes an entry reads in every Message, when they are known before it is read.
fn entry_size(entry: &Entry, types: &NamedTypes) -> Option<usize> {
    match entry {
        Entry::Padding(Amount::Constant(size)) => Some(*size),
        Entry::Padding(Amount::Expression { .. }) => None,
        Entry::Field(field) => field_size(field, types),
    }
}

/// The bytes a Field reads in every Message, when they are known before it is read.
fn field_size(field: &Field, types: &NamedTypes) -> Option<usize> {
    if field.condition.is_some() {
        return None;
    }
    let element = match &field.kind {
        FieldKind::Builtin(builtin) => match builtin.length {
            Length::Constant(size) => Some(size),
            _ => None,
        },
        FieldKind::Structure(entries) => structure_size(entries, types),
        FieldKind::Type(TypeUse { id, .. }) => structure_size(&types.get(*id).fields, types),
        FieldKind::Switch(_) => None,
    }?;
    match &field.array {
        None => Some(element),
        Some(Array::Count(Amount::Constant(count))) => element.checked_mul(*count),
        Some(_) => None,
    }
}

/// The bytes the entries of a structure read in every Message, when they are known before it is
/// read.
fn structure_size(entries: &[Entry], types: &NamedTypes) -> Option<usize> {
    entries.iter().try_fold(0usize, |total, entry| total.checked_add(entry_size(entry, types)?))
}

#[cfg(test)]
impl RawFraming {
    /// Records the parts of the `length` Expression.
    pub(crate) fn cover(&self, coverage: &mut crate::coverage::Coverage<'_>) {
        self.length.value.cover(coverage);
    }
}

/// Records where each top-level Field of `protocol` lies in every Message.
#[cfg(test)]
pub(crate) fn cover_places(protocol: &crate::description::Protocol, coverage: &mut crate::coverage::Coverage<'_>) {
    use crate::coverage::variants;
    for place in places(&protocol.fields, &protocol.types).values() {
        variants!(coverage, "Place", place, {
            Place::At(_) => "At",
            Place::Conditional => "Conditional",
            Place::Unknown => "Unknown",
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::Source;

    #[test]
    fn a_header_after_fixed_structures_and_padding_is_placed() {
        let text = "name: demo\nframing: { header: 8, length: \"len + 8\" }\nfields:\n  - { name: hdr, fields: [ { name: a, type: uint16 } ] }\n  - { padding: 2 }\n  - { name: len, type: uint32 }\n";
        assert!(crate::validate(&Source::new("case", text)).is_ok());
    }

    #[test]
    fn huge_constant_sizes_before_the_header_do_not_overflow() {
        let huge = "{ name: x, type: bytes, size: 0x7FFF_FFFF_FFFF_FFFF }";
        let text = format!(
            "name: demo\nframing: {{ header: 1, length: \"c + 1\" }}\nfields:\n  - {huge}\n  - {huge}\n  - {huge}\n  - {{ name: c, type: uint8 }}\n"
        );
        assert!(crate::validate(&Source::new("case", text.as_str())).is_err());
    }

    #[test]
    fn a_constant_length_needs_no_reference() {
        let text = "name: demo\nframing: { header: 2, length: 16 }\nfields:\n  - { name: a, type: uint16 }\n";
        assert!(crate::validate(&Source::new("case", text)).is_ok());
    }
}
