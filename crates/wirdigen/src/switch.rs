//! `switch` Fields (spec §3.9): strict deserialization (stage 2) and semantic checks (stage 4).
//!
//! A `switch` Field picks a layout from the value of its subject, an Expression: the case whose
//! key holds the value, else `default:`. A case is a Type or inline Fields, read straight into
//! the `switch` Field's subtree, so it adds no segment to filter names (spec §5.2).

use std::ops::Range;

use crate::diagnostic::{Diagnostic, Name, record};
use crate::expr::Expr;
use crate::field::{self, Builtin, Endian, Entry, Operand, Parse, RawAmount, RawEntry};
use crate::index::TypeId;
use crate::keys::{Keys, Spanned, duplicate_key, wrong_type};
use crate::mapping::{self, Enums, Key};
use crate::scalar::{Kind, resolve_plain};
use crate::scope::{self, Reference, Scope};
use crate::types::Types;
use crate::yaml::{Node, Value};

/// The keys a `switch` Field takes, in documentation order (spec §3.9).
pub(crate) const KEYS: [&str; 8] = ["name", "label", "description", "if", "hidden", "switch", "cases", "default"];

/// A `switch` Field as written, after stage 2.
#[derive(Debug, Clone)]
pub(crate) struct RawSwitch<E = Expr> {
    /// The `switch:` value: a constant or an Expression.
    pub(crate) subject: Spanned<RawAmount<E>>,
    /// The entries of `cases:`, in source order.
    pub(crate) cases: Vec<RawCase<E>>,
    /// `default:`, with the span of its key.
    pub(crate) default: Option<(Range<usize>, RawBody<E>)>,
    /// The keys present that a `switch` Field does not take, reported in stage 4.
    pub(crate) misplaced: Vec<Spanned<&'static str>>,
}

/// One entry of `cases:` as written.
#[derive(Debug, Clone)]
pub(crate) struct RawCase<E = Expr> {
    /// The values the case matches, spanning the key.
    pub(crate) key: Spanned<Key>,
    /// The key as written, for messages.
    pub(crate) text: String,
    /// What the case reads.
    pub(crate) body: RawBody<E>,
}

/// What a case reads, as written.
#[derive(Debug, Clone)]
pub(crate) enum RawBody<E = Expr> {
    /// A Type, by name.
    Type(Spanned<String>),
    /// Inline Fields, spelled like an inline structure.
    Fields(Vec<RawEntry<E>>),
}

impl RawSwitch<Parse> {
    /// Stage 3: the `switch` Field with its subject and its cases' Expressions parsed, `None`
    /// after pushing a syntax error.
    pub(crate) fn parsed(self, errors: &mut Vec<Diagnostic>) -> Option<RawSwitch> {
        let subject = self.subject.parsed(errors);
        let cases = self
            .cases
            .into_iter()
            .map(|RawCase { key, text, body }| RawCase { key, text, body: body.parsed(errors) })
            .collect();
        let default = self.default.map(|(span, body)| (span, body.parsed(errors)));
        Some(RawSwitch { subject: subject?, cases, default, misplaced: self.misplaced })
    }
}

impl RawBody<Parse> {
    /// Stage 3: the body with its Expressions parsed, leaving out the entries with a syntax
    /// error after pushing it.
    fn parsed(self, errors: &mut Vec<Diagnostic>) -> RawBody {
        match self {
            Self::Type(name) => RawBody::Type(name),
            Self::Fields(fields) => RawBody::Fields(field::parsed(fields, errors)),
        }
    }
}

impl RawSwitch {
    /// Every layout the Field can read, with the span of the key choosing it: each case, then
    /// `default:`.
    pub(crate) fn bodies(&self) -> impl Iterator<Item = (&Range<usize>, &RawBody)> {
        self.cases.iter().map(|c| (&c.key.span, &c.body)).chain(self.default.as_ref().map(|(span, body)| (span, body)))
    }
}

/// Stage 2: reads the keys of a `switch` Field other than `name:`, given the node of its
/// `switch:` value. `None` after pushing an error.
pub(crate) fn read(
    subject: &Node,
    field: &Node,
    keys: &Keys<'_>,
    errors: &mut Vec<Diagnostic>,
) -> Option<RawSwitch<Parse>> {
    let before = errors.len();
    let amount = record(field::read_amount(subject, "switch"), errors);
    let cases = if let Some(node) = keys.get("cases") {
        read_cases(node, errors)
    } else {
        if !keys.misspelt("cases") {
            errors.push(
                Diagnostic::new(Name::MissingKey, field.span.clone(), "missing required key `cases`")
                    .with_note("a `switch` Field picks its layout from `cases`", None),
            );
        }
        None
    };
    let default = keys.key_of("default").zip(keys.get("default")).and_then(|(key, value)| {
        let body = read_body(value, errors)?;
        Some((key.span.clone(), body))
    });
    let misplaced = field::KEYS
        .iter()
        .filter(|k| !KEYS.contains(k) && !field::KIND_KEYS.contains(k))
        .filter_map(|k| keys.key_of(k).map(|key| Spanned { value: *k, span: key.span.clone() }))
        .collect();
    let subject = Spanned { value: amount?, span: subject.span.clone() };
    (errors.len() == before).then_some(RawSwitch { subject, cases: cases?, default, misplaced })
}

/// Reads `cases:`, a non-empty mapping from integers or ranges to layouts. A key written twice
/// is `duplicate-key`, as in a values table; overlapping keys are a stage 4 check.
fn read_cases(node: &Node, errors: &mut Vec<Diagnostic>) -> Option<Vec<RawCase<Parse>>> {
    let Value::Mapping(pairs) = &node.value else {
        errors.push(
            wrong_type(node.span.clone(), "`cases` must map values to layouts")
                .with_note("write `cases: { 1: Login, 2: [ { name: id, type: uint8 } ] }`", None),
        );
        return None;
    };
    if pairs.is_empty() {
        errors.push(wrong_type(node.span.clone(), "`cases` must have at least one case"));
        return None;
    }
    let before = errors.len();
    let mut cases = Vec::new();
    let mut seen: Vec<(&str, bool, &Node)> = Vec::new();
    for (key, value) in pairs {
        let text = match &key.value {
            Value::Scalar { text, plain, .. } => {
                if let Some((_, _, first)) = seen.iter().find(|(t, p, _)| t == text && p == plain) {
                    errors.push(duplicate_key(text, key, &first.span));
                    continue;
                }
                seen.push((text, *plain, key));
                text.clone()
            }
            _ => String::new(),
        };
        let parsed = record(mapping::read_key(key), errors);
        let body = read_body(value, errors);
        if let (Some(parsed), Some(body)) = (parsed, body) {
            cases.push(RawCase { key: Spanned { value: parsed, span: key.span.clone() }, text, body });
        }
    }
    (errors.len() == before).then_some(cases)
}

/// Reads a case or `default:`: a Type name or a list of Fields.
fn read_body(node: &Node, errors: &mut Vec<Diagnostic>) -> Option<RawBody<Parse>> {
    match &node.value {
        Value::Sequence(_) => field::read_structure(node, errors).map(RawBody::Fields),
        Value::Scalar { text, plain, .. } if !*plain || resolve_plain(text) == Kind::Str => {
            if Builtin::from_name(text).is_some() {
                errors.push(
                    wrong_type(node.span.clone(), format!("`{text}` is a built-in type, not a Type")).with_note(
                        format!("a case is a Type or a list of Fields: write `[ {{ name: value, type: {text} }} ]`"),
                        None,
                    ),
                );
                return None;
            }
            Some(RawBody::Type(Spanned { value: text.clone(), span: node.span.clone() }))
        }
        _ => {
            errors.push(
                wrong_type(node.span.clone(), "a case is a Type name or a list of Fields")
                    .with_note("write `Login` or `[ { name: id, type: uint8 } ]`", None),
            );
            None
        }
    }
}

/// A validated `switch` Field (spec §3.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Switch {
    /// The value the case is picked from.
    pub(crate) subject: Operand,
    /// The cases, in source order; no two match one value.
    pub(crate) cases: Vec<Case>,
    /// What is read when no case matches; without it, the rest of the message is shown raw.
    pub(crate) default: Option<Body>,
}

/// A validated case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Case {
    /// The values the case matches.
    pub(crate) key: Key,
    /// What the case reads.
    pub(crate) body: Body,
}

impl Switch {
    /// Every layout the Field can read: each case, then the default.
    pub(crate) fn bodies(&self) -> impl Iterator<Item = &Body> {
        self.cases.iter().map(|c| &c.body).chain(&self.default)
    }
}

/// What a validated case or `default:` reads, into the `switch` Field's subtree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Body {
    /// Inline Fields.
    Fields(Vec<Entry>),
    /// The Fields of a Type, read by its dissect function.
    Type {
        id: TypeId,
        /// The Type's name, for Lua names and messages.
        name: String,
        /// The context table this use passes (spec §4.3).
        context: Vec<(String, Reference)>,
    },
}

/// The values of a key as an Expression sees them, signed 64-bit integers (spec §4.4): a key
/// above `i64::MAX` is the negative value a `uint64` above 2^63 reads as, so a range crossing
/// 2^63 is two ranges.
pub(crate) fn wire_ranges(low: i128, high: i128) -> Vec<(i64, i64)> {
    let wrap =
        |v: i128| i64::try_from(if v > i128::from(i64::MAX) { v - (1 << 64) } else { v }).expect("keys fit 64 bits");
    let max = i128::from(i64::MAX);
    if low <= max && high > max {
        vec![(wrap(low), i64::MAX), (i64::MIN, wrap(high))]
    } else {
        vec![(wrap(low), wrap(high))]
    }
}

/// Stage 4: checks a `switch` Field read with the byte order `endian`, at `scope`, whose
/// cases and Types are checked like an inline structure's Fields and Fields of Types.
pub(crate) fn check<'a>(
    raw: &'a RawSwitch,
    endian: Endian,
    enums: &mut Enums<'_>,
    types: &mut Types<'a>,
    scope: Scope<'a, '_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Switch> {
    for key in &raw.misplaced {
        diagnostics.push(misplaced(key));
    }
    let subject = field::check_operand(&raw.subject.value, scope, types, diagnostics);
    check_overlaps(&raw.cases, diagnostics);
    let mut ok = raw.misplaced.is_empty();
    let mut cases = Vec::new();
    for case in &raw.cases {
        match check_body(&case.body, endian, enums, types, scope, diagnostics) {
            Some(body) => cases.push(Case { key: case.key.value, body }),
            None => ok = false,
        }
    }
    let default = match &raw.default {
        None => Some(None),
        Some((_, body)) => check_body(body, endian, enums, types, scope, diagnostics).map(Some),
    };
    let (subject, default) = (subject?, default?);
    ok.then_some(Switch { subject, cases, default })
}

/// Checks what a case or the default reads, from the scope of the `switch` Field.
fn check_body<'a>(
    body: &'a RawBody,
    endian: Endian,
    enums: &mut Enums<'_>,
    types: &mut Types<'a>,
    scope: Scope<'a, '_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Body> {
    match body {
        RawBody::Fields(fields) => Some(Body::Fields(field::check(fields, endian, enums, types, scope, diagnostics))),
        RawBody::Type(name) => types.resolve(name).and_then(|id| {
            let context = scope::resolve_context(&name.value, &name.span, scope, types, diagnostics)?;
            Some(Body::Type { id, name: name.value.clone(), context })
        }),
    }
}

/// Reports each case matching a value an earlier case matches (`overlapping-cases`), comparing
/// values as the subject has them: a key above `i64::MAX` is its negative 64-bit twin.
fn check_overlaps(cases: &[RawCase], diagnostics: &mut Vec<Diagnostic>) {
    let ranges: Vec<Vec<(i64, i64)>> = cases.iter().map(|c| wire_ranges(c.key.value.low, c.key.value.high)).collect();
    let overlap = |a: &[(i64, i64)], b: &[(i64, i64)]| a.iter().any(|x| b.iter().any(|y| x.0 <= y.1 && y.0 <= x.1));
    for (index, case) in cases.iter().enumerate() {
        if let Some(first) = (0..index).find(|&i| overlap(&ranges[i], &ranges[index])) {
            let first = &cases[first];
            diagnostics.push(
                Diagnostic::new(
                    Name::OverlappingCases,
                    case.key.span.clone(),
                    format!("the case `{}` overlaps the case `{}`", case.text, first.text),
                )
                .with_note(format!("`{}` is here", first.text), Some(first.key.span.clone()))
                .with_note("a value picks one case: give each value to a single case", None),
            );
        }
    }
}

/// A key a `switch` Field does not take: a length key is `unexpected-length`, `endian:`
/// `invalid-endian`, `bits:` `invalid-bits`, `count:` and `repeat:` `invalid-array`, a value key
/// `incompatible-display` (spec §3.9).
fn misplaced(key: &Spanned<&'static str>) -> Diagnostic {
    let name = match key.value {
        "size" | "prefix" | "terminator" => Name::UnexpectedLength,
        "endian" => Name::InvalidEndian,
        "bits" => Name::InvalidBits,
        "count" | "repeat" => Name::InvalidArray,
        _ => Name::IncompatibleDisplay,
    };
    Diagnostic::new(name, key.span.clone(), format!("a `switch` Field takes no `{}`", key.value)).with_note(
        "a `switch` Field takes only `name`, `label`, `description`, `if`, `hidden`, `switch`, `cases` and `default`; \
         give the key to a Field of a case",
        None,
    )
}
