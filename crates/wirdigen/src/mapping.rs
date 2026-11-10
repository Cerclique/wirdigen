//! Value mappings and Enums (spec §3.4.7): strict deserialization (stage 2) and semantic
//! checks (stage 4).
//!
//! A Field labels its values with `values:` (an inline table or the name of an Enum), `true:` /
//! `false:` or `unit:`. A table maps an integer or a `"low-high"` range to a label; the
//! top-level `enums:` names tables so several Fields can share one.

use std::collections::BTreeMap;
use std::ops::Range;

use crate::diagnostic::{Diagnostic, Name, Severity, record};
use crate::field::Builtin;
use crate::keys::{Keys, Spanned, closest, expect_string, is_single_line, wrong_type};
use crate::scalar::{Kind, parse_int, resolve_plain};
use crate::yaml::{Node, Value};

/// The lowest key any integer type can reach: `int64`'s minimum.
const KEY_MIN: i128 = i64::MIN as i128;
/// The highest key any integer type can reach: `uint64`'s maximum.
const KEY_MAX: i128 = u64::MAX as i128;

/// A key of a values table: one value, or every value of an inclusive range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Key {
    pub(crate) low: i128,
    pub(crate) high: i128,
    /// Whether the key was written as a range, which makes the table a range string.
    pub(crate) range: bool,
}

impl Key {
    fn overlaps(self, other: Self) -> bool {
        self.low <= other.high && other.low <= self.high
    }
}

/// One label of a validated table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) key: Key,
    pub(crate) label: String,
}

/// A validated values table, in source order.
pub(crate) type Table = Vec<Entry>;

/// Whether a table is shown as a range string: when any of its keys is a range.
pub(crate) fn has_range(table: &[Entry]) -> bool {
    table.iter().any(|e| e.key.range)
}

/// The labels of a validated Field (spec §3.4.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Mapping {
    /// Labels for integer values. An Enum is kept by name, so two Fields naming one Enum have
    /// equal mappings (spec §3.4.9).
    Values(Values),
    /// Labels for the two states of a `bool`; a missing one keeps Wireshark's default.
    Bool { when_true: Option<String>, when_false: Option<String> },
    /// The unit after the value, in the singular and, if it differs, the plural.
    Unit { singular: String, plural: Option<String> },
}

/// Where a Field's `values:` table is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Values {
    Inline(Table),
    /// An Enum of [`Enums`], by name.
    Enum(String),
}

/// One entry of a table as written, after stage 2.
#[derive(Debug, Clone)]
struct RawEntry {
    key: Spanned<Key>,
    /// The key as written, for messages.
    text: String,
    label: Spanned<String>,
}

/// A Field's `values:` as written.
#[derive(Debug, Clone)]
enum RawValues {
    Inline(Vec<RawEntry>),
    Enum(Spanned<String>),
}

/// An Enum as written, after stage 2.
#[derive(Debug, Clone)]
pub(crate) struct RawEnum {
    name: Spanned<String>,
    entries: Vec<RawEntry>,
}

/// A mapping key's value with the span of the key itself, which is where a misplaced key is
/// reported.
#[derive(Debug, Clone)]
struct MappingKey<T> {
    key: Range<usize>,
    value: T,
}

/// The value-mapping keys of a Field as written, after stage 2.
#[derive(Debug, Clone, Default)]
pub(crate) struct RawMappings {
    values: Option<MappingKey<RawValues>>,
    when_true: Option<MappingKey<Spanned<String>>>,
    when_false: Option<MappingKey<Spanned<String>>>,
    unit: Option<MappingKey<(String, Option<String>)>>,
}

/// Stage 2: reads the value-mapping keys of a Field, pushing their errors.
pub(crate) fn read(keys: &Keys<'_>, errors: &mut Vec<Diagnostic>) -> RawMappings {
    fn with_key<T>(
        keys: &Keys<'_>,
        name: &str,
        errors: &mut Vec<Diagnostic>,
        read: impl FnOnce(&Node, &mut Vec<Diagnostic>) -> Option<T>,
    ) -> Option<MappingKey<T>> {
        let (key, value) = (keys.key_of(name)?, keys.get(name)?);
        read(value, errors).map(|value| MappingKey { key: key.span.clone(), value })
    }
    let label = |name: &'static str| {
        move |node: &Node, errors: &mut Vec<Diagnostic>| record(expect_string(node, name, Name::InvalidLabel), errors)
    };
    RawMappings {
        values: with_key(keys, "values", errors, read_values),
        when_true: with_key(keys, "true", errors, label("true")),
        when_false: with_key(keys, "false", errors, label("false")),
        unit: with_key(keys, "unit", errors, |node, errors| record(read_unit(node), errors)),
    }
}

/// `values:` is an inline table or the name of an Enum.
fn read_values(node: &Node, errors: &mut Vec<Diagnostic>) -> Option<RawValues> {
    match &node.value {
        Value::Mapping(_) => read_table(node, errors).map(RawValues::Inline),
        Value::Scalar { text, plain, .. } if !*plain || resolve_plain(text) == Kind::Str => {
            Some(RawValues::Enum(Spanned { value: text.clone(), span: node.span.clone() }))
        }
        _ => {
            errors.push(
                wrong_type(node.span.clone(), "`values` must be a table of labels or the name of an Enum")
                    .with_note("write `values: { 1: Request }` or `values: MsgType`", None),
            );
            None
        }
    }
}

/// `unit:` is a string, or a `[singular, plural]` list.
fn read_unit(node: &Node) -> Result<(String, Option<String>), Diagnostic> {
    let wrong = || {
        wrong_type(node.span.clone(), "`unit` must be a string or a `[singular, plural]` list")
            .with_note("write `unit: ms` or `unit: [byte, bytes]`", None)
    };
    match &node.value {
        Value::Scalar { .. } => expect_string(node, "unit", Name::WrongValueType).map(|unit| (unit.value, None)),
        Value::Sequence(items) => match items.as_slice() {
            [singular, plural] => {
                let singular = expect_string(singular, "unit", Name::WrongValueType)?;
                let plural = expect_string(plural, "unit", Name::WrongValueType)?;
                Ok((singular.value, Some(plural.value)))
            }
            _ => Err(wrong()),
        },
        Value::Mapping(_) => Err(wrong()),
    }
}

/// Reads a values table: a mapping from keys to labels. A key spelt twice is `duplicate-key`;
/// two spellings of one value are left to stage 4.
fn read_table(node: &Node, errors: &mut Vec<Diagnostic>) -> Option<Vec<RawEntry>> {
    let Value::Mapping(pairs) = &node.value else {
        errors.push(wrong_type(node.span.clone(), "a values table maps integers or ranges to labels"));
        return None;
    };
    let before = errors.len();
    let mut entries: Vec<RawEntry> = Vec::new();
    for (key, value) in pairs {
        let text = match &key.value {
            Value::Scalar { text, .. } => text.clone(),
            _ => String::new(),
        };
        if let Some(first) = entries.iter().find(|e| !text.is_empty() && e.text == text) {
            errors.push(
                Diagnostic::new(Name::DuplicateKey, key.span.clone(), format!("duplicate key `{text}`"))
                    .with_note("first defined here", Some(first.key.span.clone())),
            );
            continue;
        }
        let parsed = record(read_key(key), errors);
        let label = record(read_label(value), errors);
        if let (Some(parsed), Some(label)) = (parsed, label) {
            entries.push(RawEntry { key: Spanned { value: parsed, span: key.span.clone() }, text, label });
        }
    }
    (errors.len() == before).then_some(entries)
}

/// A table key: a YAML integer, or a string `"low-high"` with two integers.
fn read_key(node: &Node) -> Result<Key, Diagnostic> {
    let not_a_key = |text: &str| {
        wrong_type(node.span.clone(), format!("`{text}` is not an integer or a range"))
            .with_note("a key is an integer, or a range written as a string such as \"16-31\"", None)
    };
    let Value::Scalar { text, plain, .. } = &node.value else {
        return Err(wrong_type(node.span.clone(), "a values table key must be an integer or a range"));
    };
    let key = match (*plain, resolve_plain(text)) {
        (true, Kind::Int) => {
            let value = parse_int(text).ok_or_else(|| not_a_key(text))?;
            Key { low: value, high: value, range: false }
        }
        (false, _) | (true, Kind::Str) => {
            let (low, high) = parse_range(text).ok_or_else(|| not_a_key(text))?;
            if low > high {
                return Err(wrong_type(node.span.clone(), format!("the range `{text}` is empty"))
                    .with_note("write the lower bound first", None));
            }
            Key { low, high, range: true }
        }
        _ => return Err(not_a_key(text)),
    };
    if key.low < KEY_MIN || key.high > KEY_MAX {
        return Err(wrong_type(node.span.clone(), format!("`{text}` is beyond every integer type"))
            .with_note("keys run from -2^63 to 2^64 - 1", None));
    }
    Ok(key)
}

/// The bounds of a `"low-high"` range, each an integer literal; spaces around them are allowed.
/// The `-` between them is the first one that leaves an integer on each side, so negative
/// bounds read naturally: `"-5--1"`.
fn parse_range(text: &str) -> Option<(i128, i128)> {
    text.match_indices('-').filter(|(i, _)| *i > 0).find_map(|(i, _)| {
        let low = parse_int(text[..i].trim())?;
        let high = parse_int(text[i + 1..].trim())?;
        Some((low, high))
    })
}

/// A label is a string; whether it is a non-empty single line is checked in stage 4.
fn read_label(node: &Node) -> Result<Spanned<String>, Diagnostic> {
    match &node.value {
        Value::Scalar { text, plain, .. } if !*plain || resolve_plain(text) == Kind::Str => {
            Ok(Spanned { value: text.clone(), span: node.span.clone() })
        }
        Value::Scalar { .. } => Err(Diagnostic::new(Name::InvalidLabel, node.span.clone(), "a label must be a string")
            .with_note("quote the value to make it a string", None)),
        _ => Err(wrong_type(node.span.clone(), "a label must be a string")),
    }
}

/// Stage 2: reads the top-level `enums:`, a mapping from Enum names to values tables.
pub(crate) fn read_enums(node: &Node, errors: &mut Vec<Diagnostic>) -> Vec<RawEnum> {
    let Value::Mapping(pairs) = &node.value else {
        errors.push(
            wrong_type(node.span.clone(), "`enums` must map Enum names to values tables")
                .with_note("write `enums: { MsgType: { 1: Request } }`", None),
        );
        return Vec::new();
    };
    let mut enums: Vec<RawEnum> = Vec::new();
    for (key, value) in pairs {
        // Whether a name is valid is a stage 4 check, as for Fields; `1:` is a name too.
        let Value::Scalar { text, .. } = &key.value else {
            errors.push(wrong_type(key.span.clone(), "an Enum name must be a string"));
            continue;
        };
        if let Some(first) = enums.iter().find(|e| e.name.value == *text) {
            errors.push(
                Diagnostic::new(Name::DuplicateKey, key.span.clone(), format!("duplicate key `{text}`"))
                    .with_note("first defined here", Some(first.name.span.clone())),
            );
            continue;
        }
        if let Some(entries) = read_table(value, errors) {
            enums.push(RawEnum { name: Spanned { value: text.clone(), span: key.span.clone() }, entries });
        }
    }
    enums
}

/// The Enums of a description, during stage 4: what Fields look up and mark as used.
pub(crate) struct Enums<'a> {
    enums: Vec<CheckedEnum<'a>>,
}

struct CheckedEnum<'a> {
    raw: &'a RawEnum,
    table: Table,
    used: bool,
    /// For each entry, whether `unreachable-value` was reported already: an entry is reported
    /// once, from the first Field whose type cannot reach it.
    unreachable_reported: Vec<bool>,
}

impl<'a> Enums<'a> {
    /// Stage 4: checks every Enum's name and table.
    pub(crate) fn check(raw: &'a [RawEnum], diagnostics: &mut Vec<Diagnostic>) -> Self {
        let enums = raw
            .iter()
            .map(|e| {
                if !is_type_name(&e.name.value) {
                    diagnostics.push(
                        Diagnostic::new(
                            Name::InvalidTypeName,
                            e.name.span.clone(),
                            format!("`{}` is not a valid Enum name", e.name.value),
                        )
                        .with_note("an Enum name is an uppercase letter then letters or digits", None),
                    );
                }
                let table = check_table(&e.entries, diagnostics);
                CheckedEnum { raw: e, table, used: false, unreachable_reported: vec![false; e.entries.len()] }
            })
            .collect();
        Self { enums }
    }

    /// Reports every Enum no Field uses, and returns the tables by name.
    pub(crate) fn finish(self, diagnostics: &mut Vec<Diagnostic>) -> BTreeMap<String, Table> {
        let mut tables = BTreeMap::new();
        for e in self.enums {
            let name = &e.raw.name;
            if !e.used {
                diagnostics.push(
                    Diagnostic::new(
                        Name::UnusedEnum,
                        name.span.clone(),
                        format!("the Enum `{}` is never used", name.value),
                    )
                    .with_note(format!("use it as `values: {}`, or remove it", name.value), None),
                );
            }
            tables.insert(name.value.clone(), e.table);
        }
        tables
    }
}

/// A Field's value mappings are wrong; the errors saying why are already pushed.
#[derive(Debug)]
pub(crate) struct Invalid;

/// Stage 4: the labels of a Field of type `builtin`, written `ty`.
///
/// Returns [`Invalid`] after an error, which is already pushed, and `Ok(None)` for a Field without
/// value mappings.
pub(crate) fn check(
    raw: &RawMappings,
    ty: &Spanned<String>,
    builtin: Builtin,
    enums: &mut Enums<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Option<Mapping>, Invalid> {
    let before = errors(diagnostics);
    let range = builtin.int_range();
    let takes_unit = range.is_some() || matches!(builtin, Builtin::Float32 | Builtin::Float64);
    let misplaced = |key: &Range<usize>, what: &str, takers: &str| {
        Diagnostic::new(Name::IncompatibleDisplay, key.clone(), format!("`{}` takes no `{what}`", ty.value))
            .with_note(format!("only {takers} take `{what}`"), None)
    };
    if let (Some(values), None) = (&raw.values, range) {
        diagnostics.push(misplaced(&values.key, "values", "integer types"));
    }
    if builtin != Builtin::Bool {
        for (label, what) in [(&raw.when_true, "true"), (&raw.when_false, "false")] {
            if let Some(label) = label {
                diagnostics.push(misplaced(&label.key, what, "`bool` Fields"));
            }
        }
    }
    if let (Some(unit), false) = (&raw.unit, takes_unit) {
        diagnostics.push(misplaced(&unit.key, "unit", "integer and float types"));
    }
    if let (Some(values), Some(unit), Some(_)) = (&raw.values, &raw.unit, range) {
        diagnostics.push(
            Diagnostic::new(
                Name::ConflictingMappings,
                unit.key.clone(),
                "a Field cannot have both `values` and `unit`",
            )
            .with_note("`values` is here", Some(values.key.clone())),
        );
    }
    if errors(diagnostics) > before {
        return Err(Invalid);
    }

    let mapping = if let (Some(values), Some(range)) = (&raw.values, range) {
        let unreachable = |entry: &RawEntry| entry.key.value.high < range.0 || entry.key.value.low > range.1;
        let report = |entry: &RawEntry| {
            Diagnostic::new(
                Name::UnreachableValue,
                entry.key.span.clone(),
                format!("`{}` is never a `{}` value", entry.text, ty.value),
            )
            .with_note(format!("`{}` holds {} to {}", ty.value, range.0, range.1), Some(ty.span.clone()))
        };
        Some(Mapping::Values(match &values.value {
            RawValues::Inline(entries) => {
                let table = check_table(entries, diagnostics);
                diagnostics.extend(entries.iter().filter(|e| unreachable(e)).map(report));
                Values::Inline(table)
            }
            RawValues::Enum(name) => {
                let Some(found) = enums.enums.iter_mut().find(|e| e.raw.name.value == name.value) else {
                    diagnostics.push(unknown_enum(name, enums));
                    return Err(Invalid);
                };
                found.used = true;
                for (entry, reported) in found.raw.entries.iter().zip(&mut found.unreachable_reported) {
                    if !*reported && unreachable(entry) {
                        *reported = true;
                        diagnostics.push(report(entry));
                    }
                }
                Values::Enum(name.value.clone())
            }
        }))
    } else if raw.when_true.is_some() || raw.when_false.is_some() {
        let mut label = |label: &Option<MappingKey<Spanned<String>>>| {
            label.as_ref().map(|l| {
                check_label(&l.value, diagnostics);
                l.value.value.clone()
            })
        };
        Some(Mapping::Bool { when_true: label(&raw.when_true), when_false: label(&raw.when_false) })
    } else {
        raw.unit.as_ref().map(|unit| Mapping::Unit { singular: unit.value.0.clone(), plural: unit.value.1.clone() })
    };
    if errors(diagnostics) == before { Ok(mapping) } else { Err(Invalid) }
}

fn errors(diagnostics: &[Diagnostic]) -> usize {
    diagnostics.iter().filter(|d| d.severity() == Severity::Error).count()
}

/// Why `values:` names no Enum. The Enum it most likely misspells counts as used: one mistake
/// is one error, not also an `unused-enum`.
fn unknown_enum(name: &Spanned<String>, enums: &mut Enums<'_>) -> Diagnostic {
    let unknown =
        Diagnostic::new(Name::UnknownEnum, name.span.clone(), format!("there is no Enum named `{}`", name.value));
    let names: Vec<&str> = enums.enums.iter().map(|e| e.raw.name.value.as_str()).collect();
    let note = match closest(&name.value, &names).map(str::to_owned) {
        Some(guess) => {
            if let Some(meant) = enums.enums.iter_mut().find(|e| e.raw.name.value == guess) {
                meant.used = true;
            }
            format!("did you mean `{guess}`?")
        }
        None if names.is_empty() => "declare it under the top-level `enums`".to_owned(),
        None => format!("the Enums are: {}", names.join(", ")),
    };
    unknown.with_note(note, None)
}

/// Checks a table's labels and that no two keys overlap, returning the validated table.
fn check_table(entries: &[RawEntry], diagnostics: &mut Vec<Diagnostic>) -> Table {
    for (index, entry) in entries.iter().enumerate() {
        check_label(&entry.label, diagnostics);
        if let Some(first) = entries[..index].iter().find(|e| e.key.value.overlaps(entry.key.value)) {
            diagnostics.push(
                Diagnostic::new(
                    Name::OverlappingValues,
                    entry.key.span.clone(),
                    format!("`{}` overlaps `{}` of the same table", entry.text, first.text),
                )
                .with_note(format!("`{}` is here", first.text), Some(first.key.span.clone())),
            );
        }
    }
    entries.iter().map(|e| Entry { key: e.key.value, label: e.label.value.clone() }).collect()
}

/// A label is a non-empty single line, like a Field's (spec §3.4.8).
fn check_label(label: &Spanned<String>, diagnostics: &mut Vec<Diagnostic>) {
    if label.value.trim().is_empty() || !is_single_line(&label.value) {
        diagnostics.push(Diagnostic::new(
            Name::InvalidLabel,
            label.span.clone(),
            "a label must be a non-empty single line",
        ));
    }
}

/// `[A-Z][A-Za-z0-9]*` (spec §3.4.2).
fn is_type_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_uppercase()) && chars.all(|c| c.is_ascii_alphanumeric())
}
