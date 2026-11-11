//! Value mappings and Enums (spec §3.4.7): strict deserialization (stage 2) and semantic
//! checks (stage 4).
//!
//! A Field labels its values with `values:` (an inline table or the name of an Enum), `true:` /
//! `false:` or `unit:`. A table maps an integer or a `"low-high"` range to a label; the
//! top-level `enums:` names tables so several Fields can share one.

use std::collections::BTreeMap;
use std::ops::{Range, RangeInclusive};

use crate::diagnostic::{Diagnostic, Name, Severity, record};
use crate::field::Builtin;
use crate::keys::{Keys, Spanned, closest, duplicate_key, expect_string, is_single_line, is_type_name, wrong_type};
use crate::scalar::{Kind, parse_int, resolve_plain};
use crate::yaml::{Node, Value};

/// The lowest key any integer type can reach: `int64`'s minimum.
const KEY_MIN: i128 = i64::MIN as i128;
/// The highest key any integer type can reach: `uint64`'s maximum.
const KEY_MAX: i128 = u64::MAX as i128;

/// A key of a values table: one value, or every value of an inclusive range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Key {
    /// The lowest value the key matches.
    pub(crate) low: i128,
    /// The highest value the key matches, `low` itself for a single value.
    pub(crate) high: i128,
    /// Whether the key was written as a range, which makes the table a range string.
    pub(crate) range: bool,
}

impl Key {
    /// Whether some value matches both keys.
    fn overlaps(self, other: Self) -> bool {
        self.low <= other.high && other.low <= self.high
    }

    /// Whether no value the key matches is in `range`, the values of a Field's type.
    fn outside(self, range: &RangeInclusive<i128>) -> bool {
        self.high < *range.start() || self.low > *range.end()
    }
}

/// One label of a validated table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    /// The values labelled.
    pub(crate) key: Key,
    /// The text shown in place of those values.
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
    /// Written in the Field's own `values:`.
    Inline(Table),
    /// An Enum of [`Enums`], by name.
    Enum(String),
}

/// One entry of a table as written, after stage 2.
#[derive(Debug, Clone)]
struct RawEntry {
    /// The values labelled, spanning the key.
    key: Spanned<Key>,
    /// The key as written, for messages.
    text: String,
    /// The label, not yet checked to be a non-empty single line.
    label: Spanned<String>,
}

/// A Field's `values:` as written.
#[derive(Debug, Clone)]
enum RawValues {
    /// A table of the Field's own.
    Inline(Vec<RawEntry>),
    /// The name of an Enum, not yet looked up.
    Enum(Spanned<String>),
}

/// An Enum as written, after stage 2.
#[derive(Debug, Clone)]
pub(crate) struct RawEnum {
    /// The name, not yet checked against the naming rule.
    name: Spanned<String>,
    /// The table, in source order.
    entries: Vec<RawEntry>,
}

/// A mapping key's value with the span of the key itself, which is where a misplaced key is
/// reported.
#[derive(Debug, Clone)]
struct MappingKey<T> {
    /// The span of the key (`values`, `unit`, ...).
    key: Range<usize>,
    value: T,
}

/// The value-mapping keys of a Field as written, after stage 2.
#[derive(Debug, Clone)]
pub(crate) struct RawMappings {
    values: Option<MappingKey<RawValues>>,
    when_true: Option<MappingKey<Spanned<String>>>,
    when_false: Option<MappingKey<Spanned<String>>>,
    unit: Option<MappingKey<RawUnit>>,
}

/// A `unit:` as written, after stage 2: its forms are strings, not yet checked to be non-empty
/// single lines.
#[derive(Debug, Clone)]
struct RawUnit {
    singular: Spanned<String>,
    plural: Option<Spanned<String>>,
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

/// `unit:` is a string, or a `[singular, plural]` list of exactly two strings. A unit with one
/// form is a plain string, never a one-item list.
fn read_unit(node: &Node) -> Result<RawUnit, Diagnostic> {
    let wrong = |note: String| {
        wrong_type(node.span.clone(), "`unit` must be a string or a `[singular, plural]` list").with_note(note, None)
    };
    let string = |node: &Node| expect_string(node, "unit", Name::InvalidUnit);
    match &node.value {
        Value::Scalar { .. } => Ok(RawUnit { singular: string(node)?, plural: None }),
        Value::Sequence(items) => match items.as_slice() {
            [singular, plural] => Ok(RawUnit { singular: string(singular)?, plural: Some(string(plural)?) }),
            [only] => Err(wrong(match &only.value {
                Value::Scalar { text, .. } => format!("a unit with one form is a string: write `unit: {text}`"),
                _ => "write `unit: ms` or `unit: [byte, bytes]`".to_owned(),
            })),
            _ => Err(wrong("write `unit: ms` or `unit: [byte, bytes]`".to_owned())),
        },
        Value::Mapping(_) => Err(wrong("write `unit: ms` or `unit: [byte, bytes]`".to_owned())),
    }
}

/// Reads a values table: a mapping from keys to labels. A key written twice is `duplicate-key`
/// (YAML keys: `16` and `"16"` differ); two spellings of one value are left to stage 4.
fn read_table(node: &Node, errors: &mut Vec<Diagnostic>) -> Option<Vec<RawEntry>> {
    let Value::Mapping(pairs) = &node.value else {
        errors.push(wrong_type(node.span.clone(), "a values table maps integers or ranges to labels"));
        return None;
    };
    let before = errors.len();
    let mut entries: Vec<RawEntry> = Vec::new();
    // Every scalar key seen, read or not, as (text, plain): what makes two YAML keys the same.
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
            errors.push(duplicate_key(text, key, &first.name.span));
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
    /// In source order.
    enums: Vec<CheckedEnum<'a>>,
}

/// An Enum whose name and table were checked, with what its uses found so far.
struct CheckedEnum<'a> {
    raw: &'a RawEnum,
    /// The validated table, even when it has errors: the run fails on them anyway.
    table: Table,
    /// Whether a Field names it, or misspells its name (one mistake, one error).
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

    /// The Enum named `name`.
    fn get_mut(&mut self, name: &str) -> Option<&mut CheckedEnum<'a>> {
        self.enums.iter_mut().find(|e| e.raw.name.value == name)
    }

    /// The names of the Enums, in source order.
    fn names(&self) -> Vec<&str> {
        self.enums.iter().map(|e| e.raw.name.value.as_str()).collect()
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
    let start = diagnostics.len();
    let range = builtin.int_range();
    let takes_unit = range.is_some() || matches!(builtin, Builtin::Float32 | Builtin::Float64);
    let misplaced = |key: &Range<usize>, what: &str, takers: &str| {
        Diagnostic::new(Name::IncompatibleDisplay, key.clone(), format!("`{}` takes no `{what}`", ty.value))
            .with_note(format!("only {takers} take `{what}`"), None)
    };
    if let (Some(values), None) = (&raw.values, &range) {
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
    if let (Some(values), Some(unit), Some(_)) = (&raw.values, &raw.unit, &range) {
        diagnostics.push(
            Diagnostic::new(
                Name::ConflictingMappings,
                unit.key.clone(),
                "a Field cannot have both `values` and `unit`",
            )
            .with_note("`values` is here", Some(values.key.clone())),
        );
    }
    if has_errors(&diagnostics[start..]) {
        return Err(Invalid);
    }

    let mapping = match (&raw.values, range) {
        (Some(values), Some(range)) => {
            let report = |entry: &RawEntry| {
                Diagnostic::new(
                    Name::UnreachableValue,
                    entry.key.span.clone(),
                    format!("`{}` is never a `{}` value", entry.text, ty.value),
                )
                .with_note(format!("`{}` holds {} to {}", ty.value, range.start(), range.end()), Some(ty.span.clone()))
            };
            Some(Mapping::Values(match &values.value {
                RawValues::Inline(entries) => {
                    let table = check_table(entries, diagnostics);
                    diagnostics.extend(entries.iter().filter(|e| e.key.value.outside(&range)).map(report));
                    Values::Inline(table)
                }
                RawValues::Enum(name) => {
                    let names: Vec<String> = enums.names().into_iter().map(str::to_owned).collect();
                    let Some(found) = enums.get_mut(&name.value) else {
                        diagnostics.push(unknown_enum(name, &names));
                        return Err(Invalid);
                    };
                    for (entry, reported) in found.raw.entries.iter().zip(&mut found.unreachable_reported) {
                        if !*reported && entry.key.value.outside(&range) {
                            *reported = true;
                            diagnostics.push(report(entry));
                        }
                    }
                    Values::Enum(name.value.clone())
                }
            }))
        }
        _ if raw.when_true.is_some() || raw.when_false.is_some() => {
            let mut label = |label: &Option<MappingKey<Spanned<String>>>| {
                label.as_ref().map(|l| {
                    check_label(&l.value, diagnostics);
                    l.value.value.clone()
                })
            };
            Some(Mapping::Bool { when_true: label(&raw.when_true), when_false: label(&raw.when_false) })
        }
        _ => raw.unit.as_ref().map(|unit| {
            let RawUnit { singular, plural } = &unit.value;
            for form in std::iter::once(singular).chain(plural) {
                check_unit(form, diagnostics);
            }
            Mapping::Unit { singular: singular.value.clone(), plural: plural.as_ref().map(|p| p.value.clone()) }
        }),
    };
    if has_errors(&diagnostics[start..]) { Err(Invalid) } else { Ok(mapping) }
}

impl Enums<'_> {
    /// Marks the Enum a Field's `values:` names as used, or the one it most likely misspells.
    ///
    /// It runs for every Field whatever else is wrong with it, so that one mistake on the Field
    /// (a misspelt name, a type that takes no `values:`) is one error and not also an
    /// `unused-enum`.
    pub(crate) fn mark_used(&mut self, raw: &RawMappings) {
        let Some(MappingKey { value: RawValues::Enum(name), .. }) = &raw.values else { return };
        let names = self.names();
        let meant = if names.contains(&name.value.as_str()) {
            Some(name.value.clone())
        } else {
            closest(&name.value, &names).map(str::to_owned)
        };
        if let Some(meant) = meant.and_then(|m| self.get_mut(&m)) {
            meant.used = true;
        }
    }
}

/// Whether any of `diagnostics` is an error.
fn has_errors(diagnostics: &[Diagnostic]) -> bool {
    diagnostics.iter().any(|d| d.severity() == Severity::Error)
}

/// Why `values:` names no Enum, given the names of the Enums there are.
fn unknown_enum(name: &Spanned<String>, names: &[String]) -> Diagnostic {
    let unknown =
        Diagnostic::new(Name::UnknownEnum, name.span.clone(), format!("there is no Enum named `{}`", name.value));
    let candidates: Vec<&str> = names.iter().map(String::as_str).collect();
    let note = match closest(&name.value, &candidates) {
        Some(guess) => format!("did you mean `{guess}`?"),
        None if candidates.is_empty() => "declare it under the top-level `enums`".to_owned(),
        None => format!("the Enums are: {}", candidates.join(", ")),
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

/// A unit form is a non-empty single line: it is printed in the tree right after the value.
fn check_unit(form: &Spanned<String>, diagnostics: &mut Vec<Diagnostic>) {
    if form.value.trim().is_empty() || !is_single_line(&form.value) {
        diagnostics.push(Diagnostic::new(
            Name::InvalidUnit,
            form.span.clone(),
            "a unit must be a non-empty single line",
        ));
    }
}
