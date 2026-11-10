//! Stage 2 (strict deserialization of the top level) and the first semantic checks.

use std::ops::Range;

use crate::diagnostic::{Diagnostic, Name, Severity, record};
use crate::field::{self, Endian, Field, RawField};
use crate::scalar::{Kind, resolve_plain};
use crate::yaml::{Node, Value};

/// The longest protocol name Wireshark filters accept here (spec §3.3, ADR 0014).
const MAX_NAME_LEN: usize = 32;

/// The ten top-level keys, in documentation order (spec §3.2).
const KEYS: [&str; 10] =
    ["name", "title", "registration", "framing", "endian", "info", "fields", "types", "enums", "allow"];

/// A value with the span it came from.
#[derive(Debug, Clone)]
pub(crate) struct Spanned<T> {
    pub(crate) value: T,
    pub(crate) span: Range<usize>,
}

/// The top level of a Protocol Description, as written.
///
/// Keys typed by later tickets (`registration`, `framing`, ...) are recognised but not yet read.
#[derive(Debug, Clone)]
pub(crate) struct Description {
    pub(crate) name: Spanned<String>,
    pub(crate) title: Option<Spanned<String>>,
    pub(crate) endian: Option<Spanned<String>>,
    /// The top-level Fields, in order.
    pub(crate) fields: Vec<RawField>,
    /// The `allow:` entries, as written.
    pub(crate) allow: Vec<Spanned<String>>,
}

impl Description {
    /// Whether `allow:` silences this Diagnostic. Errors are never silenced (spec §6.4).
    pub(crate) fn allows(&self, diagnostic: &Diagnostic) -> bool {
        diagnostic.severity() == Severity::Warning && self.allow.iter().any(|a| a.value == diagnostic.name())
    }
}

/// A Protocol Description that passed every check: what lowering reads.
#[derive(Debug, Clone)]
pub(crate) struct Protocol {
    pub(crate) name: String,
    pub(crate) title: Option<String>,
    pub(crate) fields: Vec<Field>,
}

/// The known keys of one mapping, read by [`read_keys`].
pub(crate) struct Keys<'a> {
    /// Each known key found, with its key and value nodes.
    found: Vec<(&'static str, &'a Node, &'a Node)>,
    /// Known keys that some unknown key is probably a misspelling of.
    misspelt: Vec<&'static str>,
}

impl<'a> Keys<'a> {
    /// The value of `key`, if present.
    pub(crate) fn get(&self, key: &str) -> Option<&'a Node> {
        self.found.iter().find(|(k, ..)| *k == key).map(|(_, _, v)| *v)
    }

    /// The key node of `key`, if present.
    pub(crate) fn key_of(&self, key: &str) -> Option<&'a Node> {
        self.found.iter().find(|(k, ..)| *k == key).map(|(_, k, _)| *k)
    }

    /// Whether an unknown key was reported as a likely misspelling of `key`. A missing key that
    /// was misspelt is one mistake, which the unknown-key error already reports.
    pub(crate) fn misspelt(&self, key: &str) -> bool {
        self.misspelt.contains(&key)
    }
}

/// Reads the keys of a mapping: keys must be strings among `known`, each at most once.
pub(crate) fn read_keys<'a>(
    entries: &'a [(Node, Node)],
    known: &[&'static str],
    errors: &mut Vec<Diagnostic>,
) -> Keys<'a> {
    let mut keys = Keys { found: Vec::new(), misspelt: Vec::new() };
    for (key, value) in entries {
        let Value::Scalar { text, .. } = &key.value else {
            errors.push(wrong_type(key.span.clone(), "keys must be strings"));
            continue;
        };
        let Some(name) = known.iter().copied().find(|k| k == text) else {
            let unknown = Diagnostic::new(Name::UnknownKey, key.span.clone(), format!("unknown key `{text}`"));
            errors.push(match closest(text, known) {
                Some(guess) => {
                    keys.misspelt.push(guess);
                    unknown.with_note(format!("did you mean `{guess}`?"), None)
                }
                None => unknown.with_note(format!("the keys are: {}", known.join(", ")), None),
            });
            continue;
        };
        if let Some(first) = keys.key_of(name) {
            errors.push(
                Diagnostic::new(Name::DuplicateKey, key.span.clone(), format!("duplicate key `{name}`"))
                    .with_note("first defined here", Some(first.span.clone())),
            );
        } else {
            keys.found.push((name, key, value));
        }
    }
    keys
}

/// Stage 2: unknown and duplicate keys, required keys and value kinds.
pub(crate) fn deserialize(root: Option<&Node>) -> Result<Description, Vec<Diagnostic>> {
    let Some(root) = root else {
        return Err(vec![Diagnostic::new(
            Name::MissingKey,
            0..0,
            "the description is empty: `name` and `fields` are required",
        )]);
    };
    let Value::Mapping(entries) = &root.value else {
        return Err(vec![wrong_type(
            root.span.clone(),
            "a Protocol Description is a mapping with at least `name` and `fields`",
        )]);
    };

    let mut errors = Vec::new();
    let keys = read_keys(entries, &KEYS, &mut errors);
    for required in ["name", "fields"] {
        if keys.get(required).is_none() && !keys.misspelt(required) {
            errors.push(Diagnostic::new(
                Name::MissingKey,
                root.span.clone(),
                format!("missing required key `{required}`"),
            ));
        }
    }

    let mut string_value =
        |key: &str, invalid: Name| keys.get(key).and_then(|n| record(expect_string(n, key, invalid), &mut errors));
    let name = string_value("name", Name::InvalidProtocolName);
    let title = string_value("title", Name::InvalidProtocolTitle);
    let endian = string_value("endian", Name::InvalidEndian);
    let mut layout = Vec::new();
    if let Some(fields) = keys.get("fields") {
        match &fields.value {
            Value::Sequence(items) if items.is_empty() => errors.push(Diagnostic::new(
                Name::EmptyFields,
                fields.span.clone(),
                "`fields` must declare at least one Field",
            )),
            Value::Sequence(items) => layout = items.iter().filter_map(|item| field::read(item, &mut errors)).collect(),
            _ => errors.push(wrong_type(fields.span.clone(), "`fields` must be a list of Fields")),
        }
    }

    let allow = keys.get("allow").map_or_else(Vec::new, |node| read_allow(node, &mut errors));

    match name {
        Some(name) if errors.is_empty() => Ok(Description { name, title, endian, fields: layout, allow }),
        _ => Err(errors),
    }
}

/// Reads `allow:`, a list of strings. Whether each names a warning is a semantic check.
fn read_allow(node: &Node, errors: &mut Vec<Diagnostic>) -> Vec<Spanned<String>> {
    let Value::Sequence(items) = &node.value else {
        errors.push(wrong_type(node.span.clone(), "`allow` must be a list of warning names"));
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| record(expect_string(item, "an `allow` entry", Name::WrongValueType), errors))
        .collect()
}

/// Stage 4: semantic checks on a deserialized description.
///
/// Returns every Diagnostic, and the checked [`Protocol`] when none of them is an error.
pub(crate) fn check(description: &Description) -> (Option<Protocol>, Vec<Diagnostic>) {
    let mut diagnostics = Vec::new();
    let name = &description.name;
    if !is_protocol_name(&name.value) {
        diagnostics.push(
            Diagnostic::new(
                Name::InvalidProtocolName,
                name.span.clone(),
                format!("`{}` is not a valid protocol name", name.value),
            )
            .with_note(
                format!("a name is a lowercase letter then lowercase letters, digits, `_` or `-`, at most {MAX_NAME_LEN} characters"),
                None,
            ),
        );
    }
    if let Some(title) = &description.title {
        let line_breaks = ['\n', '\r', '\u{85}', '\u{2028}', '\u{2029}'];
        if title.value.trim().is_empty() || title.value.contains(line_breaks) {
            diagnostics.push(Diagnostic::new(
                Name::InvalidProtocolTitle,
                title.span.clone(),
                "a title must be a non-empty single line",
            ));
        }
    }
    for entry in &description.allow {
        let message = match Name::from_token(&entry.value) {
            Some(name) if name.severity() == Severity::Warning => continue,
            Some(_) => format!("`{}` is an error, and errors cannot be silenced", entry.value),
            None => format!("there is no warning named `{}`", entry.value),
        };
        diagnostics.push(Diagnostic::new(Name::UnknownAllow, entry.span.clone(), message));
    }
    let endian = match &description.endian {
        Some(value) => record(Endian::check(value), &mut diagnostics),
        None => Some(Endian::default()),
    };
    // An invalid top-level byte order is an error already, so any stand-in will do.
    let fields = field::check(&description.fields, endian.unwrap_or_default(), &mut diagnostics);
    let has_errors = diagnostics.iter().any(|d| d.severity() == Severity::Error);
    let protocol = fields.filter(|_| !has_errors).map(|fields| Protocol {
        name: description.name.value.clone(),
        title: description.title.as_ref().map(|t| t.value.clone()),
        fields,
    });
    (protocol, diagnostics)
}

fn is_protocol_name(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= MAX_NAME_LEN
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Reads a string value. A scalar that resolves to another kind (`123`, `true`, an empty value)
/// is reported under `invalid`, the key's own error; a list or mapping is a wrong value type.
pub(crate) fn expect_string(node: &Node, key: &str, invalid: Name) -> Result<Spanned<String>, Diagnostic> {
    match &node.value {
        Value::Scalar { text, plain, .. } if !*plain || resolve_plain(text) == Kind::Str => {
            Ok(Spanned { value: text.clone(), span: node.span.clone() })
        }
        Value::Scalar { .. } => Err(Diagnostic::new(invalid, node.span.clone(), format!("`{key}` must be a string"))
            .with_note("quote the value to make it a string", None)),
        _ => Err(wrong_type(node.span.clone(), format!("`{key}` must be a string"))),
    }
}

/// The candidate `word` is most likely a misspelling of, if any is close enough.
pub(crate) fn closest(word: &str, candidates: &[&'static str]) -> Option<&'static str> {
    candidates
        .iter()
        .map(|c| (edit_distance(word, c), *c))
        .filter(|(distance, c)| *distance <= (c.len() / 3).max(1))
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, c)| c)
}

/// Optimal string alignment distance: insertions, deletions, substitutions and adjacent
/// transpositions each cost 1, compared case-insensitively.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.to_lowercase().chars().collect();
    let b: Vec<char> = b.to_lowercase().chars().collect();
    // rows[i][j]: distance between a[..i] and b[..j].
    let mut rows = vec![vec![0; b.len() + 1]; a.len() + 1];
    for (i, row) in rows.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in rows[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (rows[i - 1][j] + 1).min(rows[i][j - 1] + 1).min(rows[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(rows[i - 2][j - 2] + 1);
            }
            rows[i][j] = best;
        }
    }
    rows[a.len()][b.len()]
}

pub(crate) fn wrong_type(span: Range<usize>, message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(Name::WrongValueType, span, message)
}

/// Reads a key that takes a constant: only a YAML integer, never a float or a bool.
#[cfg_attr(not(test), expect(dead_code, reason = "first used by the Fields ticket"))]
pub(crate) fn expect_integer(node: &Node, key: &str) -> Result<i64, Diagnostic> {
    let wrong = |what: &str| Diagnostic::new(Name::WrongValueType, node.span.clone(), format!("`{key}` {what}"));
    let Value::Scalar { text, plain: true, .. } = &node.value else {
        return Err(wrong("must be an integer"));
    };
    if resolve_plain(text) != Kind::Int {
        return Err(wrong("must be an integer, not a float, a bool or text"));
    }
    let (digits, radix) = if let Some(hex) = text.strip_prefix("0x") {
        (hex, 16)
    } else if let Some(oct) = text.strip_prefix("0o") {
        (oct, 8)
    } else {
        (text.strip_prefix('+').unwrap_or(text), 10)
    };
    i64::from_str_radix(digits, radix).map_err(|_| wrong("is out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yaml;

    fn int(text: &str) -> Result<i64, String> {
        let node = yaml::parse(text).unwrap().unwrap();
        expect_integer(&node, "k").map_err(|d| d.name().to_owned())
    }

    #[test]
    fn misspellings_suggest_the_closest_key() {
        assert_eq!(edit_distance("enmu", "enum"), 1, "a transposition costs 1");
        assert_eq!(edit_distance("Name", "name"), 0, "case is ignored");
        assert_eq!(edit_distance("kitten", "sitting"), 3);
        assert_eq!(closest("fieldss", &KEYS), Some("fields"));
        assert_eq!(closest("tilte", &KEYS), Some("title"));
        assert_eq!(closest("bogus", &KEYS), None);
        assert_eq!(closest("x", &KEYS), None);
    }

    #[test]
    fn integer_keys_reject_floats_and_bools() {
        assert_eq!(int("12"), Ok(12));
        assert_eq!(int("0x10"), Ok(16));
        assert_eq!(int("-4"), Ok(-4));
        assert_eq!(int("1.5"), Err("wrong-value-type".into()));
        assert_eq!(int("true"), Err("wrong-value-type".into()));
        assert_eq!(int("'12'"), Err("wrong-value-type".into()));
        assert_eq!(int("99999999999999999999"), Err("wrong-value-type".into()));
    }
}
