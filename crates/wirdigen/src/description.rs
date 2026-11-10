//! Stage 2 (strict deserialization of the top level) and the first semantic checks.

use std::ops::Range;

use crate::diagnostic::Diagnostic;
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

/// A built-in type (spec §3.4.4). Only the unsigned integers read so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Builtin {
    Uint8,
    Uint16,
    Uint32,
}

impl Builtin {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "uint8" => Some(Self::Uint8),
            "uint16" => Some(Self::Uint16),
            "uint32" => Some(Self::Uint32),
            _ => None,
        }
    }
}

/// A Field of the top-level layout.
#[derive(Debug, Clone)]
pub(crate) struct Field {
    pub(crate) name: String,
    pub(crate) ty: Builtin,
}

/// The top level of a Protocol Description.
///
/// Keys typed by later tickets (`registration`, `framing`, ...) are recognised but not yet read.
#[derive(Debug, Clone)]
pub(crate) struct Description {
    pub(crate) name: Spanned<String>,
    pub(crate) title: Option<Spanned<String>>,
    /// The top-level Fields this version understands, in order.
    pub(crate) fields: Vec<Field>,
}

/// Stage 2: unknown and duplicate keys, required keys and value kinds.
pub(crate) fn deserialize(root: Option<&Node>) -> Result<Description, Vec<Diagnostic>> {
    let Some(root) = root else {
        return Err(vec![Diagnostic::error(
            "missing-key",
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
    let mut found: Vec<(&'static str, &Node, &Node)> = Vec::new();
    for (key, value) in entries {
        let Value::Scalar { text, .. } = &key.value else {
            errors.push(wrong_type(key.span.clone(), "keys must be strings"));
            continue;
        };
        let Some(known) = KEYS.iter().copied().find(|k| k == text) else {
            errors.push(
                Diagnostic::error("unknown-key", key.span.clone(), format!("unknown key `{text}`"))
                    .with_note(format!("the keys are: {}", KEYS.join(", ")), None),
            );
            continue;
        };
        if let Some((_, first, _)) = found.iter().find(|(k, ..)| *k == known) {
            errors.push(
                Diagnostic::error("duplicate-key", key.span.clone(), format!("duplicate key `{known}`"))
                    .with_note("first defined here", Some(first.span.clone())),
            );
        } else {
            found.push((known, key, value));
        }
    }
    let get = |name: &str| found.iter().find(|(k, ..)| *k == name).map(|(_, _, v)| *v);

    for required in ["name", "fields"] {
        if get(required).is_none() {
            errors.push(Diagnostic::error(
                "missing-key",
                root.span.clone(),
                format!("missing required key `{required}`"),
            ));
        }
    }

    let mut string_value = |key: &str, invalid: &'static str| match get(key).map(|n| expect_string(n, key, invalid)) {
        Some(Ok(value)) => Some(value),
        Some(Err(error)) => {
            errors.push(error);
            None
        }
        None => None,
    };
    let name = string_value("name", "invalid-protocol-name");
    let title = string_value("title", "invalid-protocol-title");
    let mut layout = Vec::new();
    if let Some(fields) = get("fields") {
        match &fields.value {
            Value::Sequence(items) if items.is_empty() => errors.push(Diagnostic::error(
                "empty-fields",
                fields.span.clone(),
                "`fields` must declare at least one Field",
            )),
            Value::Sequence(items) => layout = items.iter().filter_map(read_field).collect(),
            _ => errors.push(wrong_type(fields.span.clone(), "`fields` must be a list of Fields")),
        }
    }

    match name {
        Some(name) if errors.is_empty() => Ok(Description { name, title, fields: layout }),
        _ => Err(errors),
    }
}

/// Reads a Field made of a `name` and a `type` this version knows.
///
/// Field validation arrives with the Fields ticket; until then any other entry is left out of the
/// layout rather than reported.
fn read_field(node: &Node) -> Option<Field> {
    let Value::Mapping(entries) = &node.value else { return None };
    let text_of = |key: &str| {
        entries.iter().find_map(|(k, v)| match (&k.value, &v.value) {
            (Value::Scalar { text: k, .. }, Value::Scalar { text, .. }) if k == key => Some(text.as_str()),
            _ => None,
        })
    };
    let name = text_of("name")?;
    let mut chars = name.chars();
    let is_name = chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    let ty = Builtin::from_name(text_of("type")?)?;
    is_name.then(|| Field { name: name.to_owned(), ty })
}

/// Semantic checks on a deserialized description.
pub(crate) fn check(description: &Description) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let name = &description.name;
    if !is_protocol_name(&name.value) {
        diagnostics.push(
            Diagnostic::error(
                "invalid-protocol-name",
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
            diagnostics.push(Diagnostic::error(
                "invalid-protocol-title",
                title.span.clone(),
                "a title must be a non-empty single line",
            ));
        }
    }
    diagnostics
}

fn is_protocol_name(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= MAX_NAME_LEN
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Reads a string value. A scalar that resolves to another kind (`123`, `true`, an empty value)
/// is reported under `invalid`, the key's own error; a list or mapping is a wrong value type.
fn expect_string(node: &Node, key: &str, invalid: &'static str) -> Result<Spanned<String>, Diagnostic> {
    match &node.value {
        Value::Scalar { text, plain } if !*plain || resolve_plain(text) == Kind::Str => {
            Ok(Spanned { value: text.clone(), span: node.span.clone() })
        }
        Value::Scalar { .. } => Err(Diagnostic::error(invalid, node.span.clone(), format!("`{key}` must be a string"))
            .with_note("quote the value to make it a string", None)),
        _ => Err(wrong_type(node.span.clone(), format!("`{key}` must be a string"))),
    }
}

fn wrong_type(span: Range<usize>, message: impl Into<String>) -> Diagnostic {
    Diagnostic::error("wrong-value-type", span, message)
}

/// Reads a key that takes a constant: only a YAML integer, never a float or a bool.
#[cfg_attr(not(test), expect(dead_code, reason = "first used by the Fields ticket"))]
pub(crate) fn expect_integer(node: &Node, key: &str) -> Result<i64, Diagnostic> {
    let wrong = |what: &str| Diagnostic::error("wrong-value-type", node.span.clone(), format!("`{key}` {what}"));
    let Value::Scalar { text, plain: true } = &node.value else {
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
