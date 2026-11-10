//! Fields of a layout: strict deserialization (stage 2) and semantic checks (stage 4).
//!
//! Stage 2 reads each entry's keys into a [`RawField`]; stage 4 turns the raw Fields into the
//! validated [`Field`]s lowering relies on, so lowering never sees a Field validation rejected.

use crate::description::{Spanned, closest, expect_string, read_keys, wrong_type};
use crate::diagnostic::{Diagnostic, Name};
use crate::yaml::{Node, Value};

/// The keys of a Field this version reads, in documentation order.
const KEYS: [&str; 8] = ["name", "type", "fields", "switch", "endian", "size", "prefix", "terminator"];

/// The keys that say what a Field is; exactly one is required (spec §3.4.3).
const KIND_KEYS: [&str; 3] = ["type", "fields", "switch"];

/// The keys that give a variable-length Field its length (spec §3.6).
const LENGTH_KEYS: [&str; 3] = ["size", "prefix", "terminator"];

/// A built-in type (spec §3.4.4). Only the fixed-size ones so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Builtin {
    /// An integer of 1 to 8 bytes.
    Int {
        signed: bool,
        bytes: usize,
    },
    /// One byte, non-zero is true.
    Bool,
    Float32,
    Float64,
    Ipv4,
    Ipv6,
    Ether,
    Eui64,
    Guid,
}

/// Every built-in this version reads, by name, in documentation order.
const BUILTINS: [(&str, Builtin); 24] = [
    ("uint8", uint(1)),
    ("uint16", uint(2)),
    ("uint24", uint(3)),
    ("uint32", uint(4)),
    ("uint40", uint(5)),
    ("uint48", uint(6)),
    ("uint56", uint(7)),
    ("uint64", uint(8)),
    ("int8", int(1)),
    ("int16", int(2)),
    ("int24", int(3)),
    ("int32", int(4)),
    ("int40", int(5)),
    ("int48", int(6)),
    ("int56", int(7)),
    ("int64", int(8)),
    ("bool", Builtin::Bool),
    ("float32", Builtin::Float32),
    ("float64", Builtin::Float64),
    ("ipv4", Builtin::Ipv4),
    ("ipv6", Builtin::Ipv6),
    ("ether", Builtin::Ether),
    ("eui64", Builtin::Eui64),
    ("guid", Builtin::Guid),
];

/// Built-ins of the format that this version does not read yet.
const NOT_YET: [&str; 4] = ["string", "bytes", "abs_time", "rel_time"];

const fn uint(bytes: usize) -> Builtin {
    Builtin::Int { signed: false, bytes }
}

const fn int(bytes: usize) -> Builtin {
    Builtin::Int { signed: true, bytes }
}

impl Builtin {
    fn from_name(name: &str) -> Option<Self> {
        BUILTINS.iter().find(|(n, _)| *n == name).map(|(_, b)| *b)
    }

    /// The number of bytes read.
    pub(crate) fn size(self) -> usize {
        match self {
            Self::Int { bytes, .. } => bytes,
            Self::Bool => 1,
            Self::Float32 | Self::Ipv4 => 4,
            Self::Ether => 6,
            Self::Float64 | Self::Eui64 => 8,
            Self::Ipv6 | Self::Guid => 16,
        }
    }

    /// Whether `endian:` changes how the value is read. Single bytes, IPv6 addresses and
    /// Ethernet addresses have no byte order.
    pub(crate) fn has_byte_order(self) -> bool {
        match self {
            Self::Int { bytes, .. } => bytes > 1,
            Self::Float32 | Self::Float64 | Self::Ipv4 | Self::Eui64 | Self::Guid => true,
            Self::Bool | Self::Ipv6 | Self::Ether => false,
        }
    }
}

/// Byte order (spec §3.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Endian {
    #[default]
    Big,
    Little,
}

impl Endian {
    /// Reads an `endian:` value, reporting anything but `big` or `little`.
    pub(crate) fn check(value: &Spanned<String>) -> Result<Self, Diagnostic> {
        match value.value.as_str() {
            "big" => Ok(Self::Big),
            "little" => Ok(Self::Little),
            other => {
                Err(Diagnostic::new(Name::InvalidEndian, value.span.clone(), format!("`{other}` is not a byte order"))
                    .with_note("`endian` is `big` or `little`", None))
            }
        }
    }
}

/// A Field as written, after stage 2: its keys are known and of the right kinds.
#[derive(Debug, Clone)]
pub(crate) struct RawField {
    name: Spanned<String>,
    ty: Spanned<String>,
    endian: Option<Spanned<String>>,
    /// The length keys present, by key span.
    length_keys: Vec<Spanned<&'static str>>,
}

/// A validated Field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Field {
    pub(crate) name: String,
    pub(crate) ty: Builtin,
    /// The byte order in effect: the Field's own, else the top level's.
    pub(crate) endian: Endian,
}

/// Stage 2: reads one entry of a structure, pushing its errors.
pub(crate) fn read(node: &Node, errors: &mut Vec<Diagnostic>) -> Option<RawField> {
    let Value::Mapping(entries) = &node.value else {
        errors.push(wrong_type(node.span.clone(), "a Field is a mapping with a `name` and a `type`"));
        return None;
    };
    let before = errors.len();
    let keys = read_keys(entries, &KEYS, errors);

    if keys.get("name").is_none() && !keys.misspelt("name") {
        errors.push(Diagnostic::new(Name::MissingKey, node.span.clone(), "missing required key `name`"));
    }
    let name = keys
        .get("name")
        .and_then(|value| expect_string(value, "name", Name::InvalidFieldName).map_err(|e| errors.push(e)).ok());

    let kinds: Vec<(&str, &Node)> = KIND_KEYS.iter().filter_map(|k| keys.key_of(k).map(|key| (*k, key))).collect();
    let ty = match kinds.as_slice() {
        [] => {
            if !KIND_KEYS.iter().any(|k| keys.misspelt(k)) {
                errors.push(
                    Diagnostic::new(Name::MissingFieldKind, node.span.clone(), "this Field has no `type`")
                        .with_note("a Field needs exactly one of `type`, `fields` or `switch`", None),
                );
            }
            None
        }
        [("type", _)] => {
            let value = keys.get("type").expect("the key was found");
            expect_string(value, "type", Name::WrongValueType).map_err(|e| errors.push(e)).ok()
        }
        [(kind, key)] => {
            errors.push(Diagnostic::new(
                Name::UnknownKey,
                key.span.clone(),
                format!("`{kind}` Fields are not supported by this version of Wirdigen yet"),
            ));
            None
        }
        [(first, first_key), rest @ ..] => {
            for (kind, key) in rest {
                errors.push(
                    Diagnostic::new(
                        Name::ConflictingFieldKind,
                        key.span.clone(),
                        format!("a Field cannot have both `{first}` and `{kind}`"),
                    )
                    .with_note(format!("`{first}` is here"), Some(first_key.span.clone())),
                );
            }
            None
        }
    };

    let endian = keys
        .get("endian")
        .and_then(|value| expect_string(value, "endian", Name::InvalidEndian).map_err(|e| errors.push(e)).ok());
    let length_keys = LENGTH_KEYS
        .iter()
        .filter_map(|k| keys.key_of(k).map(|key| Spanned { value: *k, span: key.span.clone() }))
        .collect();

    match (name, ty) {
        (Some(name), Some(ty)) if errors.len() == before => Some(RawField { name, ty, endian, length_keys }),
        _ => None,
    }
}

/// Stage 4: checks the Fields of one structure, pushing every Diagnostic. The Fields are
/// returned only when none of them is wrong.
pub(crate) fn check(fields: &[RawField], endian: Endian, diagnostics: &mut Vec<Diagnostic>) -> Option<Vec<Field>> {
    let before = diagnostics.len();
    let mut layout = Vec::new();
    for (index, field) in fields.iter().enumerate() {
        let name = &field.name;
        if !is_field_name(&name.value) {
            diagnostics.push(
                Diagnostic::new(
                    Name::InvalidFieldName,
                    name.span.clone(),
                    format!("`{}` is not a valid Field name", name.value),
                )
                .with_note("a Field name is a lowercase letter then lowercase letters, digits or `_`", None),
            );
        }
        if let Some(first) = fields[..index].iter().find(|f| f.name.value == name.value) {
            diagnostics.push(
                Diagnostic::new(
                    Name::DuplicateFieldName,
                    name.span.clone(),
                    format!("there is already a Field named `{}` here", name.value),
                )
                .with_note("first defined here", Some(first.name.span.clone())),
            );
        }
        let ty = Builtin::from_name(&field.ty.value);
        match ty {
            Some(_) => {
                for key in &field.length_keys {
                    diagnostics.push(
                        Diagnostic::new(
                            Name::UnexpectedLength,
                            key.span.clone(),
                            format!("`{}` has a fixed size and takes no `{}`", field.ty.value, key.value),
                        )
                        .with_note(format!("remove `{}`", key.value), None),
                    );
                }
            }
            None => diagnostics.push(unknown_type(&field.ty)),
        }
        let endian = match &field.endian {
            Some(value) => Endian::check(value).map_err(|e| diagnostics.push(e)).ok(),
            None => Some(endian),
        };
        if let (Some(ty), Some(endian)) = (ty, endian) {
            layout.push(Field { name: name.value.clone(), ty, endian });
        }
    }
    (diagnostics.len() == before).then_some(layout)
}

fn unknown_type(ty: &Spanned<String>) -> Diagnostic {
    let name = ty.value.as_str();
    if NOT_YET.contains(&name) {
        return Diagnostic::new(
            Name::UnknownType,
            ty.span.clone(),
            format!("`{name}` is not supported by this version of Wirdigen yet"),
        );
    }
    if name.starts_with(|c: char| c.is_ascii_uppercase()) {
        return Diagnostic::new(Name::UnknownType, ty.span.clone(), format!("there is no Type named `{name}`"));
    }
    let names: Vec<&'static str> = BUILTINS.iter().map(|(n, _)| *n).collect();
    let unknown = Diagnostic::new(Name::UnknownType, ty.span.clone(), format!("there is no built-in type `{name}`"));
    match closest(name, &names) {
        Some(guess) => unknown.with_note(format!("did you mean `{guess}`?"), None),
        None => unknown.with_note(format!("the built-in types are: {}", names.join(", ")), None),
    }
}

/// `[a-z][a-z0-9_]*` (spec §3.4.2).
fn is_field_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The default tree text of a Field: `msg_type` becomes "Msg type" (spec §3.4.8).
pub(crate) fn default_label(name: &str) -> String {
    let spaced = name.replace('_', " ");
    let mut chars = spaced.chars();
    chars.next().map_or_else(String::new, |first| first.to_uppercase().chain(chars).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_come_from_names() {
        assert_eq!(default_label("msg_type"), "Msg type");
        assert_eq!(default_label("id"), "Id");
        assert_eq!(default_label("ip_v4_addr"), "Ip v4 addr");
    }
}
