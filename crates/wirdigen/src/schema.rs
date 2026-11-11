//! The JSON Schema of a Protocol Description, for editor completion and hover (spec §6.6,
//! ADR 0008). Wirdigen never validates with it.
//!
//! The schema is derived from a model of the description as written: the types below exist only
//! for it, and their doc comments become the `description`s editors show on hover. The values the
//! readers enumerate (built-in types, displays, encodings, warning names) come from the readers'
//! own tables, and a test checks that every mapping lists exactly the keys its reader accepts.

#![expect(dead_code, reason = "the model is never built: it only describes the YAML for schemars")]

use std::borrow::Cow;
use std::collections::BTreeMap;

use schemars::generate::SchemaSettings;
use schemars::transform::RecursiveTransform;
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde_json::Value as Json;

use crate::description::MAX_NAME_LEN;
use crate::diagnostic::{Name, Severity};
use crate::field::Builtin;

/// The JSON Schema (draft-07, which `yaml-language-server` and `SchemaStore` read), pretty-printed with
/// a trailing newline. The same Wirdigen version always gives the same bytes.
pub(crate) fn json_schema() -> String {
    let generator =
        SchemaSettings::draft07().with(|s| s.transforms.push(Box::new(RecursiveTransform(tidy)))).into_generator();
    let schema = generator.into_root_schema_for::<Description>();
    let mut text = serde_json::to_string_pretty(&schema).expect("a schema always serializes");
    text.push('\n');
    text
}

/// Tidies one schema of the generated tree for editors:
///
/// - takes `null` out: schemars allows it for every `Option`, but an optional key is left out,
///   never written empty. What is left of an `anyOf` is merged into the schema, except a `$ref`
///   with siblings, which stays wrapped in an `allOf` as draft-07 ignores the siblings of a `$ref`;
/// - drops the integer `format`s (`uint8`, `uint64`), which are not JSON Schema's;
/// - joins the lines of a doc comment, keeping its paragraphs.
fn tidy(schema: &mut Schema) {
    let Some(object) = schema.as_object_mut() else { return };
    if let Some(Json::Array(types)) = object.get_mut("type") {
        types.retain(|t| t != "null");
        if let [only] = types.as_slice() {
            let only = only.clone();
            object.insert("type".to_owned(), only);
        }
    }
    if let Some(Json::Array(values)) = object.get_mut("enum") {
        values.retain(|v| !v.is_null());
    }
    if let Some(Json::Array(options)) = object.get_mut("anyOf") {
        options.retain(|o| o.get("type").is_none_or(|t| t != "null"));
        if let [Json::Object(only)] = options.as_slice() {
            let only = only.clone();
            object.remove("anyOf");
            if only.contains_key("$ref") && !object.is_empty() {
                object.insert("allOf".to_owned(), Json::Array(vec![Json::Object(only)]));
            } else {
                object.extend(only);
            }
        }
    }
    if object.get("type").is_some_and(|t| t == "integer") {
        object.remove("format");
    }
    if let Some(Json::String(description)) = object.get_mut("description") {
        let paragraphs: Vec<String> = description.split("\n\n").map(|p| p.replace('\n', " ")).collect();
        *description = paragraphs.join("\n\n");
    }
}

/// `[a-z][a-z0-9_]*`, the names of Fields and sub-Fields (spec §3.4.2).
const FIELD_NAME: &str = "^[a-z][a-z0-9_]*$";
/// `[A-Z][A-Za-z0-9]*`, the names of Types and Enums (spec §3.4.2).
const TYPE_NAME: &str = "^[A-Z][A-Za-z0-9]*$";
/// An integer literal as YAML's core schema spells it, inside a range string.
const INT: &str = "(0x[0-9a-fA-F]+|0o[0-7]+|[-+]?[0-9]+)";

/// A `"low-high"` range string, spaces allowed around the bounds.
fn range_pattern() -> String {
    format!(r"^\s*{INT}\s*-\s*{INT}\s*$")
}

/// A Wirdigen Protocol Description: one protocol's identity, its Registration and the layout of
/// its payload.
#[derive(JsonSchema)]
#[schemars(title = "Wirdigen Protocol Description", deny_unknown_fields)]
struct Description {
    /// Filter name of the protocol, such as `dns`: lowercase letters, digits, `_` and `-`, starting
    /// with a letter, at most 32 characters. Its uppercase is the short name shown in the Protocol
    /// column.
    #[schemars(regex(pattern = r"^[a-z][a-z0-9_-]*$"), length(max = MAX_NAME_LEN))]
    name: String,
    /// Full name of the protocol at the tree root; defaults to the short name. One line.
    #[schemars(length(min = 1))]
    title: Option<String>,
    /// The ports the Dissector claims by default. Leaving it out means Decode As only; every
    /// Dissector is offered in Decode As on UDP and TCP ports.
    registration: Option<Registration>,
    /// How each Message is found in a TCP stream.
    framing: Option<Framing>,
    /// Default byte order of the protocol.
    endian: Option<ByteOrder>,
    /// Info column template, such as `"{msg_type} id={id}"`: Field paths in braces, `{{` and `}}`
    /// for literal braces. Without it, the Info column shows the outermost `switch` Field's case.
    info: Option<String>,
    /// The top-level layout: the Fields of a Message, read one after another.
    #[schemars(length(min = 1))]
    fields: Vec<Entry>,
    /// Named, reusable groups of Fields, by Type name (`[A-Z][A-Za-z0-9]*`).
    #[schemars(extend("propertyNames" = { "pattern": TYPE_NAME }))]
    types: Option<BTreeMap<String, Type>>,
    /// Named tables of labels for integer values, by Enum name (`[A-Z][A-Za-z0-9]*`), used as
    /// `values: <EnumName>`.
    #[schemars(extend("propertyNames" = { "pattern": TYPE_NAME }))]
    enums: Option<BTreeMap<String, Table>>,
    /// Names of warnings to silence in this description. Errors cannot be silenced.
    allow: Option<Vec<WarningName>>,
}

/// The ports a Dissector claims by default.
#[derive(JsonSchema)]
#[schemars(deny_unknown_fields)]
struct Registration {
    /// Ports per transport, each a number or a `"low-high"` range string.
    ports: Option<Ports>,
}

/// Ports per transport.
#[derive(JsonSchema)]
#[schemars(deny_unknown_fields)]
struct Ports {
    /// UDP ports, such as `[5000, "6000-6010"]`.
    #[schemars(length(min = 1))]
    udp: Option<Vec<Port>>,
    /// TCP ports, such as `[5000]`. TCP without `framing:` dissects each segment as one Message.
    #[schemars(length(min = 1))]
    tcp: Option<Vec<Port>>,
}

/// A byte order: most significant byte first (`big`) or last (`little`).
#[derive(JsonSchema)]
#[schemars(rename_all = "lowercase")]
enum ByteOrder {
    Big,
    Little,
}

/// A Type: a named, reusable group of Fields.
#[derive(JsonSchema)]
#[schemars(deny_unknown_fields)]
struct Type {
    /// The Fields of the Type, read one after another.
    #[schemars(length(min = 1))]
    fields: Vec<Entry>,
    /// The byte order the Type is read in, whatever structure uses it; defaults to the top level's.
    endian: Option<ByteOrder>,
}

/// One entry of a structure: a Field, or unnamed Padding.
#[derive(JsonSchema)]
#[schemars(untagged)]
enum Entry {
    Field(Box<Field>),
    Padding(Padding),
}

/// Unnamed space that is skipped.
#[derive(JsonSchema)]
#[schemars(deny_unknown_fields)]
struct Padding {
    /// The number of bytes skipped: a constant, or an Expression over earlier Fields.
    padding: Expression,
}

/// A Field: exactly one of `type`, `fields` or `switch` says what it is.
#[derive(JsonSchema)]
#[schemars(deny_unknown_fields)]
struct Field {
    /// The Field's name: lowercase letters, digits and `_`, starting with a letter. It is part of
    /// its filter name and of the Field paths of Expressions.
    #[schemars(regex(pattern = FIELD_NAME))]
    name: String,
    /// A built-in type, or the name of a Type.
    #[schemars(rename = "type")]
    ty: Option<TypeName>,
    /// An inline structure: the Fields of this Field, read one after another.
    #[schemars(length(min = 1))]
    fields: Option<Vec<Entry>>,
    /// The Subject of a switch: an Expression whose value picks one of `cases`.
    switch: Option<Expression>,
    /// The Cases of a `switch`, by value or `"low-high"` range: each a Type name or inline Fields.
    cases: Option<BTreeMap<String, Case>>,
    /// The Case of a `switch` when no other matches.
    default: Option<Case>,
    /// The sub-Fields of a fixed-size unsigned integer, most significant bit first; widths add up
    /// to the integer's size.
    #[schemars(length(min = 1))]
    bits: Option<Vec<Bit>>,
    /// An Array: the number of elements, a constant or an Expression.
    count: Option<Expression>,
    /// An Array read until its enclosing structure or the Message ends.
    repeat: Option<Repeat>,
    /// The byte order of this Field, or of the Fields of an inline structure.
    endian: Option<ByteOrder>,
    /// The length in bytes of a `string` or `bytes`: a constant, an Expression, or `"_remaining"`
    /// to read to the end of the enclosing structure or Message.
    size: Option<Expression>,
    /// The unsigned integer type the length of a `string` or `bytes` is read from, just before it.
    prefix: Option<Prefix>,
    /// The byte a `string` or `bytes` ends at, consumed but not part of the value.
    #[schemars(range(min = 0, max = 255))]
    terminator: Option<u8>,
    /// How a `string`'s text or a timestamp's bytes are read.
    encoding: Option<EncodingName>,
    /// How the value is shown.
    display: Option<DisplayName>,
    /// Labels for an integer's values: an inline table or the name of an Enum.
    values: Option<Values>,
    /// The label of a true `bool`.
    #[schemars(rename = "true")]
    when_true: Option<String>,
    /// The label of a false `bool`.
    #[schemars(rename = "false")]
    when_false: Option<String>,
    /// The unit shown after a number: a string, or `[singular, plural]`.
    unit: Option<Unit>,
    /// The values the Field should hold; another value gets a warning in Wireshark.
    expect: Option<Expect>,
    /// The name of a Wireshark Dissector the bytes of a `bytes` Field are handed to.
    #[schemars(regex(pattern = r"^\S+$"))]
    dissector: Option<String>,
    /// The text shown in the tree; defaults to the name with `_` as spaces, first letter
    /// capitalised. One line.
    #[schemars(length(min = 1))]
    label: Option<String>,
    /// A one-line description of the Field, shown as its filter's blurb.
    description: Option<String>,
    /// Read the Field but leave it out of the tree; it can still be filtered and used in
    /// Expressions.
    hidden: Option<bool>,
    /// Read the Field only when this Expression is not zero.
    #[schemars(rename = "if")]
    condition: Option<Expression>,
}

/// An Array read until its enclosing structure or the Message ends.
#[derive(JsonSchema)]
enum Repeat {
    #[schemars(rename = "to_end")]
    ToEnd,
}

/// One entry of `bits:`: a sub-Field, or unnamed bits skipped.
#[derive(JsonSchema)]
#[schemars(untagged)]
enum Bit {
    SubField(Box<SubField>),
    Padding(BitPadding),
}

/// Unnamed bits that are skipped.
#[derive(JsonSchema)]
#[schemars(deny_unknown_fields)]
struct BitPadding {
    /// The number of bits skipped.
    #[schemars(range(min = 1))]
    padding: u64,
}

/// A sub-Field of a Bitfield: a boolean when it is one bit wide, an unsigned integer otherwise.
#[derive(JsonSchema)]
#[schemars(deny_unknown_fields)]
struct SubField {
    /// The sub-Field's name: lowercase letters, digits and `_`, starting with a letter.
    #[schemars(regex(pattern = FIELD_NAME))]
    name: String,
    /// The number of bits.
    #[schemars(range(min = 1))]
    width: u64,
    /// How the value is shown; makes a one-bit sub-Field an integer.
    display: Option<DisplayName>,
    /// Labels for the values: an inline table or the name of an Enum. Makes a one-bit sub-Field an
    /// integer.
    values: Option<Values>,
    /// The unit shown after the value; makes a one-bit sub-Field an integer.
    unit: Option<Unit>,
    /// The label of a set one-bit sub-Field.
    #[schemars(rename = "true")]
    when_true: Option<String>,
    /// The label of a clear one-bit sub-Field.
    #[schemars(rename = "false")]
    when_false: Option<String>,
    /// Read the sub-Field but leave it out of the tree.
    hidden: Option<bool>,
    /// The values the sub-Field should hold; another value gets a warning in Wireshark.
    expect: Option<Expect>,
    /// The text shown in the tree. One line.
    #[schemars(length(min = 1))]
    label: Option<String>,
    /// A one-line description, shown as the filter's blurb.
    description: Option<String>,
}

/// A unit: one string, or `[singular, plural]`.
#[derive(JsonSchema)]
#[schemars(untagged)]
enum Unit {
    One(#[schemars(length(min = 1))] String),
    SingularPlural([String; 2]),
}

/// One expected value or range, or a list of them.
#[derive(JsonSchema)]
#[schemars(untagged)]
enum Expect {
    One(ValueKey),
    Several(#[schemars(length(min = 1))] Vec<ValueKey>),
}

/// Labels for values, by integer or `"low-high"` range string.
#[derive(JsonSchema)]
#[schemars(transparent)]
struct Table(BTreeMap<String, String>);

/// Labels for an integer's values: an inline table, or the name of an Enum.
#[derive(JsonSchema)]
#[schemars(untagged)]
enum Values {
    Enum(#[schemars(regex(pattern = TYPE_NAME))] String),
    Inline(Table),
}

/// A Case of a `switch`: a Type name, or inline Fields.
#[derive(JsonSchema)]
#[schemars(untagged)]
enum Case {
    Type(#[schemars(regex(pattern = TYPE_NAME))] String),
    Fields(#[schemars(length(min = 1))] Vec<Entry>),
}

/// Implements [`JsonSchema`] for a marker type whose schema is built by `$schema`, inlined where
/// it is used.
macro_rules! inline_schema {
    ($(#[$doc:meta])* $name:ident => $schema:expr) => {
        $(#[$doc])*
        struct $name;

        impl JsonSchema for $name {
            fn inline_schema() -> bool {
                true
            }

            fn schema_name() -> Cow<'static, str> {
                stringify!($name).into()
            }

            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                $schema
            }
        }
    };
}

inline_schema! {
    /// `framing:`, with the keys of spec §3.13 offered for completion. Its value is not read yet,
    /// so any value is accepted: the schema must accept every description Wirdigen does.
    Framing => json_schema!({
        "properties": {
            "header": { "description": "The number of bytes needed to compute `length`: a constant." },
            "length": {
                "description": "The total length of a Message: an Expression over top-level Fields within the first `header` bytes."
            }
        }
    })
}

inline_schema! {
    /// A constant, or an Expression written as a string.
    Expression => json_schema!({ "type": ["integer", "string"] })
}

inline_schema! {
    /// A value: an integer, or a `"low-high"` range string.
    ValueKey => json_schema!({
        "anyOf": [{ "type": "integer" }, { "type": "string", "pattern": range_pattern() }]
    })
}

inline_schema! {
    /// A port, 1 to 65535, or a `"low-high"` range string.
    Port => json_schema!({
        "anyOf": [
            { "type": "integer", "minimum": 1, "maximum": 65535 },
            { "type": "string", "pattern": range_pattern() }
        ]
    })
}

inline_schema! {
    /// A built-in type, or the name of a Type.
    TypeName => json_schema!({
        "anyOf": [
            { "enum": Builtin::all().map(|(name, _)| name).collect::<Vec<_>>() },
            { "type": "string", "pattern": TYPE_NAME }
        ]
    })
}

inline_schema! {
    /// An unsigned integer type.
    Prefix => json_schema!({
        "enum": Builtin::all()
            .filter(|(_, b)| matches!(b, Builtin::Int { signed: false, .. }))
            .map(|(name, _)| name)
            .collect::<Vec<_>>()
    })
}

inline_schema! {
    /// Every `display:` value of any type.
    DisplayName => json_schema!({
        "enum": unique(Builtin::all().flat_map(|(_, b)| b.displays().iter().map(|d| d.as_str())))
    })
}

inline_schema! {
    /// Every `encoding:` value of any type.
    EncodingName => json_schema!({
        "enum": unique(Builtin::all().flat_map(|(_, b)| b.encodings().iter().map(|e| e.as_str())))
    })
}

inline_schema! {
    /// The name of a warning; any other name is itself a warning.
    WarningName => json_schema!({
        "anyOf": [
            {
                "enum": Name::ALL
                    .iter()
                    .filter(|n| n.severity() == Severity::Warning)
                    .map(|n| n.as_str())
                    .collect::<Vec<_>>()
            },
            { "type": "string" }
        ]
    })
}

/// `names` without repeats, in first-seen order.
fn unique<'a>(names: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    let mut seen = Vec::new();
    for name in names {
        if !seen.contains(&name) {
            seen.push(name);
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use serde_json::Value as Json;

    use super::json_schema;
    use crate::scalar::{Kind, parse_int, resolve_plain};
    use crate::source::Source;
    use crate::yaml::{self, Node, Value};

    /// The JSON an editor sees for a YAML node, resolving plain scalars as YAML 1.2's core schema
    /// does. Mapping keys are always strings in JSON.
    fn to_json(node: &Node) -> Json {
        match &node.value {
            Value::Scalar { text, plain: false, .. } => Json::String(text.clone()),
            Value::Scalar { text, plain: true, .. } => match resolve_plain(text) {
                Kind::Null => Json::Null,
                Kind::Bool => Json::Bool(text.eq_ignore_ascii_case("true")),
                Kind::Int => {
                    let value = parse_int(text).expect("an integer");
                    match (i64::try_from(value), u64::try_from(value)) {
                        (Ok(v), _) => Json::from(v),
                        (_, Ok(v)) => Json::from(v),
                        _ => Json::from(text.parse::<f64>().unwrap_or(f64::NAN)),
                    }
                }
                Kind::Float => Json::from(text.parse::<f64>().unwrap_or(0.0)),
                Kind::Str => Json::String(text.clone()),
            },
            Value::Sequence(items) => Json::Array(items.iter().map(to_json).collect()),
            Value::Mapping(pairs) => Json::Object(
                pairs
                    .iter()
                    .map(|(key, value)| {
                        let key = match &key.value {
                            Value::Scalar { text, .. } => text.clone(),
                            _ => panic!("a non-scalar key in a valid description"),
                        };
                        (key, to_json(value))
                    })
                    .collect(),
            ),
        }
    }

    fn descriptions(dir: &Path, found: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                descriptions(&path, found);
            } else if path.to_string_lossy().ends_with(".wirdigen.yaml") {
                found.push(path);
            }
        }
    }

    fn schema() -> Json {
        serde_json::from_str(&json_schema()).expect("the schema is JSON")
    }

    #[test]
    fn every_valid_description_passes_the_schema() {
        let validator = jsonschema::draft7::new(&schema()).expect("the schema is a valid draft-07 schema");
        let mut files = Vec::new();
        descriptions(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests"), &mut files);
        let mut checked = 0;
        let mut with_warnings = 0;
        let mut failures = Vec::new();
        for path in files {
            let text = fs::read_to_string(&path).expect("readable");
            let Ok(valid) = crate::validate(&Source::new("case", text.as_str())) else { continue };
            with_warnings += usize::from(!valid.warnings().is_empty());
            let root = yaml::parse(&text).expect("valid YAML").expect("not empty");
            let instance = to_json(&root);
            for error in validator.iter_errors(&instance) {
                failures.push(format!("{}: {} at {}", path.display(), error, error.instance_path()));
            }
            checked += 1;
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        assert!(checked > 50, "only {checked} valid descriptions found");
        assert!(with_warnings > 5, "only {with_warnings} descriptions with warnings found");
    }

    /// The property names of `definition`, or of the root for `None`, in schema order.
    fn keys(schema: &Json, definition: Option<&str>) -> Vec<String> {
        let object = match definition {
            Some(name) => &schema["definitions"][name],
            None => schema,
        };
        object["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{definition:?} has properties"))
            .keys()
            .cloned()
            .collect()
    }

    #[test]
    fn every_mapping_lists_the_keys_its_reader_accepts_in_documentation_order() {
        let schema = schema();
        let transports: Vec<&str> = crate::registration::Transport::ALL.iter().map(|t| t.key()).collect();
        for (definition, expected) in [
            (None, &crate::description::KEYS[..]),
            (Some("Field"), &crate::field::KEYS[..]),
            (Some("SubField"), &crate::bits::KEYS[..]),
            (Some("Type"), &crate::types::KEYS[..]),
            (Some("Registration"), &crate::registration::KEYS[..]),
            (Some("Ports"), &transports[..]),
        ] {
            assert_eq!(keys(&schema, definition), expected, "{definition:?}");
        }
    }

    #[test]
    fn any_framing_value_passes_while_framing_is_not_read() {
        let validator = jsonschema::draft7::new(&schema()).expect("a draft-07 schema");
        for framing in ["true", "", "{ foo: 1 }", "{ header: 4, length: \"len + 4\" }"] {
            let text = format!("name: demo\nframing: {framing}\nfields:\n  - {{ name: len, type: uint32 }}\n");
            assert!(crate::validate(&Source::new("case", text.as_str())).is_ok(), "{text}");
            let root = yaml::parse(&text).expect("valid YAML").expect("not empty");
            assert!(validator.is_valid(&to_json(&root)), "{text}");
        }
    }
}
