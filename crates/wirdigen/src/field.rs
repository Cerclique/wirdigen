//! Fields of a layout: strict deserialization (stage 2) and semantic checks (stage 4).
//!
//! Stage 2 reads each entry's keys into a [`RawField`]; stage 4 turns the raw Fields into the
//! validated [`Field`]s lowering relies on, so lowering never sees a Field validation rejected.

use crate::diagnostic::{Diagnostic, Name, record};
use crate::keys::{Keys, Spanned, closest, expect_integer, expect_string, is_single_line, read_keys, wrong_type};
use crate::mapping::{self, Enums, Mapping};
use crate::scalar::{Kind, resolve_plain};
use crate::yaml::{Node, Value};

/// The keys of a Field this version reads, in documentation order.
const KEYS: [&str; 16] = [
    "name",
    "type",
    "fields",
    "switch",
    "endian",
    "size",
    "prefix",
    "terminator",
    "encoding",
    "display",
    "values",
    "true",
    "false",
    "unit",
    "label",
    "description",
];

/// The keys that say what a Field is; exactly one is required (spec §3.4.3).
const KIND_KEYS: [&str; 3] = ["type", "fields", "switch"];

/// How stage 2 reads the value of one length key.
type ReadLength = fn(&Node) -> Result<RawLength, Diagnostic>;

/// The keys that give a variable-length Field its length (spec §3.6), each with its reader.
const LENGTH_KEYS: [(&str, ReadLength); 3] =
    [("size", read_size), ("prefix", read_prefix), ("terminator", read_terminator)];

/// A built-in type (spec §3.4.4).
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
    /// Text, as long as its length key says.
    String,
    /// Raw bytes, as long as their length key says.
    Bytes,
    Ipv4,
    Ipv6,
    Ether,
    Eui64,
    Guid,
    /// A point in time, as long as its encoding says.
    AbsTime,
    /// A duration, as long as its encoding says.
    RelTime,
}

/// Every built-in, by name, in documentation order.
const BUILTINS: [(&str, Builtin); 28] = [
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
    ("string", Builtin::String),
    ("bytes", Builtin::Bytes),
    ("ipv4", Builtin::Ipv4),
    ("ipv6", Builtin::Ipv6),
    ("ether", Builtin::Ether),
    ("eui64", Builtin::Eui64),
    ("guid", Builtin::Guid),
    ("abs_time", Builtin::AbsTime),
    ("rel_time", Builtin::RelTime),
];

const fn uint(bytes: usize) -> Builtin {
    Builtin::Int { signed: false, bytes }
}

const fn int(bytes: usize) -> Builtin {
    Builtin::Int { signed: true, bytes }
}

impl Builtin {
    /// The width of an unsigned integer type, the only types a `prefix:` takes.
    fn unsigned_bytes(self) -> Option<usize> {
        match self {
            Self::Int { signed: false, bytes } => Some(bytes),
            _ => None,
        }
    }

    /// The lowest and highest values of an integer type, or `None` for any other type.
    pub(crate) fn int_range(self) -> Option<(i128, i128)> {
        match self {
            Self::Int { signed: false, bytes } => Some((0, (1_i128 << (8 * bytes)) - 1)),
            Self::Int { signed: true, bytes } => {
                let half = 1_i128 << (8 * bytes - 1);
                Some((-half, half - 1))
            }
            _ => None,
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        BUILTINS.iter().find(|(n, _)| *n == name).map(|(_, b)| *b)
    }

    /// The number of bytes read, or `None` when something else says: the length key of a
    /// `string` or `bytes`, the [`Encoding::time_size`] of a timestamp.
    pub(crate) fn fixed_size(self) -> Option<usize> {
        match self {
            Self::Int { bytes, .. } => Some(bytes),
            Self::Bool => Some(1),
            Self::Float32 | Self::Ipv4 => Some(4),
            Self::Ether => Some(6),
            Self::Float64 | Self::Eui64 => Some(8),
            Self::Ipv6 | Self::Guid => Some(16),
            Self::String | Self::Bytes | Self::AbsTime | Self::RelTime => None,
        }
    }

    /// The `display:` values this type takes, the default first (spec §3.4.6). Empty when the
    /// type takes none.
    pub(crate) fn displays(self) -> &'static [Display] {
        match self {
            Self::Int { signed: false, .. } => &UNSIGNED_DISPLAYS,
            Self::Int { signed: true, .. } => &[Display::Dec],
            Self::Bytes => &BYTES_DISPLAYS,
            Self::AbsTime => &[Display::Local, Display::Utc, Display::DoyUtc],
            Self::Bool
            | Self::Float32
            | Self::Float64
            | Self::String
            | Self::Ipv4
            | Self::Ipv6
            | Self::Ether
            | Self::Eui64
            | Self::Guid
            | Self::RelTime => &[],
        }
    }

    /// The `encoding:` values this type takes, the default first (spec §3.4.5). Empty when the
    /// type takes none.
    pub(crate) fn encodings(self) -> &'static [Encoding] {
        match self {
            Self::String => &[Encoding::Utf8, Encoding::Ascii, Encoding::Utf16, Encoding::Ucs2, Encoding::Latin1],
            Self::AbsTime => {
                &[Encoding::Secs, Encoding::SecsNsecs, Encoding::Ntp, Encoding::Msecs, Encoding::Usecs, Encoding::Nsecs]
            }
            Self::RelTime => &[Encoding::Secs, Encoding::SecsNsecs, Encoding::Msecs, Encoding::Usecs, Encoding::Nsecs],
            Self::Int { .. }
            | Self::Bool
            | Self::Float32
            | Self::Float64
            | Self::Bytes
            | Self::Ipv4
            | Self::Ipv6
            | Self::Ether
            | Self::Eui64
            | Self::Guid => &[],
        }
    }

    /// Whether `endian:` changes how the value is read. Single bytes, raw bytes, IPv6 addresses
    /// and Ethernet addresses have no byte order; a string's or a timestamp's follows its
    /// [`Encoding`] instead.
    pub(crate) fn has_byte_order(self) -> bool {
        match self {
            Self::Int { bytes, .. } => bytes > 1,
            Self::Float32 | Self::Float64 | Self::Ipv4 | Self::Eui64 | Self::Guid => true,
            Self::Bool | Self::String | Self::Bytes | Self::Ipv6 | Self::Ether | Self::AbsTime | Self::RelTime => false,
        }
    }
}

/// How a value is shown (spec §3.4.6). Which values a type takes is [`Builtin::displays`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Display {
    Dec,
    Hex,
    Oct,
    DecHex,
    HexDec,
    /// Bytes with no separator.
    Plain,
    /// Bytes separated by `.`.
    Dot,
    /// Bytes separated by `-`.
    Dash,
    /// Bytes separated by `:`.
    Colon,
    /// Bytes separated by a space.
    Space,
    /// A point in time in the viewer's time zone.
    Local,
    /// A point in time in UTC.
    Utc,
    /// A point in time in UTC, with the day of the year in place of the month and day.
    DoyUtc,
}

/// The `display:` values of an unsigned integer, the default first.
const UNSIGNED_DISPLAYS: [Display; 5] = [Display::Dec, Display::Hex, Display::Oct, Display::DecHex, Display::HexDec];

/// The `display:` values of `bytes`, the default first.
const BYTES_DISPLAYS: [Display; 5] = [Display::Plain, Display::Dot, Display::Dash, Display::Colon, Display::Space];

impl Display {
    /// The value as written in `display:`.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Dec => "dec",
            Self::Hex => "hex",
            Self::Oct => "oct",
            Self::DecHex => "dec_hex",
            Self::HexDec => "hex_dec",
            Self::Plain => "plain",
            Self::Dot => "dot",
            Self::Dash => "dash",
            Self::Colon => "colon",
            Self::Space => "space",
            Self::Local => "local",
            Self::Utc => "utc",
            Self::DoyUtc => "doy_utc",
        }
    }

    /// Reads the `display:` value of a Field of type `builtin`, written `ty`, reporting anything
    /// outside the matrix as `incompatible-display`.
    fn check(value: &Spanned<String>, ty: &Spanned<String>, builtin: Builtin) -> Result<Self, Diagnostic> {
        let allowed = builtin.displays();
        if let Some(display) = allowed.iter().copied().find(|d| d.as_str() == value.value) {
            return Ok(display);
        }
        let error = |message: String| Diagnostic::new(Name::IncompatibleDisplay, value.span.clone(), message);
        Err(match allowed {
            [] => error(format!("`{}` takes no `display`", ty.value)).with_note("remove `display`", None),
            [only] => error(format!("`{}` is shown only as `{}`", ty.value, only.as_str()))
                .with_note("remove `display`: it is the default", None),
            _ => {
                let names: Vec<&str> = allowed.iter().map(|d| d.as_str()).collect();
                error(format!("`{}` is not a display of `{}`", value.value, ty.value))
                    .with_note(format!("`display` is one of: {}", names.join(", ")), None)
            }
        })
    }
}

/// How a value's bytes are read (spec §3.4.5): a `string`'s text encoding or a timestamp's
/// layout. Which values a type takes is [`Builtin::encodings`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Encoding {
    /// 7-bit ASCII.
    Ascii,
    /// UTF-8.
    Utf8,
    /// UTF-16, in the Field's byte order.
    Utf16,
    /// UCS-2, in the Field's byte order.
    Ucs2,
    /// ISO 8859-1.
    Latin1,
    /// 4-byte seconds since the Unix epoch, or a 4-byte duration in seconds.
    Secs,
    /// 4-byte seconds then 4-byte nanoseconds.
    SecsNsecs,
    /// 8-byte NTP timestamp: seconds since 1900, then a 32-bit fraction of a second.
    Ntp,
    /// 8-byte milliseconds.
    Msecs,
    /// 8-byte microseconds.
    Usecs,
    /// 8-byte nanoseconds.
    Nsecs,
}

impl Encoding {
    /// The value as written in `encoding:`.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Ascii => "ascii",
            Self::Utf8 => "utf8",
            Self::Utf16 => "utf16",
            Self::Ucs2 => "ucs2",
            Self::Latin1 => "latin1",
            Self::Secs => "secs",
            Self::SecsNsecs => "secs_nsecs",
            Self::Ntp => "ntp",
            Self::Msecs => "msecs",
            Self::Usecs => "usecs",
            Self::Nsecs => "nsecs",
        }
    }

    /// The bytes of one text code unit, which is also the width of a terminator: a `utf16` or
    /// `ucs2` string ends at a 2-byte zero. 1 for a timestamp, which takes no terminator.
    pub(crate) const fn unit(self) -> usize {
        match self {
            Self::Utf16 | Self::Ucs2 => 2,
            Self::Ascii
            | Self::Utf8
            | Self::Latin1
            | Self::Secs
            | Self::SecsNsecs
            | Self::Ntp
            | Self::Msecs
            | Self::Usecs
            | Self::Nsecs => 1,
        }
    }

    /// The size of a timestamp in this encoding, or `None` for a text encoding.
    pub(crate) const fn time_size(self) -> Option<usize> {
        match self {
            Self::Secs => Some(4),
            Self::SecsNsecs | Self::Ntp | Self::Msecs | Self::Usecs | Self::Nsecs => Some(8),
            Self::Ascii | Self::Utf8 | Self::Utf16 | Self::Ucs2 | Self::Latin1 => None,
        }
    }

    /// Whether the Field's `endian:` applies: to multi-byte text code units and to timestamps.
    pub(crate) const fn has_byte_order(self) -> bool {
        self.unit() > 1 || self.time_size().is_some()
    }

    /// Reads the `encoding:` value of a Field of type `builtin`, written `ty`, reporting anything
    /// outside the matrix as `incompatible-display`.
    fn check(value: &Spanned<String>, ty: &Spanned<String>, builtin: Builtin) -> Result<Self, Diagnostic> {
        let allowed = builtin.encodings();
        if let Some(encoding) = allowed.iter().copied().find(|e| e.as_str() == value.value) {
            return Ok(encoding);
        }
        let error = |message: String| Diagnostic::new(Name::IncompatibleDisplay, value.span.clone(), message);
        Err(if allowed.is_empty() {
            let takers: Vec<String> =
                BUILTINS.iter().filter(|(_, b)| !b.encodings().is_empty()).map(|(n, _)| format!("`{n}`")).collect();
            error(format!("`{}` takes no `encoding`", ty.value))
                .with_note(format!("only {} take `encoding`", takers.join(", ")), None)
        } else {
            let names: Vec<&str> = allowed.iter().map(|e| e.as_str()).collect();
            error(format!("`{}` is not an encoding of `{}`", value.value, ty.value))
                .with_note(format!("`encoding` is one of: {}", names.join(", ")), None)
        })
    }
}

/// How many bytes a validated Field reads (spec §3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Length {
    /// A constant number of bytes: a fixed-size type's, or a constant `size:`.
    Constant(usize),
    /// The number of bytes is an unsigned integer of this many bytes just before the value
    /// (`prefix:`), in the Field's byte order.
    Prefix(usize),
    /// The value ends at this byte (`terminator:`), repeated over a string's code unit. The
    /// terminator is read but is not part of the value.
    Terminator(u8),
}

/// A length key's value as written, after stage 2.
#[derive(Debug, Clone)]
enum RawLength {
    /// `size:` with a constant.
    Size(i64),
    /// `size:` with an Expression, which this version does not read yet.
    SizeExpression,
    /// `prefix:` with a type name.
    Prefix(String),
    /// `terminator:` with a constant.
    Terminator(i64),
}

/// A length key of a Field, with its value.
#[derive(Debug, Clone)]
struct LengthKey {
    key: Spanned<&'static str>,
    value: Spanned<RawLength>,
}

/// `size:` is an integer, or an Expression written as a string.
fn read_size(node: &Node) -> Result<RawLength, Diagnostic> {
    match &node.value {
        Value::Scalar { text, plain, .. } if !*plain || resolve_plain(text) == Kind::Str => {
            Ok(RawLength::SizeExpression)
        }
        _ => expect_integer(node, "size").map(RawLength::Size),
    }
}

/// `prefix:` is a type name; whether it is an unsigned integer type is checked in stage 4.
fn read_prefix(node: &Node) -> Result<RawLength, Diagnostic> {
    expect_string(node, "prefix", Name::InvalidPrefix).map(|prefix| RawLength::Prefix(prefix.value))
}

/// `terminator:` is an integer; whether it is a byte is checked in stage 4.
fn read_terminator(node: &Node) -> Result<RawLength, Diagnostic> {
    expect_integer(node, "terminator").map(RawLength::Terminator)
}

impl LengthKey {
    /// Stage 4: the length this key gives a `string` or `bytes` Field, encoded as `encoding`.
    fn check(&self, encoding: Option<Encoding>) -> Result<Length, Diagnostic> {
        let span = self.value.span.clone();
        match &self.value.value {
            RawLength::Size(size) => usize::try_from(*size).map(Length::Constant).map_err(|_| {
                Diagnostic::new(Name::InvalidSize, span, format!("a size cannot be negative, found `{size}`"))
            }),
            RawLength::SizeExpression => Err(Diagnostic::new(
                Name::NotSupportedYet,
                span,
                "`size` Expressions are not supported by this version of Wirdigen yet",
            )
            .with_note("write the size as a constant integer", None)),
            RawLength::Prefix(name) => {
                if let Some(bytes) = Builtin::from_name(name).and_then(Builtin::unsigned_bytes) {
                    return Ok(Length::Prefix(bytes));
                }
                let unsigned: Vec<&str> =
                    BUILTINS.iter().filter(|(_, b)| b.unsigned_bytes().is_some()).map(|(n, _)| *n).collect();
                Err(Diagnostic::new(Name::InvalidPrefix, span, format!("`{name}` is not an unsigned integer type"))
                    .with_note(format!("`prefix` is one of: {}", unsigned.join(", ")), None))
            }
            RawLength::Terminator(value) => match (u8::try_from(*value), encoding) {
                (Ok(byte), Some(encoding)) if byte != 0 && encoding.unit() > 1 => Err(Diagnostic::new(
                    Name::InvalidTerminator,
                    span,
                    format!("a `{}` string ends at a 2-byte zero", encoding.as_str()),
                )
                .with_note("write `terminator: 0`", None)),
                (Ok(byte), _) => Ok(Length::Terminator(byte)),
                (Err(_), _) => Err(Diagnostic::new(Name::InvalidTerminator, span, format!("`{value}` is not a byte"))
                    .with_note("a terminator is a byte, from 0 to 255", None)),
            },
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
    encoding: Option<Spanned<String>>,
    display: Option<Spanned<String>>,
    label: Option<Spanned<String>>,
    description: Option<Spanned<String>>,
    /// The length keys present, in documentation order.
    lengths: Vec<LengthKey>,
    mappings: mapping::RawMappings,
}

/// A validated Field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Field {
    pub(crate) name: String,
    pub(crate) ty: Builtin,
    /// The byte order in effect: the Field's own, else the top level's.
    pub(crate) endian: Endian,
    /// How many bytes the Field reads.
    pub(crate) length: Length,
    /// The `encoding:` value, or the default; `None` for a type that takes none.
    pub(crate) encoding: Option<Encoding>,
    /// The `display:` value, or the type's default; `None` for a type that takes none.
    pub(crate) display: Option<Display>,
    /// The tree text, when `label:` gives one (spec §3.4.8).
    pub(crate) label: Option<String>,
    /// The `ProtoField` blurb, when `description:` gives one.
    pub(crate) description: Option<String>,
    /// The labels of values, states or the unit, when the Field has any (spec §3.4.7).
    pub(crate) mapping: Option<Mapping>,
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
    let name = keys.get("name").and_then(|value| record(expect_string(value, "name", Name::InvalidFieldName), errors));

    let ty = read_kind(node, &keys, errors);

    let mut string_value =
        |key: &str, invalid: Name| keys.get(key).and_then(|value| record(expect_string(value, key, invalid), errors));
    let endian = string_value("endian", Name::InvalidEndian);
    let encoding = string_value("encoding", Name::IncompatibleDisplay);
    let display = string_value("display", Name::IncompatibleDisplay);
    let label = string_value("label", Name::InvalidLabel);
    let description = string_value("description", Name::InvalidDescription);
    let lengths = LENGTH_KEYS
        .iter()
        .filter_map(|(k, read)| {
            let (key, value) = (keys.key_of(k)?, keys.get(k)?);
            let raw = record(read(value), errors)?;
            Some(LengthKey {
                key: Spanned { value: *k, span: key.span.clone() },
                value: Spanned { value: raw, span: value.span.clone() },
            })
        })
        .collect();
    let mappings = mapping::read(&keys, errors);

    match (name, ty) {
        (Some(name), Some(ty)) if errors.len() == before => {
            Some(RawField { name, ty, endian, encoding, display, label, description, lengths, mappings })
        }
        _ => None,
    }
}

/// Reads what a Field is: its `type:` when that is its one kind key (spec §3.4.3). A missing,
/// conflicting or not yet supported kind is pushed as an error.
fn read_kind(node: &Node, keys: &Keys<'_>, errors: &mut Vec<Diagnostic>) -> Option<Spanned<String>> {
    let kinds: Vec<(&str, &Node)> = KIND_KEYS.iter().filter_map(|k| keys.key_of(k).map(|key| (*k, key))).collect();
    match kinds.as_slice() {
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
            record(expect_string(value, "type", Name::WrongValueType), errors)
        }
        [(kind, key)] => {
            errors.push(Diagnostic::new(
                Name::NotSupportedYet,
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
    }
}

/// Stage 4: checks the Fields of one structure, pushing every Diagnostic.
///
/// Returns the Fields that passed. A wrong Field is left out, so the layout is complete only
/// when no error was pushed: the caller decides on the run as a whole.
pub(crate) fn check(
    fields: &[RawField],
    endian: Endian,
    enums: &mut Enums<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<Field> {
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
        if ty.is_none() {
            diagnostics.push(unresolved_type(&field.ty));
        }
        let encoding = match (ty, &field.encoding) {
            (Some(ty), Some(value)) => record(Encoding::check(value, &field.ty, ty), diagnostics).map(Some),
            (Some(ty), None) => Some(ty.encodings().first().copied()),
            (None, _) => Some(None),
        };
        let length = ty.zip(encoding).and_then(|(ty, encoding)| check_length(field, ty, encoding, diagnostics));
        let endian = match &field.endian {
            Some(value) => record(Endian::check(value), diagnostics),
            None => Some(endian),
        };
        let display = match (ty, &field.display) {
            (Some(ty), Some(value)) => record(Display::check(value, &field.ty, ty), diagnostics).map(Some),
            (Some(ty), None) => Some(ty.displays().first().copied()),
            (None, _) => None,
        };
        let mapping = ty.and_then(|ty| mapping::check(&field.mappings, &field.ty, ty, enums, diagnostics).ok());
        check_tree_text(field, diagnostics);
        if let (Some(ty), Some(endian), Some(length), Some(encoding), Some(display), Some(mapping)) =
            (ty, endian, length, encoding, display, mapping)
        {
            let text = |value: &Option<Spanned<String>>| value.as_ref().map(|v| v.value.clone());
            let (label, description) = (text(&field.label), text(&field.description));
            layout.push(Field {
                name: name.value.clone(),
                ty,
                endian,
                length,
                encoding,
                display,
                label,
                description,
                mapping,
            });
        }
    }
    layout
}

/// The length of a Field of type `ty` encoded as `encoding`: a fixed-size type's own or a
/// timestamp's encoding's, which take no length key, or the one length key a `string` or
/// `bytes` needs (spec §3.4.5, §3.6).
fn check_length(
    field: &RawField,
    ty: Builtin,
    encoding: Option<Encoding>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Length> {
    if let Some(size) = ty.fixed_size().or_else(|| encoding.and_then(Encoding::time_size)) {
        for LengthKey { key, .. } in &field.lengths {
            diagnostics.push(
                Diagnostic::new(
                    Name::UnexpectedLength,
                    key.span.clone(),
                    format!("`{}` has a fixed size and takes no `{}`", field.ty.value, key.value),
                )
                .with_note(format!("remove `{}`", key.value), None),
            );
        }
        return Some(Length::Constant(size));
    }
    let [length, rest @ ..] = field.lengths.as_slice() else {
        diagnostics.push(
            Diagnostic::new(Name::MissingLength, field.ty.span.clone(), format!("`{}` needs a length", field.ty.value))
                .with_note("give exactly one of `size`, `prefix` or `terminator`", None),
        );
        return None;
    };
    if rest.is_empty() {
        return record(length.check(encoding), diagnostics);
    }
    for other in rest {
        diagnostics.push(
            Diagnostic::new(
                Name::ConflictingLength,
                other.key.span.clone(),
                format!("a Field cannot have both `{}` and `{}`", length.key.value, other.key.value),
            )
            .with_note(format!("`{}` is here", length.key.value), Some(length.key.span.clone())),
        );
    }
    None
}

/// `label:` is non-empty and single line, `description:` single line (spec §3.4.8).
fn check_tree_text(field: &RawField, diagnostics: &mut Vec<Diagnostic>) {
    if let Some(label) = field.label.as_ref().filter(|l| l.value.trim().is_empty() || !is_single_line(&l.value)) {
        diagnostics.push(Diagnostic::new(
            Name::InvalidLabel,
            label.span.clone(),
            "a label must be a non-empty single line",
        ));
    }
    if let Some(description) = field.description.as_ref().filter(|d| !is_single_line(&d.value)) {
        diagnostics.push(Diagnostic::new(
            Name::InvalidDescription,
            description.span.clone(),
            "a description must be a single line",
        ));
    }
}

/// Why a `type:` names no built-in: an unknown Type, or no type at all.
fn unresolved_type(ty: &Spanned<String>) -> Diagnostic {
    let name = ty.value.as_str();
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
