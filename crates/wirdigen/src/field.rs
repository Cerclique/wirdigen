//! Fields of a layout: strict deserialization (stage 2) and semantic checks (stage 4).
//!
//! Stage 2 reads each entry's keys into a [`RawField`]; stage 4 turns the raw Fields into the
//! validated [`Field`]s lowering relies on, so lowering never sees a Field validation rejected.

use std::collections::BTreeMap;
use std::ops::{Range, RangeInclusive};

use crate::bits::{self, Bit, RawBits};
use crate::diagnostic::{Diagnostic, Name, record};
use crate::expect::{self, Expect, RawExpect};
use crate::expr::{self, Expr, ExprKind, Fault};
use crate::index::{FieldId, TypeId};
use crate::keys::{
    Keys, Spanned, closest, expect_bool, expect_integer, expect_string, is_single_line, read_keys, wrong_type,
};
use crate::mapping::{self, Enums, Mapping, Subject};
use crate::scalar::{Kind, resolve_plain};
use crate::scope::{self, Level, Reference, Scope};
use crate::switch::{self, RawBody, RawSwitch, Switch};
use crate::types::Types;
use crate::yaml::{Node, Value};

/// The keys of a Field this version reads, in documentation order.
pub(crate) const KEYS: [&str; 25] = [
    "name",
    "type",
    "fields",
    "switch",
    "cases",
    "default",
    "bits",
    "count",
    "repeat",
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
    "expect",
    "dissector",
    "label",
    "description",
    "hidden",
    "if",
];

/// The keys that say what a Field is; exactly one is required (spec §3.4.3).
pub(crate) const KIND_KEYS: [&str; 3] = ["type", "fields", "switch"];

/// How stage 2 reads the value of one length key.
type ReadLength = fn(&Node) -> Result<RawLength<Parse>, Diagnostic>;

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

    /// The values of an integer type, or `None` for any other type.
    pub(crate) fn int_range(self) -> Option<RangeInclusive<i128>> {
        match self {
            Self::Int { signed: false, bytes } => Some(0..=(1_i128 << (8 * bytes)) - 1),
            Self::Int { signed: true, bytes } => {
                let half = 1_i128 << (8 * bytes - 1);
                Some(-half..=half - 1)
            }
            _ => None,
        }
    }

    pub(crate) fn from_name(name: &str) -> Option<Self> {
        BUILTINS.iter().find(|(n, _)| *n == name).map(|(_, b)| *b)
    }

    /// Every built-in with its name, in documentation order.
    pub(crate) fn all() -> impl Iterator<Item = (&'static str, Self)> {
        BUILTINS.into_iter()
    }

    /// The type's name, as written in `type:`.
    pub(crate) fn name(self) -> &'static str {
        BUILTINS.iter().find(|(_, b)| *b == self).map(|(n, _)| *n).expect("every built-in has a name")
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
    pub(crate) fn check(value: &Spanned<String>, ty: &Spanned<String>, builtin: Builtin) -> Result<Self, Diagnostic> {
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Length {
    /// A constant number of bytes: a fixed-size type's, or a constant `size:`.
    Constant(usize),
    /// As many bytes as a `size:` Expression with operators or references gives. A constant
    /// one was checked to be a size; any other is checked when the packet is read (spec §4.4).
    Expression {
        expr: Expr,
        /// What each Field Path of the Expression reads, by its segments.
        references: BTreeMap<Vec<String>, Reference>,
    },
    /// The number of bytes is an unsigned integer of this many bytes just before the value
    /// (`prefix:`), in the Field's byte order.
    Prefix(usize),
    /// The value ends at this byte (`terminator:`), repeated over a string's code unit. The
    /// terminator is read but is not part of the value.
    Terminator(u8),
}

/// An Expression as stage 2 leaves it: parsed, or its syntax error, which stage 3 reports.
///
/// The raw description types take it as their parameter until stage 3 turns each into one
/// holding a bare [`Expr`], the default, which is all stage 4 sees.
pub(crate) type Parse = Result<Expr, Diagnostic>;

/// A `size:`, `count:`, `if:` or `switch:` value as written: after stage 2 with a [`Parse`],
/// after stage 3 with a bare [`Expr`].
#[derive(Debug, Clone)]
pub(crate) enum RawAmount<E = Expr> {
    /// A constant.
    Constant(i64),
    /// An Expression.
    Expression(E),
}

impl RawAmount {
    /// The Expression, when the value is one.
    pub(crate) fn expression(&self) -> Option<&Expr> {
        match self {
            Self::Expression(expr) => Some(expr),
            Self::Constant(_) => None,
        }
    }
}

impl Spanned<RawAmount<Parse>> {
    /// Stage 3: the value with its Expression parsed, `None` after pushing its syntax error.
    pub(crate) fn parsed(self, errors: &mut Vec<Diagnostic>) -> Option<Spanned<RawAmount>> {
        let value = match self.value {
            RawAmount::Constant(value) => RawAmount::Constant(value),
            RawAmount::Expression(parse) => RawAmount::Expression(record(parse, errors)?),
        };
        Some(Spanned { value, span: self.span })
    }
}

/// A length key's value as written, after stage 2.
#[derive(Debug, Clone)]
enum RawLength<E = Expr> {
    /// `size:` with a constant or an Expression.
    Size(RawAmount<E>),
    /// `prefix:` with a type name.
    Prefix(String),
    /// `terminator:` with a constant.
    Terminator(i64),
}

/// A length key of a Field, with its value.
#[derive(Debug, Clone)]
struct LengthKey<E = Expr> {
    key: Spanned<&'static str>,
    value: Spanned<RawLength<E>>,
}

impl LengthKey<Parse> {
    /// Stage 3: the key with a `size:` Expression parsed, `None` after pushing its syntax error.
    fn parsed(self, errors: &mut Vec<Diagnostic>) -> Option<LengthKey> {
        let Spanned { value, span } = self.value;
        let value = match value {
            RawLength::Size(amount) => {
                RawLength::Size(Spanned { value: amount, span: span.clone() }.parsed(errors)?.value)
            }
            RawLength::Prefix(name) => RawLength::Prefix(name),
            RawLength::Terminator(byte) => RawLength::Terminator(byte),
        };
        Some(LengthKey { key: self.key, value: Spanned { value, span } })
    }
}

/// `size:` is an integer, or an Expression written as a string.
fn read_size(node: &Node) -> Result<RawLength<Parse>, Diagnostic> {
    read_amount(node, "size").map(RawLength::Size)
}

/// The value of `key`, `size:`, `count:`, `if:` or `switch:`: an integer, or an Expression
/// written as a string.
pub(crate) fn read_amount(node: &Node, key: &str) -> Result<RawAmount<Parse>, Diagnostic> {
    match &node.value {
        Value::Scalar { text, plain, .. } if !*plain || resolve_plain(text) == Kind::Str => {
            Ok(RawAmount::Expression(expr::parse(node, text)))
        }
        _ => expect_integer(node, key).map(RawAmount::Constant),
    }
}

/// How a Field repeats (spec §3.7), as written.
#[derive(Debug, Clone)]
enum RawArray<E = Expr> {
    /// `count:`, with its value.
    Count(Spanned<RawAmount<E>>),
    /// `repeat: to_end`.
    ToEnd,
}

impl Spanned<RawArray<Parse>> {
    /// Stage 3: the array with its `count:` Expression parsed, `None` after pushing its syntax
    /// error.
    fn parsed(self, errors: &mut Vec<Diagnostic>) -> Option<Spanned<RawArray>> {
        let value = match self.value {
            RawArray::Count(count) => RawArray::Count(count.parsed(errors)?),
            RawArray::ToEnd => RawArray::ToEnd,
        };
        Some(Spanned { value, span: self.span })
    }
}

/// Stage 2: reads `count:` and `repeat:`, which are mutually exclusive.
fn read_array(keys: &Keys<'_>, errors: &mut Vec<Diagnostic>) -> Option<Spanned<RawArray<Parse>>> {
    let count = keys.key_of("count").zip(keys.get("count"));
    let repeat = keys.key_of("repeat").zip(keys.get("repeat"));
    match (count, repeat) {
        (Some((count_key, _)), Some((repeat_key, _))) => {
            errors.push(
                Diagnostic::new(
                    Name::ConflictingRepeat,
                    repeat_key.span.clone(),
                    "a Field cannot have both `count` and `repeat`",
                )
                .with_note("`count` is here", Some(count_key.span.clone())),
            );
            None
        }
        (Some((key, value)), None) => {
            let amount = record(read_amount(value, "count"), errors)?;
            let count = Spanned { value: amount, span: value.span.clone() };
            Some(Spanned { value: RawArray::Count(count), span: key.span.clone() })
        }
        (None, Some((key, value))) => {
            record(read_repeat(value), errors)?;
            Some(Spanned { value: RawArray::ToEnd, span: key.span.clone() })
        }
        (None, None) => None,
    }
}

/// `repeat:` is `to_end`, the only way to repeat other than `count:` in this version.
fn read_repeat(node: &Node) -> Result<(), Diagnostic> {
    match &node.value {
        Value::Scalar { text, .. } if text == "to_end" => Ok(()),
        _ => Err(Diagnostic::new(Name::InvalidRepeat, node.span.clone(), "`repeat` must be `to_end`")
            .with_note("`repeat: to_end` repeats until the message ends; `count` gives a number of elements", None)),
    }
}

/// `prefix:` is a type name; whether it is an unsigned integer type is checked in stage 4.
fn read_prefix(node: &Node) -> Result<RawLength<Parse>, Diagnostic> {
    expect_string(node, "prefix", Name::InvalidPrefix).map(|prefix| RawLength::Prefix(prefix.value))
}

/// `terminator:` is an integer; whether it is a byte is checked in stage 4.
fn read_terminator(node: &Node) -> Result<RawLength<Parse>, Diagnostic> {
    expect_integer(node, "terminator").map(RawLength::Terminator)
}

impl LengthKey {
    /// Stage 4: the length this key gives a `string` or `bytes` Field, encoded as `encoding`.
    fn check<'a>(
        &self,
        encoding: Option<Encoding>,
        scope: Scope<'a, '_>,
        types: &Types<'a>,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> Option<Length> {
        record(self.check_value(encoding, scope, types, diagnostics), diagnostics).flatten()
    }

    /// The length, or `Ok(None)` when an Expression's references were reported.
    fn check_value<'a>(
        &self,
        encoding: Option<Encoding>,
        scope: Scope<'a, '_>,
        types: &Types<'a>,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> Result<Option<Length>, Diagnostic> {
        let span = self.value.span.clone();
        match &self.value.value {
            RawLength::Size(amount) => {
                Ok(check_amount(amount, span, Amounts::SIZE, scope, types, diagnostics)?.map(Length::from))
            }
            RawLength::Prefix(name) => {
                if let Some(bytes) = Builtin::from_name(name).and_then(Builtin::unsigned_bytes) {
                    return Ok(Some(Length::Prefix(bytes)));
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
                (Ok(byte), _) => Ok(Some(Length::Terminator(byte))),
                (Err(_), _) => Err(Diagnostic::new(Name::InvalidTerminator, span, format!("`{value}` is not a byte"))
                    .with_note("a terminator is a byte, from 0 to 255", None)),
            },
        }
    }
}

/// A validated number of bytes (`size:`) or of elements (`count:`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Amount {
    /// A constant, written as an integer.
    Constant(usize),
    /// An Expression with operators or references. A constant one was checked to be zero or
    /// more; any other is checked when the packet is read (spec §4.4).
    Expression {
        expr: Expr,
        /// What each Field Path of the Expression reads, by its segments.
        references: BTreeMap<Vec<String>, Reference>,
    },
}

impl From<Amount> for Length {
    fn from(amount: Amount) -> Self {
        match amount {
            Amount::Constant(size) => Self::Constant(size),
            Amount::Expression { expr, references } => Self::Expression { expr, references },
        }
    }
}

/// What an amount counts, for its Diagnostics.
#[derive(Debug, Clone, Copy)]
struct Amounts {
    /// The noun in messages: `size`, `count`.
    noun: &'static str,
    /// The error of a constant that is negative or has no value.
    invalid: Name,
}

impl Amounts {
    /// A `size:`: a number of bytes (spec §3.6).
    const SIZE: Self = Self { noun: "size", invalid: Name::InvalidSize };
    /// A `count:`: a number of array elements (spec §3.7).
    const COUNT: Self = Self { noun: "count", invalid: Name::InvalidCount };
    /// A `padding:`: a number of bytes skipped (spec §3.10).
    const PADDING: Self = Self { noun: "padding", invalid: Name::InvalidPadding };
}

/// Stage 4: the amount a `size:` or `count:` value at `span`, read from `scope`, gives (spec
/// §3.6, §3.7, §4.3). A constant must be zero or more, reached without a fault (§4.4).
/// `Ok(None)` when a reference was reported.
fn check_amount<'a>(
    amount: &RawAmount,
    span: Range<usize>,
    what: Amounts,
    scope: Scope<'a, '_>,
    types: &Types<'a>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Option<Amount>, Diagnostic> {
    let noun = what.noun;
    let expression = match amount {
        RawAmount::Constant(value) => {
            return usize::try_from(*value).map(|value| Some(Amount::Constant(value))).map_err(|_| {
                Diagnostic::new(what.invalid, span, format!("a {noun} cannot be negative, found `{value}`"))
            });
        }
        RawAmount::Expression(expression) => expression,
    };
    let Some(value) = expression.constant() else {
        let paths = paths(expression);
        let Some(references) = scope::resolve_paths(&paths, scope, types, diagnostics) else { return Ok(None) };
        return Ok(Some(Amount::Expression { expr: expression.clone(), references }));
    };
    let value = match value {
        Ok(value) => value,
        Err(fault) => {
            let message = match fault.value {
                Fault::DivisionByZero => format!("this {noun} divides by zero"),
                Fault::ShiftOutOfRange(count) => format!("this {noun} shifts by {count}, outside 0 to 63"),
            };
            return Err(Diagnostic::new(what.invalid, fault.span, message));
        }
    };
    let Ok(value) = usize::try_from(value) else {
        return Err(Diagnostic::new(what.invalid, span, format!("a {noun} cannot be negative, this one is `{value}`")));
    };
    Ok(Some(match expression.kind {
        ExprKind::Int(_) => Amount::Constant(value),
        _ => Amount::Expression { expr: expression.clone(), references: BTreeMap::new() },
    }))
}

/// The Field Paths an Expression reads, by their segments, with their spans.
fn paths(expression: &Expr) -> Vec<(&[String], Range<usize>)> {
    expression
        .references()
        .into_iter()
        .filter_map(|r| match &r.kind {
            ExprKind::Path(segments) => Some((segments.as_slice(), r.span.clone())),
            _ => None,
        })
        .collect()
}

/// Stage 3: `entries` with every Expression parsed, theirs and their inline structures', pushing
/// each syntax error. An entry with one is left out: the run stops at stage 3 then.
pub(crate) fn parsed(entries: Vec<RawEntry<Parse>>, errors: &mut Vec<Diagnostic>) -> Vec<RawEntry> {
    entries.into_iter().filter_map(|entry| entry.parsed(errors)).collect()
}

/// Byte order (spec §3.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Endian {
    #[default]
    Big,
    Little,
}

impl Endian {
    /// The byte order an optional `endian:` value sets, else `default`. An invalid value is
    /// reported and gives `default`: the run fails on it anyway, so any stand-in will do.
    pub(crate) fn resolve(value: Option<&Spanned<String>>, default: Self, diagnostics: &mut Vec<Diagnostic>) -> Self {
        value.and_then(|v| record(Self::check(v), diagnostics)).unwrap_or(default)
    }

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

/// The keys only a Field read as a value takes, in documentation order: an inline structure
/// takes none of them (spec §3.4.3).
const VALUE_KEYS: [&str; 11] =
    ["size", "prefix", "terminator", "encoding", "display", "values", "true", "false", "unit", "expect", "dissector"];

/// The keys a Field of a Type does not take, in documentation order: the value keys, and
/// `endian:`, since a Type is read in its own byte order (spec §3.5, §3.11).
const TYPE_USE_KEYS: [&str; 12] = [
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
    "expect",
    "dissector",
];

/// `dissector:` as written (spec §3.10).
#[derive(Debug, Clone)]
struct RawDissector {
    /// Where the `dissector` key is written, where a Field that takes none is reported.
    key: Range<usize>,
    /// The Dissector's name.
    name: String,
}

/// What a Field is, as written.
#[derive(Debug, Clone)]
enum RawKind<E = Expr> {
    /// `type:` with a type name, and the keys present that a Field of a Type does not take.
    Type { name: Spanned<String>, type_use_keys: Vec<Spanned<&'static str>> },
    /// `fields:` with an inline structure, and the keys present that only a value takes.
    Structure { fields: Vec<RawEntry<E>>, value_keys: Vec<Spanned<&'static str>> },
    /// `switch:`, with its cases (spec §3.9).
    Switch(RawSwitch<E>),
}

impl RawKind<Parse> {
    /// Stage 3: the kind with its Expressions parsed, `None` after pushing a syntax error.
    fn parsed(self, errors: &mut Vec<Diagnostic>) -> Option<RawKind> {
        Some(match self {
            Self::Type { name, type_use_keys } => RawKind::Type { name, type_use_keys },
            Self::Structure { fields, value_keys } => RawKind::Structure { fields: parsed(fields, errors), value_keys },
            Self::Switch(switch) => RawKind::Switch(switch.parsed(errors)?),
        })
    }
}

/// An entry of a structure as written, after stage 2 (spec §3.4.1): a Field, or bytes to skip.
#[derive(Debug, Clone)]
pub(crate) enum RawEntry<E = Expr> {
    /// A Field, boxed: it is many times the size of a padding.
    Field(Box<RawField<E>>),
    /// `{ padding: n }`.
    Padding(RawPadding<E>),
}

impl RawEntry<Parse> {
    /// Stage 3: the entry with its Expressions parsed, `None` after pushing a syntax error.
    fn parsed(self, errors: &mut Vec<Diagnostic>) -> Option<RawEntry> {
        match self {
            Self::Field(field) => field.parsed(errors).map(|f| RawEntry::Field(Box::new(f))),
            Self::Padding(RawPadding { key, amount }) => {
                Some(RawEntry::Padding(RawPadding { key, amount: amount.parsed(errors)? }))
            }
        }
    }
}

/// `{ padding: n }` as written (spec §3.10): bytes skipped, shown as one "Padding" item.
#[derive(Debug, Clone)]
pub(crate) struct RawPadding<E = Expr> {
    /// Where the `padding` key is written.
    key: Range<usize>,
    /// The number of bytes: a constant or an Expression.
    amount: Spanned<RawAmount<E>>,
}

impl RawEntry {
    /// The Field, when the entry is one.
    pub(crate) fn field(&self) -> Option<&RawField> {
        match self {
            Self::Field(field) => Some(field.as_ref()),
            Self::Padding(_) => None,
        }
    }

    /// The Field Paths the entry's own Expressions read, by their segments, with their spans.
    pub(crate) fn paths(&self) -> Vec<(&[String], Range<usize>)> {
        match self {
            Self::Field(field) => field.paths(),
            Self::Padding(padding) => padding.amount.value.expression().map(paths).unwrap_or_default(),
        }
    }
}

/// The Fields among `entries`, in order.
pub(crate) fn fields(entries: &[RawEntry]) -> impl Iterator<Item = &RawField> {
    entries.iter().filter_map(RawEntry::field)
}

/// A Field as written, after stage 2: its keys are known and of the right kinds.
#[derive(Debug, Clone)]
pub(crate) struct RawField<E = Expr> {
    /// The declaration's identity, from where its name is written.
    id: FieldId,
    name: Spanned<String>,
    kind: RawKind<E>,
    endian: Option<Spanned<String>>,
    encoding: Option<Spanned<String>>,
    display: Option<Spanned<String>>,
    label: Option<Spanned<String>>,
    description: Option<Spanned<String>>,
    /// The length keys present, in documentation order.
    lengths: Vec<LengthKey<E>>,
    mappings: mapping::RawMappings,
    /// `expect:`, the values the Field should hold (spec §3.10).
    expect: Option<RawExpect>,
    /// `dissector:`, the dissector the bytes are handed to (spec §3.10), at its key.
    dissector: Option<RawDissector>,
    /// The sub-Fields, when the Field is a bitfield (spec §3.8).
    bits: Option<RawBits>,
    /// How the Field repeats, when it is an array (spec §3.7), at its key.
    array: Option<Spanned<RawArray<E>>>,
    /// `hidden:`, which leaves the Field out of the tree (spec §3.10).
    hidden: Option<Spanned<bool>>,
    /// `if:`, the condition the Field is read under (spec §3.9): a constant or an Expression.
    condition: Option<Spanned<RawAmount<E>>>,
}

impl RawField<Parse> {
    /// Stage 3: the Field with its Expressions parsed, its inline structures' and cases' too,
    /// `None` after pushing a syntax error.
    fn parsed(self, errors: &mut Vec<Diagnostic>) -> Option<RawField> {
        let before = errors.len();
        let condition = self.condition.and_then(|c| c.parsed(errors));
        let lengths = self.lengths.into_iter().filter_map(|l| l.parsed(errors)).collect();
        let array = self.array.and_then(|a| a.parsed(errors));
        let kind = self.kind.parsed(errors);
        // A syntax error anywhere below leaves the Field out, nested ones included.
        let (Some(kind), true) = (kind, errors.len() == before) else { return None };
        Some(RawField {
            id: self.id,
            name: self.name,
            kind,
            endian: self.endian,
            encoding: self.encoding,
            display: self.display,
            label: self.label,
            description: self.description,
            lengths,
            mappings: self.mappings,
            expect: self.expect,
            dissector: self.dissector,
            bits: self.bits,
            array,
            hidden: self.hidden,
            condition,
        })
    }
}

/// What a Field written in a description is, as references see it (spec §4.3).
#[derive(Debug, Clone, Copy)]
pub(crate) enum Shape<'a> {
    /// A value of a built-in type, with the type's name as written.
    Value(Builtin, &'a str),
    /// An inline structure, with its entries.
    Structure(&'a [RawEntry]),
    /// A Field of a Type, with the entries of the Type's body.
    Type { name: &'a str, fields: &'a [RawEntry] },
    /// A `switch` Field, with its cases.
    Switch(&'a RawSwitch),
    /// A `type:` naming nothing known, which is an error of its own.
    Unknown,
}

impl RawField {
    /// The declaration's identity.
    pub(crate) fn id(&self) -> FieldId {
        self.id
    }

    pub(crate) fn name(&self) -> &Spanned<String> {
        &self.name
    }

    /// The sub-Fields, when the Field is a bitfield.
    pub(crate) fn bits(&self) -> Option<&RawBits> {
        self.bits.as_ref()
    }

    /// What the Field is, its Type looked up in `types`.
    pub(crate) fn shape<'a>(&'a self, types: &Types<'a>) -> Shape<'a> {
        match &self.kind {
            RawKind::Structure { fields, .. } => Shape::Structure(fields),
            RawKind::Switch(switch) => Shape::Switch(switch),
            RawKind::Type { name, .. } => match (Builtin::from_name(&name.value), types.body(&name.value)) {
                (Some(builtin), _) => Shape::Value(builtin, &name.value),
                (None, Some(fields)) => Shape::Type { name: &name.value, fields },
                (None, None) => Shape::Unknown,
            },
        }
    }

    /// The Field Paths the Field's own Expressions read, by their segments, with their spans.
    pub(crate) fn paths(&self) -> Vec<(&[String], Range<usize>)> {
        self.expressions().flat_map(paths).collect()
    }

    /// The Expressions the Field evaluates before reading itself: its `if:`, `switch:`, `size:`
    /// and `count:`.
    fn expressions(&self) -> impl Iterator<Item = &Expr> {
        self.amounts().filter_map(RawAmount::expression)
    }

    /// The values of the Field's `if:`, `switch:`, `size:` and `count:`.
    fn amounts(&self) -> impl Iterator<Item = &RawAmount> {
        let sizes = self.lengths.iter().filter_map(|l| match &l.value.value {
            RawLength::Size(amount) => Some(amount),
            RawLength::Prefix(_) | RawLength::Terminator(_) => None,
        });
        let count = match self.array.as_ref().map(|a| &a.value) {
            Some(RawArray::Count(count)) => Some(&count.value),
            Some(RawArray::ToEnd) | None => None,
        };
        let subject = match &self.kind {
            RawKind::Switch(switch) => Some(&switch.subject.value),
            RawKind::Type { .. } | RawKind::Structure { .. } => None,
        };
        self.condition.iter().map(|c| &c.value).chain(subject).chain(sizes).chain(count)
    }

    /// Where the `if:` value is written, when the Field is read under one (spec §3.9).
    pub(crate) fn condition_span(&self) -> Option<&Range<usize>> {
        self.condition.as_ref().map(|c| &c.span)
    }

    /// Whether the Field is an array (spec §3.7), whose Fields only its elements can read.
    pub(crate) fn is_array(&self) -> bool {
        self.array.is_some()
    }

    /// Why the Field reads up to the end of the message, if it surely does (spec §6.3
    /// `unreachable-field`): `size: "_remaining"` (§3.6) or `repeat: to_end` (§3.7), on the
    /// Field itself or on a Field it always reads, through inline structures, Types and
    /// `switch` Fields whose every case reads to the end. A Field under `if:` may not be read,
    /// and an array with a `count:` may have no element, which leaves the bytes to the Fields
    /// after it.
    fn reads_to_end(&self, types: &Types<'_>) -> Option<String> {
        self.reads_to_end_in(types, &mut Vec::new()).map(|(path, why)| match path.as_slice() {
            [] => why.to_owned(),
            _ => format!("`{}` inside it: {why}", path.join(".")),
        })
    }

    /// The path below this Field to the one that reads to the end, and why it does. `seen` holds
    /// the Types being walked, so a recursive Type, already an error, stops the walk.
    fn reads_to_end_in<'t>(&self, types: &Types<'t>, seen: &mut Vec<&'t str>) -> Option<(Vec<String>, &'static str)> {
        if self.condition.is_some() {
            return None;
        }
        match self.array.as_ref().map(|a| &a.value) {
            Some(RawArray::ToEnd) => {
                return Some((Vec::new(), "`repeat: to_end` leaves no bytes for the Fields after it"));
            }
            Some(_) => return None,
            None => {}
        }
        let remaining = self.lengths.iter().any(|l| match &l.value.value {
            RawLength::Size(amount) => {
                amount.expression().is_some_and(|e| e.kind == ExprKind::Builtin(expr::Builtin::Remaining))
            }
            RawLength::Prefix(_) | RawLength::Terminator(_) => false,
        });
        if remaining {
            return Some((Vec::new(), "`size: \"_remaining\"` leaves no bytes for the Fields after it"));
        }
        match &self.kind {
            RawKind::Structure { fields, .. } => entries_read_to_end(fields, types, seen),
            RawKind::Type { name, .. } => type_reads_to_end(&name.value, types, seen),
            RawKind::Switch(switch) => {
                let mut bodies = switch.bodies().map(|(_, body)| match body {
                    RawBody::Fields(fields) => entries_read_to_end(fields, types, seen),
                    RawBody::Type(name) => type_reads_to_end(&name.value, types, seen),
                });
                let some = !switch.cases.is_empty();
                (some && bodies.all(|reads| reads.is_some()))
                    .then(|| (Vec::new(), "every case reads to the end of the message"))
            }
        }
    }
}

/// The first Field among `entries` that reads to the end (see [`RawField::reads_to_end`]), with
/// its path below the structure, and why.
fn entries_read_to_end<'t>(
    entries: &[RawEntry],
    types: &Types<'t>,
    seen: &mut Vec<&'t str>,
) -> Option<(Vec<String>, &'static str)> {
    fields(entries).find_map(|field| {
        let (mut path, why) = field.reads_to_end_in(types, seen)?;
        path.insert(0, field.name.value.clone());
        Some((path, why))
    })
}

/// Whether the body of the Type named `name` reads to the end. A built-in or unknown type does
/// not; a Type already being walked is recursive, an error reported elsewhere.
fn type_reads_to_end<'t>(
    name: &str,
    types: &Types<'t>,
    seen: &mut Vec<&'t str>,
) -> Option<(Vec<String>, &'static str)> {
    let (name, body) = types.named_body(name)?;
    if seen.contains(&name) {
        return None;
    }
    seen.push(name);
    let reads = entries_read_to_end(body, types, seen);
    seen.pop();
    reads
}

/// A validated entry of a structure: a Field, or bytes to skip (spec §3.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Entry {
    /// A Field, boxed: it is many times the size of a padding.
    Field(Box<Field>),
    /// `{ padding: n }`: as many bytes as the amount gives, shown as one "Padding" item with no
    /// filter name.
    Padding(Amount),
}

impl Entry {
    /// The Field, when the entry is one.
    pub(crate) fn field(&self) -> Option<&Field> {
        match self {
            Self::Field(field) => Some(field.as_ref()),
            Self::Padding(_) => None,
        }
    }
}

/// A validated Field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Field {
    /// The declaration's identity, which resolved references name it by.
    pub(crate) id: FieldId,
    pub(crate) name: String,
    /// The tree text, when `label:` gives one (spec §3.4.8).
    pub(crate) label: Option<String>,
    /// The `ProtoField` blurb, when `description:` gives one.
    pub(crate) description: Option<String>,
    /// Whether the tree leaves it out (`hidden: true`); it is still filtered (spec §3.10).
    pub(crate) hidden: bool,
    pub(crate) kind: FieldKind,
    /// How the Field repeats, when it is an array of its kind (spec §3.7).
    pub(crate) array: Option<Array>,
    /// The condition the Field is read under, when it has `if:` (spec §3.9): it is read only
    /// when the value is not zero (§4.4).
    pub(crate) condition: Option<Operand>,
    /// Where the name is written, for Diagnostics about the validated layout.
    pub(crate) span: Range<usize>,
}

/// A validated `if:` or `switch:` value, any integer (spec §3.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Operand {
    /// A constant, written as an integer.
    Constant(i64),
    /// An Expression, evaluated when the packet is read: a fault, even in a constant one, is
    /// reported then (spec §4.4).
    Expression {
        expr: Expr,
        /// What each Field Path of the Expression reads, by its segments.
        references: BTreeMap<Vec<String>, Reference>,
    },
}

/// How a validated array repeats its element (spec §3.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Array {
    /// `count:` elements.
    Count(Amount),
    /// Elements until the message ends (`repeat: to_end`).
    ToEnd,
}

/// What a validated Field is (spec §3.4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FieldKind {
    /// A value of a built-in type.
    Builtin(BuiltinField),
    /// An inline structure: its entries, in order, shown as a subtree.
    Structure(Vec<Entry>),
    /// A Field of a Type, shown as a subtree.
    Type {
        id: TypeId,
        /// The Type's name, for Lua names and messages.
        name: String,
        /// The context table this use passes: what each name the Type reads but does not
        /// declare resolves to here, by the name as written (spec §4.3).
        context: Vec<(String, Reference)>,
    },
    /// A `switch` Field, shown as a subtree holding the case read (spec §3.9).
    Switch(Switch),
}

/// How a Field of a built-in type is read and shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BuiltinField {
    pub(crate) ty: Builtin,
    /// The byte order in effect: the Field's own, else the top level's.
    pub(crate) endian: Endian,
    /// How many bytes the Field reads.
    pub(crate) length: Length,
    /// The `encoding:` value, or the default; `None` for a type that takes none.
    pub(crate) encoding: Option<Encoding>,
    /// The `display:` value, or the type's default; `None` for a type that takes none.
    pub(crate) display: Option<Display>,
    /// The labels of values, states or the unit, when the Field has any (spec §3.4.7).
    pub(crate) mapping: Option<Mapping>,
    /// The values the Field should hold, when it has `expect:` (spec §3.10).
    pub(crate) expect: Option<Expect>,
    /// The name of the dissector a `bytes` Field's bytes are handed to, when it has
    /// `dissector:` (spec §3.10).
    pub(crate) dissector: Option<String>,
    /// The sub-Fields of a bitfield, most significant first; empty for any other Field.
    pub(crate) bits: Vec<Bit>,
}

/// Stage 2: reads one entry of a structure, a Field or `{ padding: n }`, pushing its errors.
fn read_entry(node: &Node, errors: &mut Vec<Diagnostic>) -> Option<RawEntry<Parse>> {
    let Value::Mapping(entries) = &node.value else {
        errors.push(wrong_type(node.span.clone(), "a Field is a mapping with a `name` and a `type`"));
        return None;
    };
    let padding = entries.iter().find(|(k, _)| matches!(&k.value, Value::Scalar { text, .. } if text == "padding"));
    let Some((key, _)) = padding else { return read(entries, node, errors).map(|f| RawEntry::Field(Box::new(f))) };
    // `{ padding: n }` takes no other key (spec §3.10).
    let keys = read_keys(entries, &["padding"], errors);
    let value = keys.get("padding")?;
    let amount = record(read_amount(value, "padding"), errors)?;
    let amount = Spanned { value: amount, span: value.span.clone() };
    Some(RawEntry::Padding(RawPadding { key: key.span.clone(), amount }))
}

/// Stage 2: reads a Field, the mapping `entries` at `node`, pushing its errors.
fn read(entries: &[(Node, Node)], node: &Node, errors: &mut Vec<Diagnostic>) -> Option<RawField<Parse>> {
    let before = errors.len();
    let keys = read_keys(entries, &KEYS, errors);

    if keys.get("name").is_none() && !keys.misspelt("name") {
        errors.push(Diagnostic::new(Name::MissingKey, node.span.clone(), "missing required key `name`"));
    }
    let name = keys.get("name").and_then(|value| record(expect_string(value, "name", Name::InvalidFieldName), errors));

    let kind = read_kind(node, &keys, errors);

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
    let expect = expect::read(&keys, errors);
    let dissector = keys.key_of("dissector").zip(keys.get("dissector")).and_then(|(key, value)| {
        let name = record(read_dissector(value), errors)?;
        Some(RawDissector { key: key.span.clone(), name })
    });
    let bits = keys.key_of("bits").zip(keys.get("bits")).and_then(|(key, value)| bits::read(key, value, errors));
    let array = read_array(&keys, errors);
    let hidden = keys.get("hidden").and_then(|value| record(expect_bool(value, "hidden"), errors));
    let condition = keys.get("if").and_then(|value| {
        let amount = record(read_amount(value, "if"), errors)?;
        Some(Spanned { value: amount, span: value.span.clone() })
    });

    match (name, kind) {
        (Some(name), Some(kind)) if errors.len() == before => Some(RawField {
            id: FieldId::at(&name.span),
            name,
            kind,
            endian,
            encoding,
            display,
            label,
            description,
            lengths,
            mappings,
            expect,
            dissector,
            bits,
            array,
            hidden,
            condition,
        }),
        _ => None,
    }
}

/// `dissector:` names a Dissector: a string of one word, else `invalid-dissector`. Whether
/// Wireshark has a dissector by that name is only known when the packet is read (spec §3.10).
fn read_dissector(node: &Node) -> Result<String, Diagnostic> {
    let name = expect_string(node, "dissector", Name::InvalidDissector)?;
    if name.value.is_empty() || name.value.contains(char::is_whitespace) {
        return Err(Diagnostic::new(Name::InvalidDissector, name.span, "`dissector` must name a Dissector")
            .with_note("a dissector name is one word, such as `json`", None));
    }
    Ok(name.value)
}

/// Stage 2: reads a structure, the value of a `fields:` key, pushing its errors (spec §3.4.1).
/// `None` when it is not a non-empty list.
pub(crate) fn read_structure(node: &Node, errors: &mut Vec<Diagnostic>) -> Option<Vec<RawEntry<Parse>>> {
    match &node.value {
        Value::Sequence(items) if items.is_empty() => {
            errors.push(Diagnostic::new(
                Name::EmptyFields,
                node.span.clone(),
                "`fields` must declare at least one Field",
            ));
            None
        }
        Value::Sequence(items) => Some(items.iter().filter_map(|item| read_entry(item, errors)).collect()),
        _ => {
            errors.push(wrong_type(node.span.clone(), "`fields` must be a list of Fields"));
            None
        }
    }
}

/// Reads what a Field is from its one kind key (spec §3.4.3). A missing, conflicting or not yet
/// supported kind is pushed as an error.
fn read_kind(node: &Node, keys: &Keys<'_>, errors: &mut Vec<Diagnostic>) -> Option<RawKind<Parse>> {
    let kinds: Vec<(&str, &Node)> = KIND_KEYS.iter().filter_map(|k| keys.key_of(k).map(|key| (*k, key))).collect();
    // `cases:` and `default:` go only with `switch:` (spec §3.9).
    let case_key = ["cases", "default"].into_iter().find_map(|k| keys.key_of(k).map(|key| (k, key)));
    match (kinds.as_slice(), case_key) {
        ([], Some((case, _))) if !keys.misspelt("switch") => {
            errors.push(
                Diagnostic::new(
                    Name::MissingFieldKind,
                    node.span.clone(),
                    format!("this Field has `{case}` but no `switch`"),
                )
                .with_note("`cases` and `default` belong to a `switch` Field: add `switch: <Expression>`", None),
            );
            return None;
        }
        ([(kind @ ("type" | "fields"), kind_key)], Some((case, case_key))) => {
            errors.push(
                Diagnostic::new(
                    Name::ConflictingFieldKind,
                    case_key.span.clone(),
                    format!("a Field cannot have both `{kind}` and `{case}`"),
                )
                .with_note(
                    format!("`{kind}` is here; `{case}` belongs to a `switch` Field"),
                    Some(kind_key.span.clone()),
                ),
            );
            return None;
        }
        _ => {}
    }
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
            let name = record(expect_string(value, "type", Name::WrongValueType), errors)?;
            Some(RawKind::Type { name, type_use_keys: present(keys, &TYPE_USE_KEYS) })
        }
        [("fields", _)] => {
            let fields = read_structure(keys.get("fields").expect("the key was found"), errors)?;
            Some(RawKind::Structure { fields, value_keys: present(keys, &VALUE_KEYS) })
        }
        [(_, _)] => {
            let subject = keys.get("switch").expect("the only other kind key is `switch`");
            switch::read(subject, node, keys, errors).map(RawKind::Switch)
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

/// Which of `names` are keys of a Field, with their spans.
fn present(keys: &Keys<'_>, names: &[&'static str]) -> Vec<Spanned<&'static str>> {
    names.iter().filter_map(|k| keys.key_of(k).map(|key| Spanned { value: *k, span: key.span.clone() })).collect()
}

/// The `type:` names of `fields` that are not built-ins and the Types of `switch` cases, inline
/// structures and cases included, in source order: the Types they use, and names [`check`] reports as unknown.
pub(crate) fn type_uses(entries: &[RawEntry]) -> Vec<&Spanned<String>> {
    fields(entries)
        .flat_map(|field| match &field.kind {
            RawKind::Type { name, .. } if Builtin::from_name(&name.value).is_none() => vec![name],
            RawKind::Type { .. } => Vec::new(),
            RawKind::Structure { fields, .. } => type_uses(fields),
            RawKind::Switch(switch) => switch
                .bodies()
                .flat_map(|(_, body)| match body {
                    RawBody::Type(name) => vec![name],
                    RawBody::Fields(fields) => type_uses(fields),
                })
                .collect(),
        })
        .collect()
}

/// Whether a `type:` names a Type rather than a built-in. Every built-in is lowercase, so an
/// uppercase first letter means a Type (spec §3.4.2); so does a lowercase name `types:` declares,
/// which is `invalid-type-name` already and must not also be `unknown-type`.
fn names_type(name: &str, types: &Types<'_>) -> bool {
    Builtin::from_name(name).is_none() && (name.starts_with(|c: char| c.is_ascii_uppercase()) || types.declares(name))
}

/// Stage 4: checks the entries of one structure, pushing every Diagnostic.
///
/// Returns the entries that passed. A wrong one is left out, so the layout is complete only
/// when no error was pushed: the caller decides on the run as a whole.
pub(crate) fn check<'a>(
    entries: &'a [RawEntry],
    endian: Endian,
    enums: &mut Enums<'_>,
    types: &mut Types<'a>,
    scope: Scope<'a, '_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<Entry> {
    let mut layout = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let levels: Vec<Level<'a>> =
            scope.levels.iter().copied().chain([Level { fields: entries, at: index }]).collect();
        let scope = Scope { ty: scope.ty, levels: &levels };
        let previous = index.checked_sub(1).and_then(|i| entries[i].field());
        if let Some((previous, why)) = previous.and_then(|f| Some((f, f.reads_to_end(types)?))) {
            let (span, what) = match entry {
                RawEntry::Field(field) => (field.name.span.clone(), format!("`{}`", field.name.value)),
                RawEntry::Padding(padding) => (padding.key.clone(), "this padding".to_owned()),
            };
            diagnostics.push(
                Diagnostic::new(
                    Name::UnreachableField,
                    span,
                    format!("{what} comes after `{}`, which reads to the end", previous.name.value),
                )
                .with_note(why, None),
            );
        }
        let field = match entry {
            RawEntry::Field(field) => field,
            RawEntry::Padding(padding) => {
                let RawPadding { amount, .. } = padding;
                let checked =
                    check_amount(&amount.value, amount.span.clone(), Amounts::PADDING, scope, types, diagnostics);
                layout.extend(record(checked, diagnostics).flatten().map(Entry::Padding));
                continue;
            }
        };
        let name = &field.name;
        check_name(name, fields(&entries[..index]).map(|f| &f.name), diagnostics);
        // A Field naming an Enum uses it, whatever else is wrong with the Field (spec §3.4.7).
        enums.mark_used(&field.mappings);
        let kind = match &field.kind {
            RawKind::Type { name, type_use_keys } if names_type(&name.value, types) => {
                for key in type_use_keys {
                    diagnostics.push(misplaced_key(key, "a Field whose type is a Type", "the Type"));
                }
                if let Some(bits) = &field.bits {
                    diagnostics.push(invalid_bits(bits, "a Field whose type is a Type has no bits"));
                }
                types.resolve(name).and_then(|id| {
                    let context = scope::resolve_context(&name.value, &name.span, scope, types, diagnostics)?;
                    Some(FieldKind::Type { id, name: name.value.clone(), context })
                })
            }
            RawKind::Type { name, .. } => {
                let endian = match &field.endian {
                    Some(value) => record(Endian::check(value), diagnostics),
                    None => Some(endian),
                };
                check_builtin(field, name, endian, enums, types, scope, diagnostics).map(FieldKind::Builtin)
            }
            RawKind::Structure { fields, value_keys } => {
                let endian = Endian::resolve(field.endian.as_ref(), endian, diagnostics);
                for key in value_keys {
                    diagnostics.push(misplaced_key(key, "an inline structure", "the structure"));
                }
                if let Some(bits) = &field.bits {
                    diagnostics.push(invalid_bits(bits, "an inline structure has no bits"));
                }
                Some(FieldKind::Structure(check(fields, endian, enums, types, scope, diagnostics)))
            }
            RawKind::Switch(raw) => switch::check(raw, endian, enums, types, scope, diagnostics).map(FieldKind::Switch),
        };
        let array = match &field.array {
            None => Some(None),
            Some(array) => check_array(field, array, types, scope, diagnostics).map(Some),
        };
        let condition = match &field.condition {
            None => Some(None),
            Some(condition) => check_operand(&condition.value, scope, types, diagnostics).map(Some),
        };
        check_text(field.label.as_ref(), field.description.as_ref(), diagnostics);
        if let (Some(kind), Some(array), Some(condition)) = (kind, array, condition) {
            let text = |value: &Option<Spanned<String>>| value.as_ref().map(|v| v.value.clone());
            layout.push(Entry::Field(Box::new(Field {
                id: field.id,
                name: name.value.clone(),
                label: text(&field.label),
                description: text(&field.description),
                hidden: field.hidden.as_ref().is_some_and(|h| h.value),
                kind,
                array,
                condition,
                span: name.span.clone(),
            })));
        }
    }
    layout
}

/// Checks a Field of type `ty` read with the byte order `endian` (`None` when its own is
/// invalid), returning how it is read when nothing is wrong.
fn check_builtin<'a>(
    field: &RawField,
    ty_name: &Spanned<String>,
    endian: Option<Endian>,
    enums: &mut Enums<'_>,
    types: &Types<'a>,
    scope: Scope<'a, '_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<BuiltinField> {
    let ty = Builtin::from_name(&ty_name.value);
    if ty.is_none() {
        diagnostics.push(unresolved_type(ty_name));
    }
    let encoding = match (ty, &field.encoding) {
        (Some(ty), Some(value)) => record(Encoding::check(value, ty_name, ty), diagnostics).map(Some),
        (Some(ty), None) => Some(ty.encodings().first().copied()),
        (None, _) => Some(None),
    };
    let length = ty
        .zip(encoding)
        .and_then(|(ty, encoding)| check_length(field, ty_name, ty, encoding, types, scope, diagnostics));
    let display = match (ty, &field.display) {
        (Some(ty), Some(value)) => record(Display::check(value, ty_name, ty), diagnostics).map(Some),
        (Some(ty), None) => Some(ty.displays().first().copied()),
        (None, _) => None,
    };
    let mapping =
        ty.and_then(|ty| mapping::check(&field.mappings, &Subject::builtin(ty_name, ty), enums, diagnostics).ok());
    let expect = match (ty, &field.expect) {
        (_, None) | (None, _) => Some(None),
        (Some(ty), Some(raw)) => record(expect::Subject::builtin(raw, ty_name, ty), diagnostics)
            .map(|subject| Some(expect::check(raw, &subject, diagnostics))),
    };
    let bits = match (&field.bits, ty) {
        (None, _) => Some(Vec::new()),
        (Some(raw), Some(Builtin::Int { signed: false, bytes })) => {
            bits::check(raw, ty_name, bytes, enums, diagnostics)
        }
        (Some(raw), Some(_)) => {
            diagnostics.push(invalid_bits(raw, &format!("`{}` is not an unsigned integer", ty_name.value)));
            None
        }
        (Some(_), None) => None,
    };
    let dissector = match (ty, &field.dissector) {
        (_, None) | (None, _) => Some(None),
        (Some(Builtin::Bytes), Some(raw)) => Some(Some(raw.name.clone())),
        (Some(_), Some(raw)) => {
            diagnostics.push(
                Diagnostic::new(
                    Name::IncompatibleDisplay,
                    raw.key.clone(),
                    format!("`{}` takes no `dissector`", ty_name.value),
                )
                .with_note("only `bytes` Fields take `dissector`", None),
            );
            None
        }
    };
    let (ty, endian, length, encoding, display, mapping, expect, dissector, bits) =
        (ty?, endian?, length?, encoding?, display?, mapping?, expect?, dissector?, bits?);
    Some(BuiltinField { ty, endian, length, encoding, display, mapping, expect, dissector, bits })
}

/// Checks how an array Field repeats (spec §3.7): only an inline structure or a Field of a Type
/// repeats, and a `count:` is resolved from `scope` like a `size:`.
fn check_array<'a>(
    field: &RawField,
    array: &Spanned<RawArray>,
    types: &Types<'a>,
    scope: Scope<'a, '_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Array> {
    if let Some(name) = match &field.kind {
        RawKind::Type { name, .. } if Builtin::from_name(&name.value).is_some() => Some(name),
        RawKind::Type { .. } | RawKind::Structure { .. } | RawKind::Switch(_) => None,
    } {
        diagnostics.push(
            Diagnostic::new(
                Name::InvalidArray,
                array.span.clone(),
                format!("a Field of type `{}` cannot repeat", name.value),
            )
            .with_note("only an inline structure or a Field of a Type repeats: put the value in its `fields`", None),
        );
        return None;
    }
    match &array.value {
        RawArray::ToEnd => Some(Array::ToEnd),
        RawArray::Count(count) => {
            let amount = check_amount(&count.value, count.span.clone(), Amounts::COUNT, scope, types, diagnostics);
            record(amount, diagnostics).flatten().map(Array::Count)
        }
    }
}

/// Checks an `if:` or a `switch:` (spec §3.9): an Expression's paths are resolved from `scope`
/// like a `size:`'s. Any value is a condition or a subject, so a constant is never wrong.
pub(crate) fn check_operand<'a>(
    operand: &RawAmount,
    scope: Scope<'a, '_>,
    types: &Types<'a>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Operand> {
    let expr = match operand {
        RawAmount::Constant(value) => return Some(Operand::Constant(*value)),
        RawAmount::Expression(expr) => expr,
    };
    let references = scope::resolve_paths(&paths(expr), scope, types, diagnostics)?;
    Some(Operand::Expression { expr: expr.clone(), references })
}

/// `bits:` on a Field that is not a fixed-size unsigned integer, saying why in `message`.
fn invalid_bits(bits: &RawBits, message: &str) -> Diagnostic {
    Diagnostic::new(Name::InvalidBits, bits.key().clone(), message)
        .with_note("only a `uint8` to `uint64` Field takes `bits`", None)
}

/// Checks the name of a Field or a sub-Field, given the names of its earlier siblings: it follows
/// the naming rule (spec §3.4.2) and no sibling has it already.
pub(crate) fn check_name<'n>(
    name: &Spanned<String>,
    mut earlier: impl Iterator<Item = &'n Spanned<String>>,
    diagnostics: &mut Vec<Diagnostic>,
) {
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
    if let Some(first) = earlier.find(|f| f.value == name.value) {
        diagnostics.push(
            Diagnostic::new(
                Name::DuplicateFieldName,
                name.span.clone(),
                format!("there is already a Field named `{}` here", name.value),
            )
            .with_note("first defined here", Some(first.span.clone())),
        );
    }
}

/// A key that `what` (an inline structure, a Field whose type is a Type) does not take, though
/// the Fields of `inner` may: a length key is `unexpected-length`, `endian:` `invalid-endian`,
/// any other `incompatible-display` (spec §3.4.3, §3.4.6, §3.5).
fn misplaced_key(key: &Spanned<&'static str>, what: &str, inner: &str) -> Diagnostic {
    let name = match key.value {
        k if LENGTH_KEYS.iter().any(|(l, _)| *l == k) => Name::UnexpectedLength,
        "endian" => Name::InvalidEndian,
        _ => Name::IncompatibleDisplay,
    };
    let error = Diagnostic::new(name, key.span.clone(), format!("{what} takes no `{}`", key.value));
    if key.value == "endian" {
        error.with_note("a Type is read in its own byte order: set `endian` on the Type", None)
    } else {
        error.with_note(format!("remove `{}`, or give it to a Field of {inner}", key.value), None)
    }
}

/// The length of a Field of type `ty`, written `ty_name`, encoded as `encoding`: a fixed-size
/// type's own or a timestamp's encoding's, which take no length key, or the one length key a
/// `string` or `bytes` needs (spec §3.4.5, §3.6).
fn check_length<'a>(
    field: &RawField,
    ty_name: &Spanned<String>,
    ty: Builtin,
    encoding: Option<Encoding>,
    types: &Types<'a>,
    scope: Scope<'a, '_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Length> {
    if let Some(size) = ty.fixed_size().or_else(|| encoding.and_then(Encoding::time_size)) {
        for LengthKey { key, .. } in &field.lengths {
            diagnostics.push(
                Diagnostic::new(
                    Name::UnexpectedLength,
                    key.span.clone(),
                    format!("`{}` has a fixed size and takes no `{}`", ty_name.value, key.value),
                )
                .with_note(format!("remove `{}`", key.value), None),
            );
        }
        return Some(Length::Constant(size));
    }
    let [length, rest @ ..] = field.lengths.as_slice() else {
        diagnostics.push(
            Diagnostic::new(Name::MissingLength, ty_name.span.clone(), format!("`{}` needs a length", ty_name.value))
                .with_note("give exactly one of `size`, `prefix` or `terminator`", None),
        );
        return None;
    };
    if rest.is_empty() {
        return length.check(encoding, scope, types, diagnostics);
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
pub(crate) fn check_text(
    label: Option<&Spanned<String>>,
    description: Option<&Spanned<String>>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if let Some(label) = label.filter(|l| l.value.trim().is_empty() || !is_single_line(&l.value)) {
        diagnostics.push(Diagnostic::new(
            Name::InvalidLabel,
            label.span.clone(),
            "a label must be a non-empty single line",
        ));
    }
    if let Some(description) = description.filter(|d| !is_single_line(&d.value)) {
        diagnostics.push(Diagnostic::new(
            Name::InvalidDescription,
            description.span.clone(),
            "a description must be a single line",
        ));
    }
}

/// Why a lowercase `type:` names no built-in.
fn unresolved_type(ty: &Spanned<String>) -> Diagnostic {
    let name = ty.value.as_str();
    let names: Vec<&'static str> = BUILTINS.iter().map(|(n, _)| *n).collect();
    let unknown = Diagnostic::new(Name::UnknownType, ty.span.clone(), format!("there is no built-in type `{name}`"));
    match closest(name, &names) {
        Some(guess) => unknown.with_note(format!("did you mean `{guess}`?"), None),
        None => unknown.with_note(format!("the built-in types are: {}", names.join(", ")), None),
    }
}

/// `[a-z][a-z0-9_]*` (spec §3.4.2).
pub(crate) fn is_field_name(name: &str) -> bool {
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
