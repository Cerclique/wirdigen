//! Lowering: a validated description becomes a private, Dissector-shaped model (ADR 0010).
//!
//! Everything lowering relies on is checked by validation, so it cannot fail: a surprise here is
//! a Wirdigen bug and panics, it is never a Diagnostic.

use crate::description::Protocol;
use crate::field::{self, Builtin, Display, Encoding, Endian, Field};
use crate::prelude;

/// The model the emitter prints.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Dissector {
    /// The Source name's last path component.
    pub(crate) source_name: String,
    /// The protocol's filter name (`demo`).
    pub(crate) filter_name: String,
    /// The Protocol column text (`DEMO`).
    pub(crate) short_name: String,
    /// The tree root text.
    pub(crate) full_name: String,
    /// The `ProtoField`s to register, each once.
    pub(crate) proto_fields: Vec<ProtoField>,
    /// The statements of the top-level layout.
    pub(crate) layout: Vec<Stmt>,
    /// The prelude chunks the Dissector uses, before dependencies are added.
    pub(crate) chunks: Vec<&'static str>,
}

/// A `ProtoField` to register.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ProtoField {
    /// The mangled Lua local (`f_length`).
    pub(crate) local: String,
    /// The filter name (`demo.length`).
    pub(crate) abbrev: String,
    /// The tree text.
    pub(crate) label: String,
    /// The blurb, if any.
    pub(crate) description: Option<String>,
    pub(crate) field_type: FieldType,
}

/// A Wireshark field type: how a `ProtoField` is declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FieldType {
    /// The `ProtoField.<constructor>` function (`uint16`, `ipv4`).
    pub(crate) constructor: &'static str,
    pub(crate) args: Args,
}

/// The arguments a `ProtoField` constructor takes after its filter name and label, which also
/// says where the blurb goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Args {
    /// `(display, valuestring, mask, description)`, as integers and `bool` take them; the
    /// display (`base.DEC`) is always written.
    Display(&'static str),
    /// `(display, description)`, as `string`, `stringz` and `bytes` take them; the display is
    /// always written.
    Base(&'static str),
    /// `(description)` only. `float` and `double` take a unit table first, but only when it is a
    /// table: without one their blurb is the third argument, not a `nil` unit then the blurb.
    Plain,
}

impl FieldType {
    const fn new(constructor: &'static str, args: Args) -> Self {
        Self { constructor, args }
    }
}

/// One step of a dissect function.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Stmt {
    /// A bounds-checked read added to the tree.
    Read {
        /// Index into [`Dissector::proto_fields`].
        field: usize,
        length: Length,
        decode: Decode,
        /// The Field's path, for the comment and the truncation report.
        path: String,
    },
}

/// Where the value of a read ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Length {
    /// After this many bytes.
    Fixed(usize),
    /// After as many bytes as the unsigned integer of `size` bytes just before the value says,
    /// read with the `TvbRange` call `read` (`uint()`).
    Prefix { size: usize, read: &'static str },
    /// Before the first `width`-byte run of `terminator`, searched in steps of `width`. The
    /// terminator is consumed but is not part of the value.
    Terminator { terminator: u8, width: usize },
}

/// Who decodes the bytes of a read, and how.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decode {
    /// Wireshark, big-endian (`tree:add`).
    Big,
    /// Wireshark, little-endian (`tree:add_le`).
    Little,
    /// Wireshark, as text in this `ENC_*` encoding (`tree:add_packet_field`).
    Encoded(&'static str),
    /// The generated Lua, with this `TvbRange` method, and the value is added as is: Lua cannot
    /// declare 40, 48 or 56-bit `ProtoField`s, so they are shown as 64-bit ones.
    Lua(&'static str),
}

pub(crate) fn lower(protocol: &Protocol, source_name: &str) -> Dissector {
    let filter_name = protocol.name.clone();
    let mut proto_fields = Vec::new();
    let mut layout = Vec::new();
    let mut chunks = vec![prelude::VERSION, prelude::MALFORMED, prelude::BOUNDS];
    for field in &protocol.fields {
        proto_fields.push(ProtoField {
            local: format!("f_{}", field.name),
            abbrev: format!("{filter_name}.{}", field.name),
            label: field.label.clone().unwrap_or_else(|| default_label(&field.name)),
            description: field.description.clone(),
            field_type: field_type(field),
        });
        let length = length(field);
        if matches!(length, Length::Terminator { .. }) && !chunks.contains(&prelude::TERMINATED) {
            chunks.push(prelude::TERMINATED);
        }
        layout.push(Stmt::Read {
            field: proto_fields.len() - 1,
            length,
            decode: decode(field),
            path: field.name.clone(),
        });
    }

    let short_name = filter_name.to_ascii_uppercase();
    Dissector {
        source_name: source_name.rsplit(['/', '\\']).next().unwrap_or(source_name).to_owned(),
        full_name: protocol.title.clone().unwrap_or_else(|| short_name.clone()),
        short_name,
        filter_name,
        proto_fields,
        layout,
        // The layout is never empty, so every Dissector reads something and checks bounds.
        chunks,
    }
}

/// The Wireshark field type a Field is shown as (spec §3.4.4, §3.4.6).
fn field_type(field: &Field) -> FieldType {
    match field.ty {
        Builtin::Int { signed, bytes } => {
            let constructor = match (signed, bytes) {
                (false, 1) => "uint8",
                (false, 2) => "uint16",
                (false, 3) => "uint24",
                (false, 4) => "uint32",
                (false, _) => "uint64",
                (true, 1) => "int8",
                (true, 2) => "int16",
                (true, 3) => "int24",
                (true, 4) => "int32",
                (true, _) => "int64",
            };
            let display = field.display.expect("validation gives every integer a display");
            FieldType::new(constructor, Args::Display(base(display)))
        }
        Builtin::Bool => FieldType::new("bool", Args::Display("base.NONE")),
        Builtin::Float32 => FieldType::new("float", Args::Plain),
        Builtin::Float64 => FieldType::new("double", Args::Plain),
        Builtin::Ipv4 => FieldType::new("ipv4", Args::Plain),
        Builtin::Ipv6 => FieldType::new("ipv6", Args::Plain),
        Builtin::Ether => FieldType::new("ether", Args::Plain),
        Builtin::Eui64 => FieldType::new("eui64", Args::Plain),
        Builtin::Guid => FieldType::new("guid", Args::Plain),
        // A `terminator: 0` string is what Wireshark calls a NUL-terminated string.
        Builtin::String if field.length == field::Length::Terminator(0) => {
            FieldType::new("stringz", Args::Base("base.NONE"))
        }
        Builtin::String => FieldType::new("string", Args::Base("base.NONE")),
        Builtin::Bytes => {
            let display = field.display.expect("validation gives `bytes` a display");
            FieldType::new("bytes", Args::Base(base(display)))
        }
    }
}

/// The Lua `base` value of a display.
fn base(display: Display) -> &'static str {
    match display {
        Display::Dec => "base.DEC",
        Display::Hex => "base.HEX",
        Display::Oct => "base.OCT",
        Display::DecHex => "base.DEC_HEX",
        Display::HexDec => "base.HEX_DEC",
        Display::Plain => "base.NONE",
        Display::Dot => "base.DOT",
        Display::Dash => "base.DASH",
        Display::Colon => "base.COLON",
        Display::Space => "base.SPACE",
    }
}

/// Where a Field's value ends, with the Lua call that reads a `prefix:` count in its width
/// and byte order. A `prefix:` beyond 2^53 loses precision in `tonumber()`, but no packet is
/// that long, so the bounds check still fails it.
fn length(field: &Field) -> Length {
    match field.length {
        field::Length::Constant(size) => Length::Fixed(size),
        field::Length::Prefix(size) => {
            let read = match (size, size > 1 && field.endian == Endian::Little) {
                (1..=4, false) => "uint()",
                (1..=4, true) => "le_uint()",
                (_, false) => "uint64():tonumber()",
                (_, true) => "le_uint64():tonumber()",
            };
            Length::Prefix { size, read }
        }
        field::Length::Terminator(terminator) => {
            Length::Terminator { terminator, width: field.encoding.map_or(1, Encoding::unit) }
        }
    }
}

/// The `ENC_*` value Wireshark decodes a string with. Only multi-byte code units have a byte
/// order.
fn encoding(encoding: Encoding, endian: Endian) -> &'static str {
    match (encoding, endian) {
        (Encoding::Ascii, _) => "ENC_ASCII",
        (Encoding::Utf8, _) => "ENC_UTF_8",
        (Encoding::Latin1, _) => "ENC_ISO_8859_1",
        (Encoding::Utf16, Endian::Big) => "ENC_UTF_16 + ENC_BIG_ENDIAN",
        (Encoding::Utf16, Endian::Little) => "ENC_UTF_16 + ENC_LITTLE_ENDIAN",
        (Encoding::Ucs2, Endian::Big) => "ENC_UCS_2 + ENC_BIG_ENDIAN",
        (Encoding::Ucs2, Endian::Little) => "ENC_UCS_2 + ENC_LITTLE_ENDIAN",
    }
}

fn decode(field: &Field) -> Decode {
    if let Some(text) = field.encoding {
        return Decode::Encoded(encoding(text, field.endian));
    }
    let little = field.endian == Endian::Little && field.ty.has_byte_order();
    match field.ty {
        Builtin::Int { signed, bytes: 5..=7 } => Decode::Lua(match (signed, little) {
            (false, false) => "uint64",
            (false, true) => "le_uint64",
            (true, false) => "int64",
            (true, true) => "le_int64",
        }),
        _ if little => Decode::Little,
        _ => Decode::Big,
    }
}

/// The default tree text of a Field: `msg_type` becomes "Msg type" (spec §3.4.8).
fn default_label(name: &str) -> String {
    let spaced = name.replace('_', " ");
    let mut chars = spaced.chars();
    chars.next().map_or_else(String::new, |first| first.to_uppercase().chain(chars).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{description, yaml};

    fn lowered(text: &str, source_name: &str) -> Dissector {
        let root = yaml::parse(text).unwrap();
        let (protocol, diagnostics) = description::check(&description::deserialize(root.as_ref()).unwrap());
        lower(&protocol.unwrap_or_else(|| panic!("{diagnostics:?}")), source_name)
    }

    #[test]
    fn labels_come_from_names() {
        assert_eq!(default_label("msg_type"), "Msg type");
        assert_eq!(default_label("id"), "Id");
        assert_eq!(default_label("ip_v4_addr"), "Ip v4 addr");
    }

    #[test]
    fn names_follow_the_identity_rules() {
        let d = lowered("name: demo\nfields: [ {name: a, type: uint8} ]\n", "dir\\sub/demo.wirdigen.yaml");
        assert_eq!((d.filter_name.as_str(), d.short_name.as_str(), d.full_name.as_str()), ("demo", "DEMO", "DEMO"));
        assert_eq!(d.source_name, "demo.wirdigen.yaml");
        let d = lowered("name: demo\ntitle: The Demo\nfields: [ {name: a, type: uint8} ]\n", "x");
        assert_eq!(d.full_name, "The Demo");
    }

    #[test]
    fn byte_order_applies_only_where_bytes_have_an_order() {
        let d = lowered(
            "name: demo\nendian: little\nfields:\n  - {name: a, type: uint16}\n  - {name: b, type: uint16, endian: big}\n  - {name: c, type: uint8}\n  - {name: d, type: ether}\n  - {name: e, type: int48}\n  - {name: f, type: uint40, endian: big}\n",
            "x",
        );
        let decodes: Vec<Decode> = d.layout.iter().map(|Stmt::Read { decode, .. }| *decode).collect();
        assert_eq!(
            decodes,
            [Decode::Little, Decode::Big, Decode::Big, Decode::Big, Decode::Lua("le_int64"), Decode::Lua("uint64")]
        );
    }

    #[test]
    fn prefixes_follow_their_width_and_byte_order() {
        let d = lowered(
            "name: demo\nendian: little\nfields:\n  - {name: a, type: string, prefix: uint8}\n  - {name: b, type: bytes, prefix: uint16}\n  - {name: c, type: bytes, prefix: uint16, endian: big}\n  - {name: d, type: string, prefix: uint64}\n",
            "x",
        );
        let lengths: Vec<Length> = d.layout.iter().map(|Stmt::Read { length, .. }| *length).collect();
        assert_eq!(
            lengths,
            [
                Length::Prefix { size: 1, read: "uint()" },
                Length::Prefix { size: 2, read: "le_uint()" },
                Length::Prefix { size: 2, read: "uint()" },
                Length::Prefix { size: 8, read: "le_uint64():tonumber()" },
            ]
        );
    }

    #[test]
    fn terminators_bring_their_chunk_and_follow_the_code_unit() {
        let d = lowered("name: demo\nfields: [ {name: a, type: string, size: 2} ]\n", "x");
        assert!(!d.chunks.contains(&prelude::TERMINATED));
        let d = lowered(
            "name: demo\nfields:\n  - {name: a, type: string, terminator: 0, encoding: ucs2}\n  - {name: b, type: bytes, terminator: 255}\n",
            "x",
        );
        assert!(d.chunks.contains(&prelude::TERMINATED));
        let lengths: Vec<Length> = d.layout.iter().map(|Stmt::Read { length, .. }| *length).collect();
        assert_eq!(
            lengths,
            [Length::Terminator { terminator: 0, width: 2 }, Length::Terminator { terminator: 255, width: 1 }]
        );
    }

    #[test]
    fn only_a_nul_terminated_string_is_a_stringz() {
        let d = lowered(
            "name: demo\nfields:\n  - {name: a, type: string, terminator: 0}\n  - {name: b, type: string, terminator: 10}\n  - {name: c, type: bytes, terminator: 0}\n",
            "x",
        );
        let constructors: Vec<&str> = d.proto_fields.iter().map(|f| f.field_type.constructor).collect();
        assert_eq!(constructors, ["stringz", "string", "bytes"]);
    }
}
