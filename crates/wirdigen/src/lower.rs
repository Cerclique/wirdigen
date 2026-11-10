//! Lowering: a validated description becomes a private, Dissector-shaped model (ADR 0010).
//!
//! Everything lowering relies on is checked by validation, so it cannot fail: a surprise here is
//! a Wirdigen bug and panics, it is never a Diagnostic.

use std::collections::BTreeMap;

use crate::description::Protocol;
use crate::field::{self, Builtin, Display, Encoding, Endian, Field};
use crate::mapping::{self, Entry, Mapping, Table, Values};
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
    /// The value tables of Enums, each declared once before the `ProtoField`s that use it.
    pub(crate) tables: Vec<SharedTable>,
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
    /// What Wireshark shows in place of, or after, the value.
    pub(crate) strings: Option<Strings>,
}

/// The labels of a `ProtoField`, in the argument a constructor calls its valuestring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Strings {
    /// A value string, or a range string (`base.RANGE_STRING`) when `range`.
    Table { table: TableRef, range: bool },
    /// A unit (`base.UNIT_STRING` on an integer), each form already starting with its space.
    Unit { singular: String, plural: Option<String> },
    /// The labels of a `bool`'s two states.
    TrueFalse { when_true: String, when_false: String },
}

/// Where a value table is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TableRef {
    /// In the `ProtoField`'s constructor call.
    Inline(LuaTable),
    /// In a local declared once: an index into [`Dissector::tables`].
    Shared(usize),
}

/// A value table as Wireshark reads it: keys and bounds as the `ProtoField`'s unsigned integers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LuaTable {
    /// `{ [key] = label }`.
    Values(Vec<(i64, String)>),
    /// `{ { low, high, label } }`.
    Ranges(Vec<(i64, i64, String)>),
}

/// The table of an Enum for the `ProtoField`s of one width and signedness.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SharedTable {
    /// The Lua local (`enum_MsgType`).
    pub(crate) local: String,
    /// The Enum it comes from.
    enum_name: String,
    pub(crate) table: LuaTable,
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
    /// Wireshark, with this `ENC_*` encoding and, when the encoding has one, this `ENC_*` byte
    /// order (`tree:add_packet_field`).
    Encoded { encoding: &'static str, endian: Option<&'static str> },
    /// The generated Lua, with this `TvbRange` method, and the value is added as is: Lua cannot
    /// declare 40, 48 or 56-bit `ProtoField`s, so they are shown as 64-bit ones.
    Lua(&'static str),
}

pub(crate) fn lower(protocol: &Protocol, source_name: &str) -> Dissector {
    let filter_name = protocol.name.clone();
    let mut proto_fields = Vec::new();
    let mut tables = Vec::new();
    let mut layout = Vec::new();
    let mut chunks = vec![prelude::VERSION, prelude::MALFORMED, prelude::BOUNDS];
    for field in &protocol.fields {
        proto_fields.push(ProtoField {
            local: format!("f_{}", field.name),
            abbrev: format!("{filter_name}.{}", field.name),
            label: field.label.clone().unwrap_or_else(|| default_label(&field.name)),
            description: field.description.clone(),
            field_type: field_type(field),
            strings: field.mapping.as_ref().map(|m| strings(m, field.ty, &protocol.enums, &mut tables)),
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
        tables,
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
        Builtin::AbsTime => {
            let display = field.display.expect("validation gives `abs_time` a display");
            FieldType::new("absolute_time", Args::Base(base(display)))
        }
        // Unlike `absolute_time`, `relative_time` takes no display: its blurb is the third argument.
        Builtin::RelTime => FieldType::new("relative_time", Args::Plain),
    }
}

/// The labels of a Field of type `ty`. An Enum's table is shared by every Field it lowers to the
/// same table for.
fn strings(mapping: &Mapping, ty: Builtin, enums: &BTreeMap<String, Table>, tables: &mut Vec<SharedTable>) -> Strings {
    match mapping {
        Mapping::Values(Values::Inline(table)) => {
            Strings::Table { table: TableRef::Inline(lua_table(table, ty)), range: mapping::has_range(table) }
        }
        Mapping::Values(Values::Enum(name)) => {
            let table = &enums[name];
            let lua = lua_table(table, ty);
            let index = tables.iter().position(|t| t.enum_name == *name && t.table == lua).unwrap_or_else(|| {
                // An Enum lowers to another table only when a Field's type cuts off some keys.
                let variants = tables.iter().filter(|t| t.enum_name == *name).count();
                let local =
                    if variants == 0 { format!("enum_{name}") } else { format!("enum_{name}_{}", variants + 1) };
                tables.push(SharedTable { local, enum_name: name.clone(), table: lua });
                tables.len() - 1
            });
            Strings::Table { table: TableRef::Shared(index), range: mapping::has_range(table) }
        }
        Mapping::Bool { when_true, when_false } => Strings::TrueFalse {
            when_true: when_true.clone().unwrap_or_else(|| "True".to_owned()),
            when_false: when_false.clone().unwrap_or_else(|| "False".to_owned()),
        },
        // Wireshark prints a unit right after the value, so the space comes with the unit.
        Mapping::Unit { singular, plural } => {
            Strings::Unit { singular: format!(" {singular}"), plural: plural.as_ref().map(|p| format!(" {p}")) }
        }
    }
}

/// A validated table as Wireshark reads it for a `ProtoField` of integer type `ty`.
///
/// Wireshark converts each key and bound to an unsigned integer of the `ProtoField`'s width
/// (32 or 64 bits), so:
/// - keys outside the type are left out and ranges are cut to it: a wider key would be
///   truncated onto a value the type does hold;
/// - a key above `i64::MAX` is written as the negative Lua integer with the same 64 bits;
/// - a range string compares values as unsigned integers, so a range crossing zero is split in
///   two, and a negative bound of a 32-bit or narrower signed type is written as its 32-bit two's
///   complement, which is what the value is compared as.
fn lua_table(table: &[Entry], ty: Builtin) -> LuaTable {
    let Builtin::Int { signed, bytes } = ty else { panic!("validation gives `values` only to integer types") };
    let (min, max) = ty.int_range().expect("an integer type has a range");
    let reachable = table.iter().filter_map(|e| {
        let (low, high) = (e.key.low.max(min), e.key.high.min(max));
        (low <= high).then(|| (low, high, e.label.clone()))
    });
    let wire = |value: i128| {
        let value = if value > i128::from(i64::MAX) { value - (1 << 64) } else { value };
        i64::try_from(value).expect("validation keeps keys within 64 bits")
    };
    if !mapping::has_range(table) {
        return LuaTable::Values(reachable.map(|(value, _, label)| (wire(value), label)).collect());
    }
    let unsigned = |value: i128| wire(if signed && bytes <= 4 && value < 0 { value + (1 << 32) } else { value });
    LuaTable::Ranges(
        reachable
            .flat_map(|(low, high, label)| {
                let halves = if low < 0 && high >= 0 { vec![(low, -1), (0, high)] } else { vec![(low, high)] };
                halves.into_iter().map(move |(l, h)| (unsigned(l), unsigned(h), label.clone()))
            })
            .collect(),
    )
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
        Display::Local => "base.LOCAL",
        Display::Utc => "base.UTC",
        Display::DoyUtc => "base.DOY_UTC",
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

/// The `ENC_*` value Wireshark decodes a string or a timestamp with, before any byte order.
fn enc_value(encoding: Encoding) -> &'static str {
    match encoding {
        Encoding::Ascii => "ENC_ASCII",
        Encoding::Utf8 => "ENC_UTF_8",
        Encoding::Latin1 => "ENC_ISO_8859_1",
        Encoding::Utf16 => "ENC_UTF_16",
        Encoding::Ucs2 => "ENC_UCS_2",
        Encoding::Secs => "ENC_TIME_SECS",
        Encoding::SecsNsecs => "ENC_TIME_SECS_NSECS",
        Encoding::Ntp => "ENC_TIME_NTP",
        Encoding::Msecs => "ENC_TIME_MSECS",
        Encoding::Usecs => "ENC_TIME_USECS",
        Encoding::Nsecs => "ENC_TIME_NSECS",
    }
}

/// The `ENC_*` value of a byte order.
fn enc_endian(endian: Endian) -> &'static str {
    match endian {
        Endian::Big => "ENC_BIG_ENDIAN",
        Endian::Little => "ENC_LITTLE_ENDIAN",
    }
}

fn decode(field: &Field) -> Decode {
    if let Some(enc) = field.encoding {
        let endian = enc.has_byte_order().then(|| enc_endian(field.endian));
        return Decode::Encoded { encoding: enc_value(enc), endian };
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

    fn tables(d: &Dissector) -> Vec<LuaTable> {
        d.proto_fields
            .iter()
            .map(|f| match &f.strings {
                Some(Strings::Table { table: TableRef::Inline(t), .. }) => t.clone(),
                Some(Strings::Table { table: TableRef::Shared(i), .. }) => d.tables[*i].table.clone(),
                other => panic!("{} has no table: {other:?}", f.local),
            })
            .collect()
    }

    fn label(text: &str) -> String {
        text.to_owned()
    }

    /// Wireshark truncates a key to the `ProtoField`'s width, so a key the type cannot hold would
    /// land on another value: it is left out, and a range is cut to the type.
    #[test]
    fn keys_outside_the_type_are_left_out() {
        let d = lowered(
            "name: demo\nfields:\n  - {name: a, type: uint8, values: {1: One, 257: Wide, -1: Neg}}\n  - {name: b, type: uint8, values: {\"250-300\": High, \"400-500\": Never}}\n",
            "x",
        );
        assert_eq!(
            tables(&d),
            [LuaTable::Values(vec![(1, label("One"))]), LuaTable::Ranges(vec![(250, 255, label("High"))])]
        );
    }

    /// Checked in tshark 4.4 and 4.6: a range string compares a value as an unsigned integer of
    /// the `ProtoField`'s width (32 bits up to `int32`, 64 bits for `int64`).
    #[test]
    fn signed_ranges_follow_wiresharks_unsigned_comparison() {
        let d = lowered(
            "name: demo\nfields:\n  - {name: a, type: int8, values: {\"-5--2\": Neg, \"-1-1\": Zero}}\n  - {name: b, type: int48, values: {\"-10-10\": Small}}\n  - {name: c, type: int16, values: {-1: MinusOne}}\n",
            "x",
        );
        assert_eq!(
            tables(&d),
            [
                LuaTable::Ranges(vec![
                    (4_294_967_291, 4_294_967_294, label("Neg")),
                    (4_294_967_295, 4_294_967_295, label("Zero")),
                    (0, 1, label("Zero")),
                ]),
                LuaTable::Ranges(vec![(-10, -1, label("Small")), (0, 10, label("Small"))]),
                LuaTable::Values(vec![(-1, label("MinusOne"))]),
            ]
        );
    }

    #[test]
    fn wide_unsigned_keys_keep_their_64_bits() {
        let d = lowered(
            "name: demo\nfields:\n  - {name: a, type: uint64, values: {0xffffffffffffffff: Max, 0x8000000000000000: Half}}\n",
            "x",
        );
        assert_eq!(tables(&d), [LuaTable::Values(vec![(-1, label("Max")), (i64::MIN, label("Half"))])]);
    }

    /// Two Fields naming one Enum have equal mappings (spec §3.4.9), and share its table while
    /// their types keep the same keys.
    #[test]
    fn an_enum_is_shared_by_its_fields() {
        let root = yaml::parse(
            "name: demo\nenums:\n  Kind: {1: One, 300: Big}\nfields:\n  - {name: a, type: uint16, values: Kind}\n  - {name: b, type: uint16, values: Kind}\n  - {name: c, type: uint8, values: Kind}\n",
        )
        .unwrap();
        let (protocol, diagnostics) = description::check(&description::deserialize(root.as_ref()).unwrap());
        let protocol = protocol.unwrap_or_else(|| panic!("{diagnostics:?}"));
        assert_eq!(protocol.fields[0].mapping, protocol.fields[1].mapping);
        let d = lower(&protocol, "x");
        let locals: Vec<&str> = d.tables.iter().map(|t| t.local.as_str()).collect();
        assert_eq!(locals, ["enum_Kind", "enum_Kind_2"]);
        let refs: Vec<Option<Strings>> = d.proto_fields.iter().map(|f| f.strings.clone()).collect();
        let shared = |i| Some(Strings::Table { table: TableRef::Shared(i), range: false });
        assert_eq!(refs, [shared(0), shared(0), shared(1)]);
        assert_eq!(d.tables[1].table, LuaTable::Values(vec![(1, label("One"))]));
    }

    #[test]
    fn units_and_states_get_wiresharks_spelling() {
        let d = lowered(
            "name: demo\nfields:\n  - {name: a, type: uint16, unit: [byte, bytes]}\n  - {name: b, type: float32, unit: m}\n  - {name: c, type: bool, false: Off}\n",
            "x",
        );
        let strings: Vec<Option<Strings>> = d.proto_fields.iter().map(|f| f.strings.clone()).collect();
        assert_eq!(
            strings,
            [
                Some(Strings::Unit { singular: label(" byte"), plural: Some(label(" bytes")) }),
                Some(Strings::Unit { singular: label(" m"), plural: None }),
                Some(Strings::TrueFalse { when_true: label("True"), when_false: label("Off") }),
            ]
        );
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

    #[test]
    fn timestamps_size_and_byte_order_follow_their_encoding() {
        let d = lowered(
            "name: demo\nendian: little\nfields:\n  - {name: a, type: abs_time}\n  - {name: b, type: rel_time, encoding: nsecs, endian: big}\n  - {name: c, type: string, size: 2, encoding: latin1}\n",
            "x",
        );
        let reads: Vec<(Length, Decode)> =
            d.layout.iter().map(|Stmt::Read { length, decode, .. }| (*length, *decode)).collect();
        assert_eq!(
            reads,
            [
                (Length::Fixed(4), Decode::Encoded { encoding: "ENC_TIME_SECS", endian: Some("ENC_LITTLE_ENDIAN") }),
                (Length::Fixed(8), Decode::Encoded { encoding: "ENC_TIME_NSECS", endian: Some("ENC_BIG_ENDIAN") }),
                (Length::Fixed(2), Decode::Encoded { encoding: "ENC_ISO_8859_1", endian: None }),
            ]
        );
        let constructors: Vec<&str> = d.proto_fields.iter().map(|f| f.field_type.constructor).collect();
        assert_eq!(constructors, ["absolute_time", "relative_time", "string"]);
    }
}
