//! Lowering: a validated description becomes a private, Dissector-shaped model (ADR 0010).
//!
//! Everything lowering relies on is checked by validation, so it cannot fail: a surprise here is
//! a Wirdigen bug and panics, it is never a Diagnostic.

use std::collections::BTreeMap;

use crate::description::Protocol;
use crate::field::{self, Builtin, BuiltinField, Display, Encoding, Endian, Field, FieldKind};
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
    /// The site tables of the uses of Types outside any Type, each declared once.
    pub(crate) sites: Vec<SharedSite>,
    /// The dissect functions of the Types, each after the Types it calls (spec §7.3).
    pub(crate) types: Vec<TypeFunction>,
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

impl LuaTable {
    fn is_empty(&self) -> bool {
        match self {
            Self::Values(entries) => entries.is_empty(),
            Self::Ranges(entries) => entries.is_empty(),
        }
    }
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

/// The dissect function of a Type: one per Type, shared by every use of it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TypeFunction {
    /// The Type's name.
    pub(crate) name: String,
    /// The statements of its Fields, whose paths are relative to the Type and whose
    /// `ProtoField`s are slots of the site table it is passed.
    pub(crate) body: Vec<Stmt>,
}

/// The site table of one use of a Type: the `ProtoField`s registered for that use (spec §5.2),
/// passed to the Type's dissect function, by slot key.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Site {
    /// The path of the Field using the Type, which the Type's paths extend in truncation reports.
    pub(crate) path: String,
    /// The slots, in the Type's layout order: `f_<path>` holds a `ProtoField`, `t_<path>` the site
    /// table of a Type the Type uses.
    pub(crate) entries: Vec<(String, SiteEntry)>,
}

/// What a slot of a site table holds.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SiteEntry {
    /// Index into [`Dissector::proto_fields`].
    Field(usize),
    /// The site table of a use of a Type inside the Type.
    Site(Site),
}

/// The site table of a use of a Type outside any Type, declared once as a Lua local.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SharedSite {
    /// The Lua local (`site_req_hdr`).
    pub(crate) local: String,
    pub(crate) site: Site,
}

/// How a statement reaches a `ProtoField` or a site table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ref {
    /// A Lua local, outside any Type: an index into [`Dissector::proto_fields`] or
    /// [`Dissector::sites`].
    Local(usize),
    /// A slot of the site table, inside a Type's dissect function.
    Slot(String),
}

/// One step of a dissect function.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Stmt {
    /// A bounds-checked read added to the tree.
    Read {
        field: Ref,
        length: Length,
        decode: Decode,
        /// The Field's path, for the comment and the truncation report.
        path: String,
    },
    /// An inline structure: a subtree item holding the statements of its Fields, as long as
    /// the bytes they read.
    Structure {
        field: Ref,
        /// The Field's path, for the comment.
        path: String,
        /// The statements of its Fields, inside the subtree.
        body: Vec<Stmt>,
    },
    /// A Field of a Type: a subtree item, filled by the Type's dissect function called with the
    /// site table of this use, as long as the bytes it read.
    Call {
        field: Ref,
        /// The Field's path, for the comment.
        path: String,
        /// The Type's name.
        ty: String,
        /// The site table of this use.
        site: Ref,
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
    let mut lowering = Lowering {
        filter_name: &protocol.name,
        enums: &protocol.enums,
        proto_fields: Vec::new(),
        tables: Vec::new(),
        slots: BTreeMap::new(),
        sites: Vec::new(),
        // The layout is never empty, so every Dissector reads something and checks bounds.
        chunks: vec![prelude::VERSION, prelude::MALFORMED, prelude::BOUNDS],
    };
    // Every Type's slots are known before any use of it builds a site table.
    let mut types = Vec::new();
    for t in &protocol.types {
        let mut slots = Vec::new();
        let body = lowering.type_structure(&t.fields, &[], &mut slots);
        lowering.slots.insert(&t.name, slots);
        types.push(TypeFunction { name: t.name.clone(), body });
    }
    let layout = lowering.structure(&protocol.fields, &[]);
    let Lowering { proto_fields, tables, sites, chunks, .. } = lowering;

    let filter_name = protocol.name.clone();
    let short_name = filter_name.to_ascii_uppercase();
    Dissector {
        source_name: source_name.rsplit(['/', '\\']).next().unwrap_or(source_name).to_owned(),
        full_name: protocol.title.clone().unwrap_or_else(|| short_name.clone()),
        short_name,
        filter_name,
        tables,
        proto_fields,
        sites,
        types,
        layout,
        chunks,
    }
}

/// A slot of a Type's site tables: what each use registers for one Field of the Type.
#[derive(Debug, Clone)]
struct Slot<'p> {
    /// The key in the site table.
    key: String,
    /// The Field's path inside the Type.
    segments: Vec<&'p str>,
    kind: SlotKind<'p>,
}

#[derive(Debug, Clone)]
enum SlotKind<'p> {
    /// The `ProtoField` of this Field.
    Field(&'p Field),
    /// The site table of this Type, which the Field is of.
    Site(&'p str),
}

/// What lowering has built so far, while it walks the layout.
struct Lowering<'p> {
    /// The protocol's filter name, the first segment of every `ProtoField`'s.
    filter_name: &'p str,
    enums: &'p BTreeMap<String, Table>,
    proto_fields: Vec<ProtoField>,
    tables: Vec<SharedTable>,
    /// The slots of each Type's site tables, in the Type's layout order.
    slots: BTreeMap<&'p str, Vec<Slot<'p>>>,
    sites: Vec<SharedSite>,
    chunks: Vec<&'static str>,
}

impl<'p> Lowering<'p> {
    /// The statements of a structure outside any Type whose Fields' paths start with `parent`.
    fn structure(&mut self, fields: &'p [Field], parent: &[&'p str]) -> Vec<Stmt> {
        fields.iter().map(|field| self.field(field, parent)).collect()
    }

    /// Registers the `ProtoField`s of a Field outside any Type whose path starts with `parent`,
    /// and returns the statement that reads it.
    fn field(&mut self, field: &'p Field, parent: &[&'p str]) -> Stmt {
        let segments: Vec<&str> = parent.iter().copied().chain([field.name.as_str()]).collect();
        let path = segments.join(".");
        let index = self.proto_field(field, &segments);
        match &field.kind {
            FieldKind::Builtin(value) => self.read(value, Ref::Local(index), path),
            FieldKind::Structure(fields) => {
                Stmt::Structure { field: Ref::Local(index), body: self.structure(fields, &segments), path }
            }
            FieldKind::Type(ty) => {
                let site = self.site(ty, &segments);
                let local =
                    unique(&format!("site_{}", segments.join("__")), |n| self.sites.iter().any(|s| s.local == n));
                self.sites.push(SharedSite { local, site });
                let site = Ref::Local(self.sites.len() - 1);
                Stmt::Call { field: Ref::Local(index), path, ty: ty.clone(), site }
            }
        }
    }

    /// The statements of a structure inside a Type whose Fields' paths, relative to the Type,
    /// start with `parent`, adding the slots they read to `slots`.
    fn type_structure(&mut self, fields: &'p [Field], parent: &[&'p str], slots: &mut Vec<Slot<'p>>) -> Vec<Stmt> {
        fields
            .iter()
            .map(|field| {
                let segments: Vec<&str> = parent.iter().copied().chain([field.name.as_str()]).collect();
                let path = segments.join(".");
                let mut slot = |prefix: &str, kind: SlotKind<'p>| {
                    let key = unique(&format!("{prefix}{}", segments.join("__")), |k| slots.iter().any(|s| s.key == k));
                    slots.push(Slot { key: key.clone(), segments: segments.clone(), kind });
                    Ref::Slot(key)
                };
                let field_ref = slot("f_", SlotKind::Field(field));
                match &field.kind {
                    FieldKind::Builtin(value) => self.read(value, field_ref, path),
                    FieldKind::Structure(fields) => {
                        let body = self.type_structure(fields, &segments, slots);
                        Stmt::Structure { field: field_ref, path, body }
                    }
                    FieldKind::Type(ty) => {
                        let site = slot("t_", SlotKind::Site(ty));
                        Stmt::Call { field: field_ref, path, ty: ty.clone(), site }
                    }
                }
            })
            .collect()
    }

    /// The site table of a use of the Type `ty` at the path `segments`, registering the
    /// `ProtoField`s of that use.
    fn site(&mut self, ty: &str, segments: &[&'p str]) -> Site {
        let slots = self.slots.get(ty).expect("every Type is lowered before any use of it").clone();
        let entries = slots
            .into_iter()
            .map(|slot| {
                let path: Vec<&str> = segments.iter().copied().chain(slot.segments).collect();
                let entry = match slot.kind {
                    SlotKind::Field(field) => SiteEntry::Field(self.proto_field(field, &path)),
                    SlotKind::Site(ty) => SiteEntry::Site(self.site(ty, &path)),
                };
                (slot.key, entry)
            })
            .collect();
        Site { path: segments.join("."), entries }
    }

    /// The statement reading a Field of a built-in type through `field`, at `path`.
    fn read(&mut self, value: &BuiltinField, field: Ref, path: String) -> Stmt {
        let length = length(value);
        if matches!(length, Length::Terminator { .. }) && !self.chunks.contains(&prelude::TERMINATED) {
            self.chunks.push(prelude::TERMINATED);
        }
        Stmt::Read { field, length, decode: decode(value), path }
    }

    /// Registers the `ProtoField` of a Field at the path `segments`, returning its index.
    fn proto_field(&mut self, field: &Field, segments: &[&str]) -> usize {
        let path = segments.join(".");
        let (field_type, strings) = match &field.kind {
            FieldKind::Builtin(value) => (
                field_type(value),
                value.mapping.as_ref().and_then(|m| strings(m, value.ty, self.enums, &mut self.tables)),
            ),
            FieldKind::Structure(_) | FieldKind::Type(_) => (FieldType::new("none", Args::Plain), None),
        };
        self.proto_fields.push(ProtoField {
            local: self.local(segments),
            abbrev: format!("{}.{path}", self.filter_name),
            label: field.label.clone().unwrap_or_else(|| default_label(&field.name)),
            description: field.description.clone(),
            field_type,
            strings,
        });
        self.proto_fields.len() - 1
    }

    /// The Lua local of the `ProtoField` at a path: `f_` then the segments joined by `__`
    /// (`f_options__ttl`).
    fn local(&self, segments: &[&str]) -> String {
        unique(&format!("f_{}", segments.join("__")), |name| self.proto_fields.iter().any(|f| f.local == name))
    }
}

/// `base`, or when `taken` says it is, `base` with the first free `_<n>` suffix. A Field name
/// can itself hold `__`, so two paths can mangle alike; filter names are never changed this way.
fn unique(base: &str, taken: impl Fn(&str) -> bool) -> String {
    if !taken(base) {
        return base.to_owned();
    }
    (2..=usize::MAX).map(|n| format!("{base}_{n}")).find(|name| !taken(name)).expect("some suffix is free")
}

/// The Wireshark field type a Field is shown as (spec §3.4.4, §3.4.6).
fn field_type(field: &BuiltinField) -> FieldType {
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
/// same table for. A table left empty by the type (every key `unreachable-value`) gives no
/// labels at all: an empty table would only make every value "Unknown".
fn strings(
    mapping: &Mapping,
    ty: Builtin,
    enums: &BTreeMap<String, Table>,
    tables: &mut Vec<SharedTable>,
) -> Option<Strings> {
    Some(match mapping {
        Mapping::Values(Values::Inline(table)) => {
            let lua = lua_table(table, ty);
            if lua.is_empty() {
                return None;
            }
            Strings::Table { table: TableRef::Inline(lua), range: mapping::has_range(table) }
        }
        Mapping::Values(Values::Enum(name)) => {
            let table = &enums[name];
            let lua = lua_table(table, ty);
            if lua.is_empty() {
                return None;
            }
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
    })
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
    let range = ty.int_range().expect("an integer type has a range");
    let (min, max) = (*range.start(), *range.end());
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
fn length(field: &BuiltinField) -> Length {
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

fn decode(field: &BuiltinField) -> Decode {
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

    /// How each top-level read ends and is decoded, for a layout of reads only.
    fn reads(d: &Dissector) -> Vec<(Length, Decode)> {
        d.layout
            .iter()
            .map(|stmt| match stmt {
                Stmt::Read { length, decode, .. } => (*length, *decode),
                Stmt::Structure { path, .. } | Stmt::Call { path, .. } => panic!("{path} is not a read"),
            })
            .collect()
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

    /// A table the type cuts to nothing gives no labels, rather than an empty table.
    #[test]
    fn a_table_with_no_reachable_key_gives_no_labels() {
        let d = lowered(
            "name: demo\nenums:\n  Big: {256: Wide}\nfields:\n  - {name: a, type: uint8, values: {256: Never}}\n  - {name: b, type: uint8, values: Big}\n",
            "x",
        );
        assert_eq!(d.proto_fields.iter().map(|f| f.strings.clone()).collect::<Vec<_>>(), [None, None]);
        assert!(d.tables.is_empty());
    }

    /// A `uint64` key above `i64::MAX` is written as the Lua integer with the same 64 bits.
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
        let mapping = |field: &Field| match &field.kind {
            FieldKind::Builtin(value) => value.mapping.clone(),
            FieldKind::Structure(_) | FieldKind::Type(_) => None,
        };
        assert_eq!(mapping(&protocol.fields[0]), mapping(&protocol.fields[1]));
        let d = lower(&protocol, "x");
        let locals: Vec<&str> = d.tables.iter().map(|t| t.local.as_str()).collect();
        assert_eq!(locals, ["enum_Kind", "enum_Kind_2"]);
        let refs: Vec<Option<Strings>> = d.proto_fields.iter().map(|f| f.strings.clone()).collect();
        let shared = |i| Some(Strings::Table { table: TableRef::Shared(i), range: false });
        assert_eq!(refs, [shared(0), shared(0), shared(1)]);
        assert_eq!(d.tables[1].table, LuaTable::Values(vec![(1, label("One"))]));
    }

    /// Units carry their leading space, and a missing state label keeps Wireshark's default.
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

    /// Spec §5.2: every shown Field, structures included, is filtered by its path.
    #[test]
    fn filter_names_follow_field_paths() {
        let d = lowered(
            "name: demo\nfields:\n  - {name: id, type: uint8}\n  - name: options\n    fields:\n      - {name: ttl, type: uint8}\n      - name: inner\n        fields: [ {name: id, type: uint16} ]\n",
            "x",
        );
        let abbrevs: Vec<&str> = d.proto_fields.iter().map(|f| f.abbrev.as_str()).collect();
        assert_eq!(
            abbrevs,
            ["demo.id", "demo.options", "demo.options.ttl", "demo.options.inner", "demo.options.inner.id"]
        );
    }

    /// A path `a.b` and a Field named `a__b` would both mangle to `f_a__b`.
    #[test]
    fn locals_stay_unique_when_paths_mangle_alike() {
        let d = lowered(
            "name: demo\nfields:\n  - name: a\n    fields: [ {name: b, type: uint8} ]\n  - {name: a__b, type: uint8}\n",
            "x",
        );
        let names: Vec<(&str, &str)> = d.proto_fields.iter().map(|f| (f.local.as_str(), f.abbrev.as_str())).collect();
        assert_eq!(names, [("f_a", "demo.a"), ("f_a__b", "demo.a.b"), ("f_a__b_2", "demo.a__b")]);
    }

    /// Spec §3.11: a structure's `endian:` is the default of the Fields inside it.
    #[test]
    fn a_structure_sets_the_byte_order_inside_it() {
        let d = lowered(
            "name: demo\nfields:\n  - name: s\n    endian: little\n    fields:\n      - {name: a, type: uint16}\n      - {name: b, type: uint16, endian: big}\n      - name: t\n        fields: [ {name: c, type: uint16} ]\n  - {name: d, type: uint16}\n",
            "x",
        );
        assert_eq!(all_decodes(&d.layout), [Decode::Little, Decode::Big, Decode::Little, Decode::Big]);
    }

    /// How every read is decoded, structures included, in layout order.
    fn all_decodes(stmts: &[Stmt]) -> Vec<Decode> {
        stmts
            .iter()
            .flat_map(|stmt| match stmt {
                Stmt::Read { decode, .. } => vec![*decode],
                Stmt::Structure { body, .. } => all_decodes(body),
                Stmt::Call { .. } => Vec::new(),
            })
            .collect()
    }

    /// A request and a response header of one Type, the Type using another Type.
    const TYPES: &str = "name: demo\nfields:\n  - {name: req, type: Header}\n  - {name: resp, type: Header}\ntypes:\n  Header:\n    fields:\n      - {name: len, type: uint16}\n      - {name: stamp, type: Stamp}\n  Stamp:\n    fields: [ {name: secs, type: uint32} ]\n";

    /// Spec §5.2: Type names never appear in filter names, and each use of a Type registers its
    /// own `ProtoField`s, so a request and a response header can be filtered apart.
    #[test]
    fn each_use_of_a_type_registers_its_own_proto_fields() {
        let d = lowered(TYPES, "x");
        let abbrevs: Vec<&str> = d.proto_fields.iter().map(|f| f.abbrev.as_str()).collect();
        assert_eq!(
            abbrevs,
            [
                "demo.req",
                "demo.req.len",
                "demo.req.stamp",
                "demo.req.stamp.secs",
                "demo.resp",
                "demo.resp.len",
                "demo.resp.stamp",
                "demo.resp.stamp.secs",
            ]
        );
    }

    /// Spec §7.3: one dissect function per Type, each defined before the functions calling it.
    #[test]
    fn types_are_defined_after_the_types_they_use() {
        let d = lowered(TYPES, "x");
        let names: Vec<&str> = d.types.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["Stamp", "Header"]);
    }

    /// Every `ProtoField` a Type's function reads through its site table is in the table of
    /// each use, and is that use's `ProtoField` for the same Field.
    #[test]
    fn each_site_holds_the_proto_fields_its_type_reads() {
        fn slots(stmts: &[Stmt]) -> Vec<(String, String)> {
            let slot = |r: &Ref, path: &str| match r {
                Ref::Slot(key) => (key.clone(), path.to_owned()),
                Ref::Local(_) => panic!("{path} reads a local inside a Type"),
            };
            stmts
                .iter()
                .flat_map(|stmt| match stmt {
                    Stmt::Read { field, path, .. } | Stmt::Call { field, path, .. } => vec![slot(field, path)],
                    Stmt::Structure { field, path, body } => {
                        [slot(field, path)].into_iter().chain(slots(body)).collect()
                    }
                })
                .collect()
        }
        fn check(d: &Dissector, site: &Site, ty: &str) {
            let function = d.types.iter().find(|t| t.name == ty).unwrap();
            for (key, path) in slots(&function.body) {
                let entry = site.entries.iter().find(|(k, _)| *k == key).map(|(_, e)| e);
                let Some(SiteEntry::Field(index)) = entry else { panic!("{} has no `{key}`", site.path) };
                assert_eq!(d.proto_fields[*index].abbrev, format!("demo.{}.{path}", site.path));
            }
            for (_, entry) in &site.entries {
                if let SiteEntry::Site(nested) = entry {
                    check(d, nested, "Stamp");
                }
            }
        }
        let d = lowered(TYPES, "x");
        let paths: Vec<&str> = d.sites.iter().map(|s| s.site.path.as_str()).collect();
        assert_eq!(paths, ["req", "resp"]);
        for shared in &d.sites {
            check(&d, &shared.site, "Header");
        }
    }

    /// Spec §3.5, §3.11: a Type reads in its own byte order, else the top level's, whatever
    /// encloses the place it is used.
    #[test]
    fn a_type_reads_in_its_own_byte_order() {
        let d = lowered(
            "name: demo\nendian: little\nfields:\n  - name: s\n    endian: big\n    fields: [ {name: a, type: A}, {name: b, type: B} ]\ntypes:\n  A:\n    fields: [ {name: x, type: uint16} ]\n  B:\n    endian: big\n    fields: [ {name: y, type: uint16}, {name: z, type: uint16, endian: little} ]\n",
            "x",
        );
        let decodes: Vec<(&str, Vec<Decode>)> =
            d.types.iter().map(|t| (t.name.as_str(), all_decodes(&t.body))).collect();
        assert_eq!(decodes, [("A", vec![Decode::Little]), ("B", vec![Decode::Big, Decode::Little])]);
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
        let decodes: Vec<Decode> = reads(&d).into_iter().map(|(_, decode)| decode).collect();
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
        let lengths: Vec<Length> = reads(&d).into_iter().map(|(length, _)| length).collect();
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
        let lengths: Vec<Length> = reads(&d).into_iter().map(|(length, _)| length).collect();
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
        let reads: Vec<(Length, Decode)> = reads(&d);
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
