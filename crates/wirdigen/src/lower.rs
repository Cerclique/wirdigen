//! Lowering: a validated description becomes a private, Dissector-shaped model (ADR 0010).
//!
//! Everything lowering relies on is checked by validation, so it cannot fail: a surprise here is
//! a Wirdigen bug and panics, it is never a Diagnostic.

use crate::description::Protocol;
use crate::field::{Builtin, Endian, Field};
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
    pub(crate) label: String,
    pub(crate) field_type: FieldType,
}

/// A Wireshark field type: how a `ProtoField` is declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FieldType {
    /// The `ProtoField.<constructor>` function (`uint16`, `ipv4`).
    pub(crate) constructor: &'static str,
    /// The display argument (`base.DEC`), for the constructors that take one.
    pub(crate) display: Option<&'static str>,
}

impl FieldType {
    const fn new(constructor: &'static str, display: Option<&'static str>) -> Self {
        Self { constructor, display }
    }
}

/// One step of a dissect function.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Stmt {
    /// A bounds-checked read of `size` bytes added to the tree.
    Read {
        /// Index into [`Dissector::proto_fields`].
        field: usize,
        size: usize,
        decode: Decode,
        /// The Field's path, for the comment and the truncation report.
        path: String,
    },
}

/// Who decodes the bytes of a read, and how.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decode {
    /// Wireshark, big-endian (`tree:add`).
    Big,
    /// Wireshark, little-endian (`tree:add_le`).
    Little,
    /// The generated Lua, with this `TvbRange` method, and the value is added as is: Lua cannot
    /// declare 40, 48 or 56-bit `ProtoField`s, so they are shown as 64-bit ones.
    Lua(&'static str),
}

pub(crate) fn lower(protocol: &Protocol, source_name: &str) -> Dissector {
    let filter_name = protocol.name.clone();
    let mut proto_fields = Vec::new();
    let mut layout = Vec::new();
    for field in &protocol.fields {
        proto_fields.push(ProtoField {
            local: format!("f_{}", field.name),
            abbrev: format!("{filter_name}.{}", field.name),
            label: default_label(&field.name),
            field_type: field_type(field.ty),
        });
        layout.push(Stmt::Read {
            field: proto_fields.len() - 1,
            size: field.ty.size(),
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
        // The layout is never empty, so every Dissector reads something.
        chunks: vec![prelude::VERSION, prelude::MALFORMED, prelude::BOUNDS],
    }
}

/// The Wireshark field type a built-in is shown as (spec §3.4.4).
fn field_type(ty: Builtin) -> FieldType {
    match ty {
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
            FieldType::new(constructor, Some("base.DEC"))
        }
        Builtin::Bool => FieldType::new("bool", Some("base.NONE")),
        Builtin::Float32 => FieldType::new("float", None),
        Builtin::Float64 => FieldType::new("double", None),
        Builtin::Ipv4 => FieldType::new("ipv4", None),
        Builtin::Ipv6 => FieldType::new("ipv6", None),
        Builtin::Ether => FieldType::new("ether", None),
        Builtin::Eui64 => FieldType::new("eui64", None),
        Builtin::Guid => FieldType::new("guid", None),
    }
}

fn decode(field: &Field) -> Decode {
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
}
