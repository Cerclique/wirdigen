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
    /// The `ProtoField.<ftype>` constructor.
    pub(crate) ftype: &'static str,
    /// The display argument (`base.DEC`), for the ftypes that take one.
    pub(crate) display: Option<&'static str>,
}

/// One step of a dissect function.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Stmt {
    /// A bounds-checked read of `size` bytes added to the tree.
    Read {
        /// Index into [`Dissector::proto_fields`].
        field: usize,
        size: usize,
        how: Add,
        /// The Field's path, for the comment and the truncation report.
        path: String,
    },
}

/// How a read value reaches the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Add {
    /// `tree:add`: Wireshark decodes the bytes, big-endian.
    Big,
    /// `tree:add_le`: Wireshark decodes the bytes, little-endian.
    Little,
    /// The generated code decodes the bytes with this `TvbRange` method and adds the value:
    /// Lua cannot declare 40, 48 or 56-bit `ProtoField`s, so they are shown as 64-bit ones.
    Value(&'static str),
}

pub(crate) fn lower(protocol: &Protocol, source_name: &str) -> Dissector {
    let filter_name = protocol.name.clone();
    let mut proto_fields = Vec::new();
    let mut layout = Vec::new();
    for field in &protocol.fields {
        let (ftype, display) = ftype(field.ty);
        proto_fields.push(ProtoField {
            local: format!("f_{}", field.name),
            abbrev: format!("{filter_name}.{}", field.name),
            label: default_label(&field.name),
            ftype,
            display,
        });
        layout.push(Stmt::Read {
            field: proto_fields.len() - 1,
            size: field.ty.size(),
            how: add(field),
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

/// The `ProtoField` constructor of a built-in, and its display argument (spec §3.4.4).
fn ftype(ty: Builtin) -> (&'static str, Option<&'static str>) {
    match ty {
        Builtin::Int { signed, bytes } => {
            let ftype = match (signed, bytes) {
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
            (ftype, Some("base.DEC"))
        }
        Builtin::Bool => ("bool", Some("base.NONE")),
        Builtin::Float32 => ("float", None),
        Builtin::Float64 => ("double", None),
        Builtin::Ipv4 => ("ipv4", None),
        Builtin::Ipv6 => ("ipv6", None),
        Builtin::Ether => ("ether", None),
        Builtin::Eui64 => ("eui64", None),
        Builtin::Guid => ("guid", None),
    }
}

fn add(field: &Field) -> Add {
    let little = field.endian == Endian::Little && field.ty.has_byte_order();
    match field.ty {
        Builtin::Int { signed, bytes: 5..=7 } => Add::Value(match (signed, little) {
            (false, false) => "uint64",
            (false, true) => "le_uint64",
            (true, false) => "int64",
            (true, true) => "le_int64",
        }),
        _ if little => Add::Little,
        _ => Add::Big,
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
        let hows: Vec<Add> = d.layout.iter().map(|Stmt::Read { how, .. }| *how).collect();
        assert_eq!(hows, [Add::Little, Add::Big, Add::Big, Add::Big, Add::Value("le_int64"), Add::Value("uint64")]);
    }
}
