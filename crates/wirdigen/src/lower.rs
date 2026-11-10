//! Lowering: a validated description becomes a private, Dissector-shaped model (ADR 0010).
//!
//! Everything lowering relies on is checked by validation, so it cannot fail: a surprise here is
//! a Wirdigen bug and panics, it is never a Diagnostic.

use crate::description::{Builtin, Description};
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
}

/// One step of a dissect function.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Stmt {
    /// A bounds-checked read of `size` big-endian bytes added to the tree.
    ReadUint {
        /// Index into [`Dissector::proto_fields`].
        field: usize,
        size: usize,
        /// The Field's path, for the comment and the truncation report.
        path: String,
    },
}

pub(crate) fn lower(description: &Description, source_name: &str) -> Dissector {
    let filter_name = description.name.value.clone();
    let mut proto_fields: Vec<ProtoField> = Vec::new();
    let mut layout = Vec::new();
    for field in &description.fields {
        let (ftype, size) = match field.ty {
            Builtin::Uint8 => ("uint8", 1),
            Builtin::Uint16 => ("uint16", 2),
            Builtin::Uint32 => ("uint32", 4),
        };
        let abbrev = format!("{filter_name}.{}", field.name);
        let index = proto_fields.iter().position(|f| f.abbrev == abbrev).unwrap_or_else(|| {
            proto_fields.push(ProtoField {
                local: format!("f_{}", field.name),
                abbrev,
                label: field.name.clone(),
                ftype,
            });
            proto_fields.len() - 1
        });
        layout.push(Stmt::ReadUint { field: index, size, path: field.name.clone() });
    }

    let mut chunks = vec![prelude::VERSION, prelude::MALFORMED];
    if !layout.is_empty() {
        chunks.push(prelude::BOUNDS);
    }
    let short_name = filter_name.to_ascii_uppercase();
    Dissector {
        source_name: source_name.rsplit(['/', '\\']).next().unwrap_or(source_name).to_owned(),
        full_name: description.title.as_ref().map_or_else(|| short_name.clone(), |t| t.value.clone()),
        short_name,
        filter_name,
        proto_fields,
        layout,
        chunks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{description, yaml};

    fn lowered(text: &str, source_name: &str) -> Dissector {
        let root = yaml::parse(text).unwrap();
        lower(&description::deserialize(root.as_ref()).unwrap(), source_name)
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
    fn fields_become_reads_and_one_proto_field_each() {
        let d = lowered(
            "name: demo\nfields: [ {name: a, type: uint8}, {name: b, type: uint32}, {name: a, type: uint8} ]\n",
            "x",
        );
        assert_eq!(d.proto_fields.len(), 2);
        assert_eq!(d.proto_fields[1].abbrev, "demo.b");
        assert_eq!(d.proto_fields[1].local, "f_b");
        assert_eq!(d.proto_fields[1].ftype, "uint32");
        let sizes: Vec<_> = d.layout.iter().map(|Stmt::ReadUint { field, size, .. }| (*field, *size)).collect();
        assert_eq!(sizes, [(0, 1), (1, 4), (0, 1)]);
    }

    #[test]
    fn bounds_chunk_is_selected_only_when_something_is_read() {
        let with = lowered("name: demo\nfields: [ {name: a, type: uint8} ]\n", "x");
        assert!(with.chunks.contains(&prelude::BOUNDS));
        let without = lowered("name: demo\nfields: [ {name: a} ]\n", "x");
        assert!(!without.chunks.contains(&prelude::BOUNDS));
        assert!(without.chunks.contains(&prelude::VERSION) && without.chunks.contains(&prelude::MALFORMED));
    }
}
