//! The identity of Field, sub-Field and Type declarations, and the index lowering finds Fields
//! and sub-Fields through.
//!
//! Validation resolves every Field Path once and records the id of the declaration it reaches
//! (ADR 0016). Lowering looks the declaration up by that id instead of resolving the path again.
//! A `type:` naming a Type is resolved once too, to the [`TypeId`] the validated Types are looked
//! up by.

use std::collections::BTreeMap;
use std::ops::Range;

use crate::bits::Bit;
use crate::description::Protocol;
use crate::field::{Entry, Field, FieldKind};
use crate::switch::Body;

/// The identity of a Field declaration: the byte offset of its `name` value in the source.
///
/// It names the declaration, not a place in the Message: a Field of a Type used twice has one id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FieldId(usize);

impl FieldId {
    /// The id of the Field whose `name` value is written at `span`.
    pub(crate) fn at(span: &Range<usize>) -> Self {
        Self(span.start)
    }
}

/// The identity of a bitfield sub-Field declaration: the byte offset of its `name` value in the
/// source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SubFieldId(usize);

impl SubFieldId {
    /// The id of the sub-Field whose `name` value is written at `span`.
    pub(crate) fn at(span: &Range<usize>) -> Self {
        Self(span.start)
    }
}

/// The identity of a Type: its position among the Types validation checks, in source order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TypeId(usize);

impl TypeId {
    /// The id of the Type declared at `position`.
    pub(crate) fn at(position: usize) -> Self {
        Self(position)
    }

    /// Where the Type is declared among the Types, in source order.
    pub(crate) fn position(self) -> usize {
        self.0
    }
}

/// Every Field and sub-Field declaration of a checked Protocol, by id: those of the top-level
/// layout and of every Type body, inline structures and `switch` cases included.
#[derive(Debug)]
pub(crate) struct FieldIndex<'p> {
    fields: BTreeMap<FieldId, &'p Field>,
    sub_fields: BTreeMap<SubFieldId, &'p Bit>,
}

impl<'p> FieldIndex<'p> {
    /// Indexes the declarations of `protocol`, in one walk.
    pub(crate) fn new(protocol: &'p Protocol) -> Self {
        let mut index = Self { fields: BTreeMap::new(), sub_fields: BTreeMap::new() };
        index.add(&protocol.fields);
        for ty in protocol.types.in_dependency_order() {
            index.add(&ty.fields);
        }
        index
    }

    fn add(&mut self, entries: &'p [Entry]) {
        for field in entries.iter().filter_map(Entry::field) {
            self.fields.insert(field.id, field);
            match &field.kind {
                FieldKind::Builtin(value) => {
                    self.sub_fields.extend(value.kind.sub_fields().iter().map(|bit| (bit.id, bit)));
                }
                FieldKind::Structure(children) => self.add(children),
                FieldKind::Switch(switch) => {
                    for body in switch.bodies() {
                        if let Body::Fields(children) = body {
                            self.add(children);
                        }
                    }
                }
                // The Type's body is indexed on its own, once.
                FieldKind::Type(_) => {}
            }
        }
    }

    /// The Field declared with `id`.
    ///
    /// # Panics
    ///
    /// When no Field of the Protocol has that id: every id is taken from a declaration of it.
    pub(crate) fn field(&self, id: FieldId) -> &'p Field {
        self.fields.get(&id).expect("every FieldId names a Field of the Protocol")
    }

    /// The sub-Field declared with `id`.
    ///
    /// # Panics
    ///
    /// When no sub-Field of the Protocol has that id: every id is taken from a declaration of it.
    pub(crate) fn sub_field(&self, id: SubFieldId) -> &'p Bit {
        self.sub_fields.get(&id).expect("every SubFieldId names a sub-Field of the Protocol")
    }

    /// Whether `id` names a Field of the Protocol.
    #[cfg(test)]
    fn has_field(&self, id: FieldId) -> bool {
        self.fields.contains_key(&id)
    }

    /// Whether `id` names a sub-Field of the Protocol.
    #[cfg(test)]
    fn has_sub_field(&self, id: SubFieldId) -> bool {
        self.sub_fields.contains_key(&id)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use proptest::prelude::*;

    use super::*;
    use crate::field::{Amount, Array, BuiltinField, Length, Operand};
    use crate::info::{Part, Target};
    use crate::scope::Reference;
    use crate::source::Source;
    use crate::types::TypeUse;

    fn protocol(text: &str) -> Protocol {
        crate::validate(&Source::new("case", text)).expect("a valid description").protocol
    }

    /// The references of the `size:` of the top-level Field `name`.
    fn size_references<'p>(protocol: &'p Protocol, name: &str) -> &'p BTreeMap<Vec<String>, Reference> {
        let field = protocol.fields.iter().filter_map(Entry::field).find(|f| f.name == name).expect("the Field");
        let FieldKind::Builtin(BuiltinField { length: Length::Expression { references, .. }, .. }) = &field.kind else {
            panic!("`{name}` has a `size:` Expression")
        };
        references
    }

    fn path(text: &str) -> Vec<String> {
        text.split('.').map(str::to_owned).collect()
    }

    #[test]
    fn a_field_of_a_type_used_twice_is_one_declaration() {
        let protocol = protocol(
            "name: demo\ntypes:\n  Pair: { fields: [ { name: a, type: uint8 } ] }\nfields:\n\
             \x20 - { name: x, type: Pair }\n  - { name: y, type: Pair }\n\
             \x20 - { name: d, type: bytes, size: \"x.a + y.a\" }\n",
        );
        let references = size_references(&protocol, "d");
        let target = |at: &str| match &references[&path(at)] {
            Reference::Field { target, .. } => *target,
            other => panic!("`{at}` reads a Field, not {other:?}"),
        };
        assert_eq!(target("x.a"), target("y.a"));
        let index = FieldIndex::new(&protocol);
        let declared = protocol.types.in_dependency_order().next().expect("a Type").fields[0].field().expect("a Field");
        assert!(std::ptr::eq(index.field(target("x.a")), declared));
    }

    #[test]
    fn a_type_id_resolves_to_the_type_whatever_the_order() {
        // `Outer` is declared first and lowered last: an id is not a place in the order.
        let protocol = protocol(
            "name: demo\ntypes:\n  Outer: { fields: [ { name: in, type: Inner } ] }\n\
             \x20 Inner: { fields: [ { name: a, type: uint8 } ] }\nfields:\n  - { name: x, type: Outer }\n",
        );
        let order: Vec<&str> = protocol.types.in_dependency_order().map(|t| t.name.as_str()).collect();
        assert_eq!(order, ["Inner", "Outer"]);
        let used = |entries: &[Entry]| match &entries[0].field().expect("a Field").kind {
            FieldKind::Type(TypeUse { id, name, .. }) => (*id, name.clone()),
            other => panic!("a Field of a Type, not {other:?}"),
        };
        let (outer, name) = used(&protocol.fields);
        assert_eq!((protocol.types.get(outer).name.as_str(), name.as_str()), ("Outer", "Outer"));
        let (inner, _) = used(&protocol.types.get(outer).fields);
        assert_eq!(protocol.types.get(inner).name, "Inner");
        assert!(protocol.types.in_dependency_order().all(|t| std::ptr::eq(protocol.types.get(t.id), t)));
    }

    #[test]
    fn a_sub_field_id_resolves_to_its_bit() {
        let protocol = protocol(
            "name: demo\nfields:\n\
             \x20 - { name: flags, type: uint8, bits: [ { name: hi, width: 3 }, { name: lo, width: 5 } ] }\n\
             \x20 - { name: d, type: bytes, size: flags.lo }\n",
        );
        let Reference::Bits { path: container, target } = &size_references(&protocol, "d")[&path("flags.lo")] else {
            panic!("`flags.lo` reads a sub-Field")
        };
        assert_eq!(container, &path("flags"));
        let bit = FieldIndex::new(&protocol).sub_field(*target);
        assert_eq!((bit.name.as_str(), bit.shift, bit.width), ("lo", 0, 5));
    }

    /// An id stored in a checked Protocol, with the name its path ends on.
    enum Stored {
        Field(FieldId, String),
        SubField(SubFieldId, String),
    }

    /// Every id a checked Protocol stores: those of Expression references, context tables,
    /// Info Template parts and Framing reads.
    fn stored(protocol: &Protocol) -> Vec<Stored> {
        let mut found = Vec::new();
        stored_in(&protocol.fields, &mut found);
        for ty in protocol.types.in_dependency_order() {
            stored_in(&ty.fields, &mut found);
        }
        for part in protocol.info.iter().flat_map(|t| &t.parts) {
            let Part::Field { path, target } = part else { continue };
            let last = path.last().expect("a path has a name").clone();
            match target {
                Target::Value(id) => found.push(Stored::Field(*id, last)),
                Target::SubField(id) => found.push(Stored::SubField(*id, last)),
                Target::Switch { .. } => {}
            }
        }
        if let Some(framing) = &protocol.framing {
            for (name, read) in &framing.reads {
                found.push(Stored::Field(read.target, name.clone()));
            }
            amount(&framing.length, &mut found);
        }
        found
    }

    fn stored_in(entries: &[Entry], found: &mut Vec<Stored>) {
        for entry in entries {
            let field = match entry {
                Entry::Field(field) => field,
                Entry::Padding(padding) => {
                    amount(padding, found);
                    continue;
                }
            };
            if let Some(condition) = &field.condition {
                operand(condition, found);
            }
            if let Some(Array::Count(count)) = &field.array {
                amount(count, found);
            }
            match &field.kind {
                FieldKind::Builtin(BuiltinField { length: Length::Expression { references, .. }, .. }) => {
                    expression(references, found);
                }
                FieldKind::Builtin(_) => {}
                FieldKind::Structure(children) => stored_in(children, found),
                FieldKind::Type(TypeUse { context, .. }) => context_table(context, found),
                FieldKind::Switch(switch) => {
                    operand(&switch.subject, found);
                    for body in switch.bodies() {
                        match body {
                            Body::Fields(children) => stored_in(children, found),
                            Body::Type(TypeUse { context, .. }) => context_table(context, found),
                        }
                    }
                }
            }
        }
    }

    fn amount(amount: &Amount, found: &mut Vec<Stored>) {
        if let Amount::Expression { references, .. } = amount {
            expression(references, found);
        }
    }

    fn operand(operand: &Operand, found: &mut Vec<Stored>) {
        if let Operand::Expression { references, .. } = operand {
            expression(references, found);
        }
    }

    fn expression(references: &BTreeMap<Vec<String>, Reference>, found: &mut Vec<Stored>) {
        for (segments, reference) in references {
            reference_id(reference, segments.last().expect("a path has a name"), found);
        }
    }

    fn context_table(context: &[(String, Reference)], found: &mut Vec<Stored>) {
        for (key, reference) in context {
            reference_id(reference, key.rsplit('.').next().expect("a key has a name"), found);
        }
    }

    fn reference_id(reference: &Reference, last: &str, found: &mut Vec<Stored>) {
        match reference {
            Reference::Field { target, .. } => found.push(Stored::Field(*target, last.to_owned())),
            Reference::Bits { target, .. } => found.push(Stored::SubField(*target, last.to_owned())),
            Reference::Context(_) => {}
        }
    }

    /// Every id a checked random description stores names a declaration of the name its path
    /// ends on.
    #[test]
    fn every_stored_id_resolves() {
        crate::random::check(|text| {
            let protocol = protocol(text);
            let index = FieldIndex::new(&protocol);
            for stored in stored(&protocol) {
                match stored {
                    Stored::Field(id, name) => {
                        prop_assert!(index.has_field(id), "no Field `{name}` with {id:?}");
                        prop_assert_eq!(&index.field(id).name, &name);
                    }
                    Stored::SubField(id, name) => {
                        prop_assert!(index.has_sub_field(id), "no sub-Field `{name}` with {id:?}");
                        prop_assert_eq!(&index.sub_field(id).name, &name);
                    }
                }
            }
            Ok(())
        });
    }
}
