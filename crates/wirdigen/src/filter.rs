//! Filter names (spec §5.2): the check that Fields reaching one filter name can share its
//! `ProtoField` (stage 4, `conflicting-filter-name`).
//!
//! Only `switch` cases make two Fields reach one path: sibling names are unique, and a Type adds
//! the name of the Field using it. The check walks the validated layout as lowering registers
//! it, each use of a Type with its own paths, so it runs only once the layout has no error: a
//! recursive Type would never end the walk.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use crate::bits::Bit;
use crate::diagnostic::{Diagnostic, Name};
use crate::field::{self, Builtin, Display, Entry, Field, FieldKind, Length};
use crate::mapping::Mapping;
use crate::switch::Body;
use crate::types::NamedType;

/// What a `ProtoField` is declared as, past its filter name: what must match for two Fields to
/// share it (spec §3.4.9).
#[derive(Debug, PartialEq, Eq)]
struct Declaration<'a> {
    kind: ProtoKind<'a>,
    display: Option<Display>,
    mapping: Option<&'a Mapping>,
    label: String,
    description: Option<&'a str>,
}

/// The type part of a [`Declaration`]: what the `ProtoField` holds.
#[derive(Debug, PartialEq, Eq)]
enum ProtoKind<'a> {
    /// A value of a built-in type; a NUL-terminated string is a `ProtoField` type of its own.
    Value {
        ty: Builtin,
        stringz: bool,
    },
    /// A bitfield sub-Field, as wide as its container and masked.
    Bit {
        container: Builtin,
        mask: u64,
    },
    Structure,
    /// A Field of the Type of this name.
    Type(&'a str),
    Switch,
}

impl ProtoKind<'_> {
    /// How messages name it.
    fn describe(&self) -> String {
        match self {
            Self::Value { stringz: true, .. } => "a NUL-terminated `string`".to_owned(),
            Self::Value { ty, .. } => format!("a `{}`", ty.name()),
            Self::Bit { mask, .. } => format!("a sub-Field of mask 0x{mask:X}"),
            Self::Structure => "an inline structure".to_owned(),
            Self::Type(name) => format!("a Field of the Type `{name}`"),
            Self::Switch => "a `switch` Field".to_owned(),
        }
    }
}

/// The first declaration seen at each filter name, with the span reported for it.
type Seen<'a> = BTreeMap<String, (Declaration<'a>, Range<usize>)>;

/// Stage 4: reports each Field reaching the filter name of an earlier one with a `ProtoField`
/// that does not match, given the checked layout and Types of a description without errors.
pub(crate) fn check(layout: &[Entry], types: &[NamedType], diagnostics: &mut Vec<Diagnostic>) {
    let mut walk = Walk { types, seen: Seen::new(), reported: BTreeSet::new(), diagnostics };
    walk.fields(layout, "");
}

/// A walk over the filter paths of a layout, in the order lowering registers them.
struct Walk<'a, 'd> {
    types: &'a [NamedType],
    seen: Seen<'a>,
    /// The pairs of spans reported already: a Type used twice would report its conflict twice.
    reported: BTreeSet<(usize, usize)>,
    diagnostics: &'d mut Vec<Diagnostic>,
}

impl<'a> Walk<'a, '_> {
    /// Walks the Fields of `entries`, whose paths extend `parent` (empty at the top level).
    /// Padding has no filter name (spec §5.2).
    fn fields(&mut self, entries: &'a [Entry], parent: &str) {
        for field in entries.iter().filter_map(Entry::field) {
            let path = if parent.is_empty() { field.name.clone() } else { format!("{parent}.{}", field.name) };
            self.field(field, &path);
        }
    }

    /// Declares the `ProtoField` of `field` at `path`, its sub-Fields', and those of the Fields
    /// it holds: a `switch` case adds no segment to the path.
    fn field(&mut self, field: &'a Field, path: &str) {
        let (kind, display, mapping) = match &field.kind {
            FieldKind::Builtin(value) => {
                let stringz = value.ty == Builtin::String && value.length == Length::Terminator(0);
                (ProtoKind::Value { ty: value.ty, stringz }, value.display, value.mapping.as_ref())
            }
            FieldKind::Structure(_) => (ProtoKind::Structure, None, None),
            FieldKind::Type { name, .. } => (ProtoKind::Type(name), None, None),
            FieldKind::Switch(_) => (ProtoKind::Switch, None, None),
        };
        let label = field.label.clone().unwrap_or_else(|| field::default_label(&field.name));
        let description = field.description.as_deref();
        self.declare(path, Declaration { kind, display, mapping, label, description }, &field.span);
        match &field.kind {
            FieldKind::Builtin(value) => {
                for bit in &value.bits {
                    self.declare(&format!("{path}.{}", bit.name), bit_declaration(value.ty, bit), &field.span);
                }
            }
            FieldKind::Structure(children) => self.fields(children, path),
            FieldKind::Type { name, .. } => self.type_fields(name, path),
            FieldKind::Switch(switch) => {
                for body in switch.bodies() {
                    match body {
                        Body::Fields(children) => self.fields(children, path),
                        Body::Type { name, .. } => self.type_fields(name, path),
                    }
                }
            }
        }
    }

    /// Walks the Fields of the Type `name` used at `path`.
    fn type_fields(&mut self, name: &str, path: &str) {
        let ty = self.types.iter().find(|t| t.name == name).expect("validation resolved every Type");
        self.fields(&ty.fields, path);
    }

    /// Records the first declaration at `path`; a later one that differs is reported once.
    fn declare(&mut self, path: &str, declaration: Declaration<'a>, span: &Range<usize>) {
        let Some((first, first_span)) = self.seen.get(path) else {
            self.seen.insert(path.to_owned(), (declaration, span.clone()));
            return;
        };
        if *first == declaration || !self.reported.insert((first_span.start, span.start)) {
            return;
        }
        let differs = if first.kind != declaration.kind {
            format!("this one is {}, the other {}", declaration.kind.describe(), first.kind.describe())
        } else if first.display != declaration.display {
            "their `display` differs".to_owned()
        } else if first.mapping != declaration.mapping {
            "their value mappings differ".to_owned()
        } else if first.label != declaration.label {
            format!("this one is labelled \"{}\", the other \"{}\"", declaration.label, first.label)
        } else {
            "their `description` differs".to_owned()
        };
        let last = path.rsplit('.').next().unwrap_or(path);
        self.diagnostics.push(
            Diagnostic::new(
                Name::ConflictingFilterName,
                span.clone(),
                format!("`{last}` reaches the filter path `{path}` of another Field, which it cannot share"),
            )
            .with_note(format!("the other Field is here; {differs}"), Some(first_span.clone()))
            .with_note(
                "Fields reaching one filter path share its ProtoField only when their type, display, value \
                 mappings, label and description match: make them match, or rename one",
                None,
            ),
        );
    }
}

/// The declaration of the sub-Field `bit` of a bitfield of type `container`.
fn bit_declaration(container: Builtin, bit: &Bit) -> Declaration<'_> {
    Declaration {
        kind: ProtoKind::Bit { container, mask: bit.mask() },
        display: bit.display,
        mapping: bit.mapping.as_ref(),
        label: bit.label.clone().unwrap_or_else(|| field::default_label(&bit.name)),
        description: bit.description.as_deref(),
    }
}
