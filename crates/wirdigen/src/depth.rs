//! Field depth (spec §3.4.1, ADR 0020): the stage 4 check that no Field is more than
//! [`MAX_DEPTH`] deep, `field-too-deep`, so the passes after it can recurse once per level.
//!
//! A Field's Depth is how many Fields enclose it, through every Type it is reached by; a
//! `switch` case adds none. A Field of a Type has a Depth per use of the Type, so the check
//! walks each Type once per Depth its Fields start at, callers before the Types they use, with an
//! explicit stack: it never recurses, however deep the description goes.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use crate::diagnostic::{Diagnostic, Name};
use crate::field::{Entry, Field, FieldKind};
use crate::index::TypeId;
use crate::switch::Body;
use crate::types::NamedTypes;

/// The deepest a Field may be: how many Fields may enclose it.
pub(crate) const MAX_DEPTH: usize = 64;

/// Stage 4: reports `field-too-deep` once at each Field, or sub-Field, that is the first past
/// [`MAX_DEPTH`] on some path, given the checked layout of the protocol `protocol` and its Types.
///
/// The Types must have no cycle: a recursive Type would make its Fields infinitely deep.
pub(crate) fn check(protocol: &str, layout: &[Entry], types: &NamedTypes, diagnostics: &mut Vec<Diagnostic>) {
    let mut walk = Walk { starts: BTreeMap::new(), reported: BTreeSet::new(), diagnostics };
    walk.structure(layout, 0, protocol);
    // Callers first: every use of a Type is recorded before the Type is walked.
    for ty in types.in_dependency_order().rev() {
        for (depth, prefix) in walk.starts.remove(&ty.id).unwrap_or_default() {
            walk.structure(&ty.fields, depth, &prefix);
        }
    }
}

/// A walk over the Fields of a description, each Type once per Depth it is used at.
struct Walk<'d> {
    /// For each Type used, the Depths its Fields start at, each with the filter name of the
    /// first Field using it there.
    starts: BTreeMap<TypeId, BTreeMap<usize, String>>,
    /// Where each Field reported is written: a Field reached too deep through several uses of a
    /// Type is reported once.
    reported: BTreeSet<usize>,
    diagnostics: &'d mut Vec<Diagnostic>,
}

impl Walk<'_> {
    /// Walks the Fields of `entries`, `depth` deep, whose filter names extend `prefix`, down to
    /// the uses of Types, which it records. A Field past [`MAX_DEPTH`] is reported, and the
    /// Fields under it are not walked.
    fn structure(&mut self, entries: &[Entry], depth: usize, prefix: &str) {
        let mut stack: Vec<(&Field, usize, String)> = Vec::new();
        push(&mut stack, entries, depth, prefix);
        while let Some((field, depth, path)) = stack.pop() {
            if depth > MAX_DEPTH {
                self.report(&field.span, &path, depth);
                continue;
            }
            match &field.kind {
                FieldKind::Builtin(value) => {
                    for bit in value.kind.sub_fields().iter().filter(|_| depth == MAX_DEPTH) {
                        self.report(&bit.span, &format!("{path}.{}", bit.name), depth + 1);
                    }
                }
                FieldKind::Structure(children) => push(&mut stack, children, depth + 1, &path),
                FieldKind::Type(used) => self.start(used.id, depth + 1, &path),
                FieldKind::Switch(switch) => {
                    // Bodies are pushed in reverse too, so the first case is walked first.
                    let bodies: Vec<&Body> = switch.bodies().collect();
                    for body in bodies.into_iter().rev() {
                        match body {
                            Body::Fields(children) => push(&mut stack, children, depth + 1, &path),
                            Body::Type(used) => self.start(used.id, depth + 1, &path),
                        }
                    }
                }
            }
        }
    }

    /// Records that the Fields of the Type `id` start `depth` deep under the filter name
    /// `prefix`, unless an earlier use starts them as deep.
    fn start(&mut self, id: TypeId, depth: usize, prefix: &str) {
        self.starts.entry(id).or_default().entry(depth).or_insert_with(|| prefix.to_owned());
    }

    fn report(&mut self, span: &Range<usize>, path: &str, depth: usize) {
        if !self.reported.insert(span.start) {
            return;
        }
        self.diagnostics.push(
            Diagnostic::new(
                Name::FieldTooDeep,
                span.clone(),
                format!("`{path}` is {depth} Fields deep; the limit is {MAX_DEPTH}"),
            )
            .with_note(
                "the Fields enclosing a Field count through every Type it is reached by, a `switch` case \
                 adding none: move it, or a Field enclosing it, closer to the top level",
                None,
            ),
        );
    }
}

/// Pushes the Fields of `entries`, `depth` deep under the filter name `prefix`, last first, so
/// they are popped in source order. Padding has no filter name and holds no Field.
fn push<'e>(stack: &mut Vec<(&'e Field, usize, String)>, entries: &'e [Entry], depth: usize, prefix: &str) {
    let fields = entries.iter().filter_map(Entry::field).rev();
    stack.extend(fields.map(|field| (field, depth, format!("{prefix}.{}", field.name))));
}
