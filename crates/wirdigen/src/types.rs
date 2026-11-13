//! Named Types (spec §3.5): reading `types:` (stage 2), and the checks that span Types (stage 4):
//! their names, which Fields use them, recursion and the order lowering defines them in.

use std::collections::{BTreeMap, BTreeSet};

use crate::diagnostic::{Diagnostic, Name, record};
use crate::expr::Expr;
use crate::field::{self, Endian, Entry, Parse, RawEntry};
use crate::index::TypeId;
use crate::keys::{Spanned, closest, duplicate_key, expect_string, is_type_name, read_keys, wrong_type};
use crate::mapping::Enums;
use crate::scope::{self, FreeRef, Reference, Scope};
use crate::yaml::{Node, Value};

/// The keys of a Type body, in documentation order.
pub(crate) const KEYS: [&str; 2] = ["fields", "endian"];

/// A Type as written, after stage 2.
#[derive(Debug, Clone)]
pub(crate) struct RawType<E = Expr> {
    name: Spanned<String>,
    endian: Option<Spanned<String>>,
    fields: Vec<RawEntry<E>>,
}

impl RawType<Parse> {
    /// Stage 3: the Type with its Expressions parsed, leaving out the entries with a syntax
    /// error after pushing it.
    pub(crate) fn parsed(self, errors: &mut Vec<Diagnostic>) -> RawType {
        RawType { name: self.name, endian: self.endian, fields: field::parsed(self.fields, errors) }
    }
}

/// A validated Type: its Fields, read in the Type's own byte order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NamedType {
    pub(crate) id: TypeId,
    /// The name as declared, for Lua names and messages: a Type is looked up by its id.
    pub(crate) name: String,
    pub(crate) fields: Vec<Entry>,
}

/// A use of a Type, by a Field or by a case of a `switch` Field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TypeUse {
    pub(crate) id: TypeId,
    /// The Type's name, for Lua names and messages.
    pub(crate) name: String,
    /// The context table this use passes: what each name the Type reads but does not declare
    /// resolves to here, by the name as written (spec §4.3).
    pub(crate) context: Vec<(String, Reference)>,
}

impl TypeUse {
    /// Resolves the use of the Type `name`, written in `scope`: the Type it names, marked as
    /// used, and the context table it passes. `None` when no Type has that name, which `types`
    /// reports, or after pushing why the context table does not resolve.
    pub(crate) fn resolve<'a>(
        name: &Spanned<String>,
        scope: Scope<'a, '_>,
        types: &mut Types<'a>,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> Option<Self> {
        let id = types.resolve(name)?;
        let context = scope::resolve_context(&name.value, &name.span, scope, types, diagnostics)?;
        Some(Self { id, name: name.value.clone(), context })
    }
}

/// The validated Types of a description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NamedTypes {
    /// In source order: each Type at the position its id holds.
    declared: Vec<NamedType>,
    /// Every Type once, each after the Types it uses.
    order: Vec<TypeId>,
}

impl NamedTypes {
    /// The Type a resolved `type:` names.
    ///
    /// # Panics
    ///
    /// When no Type of the description has that id: every id is given out for one of them.
    pub(crate) fn get(&self, id: TypeId) -> &NamedType {
        self.declared.get(id.position()).expect("every TypeId names a Type of the description")
    }

    /// The Types in dependency order, each after the Types it uses, so lowering can define each
    /// one before its callers (spec §7.3).
    pub(crate) fn in_dependency_order(&self) -> impl DoubleEndedIterator<Item = &NamedType> {
        self.order.iter().map(|&id| self.get(id))
    }
}

/// Stage 2: reads the top-level `types:`, a mapping from Type names to Type bodies.
pub(crate) fn read(node: &Node, errors: &mut Vec<Diagnostic>) -> Vec<RawType<Parse>> {
    let Value::Mapping(pairs) = &node.value else {
        errors.push(
            wrong_type(node.span.clone(), "`types` must map Type names to Type bodies")
                .with_note("write `types: { Header: { fields: [...] } }`", None),
        );
        return Vec::new();
    };
    let mut types: Vec<RawType<Parse>> = Vec::new();
    for (key, value) in pairs {
        // Whether a name is valid is a stage 4 check, as for Enums.
        let Value::Scalar { text, .. } = &key.value else {
            errors.push(wrong_type(key.span.clone(), "a Type name must be a string"));
            continue;
        };
        if let Some(first) = types.iter().find(|t| t.name.value == *text) {
            errors.push(duplicate_key(text, key, &first.name.span));
            continue;
        }
        let name = Spanned { value: text.clone(), span: key.span.clone() };
        types.extend(read_body(name, value, errors));
    }
    types
}

/// Reads the body of the Type `name`, `{ fields: [...], endian: ... }`. `None` when it has
/// errors.
fn read_body(name: Spanned<String>, node: &Node, errors: &mut Vec<Diagnostic>) -> Option<RawType<Parse>> {
    let Value::Mapping(entries) = &node.value else {
        errors.push(
            wrong_type(node.span.clone(), "a Type is a mapping with `fields`")
                .with_note("write `{ fields: [...] }`", None),
        );
        return None;
    };
    let before = errors.len();
    let keys = read_keys(entries, &KEYS, errors);
    if keys.get("fields").is_none() && !keys.misspelt("fields") {
        errors.push(Diagnostic::new(Name::MissingKey, node.span.clone(), "missing required key `fields`"));
    }
    let endian = keys.get("endian").and_then(|n| record(expect_string(n, "endian", Name::InvalidEndian), errors));
    let fields = keys.get("fields").and_then(|n| field::read_structure(n, errors))?;
    (errors.len() == before).then_some(RawType { name, endian, fields })
}

/// The Types of a description, during stage 4: what Fields look up and mark as used.
pub(crate) struct Types<'a> {
    /// In source order.
    raw: &'a [RawType],
    /// Whether some Field uses each Type of `raw`.
    used: Vec<bool>,
    /// One `unknown-type` per unknown name, at its first use in the source: an unknown Type is
    /// one error, not one per use.
    unknown: Vec<(String, Diagnostic)>,
    /// The names each Type reads but does not declare, once computed; `None` while a Type is
    /// being walked, so a recursive Type stops the walk (spec §4.3).
    pub(crate) free: BTreeMap<String, Option<Vec<FreeRef>>>,
}

impl<'a> Types<'a> {
    fn new(raw: &'a [RawType]) -> Self {
        Self { raw, used: vec![false; raw.len()], unknown: Vec::new(), free: BTreeMap::new() }
    }

    /// The Fields of the Type named `name`, as written.
    pub(crate) fn body(&self, name: &str) -> Option<&'a [RawEntry]> {
        self.position(name).map(|i| self.raw[i].fields.as_slice())
    }

    /// The Type named `name`, by its name as declared, and its Fields as written.
    pub(crate) fn named_body(&self, name: &str) -> Option<(&'a str, &'a [RawEntry])> {
        let raw: &'a [RawType] = self.raw;
        raw.iter().find(|t| t.name.value == name).map(|t| (t.name.value.as_str(), t.fields.as_slice()))
    }

    fn position(&self, name: &str) -> Option<usize> {
        self.raw.iter().position(|t| t.name.value == name)
    }

    /// Whether `types:` declares a Type named `name`, valid name or not, so that a Field using
    /// a wrongly named Type is not also `unknown-type` (spec §6.1).
    pub(crate) fn declares(&self, name: &str) -> bool {
        self.position(name).is_some()
    }

    /// Looks up the Type a Field's `type:` names, marking it as used, and returns its id. An
    /// unknown name marks the Type it most likely misspells instead, so a typo is not also an
    /// `unused-type`, and is reported the first time only.
    pub(crate) fn resolve(&mut self, name: &Spanned<String>) -> Option<TypeId> {
        if let Some(index) = self.position(&name.value) {
            self.used[index] = true;
            return Some(TypeId::at(index));
        }
        let names: Vec<&str> = self.raw.iter().map(|t| t.name.value.as_str()).collect();
        let guess = closest(&name.value, &names);
        if let Some(index) = guess.and_then(|g| self.position(g)) {
            self.used[index] = true;
        }
        let unknown =
            Diagnostic::new(Name::UnknownType, name.span.clone(), format!("there is no Type named `{}`", name.value));
        let unknown = match guess {
            Some(guess) => unknown.with_note(format!("did you mean `{guess}`?"), None),
            None if names.is_empty() => unknown.with_note("declare it under the top-level `types`", None),
            None => unknown.with_note(format!("the Types are: {}", names.join(", ")), None),
        };
        match self.unknown.iter_mut().find(|(n, _)| *n == name.value) {
            Some((_, first)) if first.span().start > name.span.start => *first = unknown,
            Some(_) => {}
            None => self.unknown.push((name.value.clone(), unknown)),
        }
        None
    }
}

/// Stage 4: checks every Type's name and body, the top-level layout `top`, which uses Types too,
/// and the uses between Types.
///
/// Returns the checked layout and the checked Types, which know their dependency order.
pub(crate) fn check<'a>(
    raw: &'a [RawType],
    top: &'a [RawEntry],
    endian: Endian,
    enums: &mut Enums<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> (Vec<Entry>, NamedTypes) {
    let mut types = Types::new(raw);
    let mut bodies = Vec::new();
    for t in raw {
        if !is_type_name(&t.name.value) {
            diagnostics.push(
                Diagnostic::new(
                    Name::InvalidTypeName,
                    t.name.span.clone(),
                    format!("`{}` is not a valid Type name", t.name.value),
                )
                .with_note("a Type name is an uppercase letter then letters or digits", None),
            );
        }
        let endian = Endian::resolve(t.endian.as_ref(), endian, diagnostics);
        let scope = Scope { ty: Some(&t.name.value), levels: &[] };
        bodies.push(field::check(&t.fields, endian, enums, &mut types, scope, diagnostics));
    }
    let layout = field::check(top, endian, enums, &mut types, Scope { ty: None, levels: &[] }, diagnostics);
    diagnostics.extend(types.unknown.into_iter().map(|(_, d)| d));
    for (t, used) in raw.iter().zip(&types.used) {
        if !used {
            diagnostics.push(
                Diagnostic::new(
                    Name::UnusedType,
                    t.name.span.clone(),
                    format!("the Type `{}` is never used", t.name.value),
                )
                .with_note(format!("use it as `type: {}`, or remove it", t.name.value), None),
            );
        }
    }
    let order = Walk::new(raw).dependency_order(diagnostics).into_iter().map(TypeId::at).collect();
    let declared = raw
        .iter()
        .zip(bodies)
        .enumerate()
        .map(|(position, (t, fields))| NamedType { id: TypeId::at(position), name: t.name.value.clone(), fields })
        .collect();
    (layout, NamedTypes { declared, order })
}

/// Where a depth-first walk over the uses between Types stands with one Type.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Visit {
    New,
    /// On the current path: a use reaching it closes a cycle.
    Open,
    Done,
}

/// A depth-first walk over the uses between Types, in source order.
struct Walk<'a> {
    raw: &'a [RawType],
    /// For each Type, the Types its Fields use, by index, with the `type:` naming each.
    uses: Vec<Vec<(usize, &'a Spanned<String>)>>,
    state: Vec<Visit>,
    /// The Types being visited, outermost first.
    path: Vec<usize>,
    /// The Types visited, each after the Types it uses.
    order: Vec<usize>,
    /// The Types of each cycle reported, so a cycle closed by several uses is one error.
    cycles: BTreeSet<Vec<usize>>,
}

impl<'a> Walk<'a> {
    fn new(raw: &'a [RawType]) -> Self {
        let uses = raw
            .iter()
            .map(|t| {
                field::type_uses(&t.fields)
                    .into_iter()
                    .filter_map(|u| raw.iter().position(|r| r.name.value == u.value).map(|i| (i, u)))
                    .collect()
            })
            .collect();
        Self {
            raw,
            uses,
            state: vec![Visit::New; raw.len()],
            path: Vec::new(),
            order: Vec::new(),
            cycles: BTreeSet::new(),
        }
    }

    /// The indices of the Types in dependency order, reporting each cycle once as
    /// `recursive-type` (spec §3.5).
    fn dependency_order(mut self, diagnostics: &mut Vec<Diagnostic>) -> Vec<usize> {
        for start in 0..self.raw.len() {
            self.visit(start, diagnostics);
        }
        self.order
    }

    fn visit(&mut self, node: usize, diagnostics: &mut Vec<Diagnostic>) {
        if self.state[node] != Visit::New {
            return;
        }
        self.state[node] = Visit::Open;
        self.path.push(node);
        for use_index in 0..self.uses[node].len() {
            let next = self.uses[node][use_index].0;
            match self.state[next] {
                Visit::New => self.visit(next, diagnostics),
                Visit::Open => {
                    let from = self.path.iter().position(|&n| n == next).expect("an open Type is on the path");
                    let cycle = self.path[from..].to_vec();
                    let mut members = cycle.clone();
                    members.sort_unstable();
                    if self.cycles.insert(members) {
                        diagnostics.push(self.recursion(&cycle));
                    }
                }
                Visit::Done => {}
            }
        }
        self.path.pop();
        self.state[node] = Visit::Done;
        self.order.push(node);
    }

    /// The Diagnostic of the cycle through `cycle`, in use order, each Type using the next and
    /// the last the first. It points at the use the cycle's first-declared Type makes of the
    /// next one.
    fn recursion(&self, cycle: &[usize]) -> Diagnostic {
        let first = (0..cycle.len()).min_by_key(|&i| cycle[i]).expect("a cycle has a Type");
        let (from, to) = (cycle[first], cycle[(first + 1) % cycle.len()]);
        let (_, site) = self.uses[from].iter().find(|(n, _)| *n == to).expect("each Type of a cycle uses the next");
        let names: Vec<&str> =
            cycle[first..].iter().chain(&cycle[..=first]).map(|&i| self.raw[i].name.value.as_str()).collect();
        let message = if cycle.len() == 1 {
            format!("the Type `{}` contains itself", names[0])
        } else {
            format!("the Type `{}` contains itself through {}", names[0], names[1..names.len() - 1].join(", "))
        };
        Diagnostic::new(Name::RecursiveType, site.span.clone(), message)
            .with_note(format!("a Type cannot contain itself: {}", names.join(" → ")), None)
    }
}
