//! Named Types (spec §3.5): reading `types:` (stage 2), and the checks that span Types (stage 4):
//! their names, which Fields use them, recursion and the order lowering defines them in.

use std::collections::{BTreeMap, BTreeSet};

use crate::diagnostic::{Diagnostic, Name, record};
use crate::field::{self, Endian, Entry, RawEntry};
use crate::keys::{Spanned, closest, duplicate_key, expect_string, is_type_name, read_keys, wrong_type};
use crate::mapping::Enums;
use crate::scope::{FreeRef, Scope};
use crate::yaml::{Node, Value};

/// The keys of a Type body, in documentation order.
pub(crate) const KEYS: [&str; 2] = ["fields", "endian"];

/// A Type as written, after stage 2.
#[derive(Debug, Clone)]
pub(crate) struct RawType {
    name: Spanned<String>,
    endian: Option<Spanned<String>>,
    fields: Vec<RawEntry>,
}

impl RawType {
    /// The Fields of the Type body, as written.
    pub(crate) fn fields(&self) -> &[RawEntry] {
        &self.fields
    }
}

/// A validated Type: its Fields, read in the Type's own byte order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NamedType {
    pub(crate) name: String,
    pub(crate) fields: Vec<Entry>,
}

/// Stage 2: reads the top-level `types:`, a mapping from Type names to Type bodies.
pub(crate) fn read(node: &Node, errors: &mut Vec<Diagnostic>) -> Vec<RawType> {
    let Value::Mapping(pairs) = &node.value else {
        errors.push(
            wrong_type(node.span.clone(), "`types` must map Type names to Type bodies")
                .with_note("write `types: { Header: { fields: [...] } }`", None),
        );
        return Vec::new();
    };
    let mut types: Vec<RawType> = Vec::new();
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
fn read_body(name: Spanned<String>, node: &Node, errors: &mut Vec<Diagnostic>) -> Option<RawType> {
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

    fn position(&self, name: &str) -> Option<usize> {
        self.raw.iter().position(|t| t.name.value == name)
    }

    /// Whether `types:` declares a Type named `name`, valid name or not, so that a Field using
    /// a wrongly named Type is not also `unknown-type` (spec §6.1).
    pub(crate) fn declares(&self, name: &str) -> bool {
        self.position(name).is_some()
    }

    /// Looks up the Type a Field's `type:` names, marking it as used. An unknown name marks the
    /// Type it most likely misspells instead, so a typo is not also an `unused-type`, and is
    /// reported the first time only.
    pub(crate) fn resolve(&mut self, name: &Spanned<String>) -> Option<String> {
        if let Some(index) = self.position(&name.value) {
            self.used[index] = true;
            return Some(name.value.clone());
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
/// Returns the checked layout, and the Types in dependency order, each after the Types it uses,
/// so lowering can define each one before its callers.
pub(crate) fn check<'a>(
    raw: &'a [RawType],
    top: &'a [RawEntry],
    endian: Endian,
    enums: &mut Enums<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> (Vec<Entry>, Vec<NamedType>) {
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
        bodies.push(Some(field::check(&t.fields, endian, enums, &mut types, scope, diagnostics)));
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
    let named = Walk::new(raw).dependency_order(diagnostics).into_iter().map(|i| NamedType {
        name: raw[i].name.value.clone(),
        fields: bodies[i].take().expect("each Type comes once in the order"),
    });
    (layout, named.collect())
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
