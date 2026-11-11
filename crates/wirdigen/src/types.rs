//! Named Types (spec §3.5): reading `types:` (stage 2), and the checks that span Types (stage 4):
//! their names, which Fields use them, recursion and the order lowering defines them in.

use crate::diagnostic::{Diagnostic, Name, record};
use crate::field::{self, Endian, Field, RawField};
use crate::keys::{Spanned, closest, duplicate_key, expect_string, is_type_name, read_keys, wrong_type};
use crate::mapping::Enums;
use crate::yaml::{Node, Value};

/// The keys of a Type body, in documentation order.
const KEYS: [&str; 2] = ["fields", "endian"];

/// A Type as written, after stage 2.
#[derive(Debug, Clone)]
pub(crate) struct RawType {
    name: Spanned<String>,
    endian: Option<Spanned<String>>,
    fields: Vec<RawField>,
}

/// A validated Type: its Fields, read in the Type's own byte order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NamedType {
    pub(crate) name: String,
    pub(crate) fields: Vec<Field>,
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
        if let Some(body) = read_body(value, errors) {
            let (endian, fields) = body;
            types.push(RawType { name: Spanned { value: text.clone(), span: key.span.clone() }, endian, fields });
        }
    }
    types
}

/// Reads a Type body, `{ fields: [...], endian: ... }`. `None` when it has errors.
fn read_body(node: &Node, errors: &mut Vec<Diagnostic>) -> Option<(Option<Spanned<String>>, Vec<RawField>)> {
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
    let fields = keys.get("fields").and_then(|n| field::read_structure(n, errors));
    match fields {
        Some(fields) if errors.len() == before => Some((endian, fields)),
        _ => None,
    }
}

/// The Types of a description, during stage 4: what Fields look up and mark as used.
pub(crate) struct Types<'a> {
    /// In source order.
    raw: &'a [RawType],
    used: Vec<bool>,
    /// One `unknown-type` per unknown name, at its first use in the source: an unknown Type is
    /// one error, not one per use.
    unknown: Vec<(String, Diagnostic)>,
}

impl<'a> Types<'a> {
    pub(crate) fn new(raw: &'a [RawType]) -> Self {
        Self { raw, used: vec![false; raw.len()], unknown: Vec::new() }
    }

    fn names(&self) -> Vec<&'a str> {
        self.raw.iter().map(|t| t.name.value.as_str()).collect()
    }

    /// Looks up the Type a Field's `type:` names, marking it as used. An unknown name marks the
    /// Type it most likely misspells instead, so a typo is not also an `unused-type`, and is
    /// reported the first time only.
    pub(crate) fn resolve(&mut self, name: &Spanned<String>) -> Option<String> {
        let names = self.names();
        if let Some(index) = names.iter().position(|n| *n == name.value) {
            self.used[index] = true;
            return Some(name.value.clone());
        }
        let guess = closest(&name.value, &names);
        if let Some(index) = guess.and_then(|g| names.iter().position(|n| *n == g)) {
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

/// Stage 4: checks every Type's name and body, then the uses between Types.
///
/// Returns the Types in dependency order, each after the Types it uses, so lowering can define
/// each one before its callers. `top` is the top-level layout, which uses Types too.
pub(crate) fn check(
    raw: &[RawType],
    top: &[RawField],
    endian: Endian,
    enums: &mut Enums<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> (Vec<Field>, Vec<NamedType>) {
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
        // An invalid byte order is an error already, so any stand-in will do.
        let endian = match &t.endian {
            Some(value) => record(Endian::check(value), diagnostics).unwrap_or_default(),
            None => endian,
        };
        bodies.push(field::check(&t.fields, endian, enums, &mut types, diagnostics));
    }
    let layout = field::check(top, endian, enums, &mut types, diagnostics);
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
    let order = dependency_order(raw, diagnostics);
    let named = order.into_iter().map(|i| NamedType { name: raw[i].name.value.clone(), fields: bodies[i].clone() });
    (layout, named.collect())
}

/// Where a DFS over the uses between Types stands with one Type.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Visit {
    New,
    /// On the current path: a use reaching it closes a cycle.
    Open,
    Done,
}

/// The indices of the Types in dependency order, reporting each cycle once as `recursive-type`
/// (spec §3.5), at the use the cycle's first-declared Type makes of the next one.
fn dependency_order(raw: &[RawType], diagnostics: &mut Vec<Diagnostic>) -> Vec<usize> {
    let uses: Vec<Vec<(usize, &Spanned<String>)>> = raw
        .iter()
        .map(|t| {
            field::type_uses(&t.fields)
                .into_iter()
                .filter_map(|u| raw.iter().position(|r| r.name.value == u.value).map(|i| (i, u)))
                .collect()
        })
        .collect();
    let mut state = vec![Visit::New; raw.len()];
    let mut order = Vec::new();
    let mut path = Vec::new();
    for start in 0..raw.len() {
        visit(start, &uses, &mut state, &mut path, &mut order, raw, diagnostics);
    }
    order
}

fn visit(
    node: usize,
    uses: &[Vec<(usize, &Spanned<String>)>],
    state: &mut [Visit],
    path: &mut Vec<usize>,
    order: &mut Vec<usize>,
    raw: &[RawType],
    diagnostics: &mut Vec<Diagnostic>,
) {
    if state[node] != Visit::New {
        return;
    }
    state[node] = Visit::Open;
    path.push(node);
    for &(next, _) in &uses[node] {
        match state[next] {
            Visit::New => visit(next, uses, state, path, order, raw, diagnostics),
            Visit::Open => {
                let from = path.iter().position(|&n| n == next).expect("an open Type is on the path");
                diagnostics.push(recursion(&path[from..], uses, raw));
            }
            Visit::Done => {}
        }
    }
    path.pop();
    state[node] = Visit::Done;
    order.push(node);
}

/// The Diagnostic of the cycle through `cycle`, in use order, each Type using the next and the
/// last the first.
fn recursion(cycle: &[usize], uses: &[Vec<(usize, &Spanned<String>)>], raw: &[RawType]) -> Diagnostic {
    let first = (0..cycle.len()).min_by_key(|&i| cycle[i]).expect("a cycle has a Type");
    let (from, to) = (cycle[first], cycle[(first + 1) % cycle.len()]);
    let (_, site) = uses[from].iter().find(|(n, _)| *n == to).expect("each Type of a cycle uses the next");
    let names: Vec<&str> = cycle[first..].iter().chain(&cycle[..=first]).map(|&i| raw[i].name.value.as_str()).collect();
    let message = if cycle.len() == 1 {
        format!("the Type `{}` contains itself", names[0])
    } else {
        format!("the Type `{}` contains itself through {}", names[0], names[1..names.len() - 1].join(", "))
    };
    Diagnostic::new(Name::RecursiveType, site.span.clone(), message)
        .with_note(format!("a Type cannot contain itself: {}", names.join(" → ")), None)
}
