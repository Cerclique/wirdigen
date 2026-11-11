//! Resolving the Field paths of Expressions (spec §4.3), a semantic check (stage 4).
//!
//! A path's first name resolves nearest first: the earlier Fields of the structure the
//! Expression is in, then those of each enclosing structure, out to the top-level layout or the
//! Type body. The rest of the path then descends into the structures and Types read there.
//!
//! Inside a Type, a name the Type does not read is *free*: each use of the Type resolves it in
//! its own scope, and reports there what it cannot resolve (spec §3.5).

use std::collections::BTreeMap;
use std::ops::Range;

use crate::bits::Lookup;
use crate::diagnostic::{Diagnostic, Name};
use crate::field::{self, Builtin, RawEntry, RawField, Shape};
use crate::keys::closest;
use crate::switch::{RawBody, RawSwitch};
use crate::types::Types;

/// What a resolved path reads, from the dissect function the Expression is in (spec §7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reference {
    /// A Field read by the same function: its path from the function's root (the top-level
    /// layout or the Type body), through inline structures and Fields of Types.
    Field(Vec<String>),
    /// A bitfield sub-Field (spec §3.8): `width` bits, `shift` bits up from the least significant
    /// one, of the value of the container Field at `container`, read by the same function.
    Bits { container: Vec<String>, shift: u32, width: u32 },
    /// A value the caller passes in the context table, under the path as written in the Type.
    Context(String),
}

/// One structure enclosing a reference: its entries, and the index of the entry being read.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Level<'a> {
    pub(crate) fields: &'a [RawEntry],
    pub(crate) at: usize,
}

impl<'a> Level<'a> {
    /// The Fields read before the entry being read.
    fn earlier(&self) -> impl DoubleEndedIterator<Item = &'a RawField> + use<'a> {
        self.fields[..self.at].iter().filter_map(RawEntry::field)
    }

    /// The Field being read, which encloses the reference when the level is not the innermost:
    /// only a Field has entries to enclose it.
    fn enclosing(&self) -> &'a RawField {
        self.fields[self.at].field().expect("only a Field encloses entries")
    }
}

/// Where a path is read from.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Scope<'a, 'l> {
    /// The Type whose body the levels are in, `None` in the top-level layout.
    pub(crate) ty: Option<&'l str>,
    /// The structures enclosing the reference, the function's root first.
    pub(crate) levels: &'l [Level<'a>],
}

/// A name a Type reads but does not declare before reading it: each use of the Type resolves it.
#[derive(Debug, Clone)]
pub(crate) struct FreeRef {
    /// The path as written, the key of the context table.
    pub(crate) key: String,
    /// The path's names, as the key spells them separated by `.`.
    pub(crate) segments: Vec<String>,
    /// Where the path is written, in this Type or a Type it uses.
    pub(crate) origin: Range<usize>,
    /// The Type the path is written in.
    pub(crate) ty: String,
    /// A Field of that name the Type reads only later, which makes an unresolved use a forward
    /// reference.
    pub(crate) later: Option<Range<usize>>,
}

/// Why a path resolves to nothing usable.
#[derive(Debug, Clone)]
pub(crate) enum Miss {
    /// No earlier Field has the first name, but a later one does, at this span.
    Forward(Range<usize>),
    /// No Field has the first name; the earlier ones are the candidates.
    Unknown(Vec<String>),
    /// The first name is a structure still being read.
    Enclosing,
    /// A structure on the path has no Field of the next name.
    NoMember { parent: String, member: String, candidates: Vec<String> },
    /// A Field on the path is not a structure, but the path goes on.
    NotStructure(String),
    /// A Field on the path is an array, whose Fields only its elements can read (spec §4.3).
    IntoArray(String),
    /// A Field on the path is read under an `if:`, at this span, that does not enclose the
    /// reference (spec §3.9, §4.3).
    Conditional { field: String, condition: Range<usize> },
    /// A Field on the path is read only in a case, at this span, of the `switch` Field `switch`
    /// (spec §3.9, §4.3).
    InCase { switch: String, member: String, case: Range<usize> },
    /// The path ends on a Field that is not an integer or a `bool`.
    NonNumeric { what: String, span: Range<usize> },
}

/// What resolving a path gives.
enum Resolution {
    Found(Reference),
    /// Not read in the Type: its uses resolve it.
    Free {
        later: Option<Range<usize>>,
    },
    /// The path leads to a Field already in error (an unknown type): nothing more is said.
    Suppressed,
    Miss(Miss),
}

/// Resolves `segments` from `scope` (spec §4.3).
fn resolve<'a>(segments: &[String], scope: Scope<'a, '_>, types: &Types<'a>) -> Resolution {
    let first = segments[0].as_str();
    for (depth, level) in scope.levels.iter().enumerate().rev() {
        let Some(field) = level.earlier().rev().find(|f| f.name().value == first) else {
            continue;
        };
        let mut path: Vec<String> = scope.levels[..depth].iter().map(|l| l.enclosing().name().value.clone()).collect();
        path.push(first.to_owned());
        return descend(field, &segments[1..], path, types);
    }
    // The Field being read counts as later, but not the structures enclosing it.
    let innermost = scope.levels.len() - 1;
    let later = scope
        .levels
        .iter()
        .enumerate()
        .rev()
        .find_map(|(depth, l)| {
            let from = if depth == innermost { l.at } else { l.at + 1 };
            field::fields(&l.fields[from..]).find(|f| f.name().value == first)
        })
        .map(|f| f.name().span.clone());
    if scope.ty.is_some() {
        return Resolution::Free { later };
    }
    if let Some(later) = later {
        return Resolution::Miss(Miss::Forward(later));
    }
    if scope.levels[..scope.levels.len() - 1].iter().any(|l| l.enclosing().name().value == first) {
        return Resolution::Miss(Miss::Enclosing);
    }
    let earlier = scope.levels.iter().flat_map(Level::earlier).map(|f| f.name().value.clone()).collect();
    Resolution::Miss(Miss::Unknown(earlier))
}

/// Follows the rest of a path from `field`, found at `path`. Every Field on the way must be read
/// unconditionally: `field` is an earlier Field, never one enclosing the reference, so no `if:`
/// on the way encloses it either (spec §4.3).
fn descend<'a>(mut field: &'a RawField, rest: &[String], mut path: Vec<String>, types: &Types<'a>) -> Resolution {
    for (index, segment) in rest.iter().enumerate() {
        if let Some(miss) = conditional_miss(field) {
            return Resolution::Miss(miss);
        }
        if field.is_array() {
            return Resolution::Miss(Miss::IntoArray(field.name().value.clone()));
        }
        let children = match field.shape(types) {
            Shape::Structure(children) | Shape::Type { fields: children, .. } => children,
            Shape::Switch(switch) => return into_case(field, switch, segment, types),
            Shape::Unknown => return Resolution::Suppressed,
            Shape::Value(builtin, _) => {
                let Some(bits) = field.bits() else {
                    return Resolution::Miss(Miss::NotStructure(field.name().value.clone()));
                };
                return match bits.lookup(segment, builtin) {
                    Lookup::Missing => Resolution::Miss(Miss::NoMember {
                        parent: field.name().value.clone(),
                        member: segment.clone(),
                        candidates: bits.names(),
                    }),
                    Lookup::Found { .. } if index + 1 < rest.len() => {
                        Resolution::Miss(Miss::NotStructure(segment.clone()))
                    }
                    Lookup::Found { shift, width } => {
                        Resolution::Found(Reference::Bits { container: path, shift, width })
                    }
                    Lookup::Invalid => Resolution::Suppressed,
                };
            }
        };
        let Some(child) = field::fields(children).find(|f| f.name().value == *segment) else {
            let candidates = field::fields(children).map(|f| f.name().value.clone()).collect();
            let (parent, member) = (field.name().value.clone(), segment.clone());
            return Resolution::Miss(Miss::NoMember { parent, member, candidates });
        };
        field = child;
        path.push(segment.clone());
    }
    if let Some(miss) = conditional_miss(field) {
        return Resolution::Miss(miss);
    }
    let what = match field.shape(types) {
        Shape::Unknown => return Resolution::Suppressed,
        _ if field.is_array() => "an array".to_owned(),
        Shape::Value(Builtin::Int { .. } | Builtin::Bool, _) => return Resolution::Found(Reference::Field(path)),
        Shape::Value(_, written) => format!("a `{written}`"),
        Shape::Structure(_) => "a structure".to_owned(),
        Shape::Type { name, .. } => format!("a Field of the Type `{name}`"),
        Shape::Switch(_) => "a `switch` Field".to_owned(),
    };
    Resolution::Miss(Miss::NonNumeric { what, span: field.name().span.clone() })
}

/// Why a path cannot go on from the `switch` Field `field` to its Field `segment`: every Field
/// of a case is read only when the case matches (spec §3.9, §4.3).
fn into_case(field: &RawField, switch: &RawSwitch, segment: &str, types: &Types<'_>) -> Resolution {
    let mut candidates = Vec::new();
    for (case, body) in switch.bodies() {
        let fields = match body {
            RawBody::Fields(fields) => fields.as_slice(),
            RawBody::Type(name) => match types.body(&name.value) {
                Some(fields) => fields,
                None => continue,
            },
        };
        if field::fields(fields).any(|f| f.name().value == segment) {
            let (switch, member) = (field.name().value.clone(), segment.to_owned());
            return Resolution::Miss(Miss::InCase { switch, member, case: case.clone() });
        }
        candidates.extend(field::fields(fields).map(|f| f.name().value.clone()));
    }
    let (parent, member) = (field.name().value.clone(), segment.to_owned());
    Resolution::Miss(Miss::NoMember { parent, member, candidates })
}

/// Why a path cannot go through `field`, when it is read under an `if:`.
fn conditional_miss(field: &RawField) -> Option<Miss> {
    let condition = field.condition_span()?.clone();
    Some(Miss::Conditional { field: field.name().value.clone(), condition })
}

/// The notes of a Diagnostic: each message, with the span it points at if any.
type Notes = Vec<(String, Option<Range<usize>>)>;

/// The name of a miss, and the message and notes saying why `key` resolves to nothing usable.
fn explain(miss: &Miss, key: &str, segments: &[String]) -> (Name, String, Notes) {
    let first = &segments[0];
    match miss {
        Miss::Forward(later) => (
            Name::ForwardReference,
            format!("`{first}` is read only after this"),
            vec![
                (format!("`{first}` comes later, here"), Some(later.clone())),
                ("only Fields read earlier can be referenced".to_owned(), None),
            ],
        ),
        Miss::Unknown(candidates) => {
            let names: Vec<&str> = candidates.iter().map(String::as_str).collect();
            let note = closest(first, &names).map(|guess| (format!("did you mean `{guess}`?"), None));
            (Name::UnknownField, format!("no Field named `{first}` is read before this"), note.into_iter().collect())
        }
        Miss::Enclosing => (
            Name::UnknownField,
            format!("`{first}` is still being read here"),
            vec![(format!("name its Fields without `{first}.`"), None)],
        ),
        Miss::NoMember { parent, member, candidates } => {
            let names: Vec<&str> = candidates.iter().map(String::as_str).collect();
            let note = match closest(member, &names) {
                Some(guess) => format!("did you mean `{guess}`?"),
                None => format!("the Fields of `{parent}` are: {}", names.join(", ")),
            };
            (Name::UnknownField, format!("`{parent}` has no Field named `{member}`"), vec![(note, None)])
        }
        Miss::NotStructure(field) => (
            Name::UnknownField,
            format!("`{field}` has no Fields"),
            vec![(format!("`{key}` goes into `{field}`, which is not a structure"), None)],
        ),
        Miss::IntoArray(array) => (
            Name::UnknownField,
            format!("`{array}` is an array, whose Fields are read once per element"),
            vec![(format!("only Fields inside an element of `{array}` can read its Fields"), None)],
        ),
        Miss::Conditional { field, condition } => (
            Name::ConditionalReference,
            format!("`{field}` is read only under its `if`, which does not enclose this"),
            vec![
                (format!("`{field}` is read only when this is not zero"), Some(condition.clone())),
                (
                    format!(
                        "only Fields inside the Field carrying that `if` can read `{key}`: read it from \
                         an inline structure carrying the `if`"
                    ),
                    None,
                ),
            ],
        ),
        Miss::InCase { switch, member, case } => (
            Name::ConditionalReference,
            format!("`{member}` is read only in a case of `{switch}`, which does not enclose this"),
            vec![
                (format!("`{member}` is read only when this case matches"), Some(case.clone())),
                (format!("only Fields inside that case can read `{key}`"), None),
            ],
        ),
        Miss::NonNumeric { what, span } => {
            let last = segments.last().expect("a path has a name");
            (
                Name::NonNumericReference,
                format!("`{last}` is {what}, not an integer or a `bool`"),
                vec![
                    (format!("`{last}` is declared here"), Some(span.clone())),
                    ("only integer and `bool` Fields can be referenced".to_owned(), None),
                ],
            )
        }
    }
}

/// Resolves the Field paths of an Expression written at a Field of `scope`, given by their
/// segments and spans. Returns what each path reads, or pushes why it reads nothing.
pub(crate) fn resolve_paths<'a>(
    paths: &[(&[String], Range<usize>)],
    scope: Scope<'a, '_>,
    types: &Types<'a>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<BTreeMap<Vec<String>, Reference>> {
    let mut references = BTreeMap::new();
    let mut ok = true;
    for (segments, span) in paths {
        let key = segments.join(".");
        let reference = match resolve(segments, scope, types) {
            Resolution::Found(reference) => reference,
            Resolution::Free { .. } => Reference::Context(key),
            Resolution::Suppressed => {
                ok = false;
                continue;
            }
            Resolution::Miss(miss) => {
                let (name, message, notes) = explain(&miss, &key, segments);
                diagnostics.push(with_notes(Diagnostic::new(name, span.clone(), message), notes));
                ok = false;
                continue;
            }
        };
        references.insert(segments.to_vec(), reference);
    }
    ok.then_some(references)
}

/// Resolves, at a use of the Type `ty` written at `site` in `scope`, every name the Type reads
/// but does not declare. Returns the context table the use passes, by key, or pushes why some
/// name resolves to nothing, at the use.
pub(crate) fn resolve_context<'a>(
    ty: &str,
    site: &Range<usize>,
    scope: Scope<'a, '_>,
    types: &mut Types<'a>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Vec<(String, Reference)>> {
    let mut context = Vec::new();
    let mut ok = true;
    for free in free_refs(types, ty) {
        let segments = &free.segments;
        let reference = match resolve(segments, scope, types) {
            Resolution::Found(reference) => reference,
            Resolution::Free { .. } => Reference::Context(free.key.clone()),
            Resolution::Suppressed => {
                ok = false;
                continue;
            }
            Resolution::Miss(miss) => {
                // A name the Type reads later is a forward reference inside the Type.
                let miss = match (miss, &free.later) {
                    (Miss::Unknown(_), Some(later)) => Miss::Forward(later.clone()),
                    (miss, _) => miss,
                };
                let (name, message, notes) = explain(&miss, &free.key, segments);
                let at_site = format!("the Type `{ty}` reads `{}` here, but {message}", free.key);
                let read = format!("`{}` is read here, in the Type `{}`", free.key, free.ty);
                let diagnostic =
                    Diagnostic::new(name, site.clone(), at_site).with_note(read, Some(free.origin.clone()));
                diagnostics.push(with_notes(diagnostic, notes));
                ok = false;
                continue;
            }
        };
        context.push((free.key, reference));
    }
    ok.then_some(context)
}

/// The Diagnostic, at `span`, saying why the path `segments` resolves to nothing usable.
pub(crate) fn miss_diagnostic(miss: &Miss, segments: &[String], span: Range<usize>) -> Diagnostic {
    let (name, message, notes) = explain(miss, &segments.join("."), segments);
    with_notes(Diagnostic::new(name, span, message), notes)
}

fn with_notes(diagnostic: Diagnostic, notes: Notes) -> Diagnostic {
    notes.into_iter().fold(diagnostic, |d, (message, span)| d.with_note(message, span))
}

/// The names the Type `ty` reads but does not declare, each once, in source order. A Type in a
/// cycle (`recursive-type`) stops the walk.
pub(crate) fn free_refs(types: &mut Types<'_>, ty: &str) -> Vec<FreeRef> {
    if let Some(known) = types.free.get(ty) {
        return known.clone().unwrap_or_default();
    }
    let Some(body) = types.body(ty) else { return Vec::new() };
    types.free.insert(ty.to_owned(), None);
    let mut found = Vec::new();
    collect_free(body, ty, &mut Vec::new(), types, &mut found);
    types.free.insert(ty.to_owned(), Some(found.clone()));
    found
}

/// Adds to `found` the names the Type `name`, used at `levels` in the Type `ty`, reads that `ty`
/// does not declare either.
fn collect_type<'a>(name: &str, ty: &str, levels: &[Level<'a>], types: &mut Types<'a>, found: &mut Vec<FreeRef>) {
    for free in free_refs(types, name) {
        let scope = Scope { ty: Some(ty), levels };
        if let Resolution::Free { .. } = resolve(&free.segments, scope, types) {
            add_free(found, free);
        }
    }
}

/// Adds `free` to `found`, unless a name with the same key is there already.
fn add_free(found: &mut Vec<FreeRef>, free: FreeRef) {
    if !found.iter().any(|f| f.key == free.key) {
        found.push(free);
    }
}

fn collect_free<'a>(
    fields: &'a [RawEntry],
    ty: &str,
    levels: &mut Vec<Level<'a>>,
    types: &mut Types<'a>,
    found: &mut Vec<FreeRef>,
) {
    for (at, entry) in fields.iter().enumerate() {
        levels.push(Level { fields, at });
        let scope = Scope { ty: Some(ty), levels };
        for (segments, span) in entry.paths() {
            if let Resolution::Free { later } = resolve(segments, scope, types) {
                let (key, segments) = (segments.join("."), segments.to_vec());
                add_free(found, FreeRef { key, segments, origin: span, ty: ty.to_owned(), later });
            }
        }
        match entry.field().map(|f| f.shape(types)) {
            Some(Shape::Structure(children)) => collect_free(children, ty, levels, types, found),
            Some(Shape::Type { name, .. }) => collect_type(name, ty, levels, types, found),
            Some(Shape::Switch(switch)) => {
                for (_, body) in switch.bodies() {
                    match body {
                        RawBody::Fields(children) => collect_free(children, ty, levels, types, found),
                        RawBody::Type(name) => collect_type(&name.value, ty, levels, types, found),
                    }
                }
            }
            Some(Shape::Value(..) | Shape::Unknown) | None => {}
        }
        levels.pop();
    }
}
