//! The Info column (spec §3.14): an `info:` template of Field references, parsed when the
//! description is read and with the Expressions (stage 3), its references resolved with the
//! semantic checks (stage 4).
//!
//! A template is text with `{path}` references and the escapes `{{` and `}}`. A reference is a
//! Field Path, nothing more: no Expression, no format specifier. It is resolved from the
//! top-level layout once the whole Message is read, so every Field is earlier; it may reach into
//! a Conditional Scope, whose Fields show nothing when they were not read, but never into an
//! array, whose Fields have one value per Element.

use std::ops::Range;

use crate::diagnostic::{Diagnostic, Name};
use crate::field::{Entry, FieldKind, is_field_name};
use crate::index::{FieldId, SubFieldId};
use crate::keys::{closest, expect_string, is_single_line};
use crate::scope::{self, Miss};
use crate::switch::Body;
use crate::types::NamedType;
use crate::yaml::Node;

/// `info:` as written, after stage 2.
#[derive(Debug, Clone)]
pub(crate) struct RawInfo {
    /// The pieces of the template, or why it does not parse.
    parsed: Result<Vec<Piece>, Diagnostic>,
}

/// A piece of a template as written: text, or a Field Path with its span in the source.
#[derive(Debug, Clone)]
enum Piece {
    /// Text shown as is, escapes undone.
    Text(String),
    /// A Field Path, by its names, written at `span` (its braces included).
    Path { segments: Vec<String>, span: Range<usize> },
}

/// A checked template: what the Info column shows, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Template {
    /// The parts, shown one after another.
    pub(crate) parts: Vec<Part>,
}

/// A part of a checked template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Part {
    /// Text shown as is, escapes undone.
    Text(String),
    /// The Field at `path` from the top-level layout, which is its Filter Name without the
    /// protocol's, and what it shows.
    Field { path: Vec<String>, target: Target },
}

/// Stage 2: reads `info:`, a single-line string, and parses its template.
pub(crate) fn read(node: &Node, errors: &mut Vec<Diagnostic>) -> Option<RawInfo> {
    let text = match expect_string(node, "info", Name::InvalidInfo) {
        Ok(text) => text,
        Err(error) => {
            errors.push(error);
            return None;
        }
    };
    let parsed = if is_single_line(&text.value) {
        parse(&text.value).map_err(|error| error.at(node)).map(|pieces| {
            pieces
                .into_iter()
                .map(|piece| match piece {
                    Piece::Path { segments, span } => Piece::Path { segments, span: node.token_span(span) },
                    text @ Piece::Text(_) => text,
                })
                .collect()
        })
    } else {
        Err(Diagnostic::new(Name::InvalidInfo, node.span.clone(), "`info` must be a single line"))
    };
    Some(RawInfo { parsed })
}

impl RawInfo {
    /// Stage 3: why the template does not parse, if it does not.
    pub(crate) fn syntax_error(&self) -> Option<&Diagnostic> {
        self.parsed.as_ref().err()
    }
}

/// A syntax error, with the span of the offending token in the template's text.
#[derive(Debug)]
struct SyntaxError {
    span: Range<usize>,
    message: String,
    note: &'static str,
}

impl SyntaxError {
    /// An error at `span`, explained by `message` and the hint `note`.
    fn new(span: Range<usize>, message: impl Into<String>, note: &'static str) -> Self {
        Self { span, message: message.into(), note }
    }

    /// The Diagnostic, pointing into the source of `node`, the string the template is written in.
    fn at(self, node: &Node) -> Diagnostic {
        Diagnostic::new(Name::InvalidInfo, node.token_span(self.span), self.message).with_note(self.note, None)
    }
}

/// The note of every pair of braces that does not hold a bare Field Path.
const PATH_ONLY: &str = "write a Field path in braces, such as `{msg_type}` or `{header.id}`: \
                         no Expression, no format specifier";

/// Parses a template, with spans into `text`.
fn parse(text: &str) -> Result<Vec<Piece>, SyntaxError> {
    let mut pieces = Vec::new();
    let mut literal = String::new();
    let mut rest = text.char_indices().peekable();
    while let Some((at, c)) = rest.next() {
        match c {
            '{' if rest.next_if(|&(_, c)| c == '{').is_some() => literal.push('{'),
            '}' if rest.next_if(|&(_, c)| c == '}').is_some() => literal.push('}'),
            '}' => {
                return Err(SyntaxError::new(at..at + 1, "this `}` closes no `{`", "write `}}` for a literal `}`"));
            }
            '{' => {
                let Some(close) = text[at..].find('}').map(|i| at + i) else {
                    return Err(SyntaxError::new(
                        at..at + 1,
                        "this `{` is never closed",
                        "write `{{` for a literal `{`",
                    ));
                };
                let span = at..close + 1;
                let inside = &text[at + 1..close];
                if inside.is_empty() {
                    return Err(SyntaxError::new(span, "these braces name no Field", PATH_ONLY));
                }
                let segments: Vec<String> = inside.split('.').map(str::to_owned).collect();
                if !segments.iter().all(|s| is_field_name(s)) {
                    return Err(SyntaxError::new(span, format!("`{inside}` is not a Field path"), PATH_ONLY));
                }
                if !literal.is_empty() {
                    pieces.push(Piece::Text(std::mem::take(&mut literal)));
                }
                pieces.push(Piece::Path { segments, span });
                while rest.next_if(|&(i, _)| i <= close).is_some() {}
            }
            c => literal.push(c),
        }
    }
    if !literal.is_empty() {
        pieces.push(Piece::Text(literal));
    }
    Ok(pieces)
}

/// Stage 4: resolves the references of a template from the checked top-level layout `top`, whose
/// Types are `types`. Run once the rest of the description has no error, so a Field in error
/// is never reported again here. Returns the checked template, or pushes why some reference
/// shows nothing.
pub(crate) fn check(
    raw: &RawInfo,
    top: &[Entry],
    types: &[NamedType],
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Template> {
    let pieces = raw.parsed.as_ref().ok()?;
    let mut parts = Vec::new();
    let mut ok = true;
    for piece in pieces {
        match piece {
            Piece::Text(text) => parts.push(Part::Text(text.clone())),
            Piece::Path { segments, span } => match find(top, types, segments) {
                Ok(target) => parts.push(Part::Field { path: segments.clone(), target }),
                Err(unresolved) => {
                    diagnostics.push(unresolved.diagnostic(segments, span.clone()));
                    ok = false;
                }
            },
        }
    }
    ok.then_some(Template { parts })
}

/// A Field the Info column can show, as [`find`] finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    /// A Field of a built-in type.
    Value(FieldId),
    /// A bitfield sub-Field.
    SubField(SubFieldId),
    /// A `switch` Field: the Type it is in, `None` in the top-level layout, and its path from
    /// the Type's body or the top-level layout, where its dissect function reads it.
    Switch { ty: Option<String>, path: Vec<String> },
}

/// Why a template's Field Path shows nothing.
#[derive(Debug)]
pub(crate) enum Unresolved {
    /// No top-level Field has the path's first name; the closest name, if any is close.
    Unknown(Option<String>),
    /// The path finds no Field on the way.
    Miss(Miss),
    /// The path ends on a Field with no value of its own (`what`), declared at `declared`.
    NoValue { what: &'static str, declared: Range<usize> },
}

impl Unresolved {
    /// The Diagnostic of the path `segments`, written at `span`.
    fn diagnostic(self, segments: &[String], span: Range<usize>) -> Diagnostic {
        match self {
            Self::Unknown(guess) => {
                let message = format!("no top-level Field is named `{}`", segments[0]);
                let unknown = Diagnostic::new(Name::UnknownField, span, message);
                match guess {
                    Some(guess) => unknown.with_note(format!("did you mean `{guess}`?"), None),
                    None => unknown.with_note("a Field path starts from a Field of the top-level `fields`", None),
                }
            }
            Self::Miss(miss) => scope::miss_diagnostic(&miss, segments, span),
            Self::NoValue { what, declared } => {
                let last = segments.last().expect("a path has a name");
                let message = format!("`{last}` is {what}, which has no value to show");
                Diagnostic::new(Name::InvalidInfo, span, message)
                    .with_note(format!("`{last}` is declared here"), Some(declared))
                    .with_note(
                        "the Info column shows a Field of a built-in type, a bitfield sub-Field or a `switch` Field",
                        None,
                    )
            }
        }
    }
}

/// Follows the Field Path `path` from the top-level layout `top`, into inline structures, Types
/// (`types`), `switch` cases and bitfields. Cases add no segment, so the path goes on in the
/// case that has the next Field; cases reaching one path share its `ProtoField` (spec §3.9).
/// Only validation resolves a template's paths; lowering takes the [`Target`] it recorded.
fn find<'p>(top: &'p [Entry], types: &'p [NamedType], path: &[String]) -> Result<Target, Unresolved> {
    let names = |entries: &'p [Entry]| entries.iter().filter_map(Entry::field);
    let Some(mut field) = names(top).find(|f| f.name == path[0]) else {
        let candidates: Vec<&str> = names(top).map(|f| f.name.as_str()).collect();
        return Err(Unresolved::Unknown(closest(&path[0], &candidates).map(str::to_owned)));
    };
    let body = |name: &str| &types.iter().find(|t| t.name == name).expect("validation resolved the Type").fields;
    // The Type the Field is in, and the Field's path from the Type's body or the top level.
    let (mut ty, mut at): (Option<&'p str>, Vec<String>) = (None, vec![field.name.clone()]);
    for (index, segment) in path.iter().enumerate().skip(1) {
        if field.array.is_some() {
            return Err(Unresolved::Miss(Miss::IntoArray(field.name.clone())));
        }
        let no_member = |candidates| {
            let (parent, member) = (field.name.clone(), segment.clone());
            Unresolved::Miss(Miss::NoMember { parent, member, candidates })
        };
        // Each place the next Field can be, with the Type it is in and the path there of what
        // holds it.
        let places: Vec<(&'p [Entry], Option<&'p str>, Vec<String>)> = match &field.kind {
            FieldKind::Structure(children) => vec![(children.as_slice(), ty, at.clone())],
            FieldKind::Type { name, .. } => vec![(body(name).as_slice(), Some(name.as_str()), Vec::new())],
            FieldKind::Switch(switch) => switch
                .bodies()
                .map(|case| match case {
                    Body::Fields(children) => (children.as_slice(), ty, at.clone()),
                    Body::Type { name, .. } => (body(name).as_slice(), Some(name.as_str()), Vec::new()),
                })
                .collect(),
            FieldKind::Builtin(value) => {
                let Some(bit) = value.bits.iter().find(|b| b.name == *segment) else {
                    if value.bits.is_empty() {
                        return Err(Unresolved::Miss(Miss::NotStructure(field.name.clone())));
                    }
                    return Err(no_member(value.bits.iter().map(|b| b.name.clone()).collect()));
                };
                if index + 1 < path.len() {
                    return Err(Unresolved::Miss(Miss::NotStructure(segment.clone())));
                }
                return Ok(Target::SubField(bit.id));
            }
        };
        let found =
            places.iter().find_map(|(entries, ty, at)| Some((names(entries).find(|f| f.name == *segment)?, ty, at)));
        let Some((child, child_ty, holder)) = found else {
            let candidates = places.iter().flat_map(|(entries, ..)| names(entries)).map(|f| f.name.clone()).collect();
            return Err(no_member(candidates));
        };
        (field, ty, at) = (child, *child_ty, [holder.as_slice(), std::slice::from_ref(segment)].concat());
    }
    let what = match &field.kind {
        _ if field.array.is_some() => "an array",
        FieldKind::Builtin(_) => return Ok(Target::Value(field.id)),
        FieldKind::Switch(_) => return Ok(Target::Switch { ty: ty.map(str::to_owned), path: at }),
        FieldKind::Structure(_) => "a structure",
        FieldKind::Type { .. } => "a Field of a Type",
    };
    Err(Unresolved::NoValue { what, declared: field.span.clone() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pieces(text: &str) -> Vec<String> {
        parse(text)
            .unwrap()
            .into_iter()
            .map(|piece| match piece {
                Piece::Text(text) => format!("text {text:?}"),
                Piece::Path { segments, span } => format!("ref {} at {span:?}", segments.join(".")),
            })
            .collect()
    }

    fn error(text: &str) -> (Range<usize>, String) {
        let error = parse(text).unwrap_err();
        (error.span, error.message)
    }

    #[test]
    fn references_split_the_text() {
        assert_eq!(
            pieces("{msg_type} id={hdr.id}"),
            ["ref msg_type at 0..10", "text \" id=\"", "ref hdr.id at 14..22"]
        );
        assert_eq!(pieces(""), Vec::<String>::new());
    }

    #[test]
    fn doubled_braces_are_literal() {
        assert_eq!(pieces("{{{a}}}"), ["text \"{\"", "ref a at 2..5", "text \"}\""]);
        assert_eq!(pieces("{{a}}"), ["text \"{a}\""]);
    }

    #[test]
    fn a_reference_is_a_bare_field_path() {
        assert_eq!(error("x {a:08}"), (2..8, "`a:08` is not a Field path".to_owned()));
        assert_eq!(error("{a + 1}"), (0..7, "`a + 1` is not a Field path".to_owned()));
        assert_eq!(error("{ a }"), (0..5, "` a ` is not a Field path".to_owned()));
        assert_eq!(error("{_offset}"), (0..9, "`_offset` is not a Field path".to_owned()));
        assert_eq!(error("{a..b}"), (0..6, "`a..b` is not a Field path".to_owned()));
        assert_eq!(error("{}"), (0..2, "these braces name no Field".to_owned()));
    }

    #[test]
    fn braces_must_pair() {
        assert_eq!(error("a { b"), (2..3, "this `{` is never closed".to_owned()));
        assert_eq!(error("a } b"), (2..3, "this `}` closes no `{`".to_owned()));
        assert_eq!(error("{a}}"), (3..4, "this `}` closes no `{`".to_owned()));
    }

    #[test]
    fn spans_count_bytes() {
        assert_eq!(pieces("é{a}"), ["text \"é\"", "ref a at 2..5"]);
    }
}
