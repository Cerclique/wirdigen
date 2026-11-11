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

use crate::bits::Lookup;
use crate::diagnostic::{Diagnostic, Name};
use crate::field::{self, RawEntry, RawField, Shape, is_field_name};
use crate::keys::{closest, expect_string, is_single_line};
use crate::scope::{self, Miss};
use crate::switch::RawBody;
use crate::types::Types;
use crate::yaml::Node;

/// `info:` as written, after stage 2.
#[derive(Debug, Clone)]
pub(crate) struct RawInfo {
    /// The pieces of the template, or why it does not parse.
    parsed: Result<Vec<Piece>, Diagnostic>,
}

/// A piece of a template as written: text, or a reference with its span in the source.
#[derive(Debug, Clone)]
enum Piece {
    Text(String),
    Reference { segments: Vec<String>, span: Range<usize> },
}

/// A checked template: what the Info column shows, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Template {
    pub(crate) parts: Vec<Part>,
}

/// A part of a checked template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Part {
    /// Text shown as is, escapes undone.
    Text(String),
    /// The Field at this path from the top-level layout, which is its Filter Name without the
    /// protocol's: a built-in Field, a bitfield sub-Field or a `switch` Field.
    Field(Vec<String>),
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
                    Piece::Reference { segments, span } => Piece::Reference { segments, span: node.token_span(span) },
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
    fn new(span: Range<usize>, message: impl Into<String>, note: &'static str) -> Self {
        Self { span, message: message.into(), note }
    }

    /// The Diagnostic, pointing into the source of `node`, the string the template is written in.
    fn at(self, node: &Node) -> Diagnostic {
        Diagnostic::new(Name::InvalidInfo, node.token_span(self.span), self.message).with_note(self.note, None)
    }
}

/// The note of every reference that is not a bare Field Path.
const PATH_ONLY: &str = "a reference is a Field path only, such as `{msg_type}` or `{header.id}`: \
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
                    return Err(SyntaxError::new(span, "this reference names no Field", PATH_ONLY));
                }
                let segments: Vec<String> = inside.split('.').map(str::to_owned).collect();
                if !segments.iter().all(|s| is_field_name(s)) {
                    return Err(SyntaxError::new(span, format!("`{inside}` is not a Field path"), PATH_ONLY));
                }
                if !literal.is_empty() {
                    pieces.push(Piece::Text(std::mem::take(&mut literal)));
                }
                pieces.push(Piece::Reference { segments, span });
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

/// Stage 4: resolves the references of a template from the top-level layout `top`. Returns the
/// checked template, or pushes why some reference shows nothing.
pub(crate) fn check(
    raw: &RawInfo,
    top: &[RawEntry],
    types: &Types<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Template> {
    let pieces = raw.parsed.as_ref().ok()?;
    let mut parts = Vec::new();
    let mut ok = true;
    for piece in pieces {
        match piece {
            Piece::Text(text) => parts.push(Part::Text(text.clone())),
            Piece::Reference { segments, span } => {
                match resolve(segments, top, types) {
                    Ok(()) => parts.push(Part::Field(segments.clone())),
                    Err(Unresolved::Suppressed) => ok = false,
                    Err(Unresolved::Unknown(guess)) => {
                        let message = format!("no top-level Field is named `{}`", segments[0]);
                        let unknown = Diagnostic::new(Name::UnknownField, span.clone(), message);
                        diagnostics.push(match guess {
                            Some(guess) => unknown.with_note(format!("did you mean `{guess}`?"), None),
                            None => {
                                unknown.with_note("a reference starts from a Field of the top-level `fields`", None)
                            }
                        });
                        ok = false;
                    }
                    Err(Unresolved::Miss(miss)) => {
                        diagnostics.push(scope::miss_diagnostic(&miss, segments, span.clone()));
                        ok = false;
                    }
                    Err(Unresolved::NoValue { what, declared }) => {
                        let last = segments.last().expect("a path has a name");
                        diagnostics.push(
                        Diagnostic::new(Name::InvalidInfo, span.clone(), format!("`{last}` is {what}, which has no value to show"))
                            .with_note(format!("`{last}` is declared here"), Some(declared))
                            .with_note(
                                "a reference shows a Field of a built-in type, a bitfield sub-Field or a `switch` Field",
                                None,
                            ),
                    );
                        ok = false;
                    }
                }
            }
        }
    }
    ok.then_some(Template { parts })
}

/// Why a reference shows nothing.
enum Unresolved {
    /// No top-level Field has the path's first name; the closest name, if any is close.
    Unknown(Option<String>),
    /// The path finds no Field it can show.
    Miss(Miss),
    /// The path ends on a Field with no value of its own, declared at `declared`.
    NoValue { what: &'static str, declared: Range<usize> },
    /// The path leads to a Field already in error (an unknown type): nothing more is said.
    Suppressed,
}

/// Follows `segments` from the top-level layout: a Field whose value the column can show.
fn resolve(segments: &[String], top: &[RawEntry], types: &Types<'_>) -> Result<(), Unresolved> {
    let first = &segments[0];
    let Some(mut field) = field::fields(top).find(|f| f.name().value == *first) else {
        let names: Vec<&str> = field::fields(top).map(|f| f.name().value.as_str()).collect();
        return Err(Unresolved::Unknown(closest(first, &names).map(str::to_owned)));
    };
    for (index, segment) in segments.iter().enumerate().skip(1) {
        if field.is_array() {
            return Err(Unresolved::Miss(Miss::IntoArray(field.name().value.clone())));
        }
        let no_member = |candidates| {
            let (parent, member) = (field.name().value.clone(), segment.clone());
            Unresolved::Miss(Miss::NoMember { parent, member, candidates })
        };
        let children: Vec<&RawField> = match field.shape(types) {
            Shape::Structure(children) | Shape::Type { fields: children, .. } => field::fields(children).collect(),
            // A case adds no segment: the path goes on in whichever case reads the Field.
            Shape::Switch(switch) => switch
                .bodies()
                .filter_map(|(_, body)| match body {
                    RawBody::Fields(fields) => Some(fields.as_slice()),
                    RawBody::Type(name) => types.body(&name.value),
                })
                .flat_map(field::fields)
                .collect(),
            Shape::Unknown => return Err(Unresolved::Suppressed),
            Shape::Value(builtin, _) => {
                let Some(bits) = field.bits() else {
                    return Err(Unresolved::Miss(Miss::NotStructure(field.name().value.clone())));
                };
                return match bits.lookup(segment, builtin) {
                    Lookup::Missing => Err(no_member(bits.names())),
                    Lookup::Found { .. } if index + 1 < segments.len() => {
                        Err(Unresolved::Miss(Miss::NotStructure(segment.clone())))
                    }
                    Lookup::Found { .. } => Ok(()),
                    Lookup::Invalid => Err(Unresolved::Suppressed),
                };
            }
        };
        let Some(child) = children.iter().find(|f| f.name().value == *segment) else {
            return Err(no_member(children.iter().map(|f| f.name().value.clone()).collect()));
        };
        field = child;
    }
    let what = match field.shape(types) {
        Shape::Unknown => return Err(Unresolved::Suppressed),
        _ if field.is_array() => "an array",
        Shape::Value(..) | Shape::Switch(_) => return Ok(()),
        Shape::Structure(_) => "a structure",
        Shape::Type { .. } => "a Field of a Type",
    };
    Err(Unresolved::NoValue { what, declared: field.name().span.clone() })
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
                Piece::Reference { segments, span } => format!("ref {} at {span:?}", segments.join(".")),
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
        assert_eq!(error("{}"), (0..2, "this reference names no Field".to_owned()));
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
