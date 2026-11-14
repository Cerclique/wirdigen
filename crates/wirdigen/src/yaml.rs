//! Stage 1: YAML parse into a span-carrying tree, enforcing the YAML subset (ADR 0005).

use std::ops::Range;

use saphyr_parser::{Event, Parser, ScalarStyle, Span};

use crate::diagnostic::{Diagnostic, Name};

/// The deepest level a YAML node may be at, the root being level 1 (ADR 0020): the reader, and
/// the passes after it, recurse once per level.
pub(crate) const MAX_LEVEL: usize = 256;

/// What `saphyr-parser` reports when flow collections nest past what it counts.
const FLOW_LIMIT: &str = "recursion limit exceeded";

/// The `yaml-too-deep` of a node at `span`, past [`MAX_LEVEL`].
fn too_deep(span: Range<usize>) -> Diagnostic {
    Diagnostic::new(Name::YamlTooDeep, span, format!("the YAML is nested more than {MAX_LEVEL} levels deep"))
        .with_note("no Protocol Description within the Field depth limit nests this deep", None)
}

/// A YAML node with its byte span in the source.
#[derive(Debug)]
pub(crate) struct Node {
    pub(crate) span: Range<usize>,
    pub(crate) value: Value,
}

#[derive(Debug)]
pub(crate) enum Value {
    /// `plain` is false for quoted and block scalars, which are always strings.
    Scalar {
        text: String,
        plain: bool,
        /// Where `text` starts in the source, when the source spells it byte for byte (no
        /// escapes, no folded lines, no block indicator).
        value_start: Option<usize>,
    },
    Sequence(Vec<Node>),
    Mapping(Vec<(Node, Node)>),
}

impl Node {
    /// The source span of `within`, a byte range of this scalar's value: the token itself in a
    /// string spelled verbatim, otherwise the whole value (spec §6.4).
    pub(crate) fn token_span(&self, within: Range<usize>) -> Range<usize> {
        match &self.value {
            Value::Scalar { text, value_start: Some(start), .. } if within.end <= text.len() => {
                start + within.start..start + within.end
            }
            _ => self.span.clone(),
        }
    }
}

/// Parses the text into its single document, or `None` for an empty file.
///
/// Reports every subset violation of the first document; a syntax error stops the parse.
pub(crate) fn parse(text: &str) -> Result<Option<Node>, Vec<Diagnostic>> {
    let mut reader = Reader {
        events: Parser::new_from_str(text),
        text,
        // Byte offset of every character index, plus the total length.
        offsets: text.char_indices().map(|(i, _)| i).chain([text.len()]).collect(),
        diagnostics: Vec::new(),
    };
    let root = match reader.document() {
        Ok(root) => root,
        Err(syntax) => {
            reader.diagnostics.push(syntax);
            None
        }
    };
    if reader.diagnostics.is_empty() { Ok(root) } else { Err(reader.diagnostics) }
}

struct Reader<'a> {
    events: Parser<'a, saphyr_parser::StrInput<'a>>,
    text: &'a str,
    offsets: Vec<usize>,
    diagnostics: Vec<Diagnostic>,
}

type Step<'a> = Result<(Event<'a>, Range<usize>), Diagnostic>;

impl<'a> Reader<'a> {
    fn byte(&self, char_index: usize) -> usize {
        self.offsets[char_index.min(self.offsets.len() - 1)]
    }

    fn end_of_input(&self) -> usize {
        self.offsets[self.offsets.len() - 1]
    }

    fn range(&self, span: Span) -> Range<usize> {
        self.byte(span.start.index())..self.byte(span.end.index())
    }

    fn next(&mut self) -> Step<'a> {
        match self.events.next() {
            Some(Ok((event, span))) => Ok((event, self.range(span))),
            // The scanner counts flow collections in a byte, and refuses the 256th nested one:
            // in a document whose root is a block collection, the node at level 257.
            Some(Err(error)) if error.info() == FLOW_LIMIT => {
                let at = self.byte(error.marker().index());
                Err(too_deep(at..at))
            }
            Some(Err(error)) => {
                let at = self.byte(error.marker().index());
                Err(Diagnostic::new(Name::YamlSyntax, at..at, error.info().to_owned()))
            }
            None => {
                let end = self.end_of_input();
                Err(Diagnostic::new(Name::YamlSyntax, end..end, "unexpected end of the YAML stream"))
            }
        }
    }

    fn document(&mut self) -> Result<Option<Node>, Diagnostic> {
        let (event, _) = self.next()?;
        debug_assert!(matches!(event, Event::StreamStart));
        let (event, _) = self.next()?;
        let root = match event {
            Event::StreamEnd => return Ok(None),
            Event::DocumentStart(_) => {
                let (event, span) = self.next()?;
                let root = self.node(event, span, 1)?;
                let (end, _) = self.next()?;
                debug_assert!(matches!(end, Event::DocumentEnd));
                root
            }
            _ => unreachable!("a stream starts with a document or ends"),
        };
        if let (Event::DocumentStart(_), span) = self.next()? {
            self.diagnostics.push(
                Diagnostic::new(
                    Name::MultipleDocuments,
                    span.clone(),
                    "a Protocol Description is a single YAML document",
                )
                .with_note("remove everything from this document start on", None),
            );
        }
        Ok(Some(root))
    }

    /// Reads the node that `event` starts, at `level`, the root being level 1. A node past
    /// [`MAX_LEVEL`] stops the parse before the reader recurses any deeper.
    fn node(&mut self, event: Event<'a>, span: Range<usize>, level: usize) -> Result<Node, Diagnostic> {
        if level > MAX_LEVEL {
            return Err(too_deep(span));
        }
        match event {
            Event::Scalar(text, style, anchor, tag) => {
                self.check_properties(anchor, tag.is_some(), &span);
                // A block scalar's span runs to the next line, and a quoted one in a flow
                // collection over the blanks after its quote: the value ends with its last
                // non-blank character, the closing quote for a quoted scalar.
                let span = span.start..span.start + self.text[span.clone()].trim_end().len();
                let quoted = matches!(style, ScalarStyle::SingleQuoted | ScalarStyle::DoubleQuoted);
                let spelled = match style {
                    ScalarStyle::Plain => Some(span.clone()),
                    _ if quoted && span.len() >= 2 => Some(span.start + 1..span.end - 1),
                    _ => None,
                };
                let value_start = spelled.filter(|s| self.text[s.clone()] == *text).map(|s| s.start);
                let value = Value::Scalar { text: text.into_owned(), plain: style == ScalarStyle::Plain, value_start };
                Ok(Node { span, value })
            }
            Event::Alias(_) => {
                // Keep parsing with a placeholder so later violations are reported too.
                self.diagnostics.push(Diagnostic::new(
                    Name::YamlAlias,
                    span.clone(),
                    "aliases are not allowed; reuse Fields through Types",
                ));
                Ok(Node { span, value: Value::Scalar { text: String::new(), plain: true, value_start: None } })
            }
            Event::SequenceStart(anchor, tag) => {
                self.check_properties(anchor, tag.is_some(), &span);
                let mut items = Vec::new();
                let mut end = span.end;
                loop {
                    let (event, item_span) = self.next()?;
                    if matches!(event, Event::SequenceEnd) {
                        end = end.max(item_span.end);
                        break;
                    }
                    let item = self.node(event, item_span, level + 1)?;
                    end = end.max(item.span.end);
                    items.push(item);
                }
                Ok(Node { span: span.start..end, value: Value::Sequence(items) })
            }
            Event::MappingStart(anchor, tag) => {
                self.check_properties(anchor, tag.is_some(), &span);
                let mut entries = Vec::new();
                let mut end = span.end;
                loop {
                    let (event, key_span) = self.next()?;
                    if matches!(event, Event::MappingEnd) {
                        end = end.max(key_span.end);
                        break;
                    }
                    let key = self.node(event, key_span, level + 1)?;
                    let is_merge_key = matches!(&key.value, Value::Scalar { text, plain: true, .. } if text == "<<");
                    if is_merge_key {
                        self.diagnostics.push(Diagnostic::new(
                            Name::MergeKey,
                            key.span.clone(),
                            "merge keys (`<<`) are not allowed; reuse Fields through Types",
                        ));
                    }
                    let (event, value_span) = self.next()?;
                    let value = self.node(event, value_span, level + 1)?;
                    end = end.max(value.span.end);
                    entries.push((key, value));
                }
                Ok(Node { span: span.start..end, value: Value::Mapping(entries) })
            }
            _ => unreachable!("the parser only emits node events here"),
        }
    }

    fn check_properties(&mut self, anchor: usize, tagged: bool, span: &Range<usize>) {
        if anchor != 0 {
            self.diagnostics.push(Diagnostic::new(
                Name::YamlAnchor,
                span.clone(),
                "anchors are not allowed; reuse Fields through Types",
            ));
        }
        if tagged {
            self.diagnostics.push(Diagnostic::new(Name::YamlTag, span.clone(), "YAML tags are not allowed"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The source text a token at `within` (byte offsets into the value) is reported at.
    fn token(text: &str, within: Range<usize>) -> &str {
        let root = parse(text).unwrap().unwrap();
        let Value::Mapping(entries) = &root.value else { panic!("not a mapping") };
        &text[entries[0].1.token_span(within)]
    }

    #[test]
    fn tokens_in_verbatim_strings_get_their_own_span() {
        assert_eq!(token("size: a + bc\n", 4..6), "bc");
        assert_eq!(token("size: 'a + bc'\n", 4..6), "bc");
        assert_eq!(token("size: \"a + bc\"\n", 0..1), "a");
        assert_eq!(token("{size: a + bc}\n", 4..6), "bc");
        assert_eq!(token("{size: 'a + bc' }\n", 4..6), "bc");
        assert_eq!(token("{size: \"a + bc\" , x: 1}\n", 0..1), "a");
    }

    #[test]
    fn quoted_strings_in_flow_mappings_end_at_their_quote() {
        assert_eq!(token("{size: \"a\\tb\" }\n", 0..1), "\"a\\tb\"");
        assert_eq!(token("{size: 'a ' , x: 1}\n", 0..9), "'a '");
    }

    #[test]
    fn escaped_or_multi_line_strings_point_at_the_whole_value() {
        assert_eq!(token("size: \"a +\\tbc\"\n", 4..6), "\"a +\\tbc\"");
        assert_eq!(token("size: 'it''s'\n", 0..1), "'it''s'");
        assert_eq!(token("size: a +\n  bc\n", 4..6), "a +\n  bc");
        assert_eq!(token("size: |\n  a + bc\n", 4..6), "a + bc");
        assert_eq!(token("size: >\n  a + bc\n", 4..6), "a + bc");
    }
}
