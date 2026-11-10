//! Stage 1: YAML parse into a span-carrying tree, enforcing the YAML subset (ADR 0005).

use std::ops::Range;

use saphyr_parser::{Event, Parser, ScalarStyle, Span};

use crate::diagnostic::Diagnostic;

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
    },
    Sequence(Vec<Node>),
    Mapping(Vec<(Node, Node)>),
}

/// Parses the text into its single document, or `None` for an empty file.
///
/// Reports every subset violation of the first document; a syntax error stops the parse.
pub(crate) fn parse(text: &str) -> Result<Option<Node>, Vec<Diagnostic>> {
    let mut reader = Reader {
        events: Parser::new_from_str(text),
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
            Some(Err(error)) => {
                let at = self.byte(error.marker().index());
                Err(Diagnostic::error("yaml-syntax", at..at, error.info().to_owned()))
            }
            None => {
                let end = self.end_of_input();
                Err(Diagnostic::error("yaml-syntax", end..end, "unexpected end of the YAML stream"))
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
                let root = self.node(event, span)?;
                let (end, _) = self.next()?;
                debug_assert!(matches!(end, Event::DocumentEnd));
                root
            }
            _ => unreachable!("a stream starts with a document or ends"),
        };
        if let (Event::DocumentStart(_), span) = self.next()? {
            self.diagnostics.push(
                Diagnostic::error(
                    "multiple-documents",
                    span.clone(),
                    "a Protocol Description is a single YAML document",
                )
                .with_note("remove everything from this document start on", None),
            );
        }
        Ok(Some(root))
    }

    fn node(&mut self, event: Event<'a>, span: Range<usize>) -> Result<Node, Diagnostic> {
        match event {
            Event::Scalar(text, style, anchor, tag) => {
                self.check_properties(anchor, tag.is_some(), &span);
                Ok(Node { span, value: Value::Scalar { text: text.into_owned(), plain: style == ScalarStyle::Plain } })
            }
            Event::Alias(_) => {
                // Keep parsing with a placeholder so later violations are reported too.
                self.diagnostics.push(Diagnostic::error(
                    "yaml-alias",
                    span.clone(),
                    "aliases are not allowed; reuse Fields through Types",
                ));
                Ok(Node { span, value: Value::Scalar { text: String::new(), plain: true } })
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
                    let item = self.node(event, item_span)?;
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
                    let key = self.node(event, key_span)?;
                    let is_merge_key = matches!(&key.value, Value::Scalar { text, plain: true } if text == "<<");
                    if is_merge_key {
                        self.diagnostics.push(Diagnostic::error(
                            "merge-key",
                            key.span.clone(),
                            "merge keys (`<<`) are not allowed; reuse Fields through Types",
                        ));
                    }
                    let (event, value_span) = self.next()?;
                    let value = self.node(event, value_span)?;
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
            self.diagnostics.push(Diagnostic::error(
                "yaml-anchor",
                span.clone(),
                "anchors are not allowed; reuse Fields through Types",
            ));
        }
        if tagged {
            self.diagnostics.push(Diagnostic::error("yaml-tag", span.clone(), "YAML tags are not allowed"));
        }
    }
}
