//! The JSON Lines records of `--message-format json` (spec §9.7, ADR 0013).
//!
//! The CLI alone owns this shape: the library has no `Serialize` (ADR 0012). Adding a field or a
//! record type is minor; removing or renaming one is major.

use std::ops::Range;

use serde::Serialize;
use wirdigen::{Diagnostic, Source};

/// What happened to one input, as the `status` of its `file` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FileStatus {
    /// `generate`: new bytes went to the output.
    Written,
    /// `generate`: the output already held these bytes; `--check`: the output is up to date.
    Unchanged,
    /// `--check`: the output differs or is missing.
    Stale,
    /// The input could not be read, is invalid, or its output could not be written or read.
    Failed,
    /// `validate`: the input is valid.
    Valid,
}

impl FileStatus {
    /// Whether this status makes the run exit with code 1.
    pub fn is_failure(self) -> bool {
        matches!(self, FileStatus::Stale | FileStatus::Failed)
    }
}

/// One line of output. Struct fields serialize in declaration order, so `type` comes first.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Record<'a> {
    Diagnostic {
        file: &'a str,
        name: &'a str,
        severity: &'a str,
        message: &'a str,
        span: Span,
        notes: Vec<NoteRecord<'a>>,
        rendered: &'a str,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        denied: bool,
    },
    File {
        input: &'a str,
        output: Option<&'a str>,
        status: FileStatus,
    },
    Summary {
        errors: usize,
        warnings: usize,
        exit_code: u8,
    },
}

#[derive(Serialize)]
struct NoteRecord<'a> {
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    span: Option<Span>,
}

/// A span as byte offsets plus its 1-based start and end lines and columns.
#[derive(Serialize)]
struct Span {
    start: usize,
    end: usize,
    line: usize,
    column: usize,
    end_line: usize,
    end_column: usize,
}

impl Span {
    fn new(source: &Source, span: Range<usize>) -> Self {
        let (line, column) = source.line_column(span.start);
        let (end_line, end_column) = source.line_column(span.end);
        Span { start: span.start, end: span.end, line, column, end_line, end_column }
    }
}

impl Record<'_> {
    fn to_line(&self) -> String {
        serde_json::to_string(self).expect("records hold only strings, numbers and booleans")
    }
}

/// A `diagnostic` record for one Diagnostic of the input `source`.
///
/// `rendered` is the uncoloured human rendering; `denied` marks a warning promoted by
/// `--deny-warnings`, which keeps its `warning` severity.
pub fn diagnostic(source: &Source, diagnostic: &Diagnostic, rendered: &str, denied: bool) -> String {
    let notes = diagnostic
        .notes()
        .iter()
        .map(|note| NoteRecord { message: note.message(), span: note.span().map(|span| Span::new(source, span)) })
        .collect();
    Record::Diagnostic {
        file: source.name(),
        name: diagnostic.name(),
        severity: diagnostic.severity().as_str(),
        message: diagnostic.message(),
        span: Span::new(source, diagnostic.span()),
        notes,
        rendered,
        denied,
    }
    .to_line()
}

/// A `file` record: what happened to `input`, whose Dissector goes to `output` (none under
/// `validate`).
pub fn file(input: &str, output: Option<&str>, status: FileStatus) -> String {
    Record::File { input, output, status }.to_line()
}

/// The `summary` record closing a run: the Diagnostics by severity, and the exit code.
pub fn summary(errors: usize, warnings: usize, exit_code: u8) -> String {
    Record::Summary { errors, warnings, exit_code }.to_line()
}
