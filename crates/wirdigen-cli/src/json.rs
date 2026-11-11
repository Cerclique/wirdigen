//! The JSON Lines records of `--message-format json` (spec §9.7, ADR 0013).
//!
//! The CLI alone owns this shape: the library has no `Serialize` (ADR 0012). Adding a field or a
//! record type is minor; removing or renaming one is major.

use std::ops::Range;

use serde_json::{Map, Value, json};
use wirdigen::{Diagnostic, Severity};

/// What happened to one input, as the `status` of its `file` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    fn as_str(self) -> &'static str {
        match self {
            FileStatus::Written => "written",
            FileStatus::Unchanged => "unchanged",
            FileStatus::Stale => "stale",
            FileStatus::Failed => "failed",
            FileStatus::Valid => "valid",
        }
    }
}

/// A `diagnostic` record for one Diagnostic of the input named `file`, whose text is `text`.
///
/// `rendered` is the uncoloured human rendering; `denied` marks a warning promoted by
/// `--deny-warnings`, which keeps its `warning` severity.
pub fn diagnostic(file: &str, text: &str, diagnostic: &Diagnostic, rendered: &str, denied: bool) -> String {
    let notes: Vec<Value> = diagnostic
        .notes()
        .iter()
        .map(|note| {
            let mut record = Map::new();
            record.insert("message".to_owned(), note.message().into());
            if let Some(span) = note.span() {
                record.insert("span".to_owned(), span_record(text, span));
            }
            Value::Object(record)
        })
        .collect();
    let mut record = json!({
        "type": "diagnostic",
        "file": file,
        "name": diagnostic.name(),
        "severity": severity(diagnostic.severity()),
        "message": diagnostic.message(),
        "span": span_record(text, diagnostic.span()),
        "notes": notes,
        "rendered": rendered,
    });
    if denied {
        record["denied"] = true.into();
    }
    record.to_string()
}

/// A `file` record: what happened to `input`, whose Dissector goes to `output` (none under
/// `validate`).
pub fn file(input: &str, output: Option<&str>, status: FileStatus) -> String {
    json!({ "type": "file", "input": input, "output": output, "status": status.as_str() }).to_string()
}

/// The `summary` record closing a run: the Diagnostics by severity, and the exit code.
pub fn summary(errors: usize, warnings: usize, exit_code: u8) -> String {
    json!({ "type": "summary", "errors": errors, "warnings": warnings, "exit_code": exit_code }).to_string()
}

fn severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
    }
}

/// A span as byte offsets plus its 1-based start and end lines and columns.
fn span_record(text: &str, span: Range<usize>) -> Value {
    let (line, column) = line_column(text, span.start);
    let (end_line, end_column) = line_column(text, span.end);
    json!({
        "start": span.start,
        "end": span.end,
        "line": line,
        "column": column,
        "end_line": end_line,
        "end_column": end_column,
    })
}

/// The 1-based line and column, in characters, of the byte `offset` in `text`.
fn line_column(text: &str, offset: usize) -> (usize, usize) {
    let before = &text[..offset];
    let line = before.matches('\n').count() + 1;
    let column = before.rsplit('\n').next().unwrap_or_default().chars().count() + 1;
    (line, column)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_count_characters_not_bytes() {
        assert_eq!(line_column("é: x\nab", 4), (1, 4));
        assert_eq!(line_column("é: x\nab", 7), (2, 2));
    }

    #[test]
    fn an_offset_after_a_newline_starts_the_next_line() {
        assert_eq!(line_column("a\n", 2), (2, 1));
    }
}
