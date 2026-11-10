use std::fmt;
use std::ops::Range;

/// How serious a [`Diagnostic`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    /// The description has no single meaning or contradicts itself: no Dissector is generated.
    Error,
    /// The meaning is clear but probably a mistake: generation goes ahead.
    Warning,
}

/// An extra message attached to a [`Diagnostic`], optionally pointing elsewhere in the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    message: String,
    span: Option<Range<usize>>,
}

impl Note {
    /// The note's text.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Byte offsets into the source text the note points at, if any.
    #[must_use]
    pub fn span(&self) -> Option<Range<usize>> {
        self.span.clone()
    }
}

/// An error or a warning about a Protocol Description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    name: &'static str,
    severity: Severity,
    span: Range<usize>,
    message: String,
    notes: Vec<Note>,
}

impl Diagnostic {
    pub(crate) fn error(name: &'static str, span: Range<usize>, message: impl Into<String>) -> Self {
        Self { name, severity: Severity::Error, span, message: message.into(), notes: Vec::new() }
    }

    pub(crate) fn with_note(mut self, message: impl Into<String>, span: Option<Range<usize>>) -> Self {
        self.notes.push(Note { message: message.into(), span });
        self
    }

    /// The stable kebab-case name, the same token as in `allow:`.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Whether this is an error or a warning.
    #[must_use]
    pub fn severity(&self) -> Severity {
        self.severity
    }

    /// Byte offsets into the source text. Line and column are derived from it.
    #[must_use]
    pub fn span(&self) -> Range<usize> {
        self.span.clone()
    }

    /// The human-readable message. Its wording is not stable.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Extra messages, each with an optional span.
    #[must_use]
    pub fn notes(&self) -> &[Note] {
        &self.notes
    }
}

/// Every error and warning of one validation run, in source order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostics {
    items: Vec<Diagnostic>,
}

impl Diagnostics {
    pub(crate) fn new(mut items: Vec<Diagnostic>) -> Self {
        items.sort_by_key(|d| d.span.start);
        Self { items }
    }

    pub(crate) fn into_vec(self) -> Vec<Diagnostic> {
        self.items
    }

    /// Whether at least one diagnostic is an error.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.items.iter().any(|d| d.severity == Severity::Error)
    }

    /// Iterates over the diagnostics in source order.
    pub fn iter(&self) -> std::slice::Iter<'_, Diagnostic> {
        self.items.iter()
    }
}

impl<'a> IntoIterator for &'a Diagnostics {
    type Item = &'a Diagnostic;
    type IntoIter = std::slice::Iter<'a, Diagnostic>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl fmt::Display for Diagnostics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let errors = self.items.iter().filter(|d| d.severity == Severity::Error).count();
        let warnings = self.items.len() - errors;
        let plural = |n: usize, word: &str| format!("{n} {word}{}", if n == 1 { "" } else { "s" });
        write!(f, "invalid Protocol Description: {}, {}", plural(errors, "error"), plural(warnings, "warning"))
    }
}

impl std::error::Error for Diagnostics {}
