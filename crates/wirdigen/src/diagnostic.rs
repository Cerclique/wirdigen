use std::fmt;
use std::ops::Range;

use crate::render::{self, RenderOptions};
use crate::source::Source;

/// How serious a [`Diagnostic`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    /// The description has no single meaning or contradicts itself: no Dissector is generated.
    Error,
    /// The meaning is clear but probably a mistake: generation goes ahead.
    Warning,
}

/// Declares every Diagnostic name once, with its stable kebab-case token and its severity.
macro_rules! names {
    ($($variant:ident => $token:literal, $severity:ident;)*) => {
        /// A Diagnostic name. Its token and severity are stable under semver (spec §6.5).
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[expect(clippy::enum_variant_names, reason = "variants spell their tokens, as in `invalid-protocol-name`")]
        pub(crate) enum Name {
            $($variant,)*
        }

        impl Name {
            /// Every name, so tests can keep the corpus and the book in sync (spec §10.3, §11).
            pub(crate) const ALL: &[Name] = &[$(Name::$variant,)*];

            /// The kebab-case token, as written in `allow:`.
            pub(crate) const fn as_str(self) -> &'static str {
                match self {
                    $(Name::$variant => $token,)*
                }
            }

            pub(crate) const fn severity(self) -> Severity {
                match self {
                    $(Name::$variant => Severity::$severity,)*
                }
            }
        }
    };
}

names! {
    YamlSyntax => "yaml-syntax", Error;
    MultipleDocuments => "multiple-documents", Error;
    YamlAlias => "yaml-alias", Error;
    YamlAnchor => "yaml-anchor", Error;
    YamlTag => "yaml-tag", Error;
    MergeKey => "merge-key", Error;
    MissingKey => "missing-key", Error;
    WrongValueType => "wrong-value-type", Error;
    UnknownKey => "unknown-key", Error;
    DuplicateKey => "duplicate-key", Error;
    EmptyFields => "empty-fields", Error;
    InvalidProtocolName => "invalid-protocol-name", Error;
    InvalidProtocolTitle => "invalid-protocol-title", Error;
    InvalidEndian => "invalid-endian", Error;
    MissingFieldKind => "missing-field-kind", Error;
    ConflictingFieldKind => "conflicting-field-kind", Error;
    InvalidFieldName => "invalid-field-name", Error;
    InvalidTypeName => "invalid-type-name", Error;
    DuplicateFieldName => "duplicate-field-name", Error;
    UnknownType => "unknown-type", Error;
    RecursiveType => "recursive-type", Error;
    UnexpectedLength => "unexpected-length", Error;
    MissingLength => "missing-length", Error;
    ConflictingLength => "conflicting-length", Error;
    InvalidSize => "invalid-size", Error;
    InvalidPrefix => "invalid-prefix", Error;
    InvalidTerminator => "invalid-terminator", Error;
    IncompatibleDisplay => "incompatible-display", Error;
    InvalidLabel => "invalid-label", Error;
    InvalidDescription => "invalid-description", Error;
    InvalidUnit => "invalid-unit", Error;
    OverlappingValues => "overlapping-values", Error;
    OverlappingCases => "overlapping-cases", Error;
    ConflictingFilterName => "conflicting-filter-name", Error;
    ConflictingMappings => "conflicting-mappings", Error;
    UnknownEnum => "unknown-enum", Error;
    InvalidBits => "invalid-bits", Error;
    InvalidBitWidth => "invalid-bit-width", Error;
    MismatchedBitWidths => "mismatched-bit-widths", Error;
    ConflictingRepeat => "conflicting-repeat", Error;
    InvalidRepeat => "invalid-repeat", Error;
    InvalidCount => "invalid-count", Error;
    InvalidArray => "invalid-array", Error;
    InvalidPadding => "invalid-padding", Error;
    InvalidDissector => "invalid-dissector", Error;
    ExpressionSyntax => "expression-syntax", Error;
    LeadingZeroLiteral => "leading-zero-literal", Error;
    ChainedComparison => "chained-comparison", Error;
    UnknownField => "unknown-field", Error;
    ForwardReference => "forward-reference", Error;
    NonNumericReference => "non-numeric-reference", Error;
    ConditionalReference => "conditional-reference", Error;
    NotSupportedYet => "not-supported-yet", Error;
    UnreachableValue => "unreachable-value", Warning;
    UnreachableField => "unreachable-field", Warning;
    UnreachableExpect => "unreachable-expect", Warning;
    UnusedEnum => "unused-enum", Warning;
    UnusedType => "unused-type", Warning;
    UnknownAllow => "unknown-allow", Warning;
}

impl Name {
    /// Looks a token up, as written in `allow:`.
    pub(crate) fn from_token(token: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|n| n.as_str() == token)
    }
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
    name: Name,
    span: Range<usize>,
    message: String,
    notes: Vec<Note>,
}

/// The value of `result`, or `None` after pushing its Diagnostic to `diagnostics`, so a check
/// can go on and report every mistake.
pub(crate) fn record<T>(result: Result<T, Diagnostic>, diagnostics: &mut Vec<Diagnostic>) -> Option<T> {
    result.map_err(|d| diagnostics.push(d)).ok()
}

impl Diagnostic {
    /// A Diagnostic whose severity is the one its name carries.
    pub(crate) fn new(name: Name, span: Range<usize>, message: impl Into<String>) -> Self {
        Self { name, span, message: message.into(), notes: Vec::new() }
    }

    pub(crate) fn with_note(mut self, message: impl Into<String>, span: Option<Range<usize>>) -> Self {
        self.notes.push(Note { message: message.into(), span });
        self
    }

    /// The stable kebab-case name, the same token as in `allow:`.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name.as_str()
    }

    /// Whether this is an error or a warning.
    #[must_use]
    pub fn severity(&self) -> Severity {
        self.name.severity()
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

    /// Renders the Diagnostic as a rustc-style snippet of `source`, the text it was found in.
    ///
    /// The text ends with a note linking to the Diagnostic's entry in the book and with a
    /// newline. Its layout is not stable.
    #[must_use]
    pub fn render(&self, source: &Source, options: &RenderOptions) -> String {
        render::render(self, source, options)
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
        self.items.iter().any(|d| d.severity() == Severity::Error)
    }

    /// Iterates over the diagnostics in source order.
    pub fn iter(&self) -> std::slice::Iter<'_, Diagnostic> {
        self.items.iter()
    }

    /// Renders every Diagnostic with [`Diagnostic::render`], in source order, separated by blank
    /// lines. There is no summary line: counting across inputs is the caller's job.
    #[must_use]
    pub fn render(&self, source: &Source, options: &RenderOptions) -> String {
        self.items.iter().map(|d| d.render(source, options)).collect::<Vec<_>>().join("\n")
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
        let errors = self.items.iter().filter(|d| d.severity() == Severity::Error).count();
        let warnings = self.items.len() - errors;
        let plural = |n: usize, word: &str| format!("{n} {word}{}", if n == 1 { "" } else { "s" });
        write!(f, "invalid Protocol Description: {}, {}", plural(errors, "error"), plural(warnings, "warning"))
    }
}

impl std::error::Error for Diagnostics {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::Path;

    use super::*;

    /// Spec §10.3: every Diagnostic name has a corpus directory and vice versa, and every
    /// warning has an `allowed` case that produces nothing.
    #[test]
    fn every_name_has_a_corpus_directory_and_vice_versa() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/diagnostics");
        let directories: BTreeSet<String> =
            fs::read_dir(&root).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        let names: BTreeSet<String> = Name::ALL.iter().map(|n| n.as_str().to_owned()).collect();
        assert_eq!(directories, names, "tests/diagnostics/ and the Diagnostic names differ");

        for name in Name::ALL.iter().filter(|n| n.severity() == Severity::Warning) {
            let expected = root.join(name.as_str()).join("allowed.expected");
            let text = fs::read_to_string(&expected)
                .unwrap_or_else(|_| panic!("warning `{}` has no `allowed` case", name.as_str()));
            assert!(text.is_empty(), "{} must be empty", expected.display());
        }
    }

    #[test]
    fn names_are_unique_kebab_case() {
        let mut seen = BTreeSet::new();
        for name in Name::ALL {
            let s = name.as_str();
            assert!(seen.insert(s), "`{s}` is listed twice");
            assert!(
                s.split('-').all(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())),
                "`{s}` is not kebab-case"
            );
        }
    }
}
