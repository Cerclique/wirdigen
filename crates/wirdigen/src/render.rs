//! Rustc-style rendering of Diagnostics, built on `annotate-snippets` (spec §6.4, §8).
//!
//! The layout is not stable (spec §6.5).

use annotate_snippets::{AnnotationKind, Level, Renderer, Snippet};

use crate::{Diagnostic, Severity, Source};

/// The book's Diagnostics index: one anchor per Diagnostic name (spec §11).
const DIAGNOSTICS_INDEX: &str = "https://cerclique.github.io/wirdigen/diagnostics.html";

/// How [`Diagnostic::render`] and [`Diagnostics::render`](crate::Diagnostics::render) lay out text.
///
/// Build it from [`Default`] and set the fields you need, so new options stay non-breaking:
///
/// ```
/// let mut options = wirdigen::RenderOptions::default();
/// options.color = true;
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RenderOptions {
    /// Whether to colour the output with ANSI escape codes. Off by default.
    pub color: bool,
    /// Whether to render warnings as errors, each with a note saying it is denied, as the CLI's
    /// `--deny-warnings` does. Off by default.
    pub deny_warnings: bool,
}

/// Renders one Diagnostic as a snippet of `source`, ending with a newline.
pub(crate) fn render(diagnostic: &Diagnostic, source: &Source, options: &RenderOptions) -> String {
    let denied = options.deny_warnings && diagnostic.severity() == Severity::Warning;
    let level = match diagnostic.severity() {
        Severity::Error => Level::ERROR,
        Severity::Warning if denied => Level::ERROR,
        Severity::Warning => Level::WARNING,
    };
    let mut snippet =
        Snippet::source(source.text()).path(source.name()).annotation(AnnotationKind::Primary.span(diagnostic.span()));
    let mut footers = Vec::new();
    for note in diagnostic.notes() {
        match note.span() {
            Some(span) => snippet = snippet.annotation(AnnotationKind::Context.span(span).label(note.message())),
            None => footers.push(Level::NOTE.message(note.message())),
        }
    }
    if denied {
        footers.push(Level::NOTE.message("warnings are denied for this run"));
    }
    let link = format!("see {DIAGNOSTICS_INDEX}#{}", diagnostic.name());
    footers.push(Level::NOTE.message(link));

    let report = [level.primary_title(diagnostic.message()).id(diagnostic.name()).element(snippet).elements(footers)];
    let renderer = if options.color { Renderer::styled() } else { Renderer::plain() };
    let mut text = renderer.render(&report);
    text.push('\n');
    text
}
