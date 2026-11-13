/// A Protocol Description's text with a label for diagnostics.
///
/// The name is only a label: it is never resolved against a filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    name: String,
    text: String,
}

impl Source {
    /// Creates a source from a label and its text.
    #[must_use]
    pub fn new(name: impl Into<String>, text: impl Into<String>) -> Self {
        Self { name: name.into(), text: text.into() }
    }

    /// The label given at construction.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The 1-based line and column of the byte `offset` in the text, with columns counted in
    /// characters. Every span a [`Diagnostic`](crate::Diagnostic) or [`Note`](crate::Note) holds
    /// is a valid offset.
    ///
    /// ```
    /// use wirdigen::Source;
    ///
    /// let source = Source::new("x", "é: x\nab");
    /// assert_eq!(source.line_column(4), (1, 4));
    /// assert_eq!(source.line_column(7), (2, 2));
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `offset` is past the end of the text or not on a character boundary.
    #[must_use]
    pub fn line_column(&self, offset: usize) -> (usize, usize) {
        let before = &self.text[..offset];
        let line = before.matches('\n').count() + 1;
        let column = before.rsplit('\n').next().unwrap_or_default().chars().count() + 1;
        (line, column)
    }

    pub(crate) fn text(&self) -> &str {
        &self.text
    }
}
