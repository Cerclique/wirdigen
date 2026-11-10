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

    pub(crate) fn text(&self) -> &str {
        &self.text
    }
}
