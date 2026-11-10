//! Generate Wireshark Lua dissectors from YAML protocol descriptions.
//!
//! The library is opaque and I/O-free (ADR 0012): it takes text in a [`Source`]
//! and returns either a [`ValidDescription`] or the [`Diagnostics`] explaining
//! why the description is wrong.
//!
//! ```
//! use wirdigen::{validate, Source};
//!
//! let source = Source::new(
//!     "demo.wirdigen.yaml",
//!     "name: demo\nfields:\n  - { name: id, type: uint8 }\n",
//! );
//! let lua = validate(&source)?.generate();
//! # let _ = lua;
//! # Ok::<(), wirdigen::Diagnostics>(())
//! ```

#![deny(missing_docs)]

mod description;
mod diagnostic;
mod emit;
mod lower;
mod prelude;
mod scalar;
mod source;
mod yaml;

pub use diagnostic::{Diagnostic, Diagnostics, Note, Severity};
pub use source::Source;

/// A Protocol Description that passed every check.
///
/// It is opaque: accessors are added as real needs appear.
#[derive(Debug, Clone)]
pub struct ValidDescription {
    source_name: String,
    description: description::Description,
    warnings: Vec<Diagnostic>,
}

impl ValidDescription {
    /// The warnings of the run, in source order, without those silenced by `allow:`.
    #[must_use]
    pub fn warnings(&self) -> &[Diagnostic] {
        &self.warnings
    }

    /// Generates the Wireshark Lua dissector. Infallible.
    ///
    /// The same description and Wirdigen version always give the same bytes.
    #[must_use]
    pub fn generate(&self) -> String {
        emit::emit(&lower::lower(&self.description, &self.source_name))
    }
}

/// Checks a Protocol Description.
///
/// Stages run in order (YAML parse, strict deserialization, semantic checks);
/// each reports all its errors and the next runs only if it found none.
///
/// # Errors
///
/// Returns every [`Diagnostic`] of the run when at least one is an error.
pub fn validate(source: &Source) -> Result<ValidDescription, Diagnostics> {
    let root = yaml::parse(source.text()).map_err(Diagnostics::new)?;
    let description = description::deserialize(root.as_ref()).map_err(Diagnostics::new)?;
    let diagnostics = Diagnostics::new(description::check(&description));
    if diagnostics.has_errors() {
        return Err(diagnostics);
    }
    Ok(ValidDescription { source_name: source.name().to_owned(), description, warnings: diagnostics.into_vec() })
}
