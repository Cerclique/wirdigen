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
//!
//! Diagnostics render as rustc-style snippets of the source. A description silences warnings
//! by name with a top-level `allow: [...]`; errors cannot be silenced.
//!
//! ```
//! use wirdigen::{validate, RenderOptions, Source};
//!
//! let source = Source::new("demo.wirdigen.yaml", "name: Demo\nfields:\n  - { name: id, type: uint8 }\n");
//! let diagnostics = validate(&source).unwrap_err();
//! let text = diagnostics.render(&source, &RenderOptions::default());
//! assert!(text.starts_with("error[invalid-protocol-name]"));
//! ```

#![deny(missing_docs)]

#[cfg(test)]
mod book;
mod description;
mod diagnostic;
mod emit;
mod expr;
mod field;
mod keys;
mod lower;
#[cfg(test)]
mod lua_check;
mod mapping;
mod prelude;
mod render;
mod scalar;
mod source;
mod types;
mod yaml;

pub use diagnostic::{Diagnostic, Diagnostics, Note, Severity};
pub use render::RenderOptions;
pub use source::Source;

/// A Protocol Description that passed every check.
///
/// It is opaque: accessors are added as real needs appear.
#[derive(Debug, Clone)]
pub struct ValidDescription {
    source_name: String,
    protocol: description::Protocol,
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
        emit::emit(&lower::lower(&self.protocol, &self.source_name))
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
    let syntax = description.expression_errors();
    if !syntax.is_empty() {
        return Err(Diagnostics::new(syntax));
    }
    let (protocol, mut checked) = description::check(&description);
    checked.retain(|d| !description.allows(d));
    let diagnostics = Diagnostics::new(checked);
    match protocol {
        Some(protocol) => {
            Ok(ValidDescription { source_name: source.name().to_owned(), protocol, warnings: diagnostics.into_vec() })
        }
        None => Err(diagnostics),
    }
}
