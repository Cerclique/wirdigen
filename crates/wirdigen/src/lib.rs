//! Generate Wireshark Lua dissectors from YAML protocol descriptions.
//!
//! A **Protocol Description** is a YAML file naming a protocol and laying out the Fields of its
//! payload. Wirdigen checks it and generates a Lua **Dissector** for Wireshark 4.4 and later.
//! The format itself is documented in the [Wirdigen book](https://cerclique.github.io/wirdigen/),
//! which also holds a tutorial and an index of every Diagnostic.
//!
//! This crate is the library behind the `wirdigen` command-line tool (crate `wirdigen-cli`).
//!
//! # Usage
//!
//! Wrap the text in a [`Source`], [`validate`] it, and [`generate`](ValidDescription::generate)
//! the Dissector. When the description is wrong, [`validate`] returns its [`Diagnostics`], which
//! render as rustc-style snippets of the source:
//!
//! ```
//! use wirdigen::{validate, RenderOptions, Source};
//!
//! /// The Dissector of `source`, or `None` after printing why it has none.
//! fn dissector(source: &Source) -> Option<String> {
//!     let options = RenderOptions::default();
//!     match validate(source) {
//!         Ok(valid) => {
//!             for warning in valid.warnings() {
//!                 eprint!("{}", warning.render(source, &options));
//!             }
//!             Some(valid.generate())
//!         }
//!         Err(diagnostics) => {
//!             eprint!("{}", diagnostics.render(source, &options));
//!             None
//!         }
//!     }
//! }
//!
//! let good = Source::new("demo.wirdigen.yaml", "name: demo\nfields:\n  - { name: id, type: uint8 }\n");
//! let lua = dissector(&good).expect("the description is valid");
//! assert!(lua.contains("Proto(\"demo\""));
//!
//! // A protocol name is lowercase: this one is an error, and no Dissector is generated.
//! let bad = Source::new("demo.wirdigen.yaml", "name: Demo\nfields:\n  - { name: id, type: uint8 }\n");
//! assert_eq!(dissector(&bad), None);
//!
//! let diagnostics = validate(&bad).unwrap_err();
//! let text = diagnostics.render(&bad, &RenderOptions::default());
//! assert!(text.starts_with("error[invalid-protocol-name]"));
//! ```
//!
//! Warnings never stop generation, so `validate(&source)?.generate()` is enough when they can be
//! ignored. A description silences warnings by name with a top-level `allow: [...]`; errors
//! cannot be silenced.
//!
//! # No I/O
//!
//! The library never touches files, the network or a terminal (ADR 0012): it takes text and
//! returns text. A [`Source`]'s name is only a label for Diagnostics and the Dissector's header,
//! never opened. Reading descriptions, writing Dissectors and colouring output are left to the
//! caller, as the `wirdigen` command does.
//!
//! # Stability
//!
//! From 1.0.0, semver covers this crate's Rust API, the Protocol Description format (what is
//! valid and what it means, Diagnostic names and severities) and the Dissector's behaviour in
//! Wireshark: its filter names and protocol tree. It does not cover the generated Lua text, the
//! layout and wording of rendered Diagnostics, or the exact text of [`json_schema`]: two
//! releases may generate different Lua for a description as long as the Dissector behaves the
//! same.
//!
//! A minor release can add a warning. A build that treats warnings as errors, such as
//! `wirdigen --deny-warnings`, can then fail after an upgrade with no change to its
//! descriptions.

#![deny(missing_docs)]

mod bits;
#[cfg(test)]
mod book;
mod builtin;
mod description;
mod diagnostic;
mod emit;
mod expect;
mod expr;
mod field;
mod filter;
mod framing;
mod info;
mod keys;
mod lower;
#[cfg(test)]
mod lua_check;
mod mapping;
mod prelude;
#[cfg(test)]
mod random;
mod registration;
mod render;
mod scalar;
mod schema;
mod scope;
mod source;
mod switch;
#[cfg(test)]
mod tshark_random;
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

/// The JSON Schema of a Protocol Description (`*.wirdigen.yaml`), for editor completion and hover.
///
/// Draft-07 JSON, pretty-printed with a trailing newline; the same Wirdigen version always gives
/// the same bytes. It accepts every description [`validate`] accepts, but only Wirdigen itself
/// validates: its exact text is not stable, and it never replaces [`validate`].
#[must_use]
pub fn json_schema() -> String {
    schema::json_schema()
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
