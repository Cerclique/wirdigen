# The library API is opaque, I/O-free and string-based

v1 is a two-crate workspace: `wirdigen` and `wirdigen-cli` (ADR 0002). Parsing, validation, lowering, the emitter, the prelude, the schema and the renderer are private modules of `wirdigen`, not separate crates. A later WASM surface is a third crate that depends on `wirdigen`.

The library never touches the filesystem or a terminal. It takes text and returns text:

```rust
pub fn validate(source: &Source) -> Result<ValidDescription, Diagnostics>;
impl ValidDescription { pub fn warnings(&self) -> &[Diagnostic]; pub fn generate(&self) -> String; }
pub fn json_schema() -> String;
impl Diagnostic { pub fn render(&self, source: &Source, options: &RenderOptions) -> String; } // and on Diagnostics
```

- **Source**: `Source::new(name, text)`. The name is a label, never resolved: Diagnostics show it whole, and the Lua header (ADR 0010) shows only its last `/`- or `\`-separated component, so output does not depend on where the CLI was run from.
- **The model stays private**: no public Protocol Description tree, parsed or validated. `ValidDescription` is opaque; accessors are added in minor releases as real needs appear.
- **Diagnostics**: `validate` fails with a `Diagnostics` newtype holding every error and warning of the run in source order (warnings silenced by `allow:` already removed). It implements `std::error::Error` with a one-line summary, so `wirdigen::validate(&src)?.generate()` works.
- **Diagnostic**: private fields behind accessors: `name() -> &'static str` (the stable name of ADR 0008, the same token as in `allow:`), `severity()` (`Severity { Error, Warning }`, exhaustive), `span() -> Range<usize>` (byte offsets into the source text), `message()`, `notes()` (each a message with an optional span). Line and column are derived, never stored.
- **Rendering** lives in the library, built on `annotate-snippets`, and returns a `String`; `RenderOptions` is `#[non_exhaustive]` with `Default` and starts with `color` only. The rendered layout is not stable (ADR 0008).
- **No serialization**: the library does not implement `serde::Serialize` for Diagnostics, and no `serde_json` or `schemars` type appears in the public API. A consumer that needs JSON (the CLI, the WASM crate) defines and owns its shape.
- **Ownership**: every public type is owned, without lifetime parameters, and `Send + Sync + 'static`, checked by a compile-time test. All public structs have private fields; only `RenderOptions` is `#[non_exhaustive]`.

## Consequences

- Under ADR 0001 the Rust API is small: four functions or methods, a handful of opaque types and one enum. Adding a format key, a Diagnostic or a prelude chunk never touches it.
- The same code runs unchanged under WASM; the CLI owns reading files, writing the `.lua`, deciding colour from the TTY, and any JSON output.
- `generate` returning a `String` keeps generation infallible (ADR 0010) and gives the CLI's up-to-date check the whole text to compare; a `generate_into(&mut impl fmt::Write)` can be added later if streaming ever matters.
- Tools cannot inspect a description's Fields or Types through the library in v1.

## Considered Options

- **Internal workspace crates** (as on `arise`): rejected; ADR 0002 makes each one published and its name permanent, and its items would have to be `pub`, against ADR 0010's private lowered model.
- **Path-based convenience functions**: rejected; they need a filesystem WASM lacks, and once published could not be removed.
- **A public description model**: rejected; every internal struct would fall under semver, so a new format key would become an API change.
- **A writer-based `generate`**: rejected; it brings back an I/O error into an otherwise infallible step.
- **A `DiagnosticName` enum**: rejected; it adds a Rust-only contract on top of the stable string names and makes retiring a Diagnostic an API break.
- **`Serialize` on Diagnostics, or returning `serde_json::Value` from `json_schema`**: rejected; it freezes the internal layout as a second contract and ties Wirdigen's majors to third-party ones.
- **Borrowed types** (`Source<'a>`, `ValidDescription<'a>`): rejected; saving a copy of a few kilobytes puts lifetimes into every caller, the WASM bindings and async code.
