# Panics mark Wirdigen bugs; the library's only error is Diagnostics, the CLI's are typed

A panic in Wirdigen means Wirdigen has a bug, never that its input was wrong (ADR 0013 already keeps exit code `101` out of the CLI contract). Each crate handles errors in its own way:

- **The library** has one error type, `Diagnostics`. Every mistake in a Protocol Description becomes a Diagnostic, and `generate` stays infallible (ADR 0010, ADR 0012). The library never returns an error for a state validation has ruled out. Such a state is an invariant, asserted with `expect("<invariant>")`, `unreachable!("<invariant>")` or `panic!("<invariant>")`, with a message saying what guarantees it.
- **The CLI** gives its failures types made with `thiserror`, in two kinds. Usage errors are found before any input is read and exit with code 2. Input errors (reading an input, writing a Dissector, reading the file `--check` compares against) fail only their own input, which gives exit code 1. Each message is written once, in `#[error(...)]`.
- **No bare `unwrap()`** in shipped code: `clippy::unwrap_used` warns across the workspace, and `clippy.toml` sets `allow-unwrap-in-tests`. An invariant panic always names its invariant.
- **Retire an invariant panic with types, not with an error.** If a type can make the bad state impossible (for example a validated amount holding a bare `Expr` instead of a `Result`, or a `TypeId` instead of a lookup by name), use the type. If it can't, the panic stays.

## Consequences

- `thiserror` is a dependency of `wirdigen-cli` only. The library keeps its hand-written `Display` and `Error` impls for `Diagnostics`, and stays lean for the WASM crate.
- `anyhow` is not used. No error travels up to the CLI's `main`, and the exit code depends on what kind of error happened, which `anyhow::Error` would erase.
- A new invariant panic is acceptable in review if its message names what guarantees it. A new `Result` for an "impossible" case is not.

## Considered Options

- **An `InternalError` returned by `generate`**: rejected. It goes back on ADR 0012's infallible `generate` for an error the caller can only report as a bug, and a panic already does that.
- **`anyhow` in the CLI, or `main() -> anyhow::Result`**: rejected. Usage and input errors would need downcasting to pick exit code 2 or 1, tests would compare strings, and `main` would have nothing to propagate.
- **`thiserror` in the library**: rejected for now. `Diagnostics` is the only error and has no `source` to chain, and its `Display` computes counts. Add it if the library ever needs a second error type.
- **Denying `expect_used`, `panic` and `unreachable`**: rejected. Each invariant would then need an `#[allow]` with a reason, which is noise that hides the better fix of removing the panic with types.
