# `wirdigen` is the library, `wirdigen-cli` the CLI

The library is published as `wirdigen`, the name it has had on crates.io since 0.2, and the CLI as `wirdigen-cli`, whose binary is named `wirdigen` (`cargo install wirdigen-cli`). Keeping the CLI in its own crate keeps clap and the other CLI dependencies out of library users' builds without a feature flag, and follows the common Rust split (`typos`/`typos-cli`, `taplo`/`taplo-cli`).

## Consequences

- Should v1 be a workspace, every crate is named `wirdigen-<part>`. A crate that a published crate depends on is itself published, because `cargo publish` rejects path-only dependencies, and its docs call it an implementation detail; only examples and test helpers are `publish = false`.
- All crates share one version from `[workspace.package]` and are released together with `cargo publish --workspace`.
- The unprefixed crate names of the `arise` branch (`dissector_configuration`, `dissector_parser`, `dissector_generator`) are not used.
- Publishing can't be undone: once `wirdigen-cli` or a `wirdigen-*` crate is published, the name is taken for good.

## Considered Options

- **One `wirdigen` crate with lib and bin, the CLI behind a default `cli` feature**: rejected; library users would have to set `default-features = false` to avoid the CLI's dependencies.
- **`wirdigen` as the CLI, the library renamed**: rejected; it reverses what the name has meant on crates.io.
