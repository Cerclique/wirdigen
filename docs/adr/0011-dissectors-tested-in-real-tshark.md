# Dissector behaviour is tested only in real tshark; Lua checks use real interpreters

ADR 0001 puts a Dissector's behaviour in Wireshark (fields, display filter names, tree layout) under semver, so only Wireshark itself can tell whether that behaviour holds. Generated Dissectors are therefore run in real tshark against captures, and the test asserts on the dissected output. There is no mock of the Wireshark Lua API (`Proto`, `ProtoField`, `TvbRange`, `TreeItem`) in Rust. A mock would be a second implementation of Wireshark's semantics (integer widths, little-endian adds, malformed-packet handling) that drifts from the real one, and a passing test against it would prove nothing about Wireshark.

tshark runs on Linux CI in two versions: the floor, Wireshark 4.4 from a `debian:trixie` container (run as a non-root user, since tshark skips `-X lua_script` as root), and the latest stable from `ppa:wireshark-dev/stable` on ubuntu-24.04, which follows upstream releases without workflow edits and so tracks ADR 0006's rolling support. Both versions must produce the same dissected output; a version-specific expectation is a documented exception.

The Lua checks that need no Wireshark (ADR 0006's Lua 5.2 parse rule, and ADR 0010's rule that each prelude chunk loads with only its declared dependencies) run against the **real** `lua5.2`, `lua5.3` and `lua5.4` interpreters in a dedicated Linux job, not through an embedded Lua. `mlua` can embed only one Lua version per build and Cargo unifies its features across the workspace, so one `cargo test` cannot hold all three.

## Consequences

- Plain `cargo test` covers generation (golden Lua, Diagnostics, schema, property tests) on every OS, but not Dissector behaviour. The tshark and Lua tests are Rust tests gated by `WIRDIGEN_TSHARK=1` and `WIRDIGEN_LUA=1`. When the variable is set they fail rather than skip if the tool is missing, and `make test-tshark` / `make test-lua` run them locally.
- The `lua`, `tshark-4.4`, `tshark-stable-24.04` and `tshark-stable-26.04` jobs are required PR checks, so a behaviour regression cannot merge just because it only shows up outside `cargo test`.
- The "never raises a Lua error on bad input" promise is tested by generated bad packets run through tshark (truncations, seeded mutations, random bytes), with no coverage-guided fuzzing: coverage cannot be seen inside Lua running in tshark.
- tshark exits 0 on a Lua load error, so the harness checks stderr, `_ws.lua.error` and the packet count rather than the exit code.
- Lua 5.3 is checked only for parsing and loading; no packaged Wireshark ≥ 4.4 is known to use it, and a source build was judged not worth its CI cost.

## Considered Options

- **A mock Wireshark Lua API in `mlua`**, with tshark as a smaller confirmation layer: rejected; fast and runs on every OS, but it is a second Wireshark that drifts.
- **Both mock and tshark, weighted equally**: rejected for the same reason, at twice the maintenance.
- **`mlua` with one unpublished crate per Lua version, outside the workspace**: rejected; it brings the Lua checks into `cargo test` on every OS, but costs three extra crates and three C builds outside the lockstep workspace, for checks that gain nothing from macOS or Windows.
- **A pure-Rust Lua parser (`full_moon`)**: rejected; it can parse but not load chunks, and its version features unify the same way.
- **Building Wireshark from source per version** (exact versions, Lua 5.3 coverage): rejected; about fifteen minutes per build plus a cache to maintain.
- **Testing only the latest stable Wireshark**: rejected; it leaves the 4.4 floor untested.
