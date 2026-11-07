# Semver covers the format, the API, the CLI and the Dissector's behaviour

From 1.0.0, a breaking change to any of four surfaces is a major release: the Protocol Description format (a description valid in 1.x stays valid and means the same in every later 1.y), the library's Rust API, the CLI (commands, flags, exit codes), and the observable behaviour of a generated Dissector in Wireshark (field names and display filters such as `myproto.length`, the protocol tree layout). Users write descriptions, script the CLI and save display filters; each of those breaks silently if it changes under them. The generated Lua text itself is not covered: two releases may produce different Lua from the same Protocol Description as long as the Dissector behaves the same, so the generator can be improved in any minor or patch release.

## Consequences

- Golden-file tests of the generated Lua are regression aids, not compatibility promises; updating one is not by itself a breaking change.
- Dropping support for a Wireshark version is a minor release, and only once that version has reached upstream end of life. Raising `rust-version` is a minor release too.
- `cargo-semver-checks` guards only the Rust API; the format, CLI and Dissector behaviour are guarded by tests and review.

## Considered Options

- **Byte-identical output across a major version**: rejected; any better comment, ordering or idiom in the generated Lua would force a major release.
- **Rust API only**: rejected; most users never touch the API, and the format and display filters are what they depend on.
