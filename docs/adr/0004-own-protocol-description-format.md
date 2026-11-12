# Wirdigen defines its own Protocol Description format

The Protocol Description format is Wirdigen's own; it does not adopt or extend Kaitai Struct, PDL or wsgd. It borrows their *concepts* (sequential layout, size and count references, repetition, conditionals and switches, enums, bitfields, message switching on a header value, value constraints, inheritance with constraints) but not their keywords or document shape: constructs are named in Wirdigen's own vocabulary, aligned with `docs/GLOSSARY.md` and Wireshark's terms. ADR 0001 promises that the format is stable across a major version, which Wirdigen can only promise for a format it owns, and none of the existing formats has a place for Wireshark concerns such as registration, display bases, value strings or Decode As.

## Consequences

- The input syntax is chosen freely; it is not tied to Kaitai's YAML shape.
- Users should not expect Kaitai semantics (its expression language, `instances`, `process`) unless Wirdigen adds them on its own terms.
- A `.ksy` importer is a possible feature after v1, not part of the v1 spec.

## Considered Options

- **Adopt Kaitai `.ksy` as is, with Wireshark settings in a sidecar or CLI flags**: rejected; Kaitai is pre-1.0, so its changes would break Wirdigen's format promise, and splitting one protocol across two files makes it harder to write.
- **Extend `.ksy` with Wirdigen-specific keys**: rejected; it ties Wirdigen to a format it does not control and invites users to expect full Kaitai compatibility.
- **A Kaitai-flavoured dialect reusing its keywords**: rejected; a look-alike that only partly matches sets wrong expectations.
- **Adopt Google PDL**: rejected; it is loosely versioned and has no Wireshark concerns either.
- **Extend wsgd**: rejected; it is a native GPL-2.0+ plugin that interprets descriptions at runtime and generates no Lua.
