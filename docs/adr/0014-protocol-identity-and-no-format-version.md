# A protocol is identified by one filter name, and descriptions carry no format version

A Protocol Description states its identity with a required `name:`, which is the protocol's display filter name: the `<protocol>` prefix of every filter name (ADR 0009). Wireshark needs three names for a protocol (filter name `dns`, short name `DNS` in the Protocol column, full name `Domain Name System` at the tree root); Wirdigen asks for one and derives the rest:

- **Filter name**: `name:` itself, matching `[a-z][a-z0-9_-]*`, at most 32 characters. Uppercase is an error, never lowercased silently as Lua's `Proto.new` would, so the filter written in the file is the one users type. A `.` is excluded because `my.proto.len` would not say where the protocol ends and the Field path begins. Violations are the error `invalid-protocol-name`.
- **Short name**: always the uppercase of `name:`, Wireshark's own convention.
- **Full name**: the optional `title:`, non-empty and on one line (error `invalid-protocol-title`), defaulting to the short name.

A `name:` or `title:` equal to a protocol built into Wireshark would fail at load time, and tshark still exits 0 when a Lua Dissector fails to load. Wirdigen reports it as the warning `protocol-name-taken`, checked against a snapshot of `tshark -G protocols` from the latest supported stable Wireshark embedded in the library. It is a warning, not an error, because the set of built-ins depends on the Wireshark version and build (ADR 0008).

A Protocol Description has no format-version key. Under ADR 0001 every 1.x description stays valid in every later 1.y, and a description using a key from a newer minor already fails on that unknown key with its line and column (ADR 0005). If a 2.0 ever needs to tell formats apart, it can require `wirdigen: 2` and read a file without the key as 1.x, so leaving the key out now closes no door.

The top level has exactly nine keys, in any order: `name` and `fields` (required, the top-level layout, spelled like an inline structure), and `title`, `registration`, `framing`, `endian`, `info`, `types`, `allow`. Docs, examples and the generated JSON Schema list them in that order. There is no `description:` key; YAML comments document a file.

## Consequences

- Changing `name:` renames every filter of that protocol, so it is a breaking change for that protocol's users, as renaming a Field is (ADR 0009).
- A short name other than the uppercase of `name:` (such as `MyProto`) needs a later `short_name:` key; adding it is a minor release.
- The built-in protocol snapshot is refreshed in patch or minor releases, and a CI job running real tshark (ADR 0011) fails when it is out of date. Clashes between two Wirdigen Dissectors loaded together are not detected, since validation sees one description at a time.
- Every Protocol Description starts without boilerplate: `name:` and `fields:` are the whole minimum.

## Considered Options

- **One `name:` with every Wireshark name derived from it**: rejected; the tree root would always read like `MYPROTO`.
- **Three explicit keys (filter, short and full name)**: rejected; the short-name key would exist only to override an uppercase rule almost nobody needs.
- **Wireshark's full filter-name character set, dots included**: rejected; a dotted protocol name makes filter names ambiguous.
- **Identifier-only names without `-`**: rejected; `name:` never appears inside an Expression, and Wireshark names such as `mac-lte` use hyphens.
- **No check for built-in clashes, or an error**: rejected; the first leaves a silent load failure, the second forbids deliberately replacing a built-in on a build without it.
- **A required or optional `wirdigen: 1` key**: rejected; boilerplate in every file for a distinction no 1.x release needs.
- **A `layout:` or `root:` key naming a Type**: rejected; a second spelling for "a structure" next to `fields:`.
- **Warning on out-of-order top-level keys**: rejected; ordering is formatter territory, not validation.
