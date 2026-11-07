# Diagnostics have stable names; the JSON Schema is generated for editors, not used to validate

Wirdigen checks a Protocol Description entirely in Rust, in stages: YAML parse, strict deserialization (ADR 0005), expression parsing, then semantic checks. Each stage reports all its errors, the next stage runs only if it found none, and errors that only follow from an earlier one are suppressed. Every Diagnostic is either an **error** (the description has no single meaning or contradicts itself; no Dissector is generated) or a **warning** (the meaning is clear but probably a mistake; generation goes ahead).

Every Diagnostic has a stable kebab-case name (`tcp-without-framing`, `unused-type`), a severity, a precise span (down to the token inside an Expression string, or the whole value for escaped or multi-line YAML strings), a message and optional notes. A description silences warnings by name with a top-level `allow: [...]`, and the CLI can fail on warnings with `--deny-warnings`. In the library, `validate` returns either a validated description plus its warnings or the Diagnostics. Generation accepts only a validated description, and turning Diagnostics into text is left to a separate renderer.

A JSON Schema for `*.wirdigen.yaml` is **generated from the Rust model** and published for editor completion only: through a library function, a CLI command, release assets and SchemaStore. Wirdigen never validates with it. The `arise` branch did the opposite: it ran a hand-written `schema.json` before deserializing. That meant two sources of truth, and its errors gave schema paths with no line or column.

Under ADR 0001 these are stable:

- **which descriptions are accepted**: rejecting one that was accepted (with or without warnings) is a major release, except for a documented bug fix;
- **Diagnostic names and severities**: turning a warning into an error is major; turning an error into a warning, or adding a new warning, is minor;
- **the Diagnostic structure in the library API**: adding a field to it is minor;
- **that the schema accepts every valid description**.

Message wording, notes, span precision, the rendered layout and the exact text of the schema are not stable.

## Consequences

- Tools and CI match on Diagnostic names, never on message text, so wording can improve in any release.
- A minor release can add a warning, which can break a `--deny-warnings` build after an upgrade; the docs say so, as Rust does for lints.
- `allow:` is a key in the format, so it falls under ADR 0001 like any other key.
- The model keeps source spans for every key and value, Expressions included, from the start.
- Editors can still flag unknown keys and bad enum values from the schema, but semantic mistakes such as forward references show up only when Wirdigen runs.
- The schema is JSON Schema serialized as `.json`, because that is what yaml-language-server and SchemaStore read.

## Considered Options

- **A hand-written JSON Schema used as the structural validator** (as on `arise`): rejected; it keeps two sources of truth and its errors lose line and column.
- **No schema in v1**: rejected; it is cheap to generate, and gives completion in every mainstream editor.
- **Stopping at the first error**: rejected; descriptions are written by hand, and one error per run is slow to work through.
- **Carrying on to semantic checks after structural errors**: rejected; it needs an error-tolerant reader instead of strict deserialization, and gains little.
- **Unnamed warnings with no way to silence them**: rejected; a warning that cannot be fixed and shows up on every run teaches users to ignore them all, and tools end up matching on message text.
- **Silencing warnings only from the CLI**: rejected; whether a warning applies is a property of the protocol, so it belongs in its description.
- **Generation that validates internally, with no validated type**: rejected; editors and a future language server need Diagnostics without generating anything, and the generator should never have to guard against unchecked input.
