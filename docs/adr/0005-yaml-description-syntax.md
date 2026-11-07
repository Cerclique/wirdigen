# Protocol Descriptions are written in a strict subset of YAML 1.2

A Protocol Description has one canonical syntax: YAML 1.2, restricted to a strict subset. Wirdigen reads no other syntax, and has no pluggable parsers as the `arise` branch planned. An existing data language gives users a familiar syntax, editor highlighting and JSON-Schema-driven completion without Wirdigen writing its own parser; YAML wins among data languages because users already know it (Kaitai's `.ksy` is YAML too) and because its nesting reads cleanly for structures and switch cases. Expressions such as sizes, counts and conditions are string values parsed by Wirdigen's own small expression language.

The subset:

- one Protocol Description per file, no multi-document streams;
- no custom tags and no merge keys (`<<:`);
- no anchors or aliases;
- unknown keys and duplicate keys are errors, reported with line and column.

By convention a Protocol Description is named `<protocol>.wirdigen.yaml`; the CLI reads any path and does not enforce it.

## Consequences

- Since ADR 0001 puts the format under semver, only this subset is promised. Allowing anchors or another YAML feature later is a minor release; banning one would be a major.
- Wirdigen needs a YAML 1.2 parser that reports positions, so `no` and `on` stay strings and errors carry line and column. `serde_yaml` is deprecated; the parser crate is an implementation detail behind the format.
- Docs, examples and error messages use one syntax only.
- A JSON form of the same model for tools, such as a future web editor, can be added after v1 as a secondary format without changing this decision.
- Reuse of Fields belongs in the language (named types), not in YAML anchors.

## Considered Options

- **Several pluggable syntaxes (JSON, YAML, TOML) over one model**: rejected; each syntax multiplies tests, error positions, docs and the surface ADR 0001 must keep stable.
- **A grammar of Wirdigen's own (PDL- or wsgd-like)**: rejected for v1; it reads best, but means writing and stabilising a parser and has no editor support. It could come later as a second front-end.
- **KDL v2**: rejected; it fits ordered, node-shaped layouts best, but few users know it, editor support is thin and its serde support is immature.
- **TOML**: rejected; nested Fields and switch cases need `[[fields.cases.fields]]` headers or single-line inline tables.
- **JSON / JSON5**: rejected; noisy to write by hand, and plain JSON has no comments.
- **Accept whatever the YAML parser accepts**: rejected; the parser's quirks would become part of the stable format.
