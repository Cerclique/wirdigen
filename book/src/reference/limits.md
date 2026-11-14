# Limits

What Wirdigen cannot describe, and what happens when a description runs into it. Each entry
says what the limit is and what you see when you reach it, and links to the section or the
[Diagnostic](../diagnostics.md) with the details.

## Size and depth {#size-and-depth}

- **An Expression nests at most 64 levels deep.** A deeper one is
  [`expression-too-deep`](../diagnostics.md#expression-too-deep): Lua could not load the
  Dissector it makes. See [Operators](expressions.md#operators) for how levels count.
- **A Field is at most 64 deep**, counted through every [Type](fields.md#types) it is reached
  by: at most 64 names lie between the protocol's and its own in its
  [filter name](fields.md#filter-names). A deeper Field is
  [`field-too-deep`](../diagnostics.md#field-too-deep).
- **YAML nests at most 256 levels**, anywhere in the file. A deeper node is
  [`yaml-too-deep`](../diagnostics.md#yaml-too-deep). A description within the Field limit
  never comes near it.
- **There is no limit on size.** A description can have any number of Fields, Types and Enums:
  one of 1,000 Fields, or of 500 Types used side by side, loads and dissects in tshark.

## The YAML subset {#yaml}

A Protocol Description is written in a subset of YAML 1.2. Fields are reused through
[Types](fields.md#types), not through YAML's own reuse features.

- **One description per file.** Several YAML documents separated by `---` are
  [`multiple-documents`](../diagnostics.md#multiple-documents).
- **No anchors or aliases.** `&name` is [`yaml-anchor`](../diagnostics.md#yaml-anchor) and
  `*name` is [`yaml-alias`](../diagnostics.md#yaml-alias).
- **No tags.** `!foo` and `!!str` are [`yaml-tag`](../diagnostics.md#yaml-tag).
- **No merge keys.** `<<:` is [`merge-key`](../diagnostics.md#merge-key).

## Expressions and references {#expressions}

[Expressions](expressions.md) do integer arithmetic on Fields read earlier, and nothing more.

- **Only Fields read earlier.** A Field read later, or the Expression's own Field, is
  [`forward-reference`](../diagnostics.md#forward-reference). See
  [References](expressions.md#references).
- **Not into arrays.** A Field inside an [array](arrays.md#rules) element can be read only from
  inside that element; from outside it is [`unknown-field`](../diagnostics.md#unknown-field).
  There is no indexing (`items[0]`) and no `_index`, both
  [`expression-syntax`](../diagnostics.md#expression-syntax).
- **Not into conditionals.** A Field under [`if:`](conditionals.md#scope) or in a
  [`switch` case](conditionals.md#switch-scope) can be read only from inside it; from outside
  it is [`conditional-reference`](../diagnostics.md#conditional-reference), even under an
  identical condition.
- **Only numbers.** Integer and `bool` Fields and bitfield sub-Fields can be read. A `string`,
  `bytes`, float, address, timestamp or structure is
  [`non-numeric-reference`](../diagnostics.md#non-numeric-reference).
- **No strings, labels, `?:` or function calls.** A string literal, a `?:` or a call is
  [`expression-syntax`](../diagnostics.md#expression-syntax). An Expression cannot compare a
  Field with one of its [`values:`](fields.md#value-mappings) labels: a label in an Expression
  is read as a Field name, so it is [`unknown-field`](../diagnostics.md#unknown-field). Compare
  with the number instead.
- **Framing's `length` reads only the header.** It reads top-level Fields, and their bitfield
  sub-Fields, lying entirely in the first `header` bytes, and not `_offset` or `_remaining`.
  Anything else is [`invalid-framing`](../diagnostics.md#invalid-framing). See
  [The header](framing.md#header).
- **The Info template takes Field Paths only.** No Expressions or format specifiers in braces:
  those are [`invalid-info`](../diagnostics.md#invalid-info). See
  [Templates](info.md#templates). `info:` is top-level only: on a Type it is
  [`unknown-key`](../diagnostics.md#unknown-key).

## Wireshark {#wireshark}

- **Lua Dissectors for Wireshark 4.4 and later.** Wirdigen generates a Lua file and nothing
  else, no C plugin. Loaded into an older Wireshark, the Dissector stops with an error naming
  the version it found. See [Installing a Dissector](../installing.md#wireshark).
- **A Lua error at load time does not fail tshark.** tshark prints it on stderr, reads the
  capture without the Dissector and exits 0. See
  [Troubleshooting](../installing.md#exit-status).
- **Wireshark shows a tree at most 500 levels deep** (the `gui.max_tree_depth` preference). The
  Field depth limit keeps a Dissector's own tree well below that.

## Not in v1 {#later}

These are not supported yet, but can come in a later 1.x release. Until then, writing one is an
error, most often [`unknown-key`](../diagnostics.md#unknown-key),
[`unknown-type`](../diagnostics.md#unknown-type) or
[`expression-syntax`](../diagnostics.md#expression-syntax).

- **Layout**: repeating until a condition (only [`count:` and `repeat: to_end`](arrays.md)),
  `align:`, a byte order chosen at runtime, computed Fields, and checksum verification.
- **Framing**: messages ended by a delimiter rather than a [length](framing.md#header).
- **Handoff**: choosing the next dissector from a Field's value or through a dissector table;
  [`dissector:`](fields.md#dissector) names one dissector.
- **Expressions**: strings, `?:`, function calls and array indexing.
- **Info column**: a per-Type `info:`.
- **Registration**: heuristic dissectors, and dissector tables other than UDP and TCP ports
  (`ethertype`, `ip.proto`, `sctp.ppi`, …). See [Registration](registration.md).
- **Built-in types**: `char`, `framenum`, `protocol`, `none`, `ipx`, `oid`, `rel_oid` and
  `systemid`, and signed [bitfield sub-Fields](bitfields.md#sub-fields).
