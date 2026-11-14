# Dissectors are generated from a lowered model, an emitter and a chunked Lua prelude

Wirdigen turns a validated Protocol Description into Lua in two steps. A **lowering** pass builds a private, Dissector-shaped model: the ProtoFields and value strings to register, one dissect function per Type, and for each a list of statements (bounds-checked read, add to tree, evaluate an Expression into a local, branch, loop, hand off), with every Expression keeping its operators. An **emitter** then prints that model as Lua through an indenting writer, mapping each Expression operator to its prelude helper. The fixed runtime (version guard, bounds-checked readers, C-style division and modulo, 64-bit bitwise operators, string readers, the Framing loop, malformed-packet reporting) is a hand-written Lua prelude embedded with `include_str!`.

The `arise` branch did placeholder substitution on a flat `template.lua`. That cannot express nested Types, `if`/`switch`, arrays and Framing, which all recurse, and a template engine would split the logic that decides what code a Field needs between template and Rust.

- **Types**: each becomes one dissect function, `wd.dissect_<Type>` (ADR 0019), defined in dependency order (recursive Types are a validation error), taking and returning the offset. Values are kept only for Fields some Expression or `info:` template references; outer scopes are reached through a context table.
- **Prelude**: split into named chunks. A chunk's dependencies are worked out from its own text: the chunks defining the `wd_` names it uses. A Dissector's chunks are worked out from its emitted Lua the same way: the emitter prints the body first, then the header (the prelude, ProtoFields and expert infos) from the chunks the body uses plus their dependencies, in the prelude's own fixed order. The version guard and malformed-packet reporting are always included. Lowering names no helper and picks no chunk.
- **Determinism**: the same description bytes and Wirdigen version produce byte-identical Lua on every OS: no timestamps or paths, ordered maps only, `\n` line endings, a trailing newline. A header comment names the Wirdigen version, the description's file name and "Requires Wireshark >= 4.4".
- **Readability**: the emitter owns a fixed format (4-space indent, no external formatter). Comments name each Type and each Field's path, but no source line numbers. User names are always mangled (`f_<name>`, `dissect_<Type>`, keys of the Dissector's table `wd` since ADR 0019) and prelude names start with `wd_`, so a Field called `end` or `type` cannot clash with Lua or the prelude.
- **Lua's limits**: how the emitted Lua stays within Lua's per-function limits of locals, upvalues, registers and nesting, whatever the size of the description, is ADR 0019.
- **Boundary**: the lowered model and the emitter are not public API. Generation from a validated description cannot fail: everything lowering relies on is a validation check, so a lowering failure is a Wirdigen bug, not a Diagnostic.

## Consequences

- The Lua 5.2 parse rule of ADR 0006 is enforced in one place: the emitter never prints a native bitwise operator or `//`, and each prelude chunk can be parse-checked on its own. The prelude chunks that need those operators for 64-bit integers keep them in a string compiled with `load` after the version guard.
- Lowering can be unit-tested on its own (description to model), and deterministic output makes golden-file tests and "is the committed Dissector up to date" checks possible.
- A helper can't be printed without its chunk: the chunks come from the names printed, so a Dissector never calls an undefined prelude name.
- A small Dissector stays mostly the user's own protocol rather than hundreds of lines of unused helpers, at the cost of a chunk parser and a test that every chunk loads on its own.
- The version in the header changes every generated file on upgrade; per ADR 0001 the Lua text is not stable anyway.
- Generation returns Lua directly rather than a `Result`; whether it writes to a string or a writer is left to the library API.

## Considered Options

- **Placeholder substitution** (as on `arise`): rejected; the recursive parts end up as Rust-built code blobs anyway, and the template only covers the outer shell.
- **A template engine** (minijinja, askama): rejected; it is good at boilerplate, but here the boilerplate is the small part, and whitespace control in recursive templates fights deterministic, readable output.
- **Inlining Types at every use**: rejected; Field scoping becomes a renaming problem, output grows with nesting, and large protocols can hit Lua's 200-locals-per-function limit.
- **The whole prelude in every Dissector**: rejected; simpler, but a 20-line protocol would ship hundreds of lines unrelated to it.
- **A public intermediate model**: rejected; it would freeze the generator's internals under semver, and no planned consumer needs more than Diagnostics and the final Lua.
