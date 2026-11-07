# The CLI has three commands, one failure exit code and JSON Lines on stdout

The `wirdigen` binary (ADR 0002) has three subcommands: `validate`, `generate` and `schema`. Checking that a committed Dissector is up to date is `generate --check`, not a command of its own: rustfmt and prettier use `check` for "is the output current" while cargo uses it for "does it compile", so the word `check` appears only as that flag, and the validate-only command takes the library's name, `validate`.

Under ADR 0001 the commands, flags, exit codes and JSON output are stable from 1.0.0:

- **Exit codes**: `0` success, `1` any failure (an error Diagnostic, warnings under `--deny-warnings`, a stale or missing file under `--check`, an unreadable input or unwritable output), `2` usage error, raised before any input is processed. A panic (`101`) is a Wirdigen bug, not part of the contract. Detail comes from stderr or the JSON `summary`, not from the code.
- **Inputs**: one or more paths, `-` (at most once) for stdin; each input succeeds or fails on its own, and the exit code is the worst result.
- **Outputs**: by default next to the input, named from its file name (`foo.wirdigen.yaml` → `foo.lua`, otherwise the last extension is replaced), so output and `--check` paths are known without parsing. `-o <file|->` takes a single input; `--out-dir <dir>` takes any number. Two inputs mapping to one output, or an output equal to its input, is a usage error.
- **Machine output**: `--message-format json` writes JSON Lines to stdout, one record per line with a `type` of `diagnostic`, `file` or `summary`. Adding record types or fields is minor; removing or renaming one is major; consumers ignore unknown fields. The library has no `Serialize` (ADR 0012), so this shape is owned and versioned by the CLI alone.
- **`--deny-warnings`**: promotes every warning to an error for the run, so the file is not written; the JSON keeps `"severity": "warning"` and adds `"denied": true`, so Diagnostic severities stay the stable ones of ADR 0008.

Human Diagnostics go to stderr through the library's renderer, and their layout stays unstable (ADR 0008).

## Consequences

- `generate` writes atomically (temporary file, then rename) and leaves an unchanged file untouched, so Wireshark never loads a half-written Dissector and make-style tools see no spurious change.
- `--check` is incompatible with `-o -`, and `--message-format json` is incompatible with `-o -`, because stdout carries the Lua.
- A split between "invalid description" and "stale Dissector" can only arrive later as an opt-in flag, never by renumbering existing codes.
- Shell completions and man pages ship as release assets generated at build time, so they add no CLI surface. There is no config file and no `WIRDIGEN_*` environment variable; colour follows `--color`, `NO_COLOR` and `CLICOLOR_FORCE`.
- CLI behaviour is tested with `trycmd` cases under `tests/cli/` reusing the library corpus (ADR 0011), plus a few `assert_cmd` tests for file mtimes and TTY colour.

## Considered Options

- **A `check` subcommand for validation** (as on `arise`): rejected; it collides with the `--check` meaning users know from formatters.
- **No subcommands, flags on a bare `wirdigen <file>`**: rejected; `--validate-only` and `--print-schema` read worse and every flag applies to only one mode.
- **Distinct exit codes per failure kind**: rejected; every code is a permanent promise, several inputs need a precedence order, and CI reacts to all failures the same way.
- **Naming the output after the protocol's name in the description**: rejected; the output path would need a parse to know, and `--check` could not say which file it compares against for an invalid description.
- **One `-o` that is a file for one input and a directory for several**: rejected; its meaning would change with the number of arguments.
- **JSON on stderr**: rejected; it avoids the clash with `-o -` but is awkward for tools to capture.
- **Promoted warnings reported as `"severity": "error"` in JSON**: rejected; tools would see a stable warning change severity depending on a flag.
