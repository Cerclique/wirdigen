# Command-line interface

The `wirdigen` command validates Protocol Descriptions and generates their Dissectors:

| Command | Does |
|---|---|
| `wirdigen validate <inputs>…` | Validates, writes nothing. |
| `wirdigen generate <inputs>…` | Validates and writes Dissectors. |
| `wirdigen generate --check <inputs>…` | Writes nothing; fails if a Dissector on disk is missing or differs. |
| `wirdigen schema [-o <file>]` | Prints the JSON Schema, for editor completion. |

This chapter covers where the output goes, running Wirdigen in CI, and the parts of the command
line that scripts rely on: the exit codes and the JSON Lines output. Every flag is described by
`wirdigen --help`, `wirdigen <command> --help` and the man pages shipped in the release archives:

```text
{{#include ../../crates/wirdigen-cli/tests/cli/help.stdout}}
```

There is no configuration file and no environment variable of Wirdigen's own; `NO_COLOR` and
`CLICOLOR_FORCE` are honoured below an explicit `--color`.

## Inputs {#inputs}

Inputs are one or more paths, named on the command line: Wirdigen walks no directory and
searches for nothing. Any extension is accepted, though `.wirdigen.yaml` is the convention.
Diagnostics name each input as it was typed. `-` reads the description from standard input,
once, under the name `<stdin>`.

## Where the Dissector goes {#output}

By default the Dissector is written next to its input, named after the input's file name, never
after the protocol's `name:`:

| Input | Dissector |
|---|---|
| `proto/telemetry.wirdigen.yaml` | `proto/telemetry.lua` |
| `proto/telemetry.yaml` | `proto/telemetry.lua` (the last extension is replaced) |
| `-` (standard input) | standard output |

Two flags move it:

- `-o <file>` writes the Dissector of the only input to `<file>`, and `-o -` to standard
  output. It takes exactly one input.
- `--out-dir <dir>` writes every Dissector into `<dir>`, under the same name as above. It
  takes any number of inputs.

```text
wirdigen generate telemetry.wirdigen.yaml                       # telemetry.lua
wirdigen generate -o plugins/telemetry.lua telemetry.wirdigen.yaml
wirdigen generate --out-dir build/ proto/*.wirdigen.yaml
wirdigen generate - < telemetry.wirdigen.yaml > telemetry.lua
```

Two inputs that would write the same file, or an output that is its own input, are a usage
error, reported before anything is read or written.

Writes are atomic: the Dissector goes to a temporary file in the same directory, which is then
renamed, so a reader never sees half a file. An existing file is overwritten without asking,
except when it already holds the same bytes: it is left alone, and keeps its modification time,
so build tools that watch it see no change.

Each input succeeds or fails on its own. When one of several inputs has errors, the others are
still written, and the exit code reports the failure.

## Checking generated Dissectors in CI {#check}

A repository that commits its generated Dissectors can check, in CI, that they match their
descriptions. `generate --check` writes nothing; it compares each Dissector on disk with the
bytes `generate` would write there, honouring `-o` and `--out-dir`, and fails when one differs
or is missing:

```text
$ wirdigen generate --check proto/*.wirdigen.yaml
error: `proto/telemetry.lua` is stale
error: `proto/tracker.lua` is stale (missing)
```

Running the same `generate` command without `--check` brings them up to date. The Diagnostics
are checked too, so `--check` also fails on an error in a description, and `--deny-warnings`
applies as it does to `generate`.

A GitHub Actions step, with `wirdigen` installed earlier in the job:

```text
- name: Check the Dissectors are up to date
  run: wirdigen generate --check --deny-warnings proto/*.wirdigen.yaml
```

`--check` needs a file to compare with: `-o -`, and standard input without `-o <file>`, are
rejected.

## Exit codes {#exit-codes}

| Code | Meaning |
|---|---|
| `0` | Success. |
| `1` | Any failure: an error Diagnostic, a denied warning, a stale or missing Dissector under `--check`, an input that cannot be read or an output that cannot be written. |
| `2` | A usage error, reported before any input is processed. |

With several inputs, the exit code is the worst result among them. Any other code, such as
`101` for a panic, is a bug: please [report it](https://github.com/Cerclique/wirdigen/issues).
These codes are stable; a finer split could only come later behind a flag of its own, never by
renumbering.

## Failing on warnings {#deny-warnings}

A warning means the description is clear but probably wrong, so by default it is shown and the
Dissector is still written. `--deny-warnings` makes warnings fail the run, for `validate` and
`generate` (with or without `--check`): each warning is rendered as an error, with a note saying
warnings are denied, and a file with only warnings is not written.

```text
$ wirdigen validate --deny-warnings demo.wirdigen.yaml
error[unused-type]: the Type `Header` is never used
 --> demo.wirdigen.yaml:5:3
  |
5 |   Header:
  |   ^^^^^^
  |
  = note: use it as `type: Header`, or remove it
  = note: warnings are denied for this run
  = note: see https://cerclique.github.io/wirdigen/diagnostics.html#unused-type

error: 1 error in 1 of 1 file
```

It is all or nothing: there is no flag to deny or allow a single warning. To accept a warning
in one description, silence it there with [`allow:`](reference/diagnostics.md#silencing-warnings).

> **A minor release can break a `--deny-warnings` build.** New warnings are added in minor
> releases, since they reject nothing on their own; under `--deny-warnings` they become errors.
> Before upgrading, read the **New warnings** group of the
> [changelog](https://github.com/Cerclique/wirdigen/blob/main/CHANGELOG.md), or pin the
> Wirdigen version your CI installs.

## JSON Lines output {#json}

`--message-format json` reports a run as JSON Lines on standard output, for editors, CI
annotations and other tools. This section is the contract of that output.

Each line is one JSON object, whose `type` says what it records:

- one `diagnostic` record per Diagnostic, for each input in argument order, and in source order
  within an input;
- one `file` record per input, after that input's Diagnostics;
- one `summary` record, last.

For example, with the `rendered` text abridged:

```text
$ wirdigen generate --message-format json --deny-warnings unused.wirdigen.yaml ok.wirdigen.yaml
{"type":"diagnostic","file":"unused.wirdigen.yaml","name":"unused-type","severity":"warning","message":"the Type `Header` is never used","span":{"start":58,"end":64,"line":5,"column":3,"end_line":5,"end_column":9},"notes":[{"message":"use it as `type: Header`, or remove it"}],"rendered":"error[unused-type]: …","denied":true}
{"type":"file","input":"unused.wirdigen.yaml","output":"unused.lua","status":"failed"}
{"type":"file","input":"ok.wirdigen.yaml","output":"ok.lua","status":"written"}
{"type":"summary","errors":0,"warnings":1,"exit_code":1}
```

### `diagnostic` {#json-diagnostic}

| Field | Value |
|---|---|
| `type` | `"diagnostic"` |
| `file` | The input's name as typed, or `"<stdin>"`. |
| `name` | The Diagnostic's name, such as `"unused-type"`: the anchor of its entry in the [Diagnostics index](diagnostics.md) and the token of `allow:`. |
| `severity` | `"error"` or `"warning"`. A warning denied by `--deny-warnings` stays `"warning"`. |
| `message` | The message, one line. |
| `span` | Where the Diagnostic points: a [span](#json-span). |
| `notes` | An array, possibly empty, of `{"message", "span"}` objects; `span` is left out when the note points nowhere. |
| `rendered` | The Diagnostic as rendered on stderr in human mode, without colour, ending with a newline. |
| `denied` | `true` when the warning was promoted by `--deny-warnings`; left out otherwise. |

### Spans {#json-span}

| Field | Value |
|---|---|
| `start`, `end` | Byte offsets into the input, `end` exclusive. |
| `line`, `column` | Where `start` falls: a 1-based line, and a 1-based column counted in characters, not bytes. |
| `end_line`, `end_column` | Where `end` falls, counted the same way. |

### `file` {#json-file}

| Field | Value |
|---|---|
| `type` | `"file"` |
| `input` | The input's name as typed, or `"<stdin>"`. |
| `output` | The path of its Dissector, as `generate` would write it; `null` under `validate`. |
| `status` | What happened to the input, below. |

| `status` | Meaning |
|---|---|
| `"valid"` | `validate`: the input is valid. |
| `"written"` | `generate`: the Dissector was written. |
| `"unchanged"` | `generate`: the file already held these bytes and was left alone. `--check`: the Dissector is up to date. |
| `"stale"` | `--check`: the Dissector differs or is missing. |
| `"failed"` | The input could not be read or has errors (denied warnings included), or its output could not be read or written. |

### `summary` {#json-summary}

| Field | Value |
|---|---|
| `type` | `"summary"` |
| `errors` | The number of error Diagnostics in the run. |
| `warnings` | The number of warning Diagnostics, denied ones included. |
| `exit_code` | The [exit code](#exit-codes) the run ends with. |

A usage error ends the run before it starts, with exit code 2, a message on stderr and nothing
on stdout.

### Standard streams {#json-streams}

Every record is emitted whatever `-q` and `-v` say. Standard error then carries only `error:`
lines for an input or output that cannot be read or written, and for each stale Dissector under
`--check`; the records already say the same, so a tool can ignore stderr.

The Dissector of standard input normally goes to standard output, which the records now use:
`--message-format json` is rejected with `-o -`, and with `-` as an input of `generate` unless
`-o <file>` is given.

### Stability {#json-stability}

The JSON Lines output is part of the CLI's compatibility promise, and its shape belongs to the CLI
alone: the library has no JSON form of its own.

- Adding a field to a record, or a new record `type`, is a minor change. Consumers must ignore
  fields and record types they do not know.
- Removing or renaming a field or a record type, or changing what one means, is a major change.
- Diagnostic messages, notes, the `rendered` text and how precise a span is are not stable,
  just as for the human output; the names and severities of Diagnostics are.
