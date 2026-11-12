# Contributing to Wirdigen

Thanks for helping. This page covers what you need to change the code: the test layers, the
corpus, and how pull requests are titled. The user guide is the [book](../book/src/introduction.md);
the full design is in [`docs/spec.md`](spec.md).

Before you start, read [`GLOSSARY.md`](GLOSSARY.md) for the project's terms (Protocol
Description, Field, Dissector, Diagnostic, …) and use them as written. The decisions behind the
design are recorded as ADRs in [`docs/adr/`](adr/). A change that goes against one needs a
new ADR, not just a code change.

## Setup

- Rust comes from `rust-toolchain.toml`, so `rustup` picks the right version.
- `make lint` and `make test` run what the `rust` and `test` CI jobs run.
- Optional: the [prek](https://github.com/j178/prek) hooks in `.pre-commit-config.yaml` run
  `cargo fmt`, clippy, `cargo machete`, `typos` and `actionlint` before each commit.
- Optional: [mdBook](https://rust-lang.github.io/mdBook/) 0.5.4 for `make book`.

## Test layers

| Layer | Command | Needs |
|---|---|---|
| Goldens, Diagnostics, renderer, schema, book snippets, property tests, CLI | `make test` | Rust only |
| Lua checks (spec §10.4) | `make test-lua` | `lua5.2`, `lua5.3` and `lua5.4` on `PATH` |
| Dissectors in real tshark (spec §10.5, §10.6) | `make test-tshark` | `tshark` and `text2pcap` from Wireshark ≥ 4.4, as a non-root user |

`make test` is plain `cargo test` and needs no tools beyond Rust. Dissector behaviour is tested only in
real tshark ([ADR 0011](adr/0011-dissectors-tested-in-real-tshark.md)); there is no mock of
Wireshark's Lua API.

The Lua and tshark tests are gated by `WIRDIGEN_LUA=1` and `WIRDIGEN_TSHARK=1`, which the make
targets set. With the variable set, a missing tool fails the tests rather than skipping them.
tshark ignores `-X lua_script` as root, so don't run the tshark layer as root.

Without the tools, run both layers in Docker; [`docker/README.md`](../docker/README.md) has the
details:

```sh
make docker-test-lua      # Lua 5.2, 5.3 and 5.4
make docker-test-tshark   # Wireshark 4.4, then the latest stable
```

CI runs these three layers on every pull request, plus a weekly run with random seeds and
larger counts. A weekly failure opens an issue with the seed. Add the smallest failing packet
to the case's `packets.txt`, or make the failing description a new corpus case.

## Adding a corpus case

A corpus case lives in `crates/wirdigen/tests/cases/<case>/`:

| File | What it is | Written by |
|---|---|---|
| `<case>.wirdigen.yaml` | the Protocol Description | you |
| `packets.txt` | text2pcap hex, one packet per run of lines from offset `0000`, each with a `#` comment saying what it holds | you |
| `<case>.lua` | the generated Dissector, compared byte for byte | blessing |
| `dissected.json` | tshark's output cut down to the protocol's layer | blessing |
| `info.txt` (optional) | the Info column, one line per packet | blessing (create an empty file first) |

1. Write the description and `packets.txt`. Cover the edge cases too, such as a short packet.
2. Add the case to the `cases!` lists in both `crates/wirdigen/tests/cases.rs` and
   `crates/wirdigen/tests/tshark.rs`. A test fails if a directory has no entry.
3. Bless the goldens (below) and **read them**. A golden is only as good as its review: check
   that each Field decodes to the value your packet comment says.

A Diagnostic case lives in `crates/wirdigen/tests/diagnostics/<diagnostic-name>/<case>.wirdigen.yaml`,
next to a hand-written `<case>.expected` that holds one `severity name line:col-line:col` per
line and no message text. A new Diagnostic also needs:

- a directory of its own, with an `allowed` case for a warning;
- an entry in the book's [Diagnostics index](../book/src/diagnostics.md).

Tests check both.

## Re-blessing goldens

Goldens are plain files, rewritten on request and never in CI. Bless them, then review the diff
like code:

```sh
WIRDIGEN_BLESS=1 cargo test -p wirdigen --test cases    # <case>.lua
WIRDIGEN_BLESS=1 cargo test -p wirdigen --test render   # rendered Diagnostic layout
make docker-bless-tshark                                # dissected.json and info.txt
TRYCMD=overwrite cargo test -p wirdigen-cli --test cli  # CLI cases in tests/cli/
```

`make docker-bless-tshark` writes from Wireshark 4.4, then checks that the latest stable agrees.
Both versions must produce the same `dissected.json`. When they can't, a
`dissected-<major>.<minor>.json` next to it is a documented exception: say why in the pull
request.

The CLI's `help` case is also the copy of `wirdigen --help` in the book's
[CLI chapter](../book/src/cli.md), so re-bless it when you change a flag.

## Pull request titles

Pull requests are squash-merged, and their title becomes the commit that the changelog is
generated from. CI checks that the title is a
[conventional commit](https://www.conventionalcommits.org/):

```text
feat: accept hex literals in `values:`
fix: clear the Info column's fence before setting it (#151)
docs: CLI chapter and JSON Lines contract (#87)
```

- `feat`, `fix`, `perf`, `docs` and `refactor` appear in the changelog. `build`, `ci`, `test`,
  `style` and `chore` don't.
- Use `!` for a breaking change, such as `feat!: …`. [ADR 0001](adr/0001-semver-scope.md)
  defines what counts as breaking.
- **A pull request that adds a warning must use the `diagnostics` scope**, such as
  `feat(diagnostics): warn on shadowed fields`. These go under **New warnings** in the
  changelog, which users check before upgrading because a new warning can break a build that
  passes `--deny-warnings`.
- Reference the issue the pull request resolves, as in `(#151)`.

[`docs/releasing.md`](releasing.md) has the full mapping from commits to changelog groups.

## Reporting

- Bugs and feature requests: [open an issue](https://github.com/Cerclique/wirdigen/issues/new/choose).
- Security issues: report them privately, as described in [`docs/SECURITY.md`](SECURITY.md).
- Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).
