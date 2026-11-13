# Test containers

Two test layers need tools a workstation often lacks: the Lua checks need `lua5.2`, `lua5.3`
and `lua5.4` (spec §10.4), and the tshark corpus needs Wireshark 4.4 and the latest stable
(spec §10.5). These images give both, and the CI jobs below run their tests in them through
the same make targets, so CI and local runs share one environment:

| Image | Base | Has | CI jobs |
|---|---|---|---|
| `tshark-4.4` | `debian:trixie` | tshark 4.4 | `tshark-4.4` |
| `tshark-stable` | `ubuntu:24.04` | tshark from `ppa:wireshark-dev/stable`, Lua 5.2, 5.3, 5.4 | `tshark-stable`, `lua` |
| `tshark-stable-26.04` | `ubuntu:26.04` | tshark from `ppa:wireshark-dev/stable` | `tshark-stable-26.04` |

Each image also has the Rust toolchain pinned by `rust-toolchain.toml`. `tshark-stable-26.04`
runs the same Wireshark as `tshark-stable`, built against the newer LTS's libraries, so a
difference between the two builds shows up. Besides the aggregates, only
`docker-refresh-protocols` also uses it; every other target uses `tshark-stable`.

## Use

With Docker installed and running:

```sh
make docker-test-lua             # make test-lua in tshark-stable
make docker-test-tshark          # make test-tshark in tshark-4.4, tshark-stable, tshark-stable-26.04
make docker-test-tshark-4.4      # make test-tshark in tshark-4.4 only
make docker-test-tshark-stable   # make test-tshark in tshark-stable only
make docker-test-tshark-stable-26.04   # make test-tshark in tshark-stable-26.04 only
make docker-test-tshark-random-4.4     # random descriptions x packets (weekly), in tshark-4.4
make docker-test-tshark-random-stable  # the same in tshark-stable
make docker-bless-tshark         # rewrite dissected.json in tshark-4.4, then check both stables
make docker-refresh-protocols    # rewrite the built-in protocols snapshot from both stables
```

Each target builds the images it needs first; an unchanged image builds from Docker's cache
in a second. The tshark targets print `tshark --version` from the image before testing. The
repository is mounted at `/work`, so goldens are written to your checkout. Builds and
downloaded crates go to `target/docker/`.

## CI

The `lua`, `tshark-4.4`, `tshark-stable` and `tshark-stable-26.04` jobs run
`make docker-test-lua`, `make docker-test-tshark-4.4`, `make docker-test-tshark-stable` and
`make docker-test-tshark-stable-26.04`. Each job first builds its
image with `docker/build-push-action`, caching the layers across workflow runs, then passes
`DOCKER_PREBUILT=1`, which skips the target's own `docker build` and uses the loaded
`wirdigen-<image>` image: the layer cache lives in a buildx builder that a plain
`docker build` would not use.

The `Weekly` workflow (`.github/workflows/weekly.yml`) runs on Sunday and on demand, with one
random seed for all its jobs. In `tshark-4.4` and `tshark-stable` it runs the bad-input harness with large
counts (`WIRDIGEN_BAD_SEED`, `WIRDIGEN_BAD_MUTATIONS`, `WIRDIGEN_BAD_RANDOM`) and
`make docker-test-tshark-random-<version>`: `PROPTEST_CASES` random descriptions (seeded by
`PROPTEST_RNG_SEED`), each with `WIRDIGEN_RANDOM_PACKETS` random packets and their truncations.
It also runs the tests and clippy on the beta toolchain and `cargo deny check advisories`. When
any job fails, a last job opens one issue titled `Weekly scheduled tests are failing`, or
comments on it while it is open, with the seed, a replay command and the end of each failing
log, which holds the smallest failing packet as text2pcap hex. The make targets pass those
variables into the container when they are set.

The `Refresh protocols` workflow (`.github/workflows/refresh-protocols.yml`) runs early each
Monday UTC, just after the stable images' weekly cache scopes roll over, and on demand. It
builds the `tshark-stable` and `tshark-stable-26.04` images as their jobs do, sharing their
caches, and runs `make docker-refresh-protocols DOCKER_PREBUILT=1`, which writes the union of
the two builds' protocols: they differ even at one version. When the snapshot changed, it force-pushes
one commit on `main` to the branch `chore/refresh-protocols` and opens a PR from it, titled
`chore: refresh built-in protocols for Wireshark <version>`, or updates the PR already open.
Otherwise it pushes nothing.

It pushes and calls the PR API with a token minted from a GitHub App, because pushes and PRs
made with `GITHUB_TOKEN` do not trigger the `pull_request` workflows. The App is set up once
by hand:

- create a GitHub App with the repository permissions *Contents: Read and write* and
  *Pull requests: Read and write*, and nothing else;
- install it on this repository only;
- add the repository secrets `PROTOCOLS_CLIENT_ID` (the App's Client ID) and
  `PROTOCOLS_APP_PRIVATE_KEY` (a private key generated for the App).

The minted token is limited to this repository with `contents: write` and
`pull-requests: write`. The PR is not merged automatically.

## Notes

- The containers run as the calling user, because tshark skips `-X lua_script` as root.
  Run the targets as a normal user, not with `sudo`.
- The images follow the moving tags `debian:trixie`, `ubuntu:24.04` and the stable PPA. After
  a Wireshark release, rebuild the stable image to pick it up:
  `docker build --no-cache -t wirdigen-tshark-stable -f docker/tshark-stable/Dockerfile .`
  CI starts a fresh layer cache for the stable image each week, so it picks up a release
  within a week.
- `crates/wirdigen/src/builtin_protocols.tsv`, the snapshot of Wireshark's built-in protocols
  behind the warning `protocol-name-taken` (spec §3.3), comes from the stable image. The
  `tshark-stable` job fails once the image's Wireshark lists other protocols or is newer than
  the snapshot; a tshark older than the snapshot, such as 4.4, is not compared. The
  `Refresh protocols` workflow (see [CI](#ci)) opens a PR with the refreshed snapshot each
  week. To refresh it by hand, run `make docker-refresh-protocols` after rebuilding the stable
  image, and commit the file.
