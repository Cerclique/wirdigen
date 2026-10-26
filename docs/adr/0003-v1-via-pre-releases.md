# v1 ships as 1.0.0 pre-releases, with no further 0.x

While v1 is implemented, releases are `1.0.0-alpha.N`, then `-beta.N` and `-rc.N`, then `1.0.0`. v1 is a rewrite with no format or API compatibility with 0.3, and Cargo never selects a pre-release unless asked: `cargo install wirdigen-cli` and `wirdigen = "0.3"` keep resolving to finished releases, while early adopters opt in with an explicit version. The number says what the release is: v1, not finished.

## Consequences

- No 0.x release is published again. 0.2.x and 0.3.0 stay on crates.io and are not yanked; the RUSTSEC advisories against their dependencies (#1, #2) are closed once v1 lands on `main`, without a 0.3.1.
- The changelog starts at the first v1 pre-release with a hand-written entry stating there is no compatibility with 0.3 and no migration path; git-cliff generates the entries after it.
- `cargo-semver-checks` has no meaningful baseline until 1.0.0 is published, so the `semver` CI job is added then.

## Considered Options

- **Breaking 0.x releases (0.4, 0.5, …), then 1.0.0**: rejected; a plain `cargo install` would pick up the unfinished rewrite, and 0.4 doesn't signal a rewrite.
- **Nothing published until 1.0.0**: rejected; no feedback from real users before the format is frozen.
