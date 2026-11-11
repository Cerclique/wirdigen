//! `trycmd` cases under `tests/cli/` (spec §10.8). `TRYCMD=overwrite` blesses them.
//!
//! A case whose colour is left at `auto` removes `NO_COLOR` and `CLICOLOR_FORCE`, so the
//! caller's environment cannot change its output.

#[test]
fn cli() {
    let cases = trycmd::TestCases::new();
    cases.case("tests/cli/*.toml");
    // annotate-snippets uses another palette on Windows, so coloured goldens only hold elsewhere.
    // Which inputs turn colour on is the same on every OS and unit-tested in `src/color.rs`.
    if cfg!(windows) {
        cases.skip("tests/cli/color-always.toml").skip("tests/cli/clicolor-force.toml");
    }
}
