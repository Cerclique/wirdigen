//! `trycmd` cases under `tests/cli/` (spec §10.8). `TRYCMD=overwrite` blesses them.
//!
//! A case whose colour is left at `auto` removes `NO_COLOR` and `CLICOLOR_FORCE`, so the
//! caller's environment cannot change its output.

#[test]
fn cli() {
    trycmd::TestCases::new().case("tests/cli/*.toml");
}
