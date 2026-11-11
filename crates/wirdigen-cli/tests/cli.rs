//! `trycmd` cases under `tests/cli/` (spec §10.8). `TRYCMD=overwrite` blesses them.

#[test]
fn cli() {
    trycmd::TestCases::new().case("tests/cli/*.toml");
}
