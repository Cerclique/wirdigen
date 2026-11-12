//! Generation corpus (spec §10.2): `tests/cases/<case>/<case>.wirdigen.yaml` next to a golden
//! `<case>.lua`, compared byte for byte. `WIRDIGEN_BLESS=1` rewrites the goldens.
//!
//! The examples of `examples/<example>/` (spec §11) are corpus cases too: each of their files
//! is a copy of the file of the same name in `tests/cases/<example>/`, so the goldens and the
//! tshark tests cover them.

use std::fs;
use std::path::Path;

use wirdigen::Source;

fn generate(path: &Path) -> String {
    let text = fs::read_to_string(path).unwrap();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap();
    wirdigen::validate(&Source::new(name, text)).unwrap_or_else(|d| panic!("{name} is invalid: {d}")).generate()
}

fn check(case: &str) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cases").join(case);
    let actual = generate(&dir.join(format!("{case}.wirdigen.yaml")));
    let golden = dir.join(format!("{case}.lua"));
    if std::env::var_os("WIRDIGEN_BLESS").is_some_and(|v| v == "1") {
        fs::write(&golden, &actual).unwrap();
    }
    let expected = fs::read_to_string(&golden).unwrap_or_else(|_| panic!("{} is missing: bless it", golden.display()));
    assert_eq!(actual, expected, "{case}: generated Lua differs from {}", golden.display());
    assert_eq!(generate(&dir.join(format!("{case}.wirdigen.yaml"))), actual, "{case}: generation is not deterministic");
    assert!(actual.ends_with('\n') && !actual.contains('\r') && !actual.ends_with("\n\n"));
}

macro_rules! cases {
    ($($test:ident => $case:literal),* $(,)?) => {
        $(#[test] fn $test() { check($case); })*

        #[test]
        fn every_case_directory_has_a_test() {
            let tested = [$($case),*];
            let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cases");
            for entry in fs::read_dir(root).unwrap() {
                let name = entry.unwrap().file_name().into_string().unwrap();
                assert!(tested.contains(&name.as_str()), "tests/cases/{name} has no test");
            }
        }
    };
}

cases! {
    uints => "uints",
    lua_keywords => "lua-keywords",
    integers => "integers",
    fixed_types => "fixed-types",
    endian => "endian",
    display => "display",
    tree_text => "tree-text",
    strings => "strings",
    bytes => "bytes",
    prefixes => "prefixes",
    timestamps => "timestamps",
    timestamps_le => "timestamps-le",
    values => "values",
    structures => "structures",
    types => "types",
    expressions => "expressions",
    framing => "framing",
    references => "references",
    runtime => "runtime",
    bitfields => "bitfields",
    bitfield_references => "bitfield-references",
    arrays => "arrays",
    conditionals => "conditionals",
    switch => "switch",
    hidden => "hidden",
    padding => "padding",
    expect => "expect",
    handoff => "handoff",
    registration => "registration",
    info => "info",
    info_default => "info-default",
    info_empty => "info-empty",
    info_framing => "info-framing",
    telemetry => "telemetry",
    kvstore => "kvstore",
}

/// Spec §11: every example is a corpus case, so its description and packets are checked.
#[test]
fn every_example_is_a_copy_of_its_corpus_case() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let examples = root.join("../../examples");
    let mut count = 0;
    for entry in fs::read_dir(&examples).unwrap() {
        let dir = entry.unwrap().path();
        let example = dir.file_name().and_then(|n| n.to_str()).unwrap().to_owned();
        let case = root.join("tests/cases").join(&example);
        assert!(dir.join(format!("{example}.wirdigen.yaml")).exists(), "examples/{example} has no description");
        for file in fs::read_dir(&dir).unwrap() {
            let file = file.unwrap();
            let name = file.file_name().into_string().unwrap();
            let copy = fs::read_to_string(case.join(&name))
                .unwrap_or_else(|_| panic!("examples/{example}/{name} is not in tests/cases/{example}"));
            assert_eq!(
                fs::read_to_string(file.path()).unwrap(),
                copy,
                "examples/{example}/{name} differs from its corpus case"
            );
        }
        count += 1;
    }
    assert!(count > 0, "examples/ is empty");
}
