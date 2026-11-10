//! Generation corpus (spec §10.2): `tests/cases/<case>/<case>.wirdigen.yaml` next to a golden
//! `<case>.lua`, compared byte for byte. `WIRDIGEN_BLESS=1` rewrites the goldens.

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
}
