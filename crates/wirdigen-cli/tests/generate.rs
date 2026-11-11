//! `wirdigen generate` on every `tests/cases/` case of the library corpus writes the golden
//! `<case>.lua` next to its input, byte for byte (spec §9.3, §10.2).

use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn writes_every_corpus_golden_next_to_its_input() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../wirdigen/tests/cases");
    let mut cases = 0;
    let mut failures = Vec::new();
    for entry in fs::read_dir(&corpus).unwrap() {
        let dir = entry.unwrap().path();
        let case = dir.file_name().unwrap().to_str().unwrap().to_owned();
        let input = format!("{case}.wirdigen.yaml");
        let work = tempfile::tempdir().unwrap();
        fs::copy(dir.join(&input), work.path().join(&input)).unwrap();

        let output = Command::new(env!("CARGO_BIN_EXE_wirdigen"))
            .args(["generate", &input])
            .current_dir(work.path())
            .output()
            .unwrap();
        assert!(output.status.success(), "{case}: {}", String::from_utf8_lossy(&output.stderr));
        assert!(output.stderr.is_empty(), "{case}: success is silent");

        let golden = fs::read(dir.join(format!("{case}.lua"))).unwrap();
        let written = fs::read(work.path().join(format!("{case}.lua"))).unwrap();
        if written != golden {
            failures.push(case);
        }
        cases += 1;
    }
    assert!(failures.is_empty(), "written Lua differs from the golden: {failures:?}");
    assert!(cases > 0);
}
