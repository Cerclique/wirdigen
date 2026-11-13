//! Diagnostics corpus (spec §10.3): `tests/diagnostics/<name>/<case>.wirdigen.yaml`
//! next to `<case>.expected`, one `severity name line:col-line:col` per line.

use std::fs;
use std::path::Path;

use wirdigen::Source;

fn actual(text: &str) -> Vec<String> {
    let source = Source::new("case", text);
    let diagnostics = match wirdigen::validate(&source) {
        Ok(valid) => return valid.warnings().iter().map(|d| line_of(&source, d)).collect(),
        Err(diagnostics) => diagnostics,
    };
    diagnostics.iter().map(|d| line_of(&source, d)).collect()
}

fn line_of(source: &Source, d: &wirdigen::Diagnostic) -> String {
    let span = d.span();
    let (l1, c1) = source.line_column(span.start);
    let (l2, c2) = source.line_column(span.end);
    format!("{} {} {l1}:{c1}-{l2}:{c2}", d.severity().as_str(), d.name())
}

#[test]
fn corpus() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/diagnostics");
    let mut cases = 0;
    let mut failures = Vec::new();
    for dir in fs::read_dir(&root).unwrap() {
        let dir = dir.unwrap().path();
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let Some(file) = path.file_name().and_then(|f| f.to_str()) else { continue };
            let Some(case) = file.strip_suffix(".wirdigen.yaml") else { continue };
            let text = fs::read_to_string(&path).unwrap();
            let expected = fs::read_to_string(dir.join(format!("{case}.expected"))).unwrap();
            let expected: Vec<&str> = expected.lines().collect();
            let actual = actual(&text);
            if actual != expected {
                failures.push(format!("{}\n  expected {expected:?}\n  actual   {actual:?}", path.display()));
            }
            cases += 1;
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(cases > 0);
}

#[test]
fn valid_corpus_has_no_diagnostics() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/valid");
    for entry in fs::read_dir(&root).unwrap() {
        let path = entry.unwrap().path();
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(actual(&text), Vec::<String>::new(), "{}", path.display());
    }
}
