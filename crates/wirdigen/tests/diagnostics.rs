//! Diagnostics corpus (spec §10.3): `tests/diagnostics/<name>/<case>.wirdigen.yaml`
//! next to `<case>.expected`, one `severity name line:col-line:col` per line.

use std::fs;
use std::path::Path;

use wirdigen::{Severity, Source};

/// 1-based line and column (in characters) of a byte offset.
fn line_col(text: &str, offset: usize) -> (usize, usize) {
    let before = &text[..offset];
    let line = before.matches('\n').count() + 1;
    let col = before.rsplit('\n').next().unwrap_or("").chars().count() + 1;
    (line, col)
}

fn actual(text: &str) -> Vec<String> {
    let diagnostics = match wirdigen::validate(&Source::new("case", text)) {
        Ok(valid) => return valid.warnings().iter().map(|d| line_of(text, d)).collect(),
        Err(diagnostics) => diagnostics,
    };
    diagnostics.iter().map(|d| line_of(text, d)).collect()
}

fn line_of(text: &str, d: &wirdigen::Diagnostic) -> String {
    let severity = match d.severity() {
        Severity::Error => "error",
        Severity::Warning => "warning",
    };
    let span = d.span();
    let (l1, c1) = line_col(text, span.start);
    let (l2, c2) = line_col(text, span.end);
    format!("{severity} {} {l1}:{c1}-{l2}:{c2}", d.name())
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
