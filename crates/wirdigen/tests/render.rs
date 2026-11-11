//! Colour-off renderer goldens (spec §10.3): `tests/render/<case>.wirdigen.yaml` next to the
//! rendered `<case>.txt`. The layout is not stable (spec §6.5); `WIRDIGEN_BLESS=1` rewrites them.

use std::fs;
use std::path::Path;

use wirdigen::{RenderOptions, Source};

fn render(source: &Source, options: &RenderOptions) -> String {
    match wirdigen::validate(source) {
        Ok(valid) => valid.warnings().iter().map(|d| d.render(source, options)).collect::<Vec<_>>().join("\n"),
        Err(diagnostics) => diagnostics.render(source, options),
    }
}

#[test]
fn goldens() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/render");
    let bless = std::env::var_os("WIRDIGEN_BLESS").is_some_and(|v| v == "1");
    let mut cases = 0;
    let mut failures = Vec::new();
    for entry in fs::read_dir(&root).unwrap() {
        let path = entry.unwrap().path();
        let Some(case) = path.file_name().and_then(|f| f.to_str()).and_then(|f| f.strip_suffix(".wirdigen.yaml"))
        else {
            continue;
        };
        let source = Source::new(format!("{case}.wirdigen.yaml"), fs::read_to_string(&path).unwrap());
        let actual = render(&source, &RenderOptions::default());
        let golden = root.join(format!("{case}.txt"));
        if bless {
            fs::write(&golden, &actual).unwrap();
        }
        let expected =
            fs::read_to_string(&golden).unwrap_or_else(|_| panic!("{} is missing: bless it", golden.display()));
        if actual != expected {
            failures.push(format!("{case}:\n--- expected\n{expected}\n--- actual\n{actual}"));
        }
        cases += 1;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(cases > 0);
}

#[test]
fn every_rendered_diagnostic_ends_with_its_book_link() {
    let source = Source::new("x.wirdigen.yaml", "name: Demo\nbogus: 1\nfields: [ {name: a, type: uint8} ]\n");
    let diagnostics = wirdigen::validate(&source).unwrap_err();
    for d in &diagnostics {
        let rendered = d.render(&source, &RenderOptions::default());
        let last = rendered.trim_end().lines().last().unwrap();
        let link = format!("https://cerclique.github.io/wirdigen/diagnostics.html#{}", d.name());
        assert!(last.contains(&link), "last line {last:?} lacks {link}");
    }
}

#[test]
fn colour_is_opt_in() {
    let source = Source::new("x", "name: Demo\nfields: [ {name: a, type: uint8} ]\n");
    let diagnostics = wirdigen::validate(&source).unwrap_err();
    assert!(!diagnostics.render(&source, &RenderOptions::default()).contains('\x1b'));
    let mut options = RenderOptions::default();
    options.color = true;
    assert!(diagnostics.render(&source, &options).contains('\x1b'));
}

#[test]
fn denied_warnings_render_as_errors_with_a_note() {
    let text = include_str!("diagnostics/unused-type/unused.wirdigen.yaml");
    let source = Source::new("unused.wirdigen.yaml", text);
    let valid = wirdigen::validate(&source).unwrap();
    let warning = &valid.warnings()[0];
    let mut options = RenderOptions::default();
    options.deny_warnings = true;
    let rendered = warning.render(&source, &options);
    assert!(rendered.starts_with("error[unused-type]:"), "{rendered}");
    let lines: Vec<&str> = rendered.trim_end().lines().collect();
    assert_eq!(lines[lines.len() - 2], "  = note: warnings are denied for this run");
    assert!(lines[lines.len() - 1].ends_with("diagnostics.html#unused-type"));
}

#[test]
fn deny_warnings_leaves_errors_alone() {
    let source = Source::new("x", "name: Demo\nfields: [ {name: a, type: uint8} ]\n");
    let diagnostics = wirdigen::validate(&source).unwrap_err();
    let mut options = RenderOptions::default();
    options.deny_warnings = true;
    assert_eq!(diagnostics.render(&source, &options), diagnostics.render(&source, &RenderOptions::default()));
}
