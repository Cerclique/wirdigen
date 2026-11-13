//! Checks of the book in `book/` (spec §11).
//!
//! Every ` ```yaml ` block of the book is a complete Protocol Description run through
//! [`validate`](crate::validate). A plain block must produce no Diagnostic at all; a block marked
//! ` ```yaml,diagnostic=<name> ` must produce exactly the named Diagnostics (the marker can
//! repeat for cascades such as `yaml-alias`, which needs an anchor too).

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::diagnostic::Name;
use crate::{RenderOptions, Severity, Source};

/// A ` ```yaml ` block of the book.
struct Snippet {
    /// `<file>:<line>` of the opening fence, for messages.
    location: String,
    text: String,
    /// The tokens of the Diagnostic names the block is marked as producing.
    expected: BTreeSet<&'static str>,
}

fn book_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../book/src")
}

/// A page of the book, by its path under `book/src`.
fn read_page(path: &str) -> String {
    let path = book_src().join(path);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Every Markdown file under `dir`, sorted so failures come in a stable order.
fn markdown_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(markdown_files(&path));
        } else if path.extension().is_some_and(|e| e == "md") {
            files.push(path);
        }
    }
    files.sort();
    files
}

/// The ` ```yaml ` blocks of one Markdown file. Panics on a block that would escape the check
/// (a `yml` block, an unknown marker) or name a Diagnostic that does not exist.
fn snippets(name: &str, markdown: &str) -> Vec<Snippet> {
    let mut snippets = Vec::new();
    let mut lines = markdown.lines().enumerate();
    while let Some((index, line)) = lines.next() {
        let Some(info) = line.trim_start().strip_prefix("```") else { continue };
        let mut words = info.split([',', ' ']).filter(|w| !w.is_empty());
        let language = words.next().unwrap_or("");
        let location = format!("{name}:{}", index + 1);
        assert_ne!(language, "yml", "{location}: write ```yaml so the block is checked");
        let mut body = Vec::new();
        for (_, line) in lines.by_ref() {
            if line.trim() == "```" {
                break;
            }
            body.push(line);
        }
        if language != "yaml" {
            continue;
        }
        let expected = words
            .map(|w| {
                let token = w.strip_prefix("diagnostic=").unwrap_or_else(|| panic!("{location}: unknown marker `{w}`"));
                let name =
                    Name::from_token(token).unwrap_or_else(|| panic!("{location}: no Diagnostic is named `{token}`"));
                name.as_str()
            })
            .collect();
        let mut text = body.join("\n");
        text.push('\n');
        snippets.push(Snippet { location, text, expected });
    }
    snippets
}

/// What validating a snippet reports.
struct Outcome {
    /// The distinct Diagnostic names.
    names: BTreeSet<&'static str>,
    /// Every Diagnostic rendered, for failure messages.
    rendered: String,
}

fn diagnose(snippet: &Snippet) -> Outcome {
    let source = Source::new(snippet.location.clone(), snippet.text.clone());
    let diagnostics = match crate::validate(&source) {
        Ok(valid) => valid.warnings().to_vec(),
        Err(diagnostics) => diagnostics.into_vec(),
    };
    Outcome {
        names: diagnostics.iter().map(crate::Diagnostic::name).collect(),
        rendered: diagnostics.iter().map(|d| d.render(&source, &RenderOptions::default())).collect(),
    }
}

fn book_snippets() -> Vec<Snippet> {
    let root = book_src();
    markdown_files(&root)
        .iter()
        .flat_map(|path| {
            let page = path.strip_prefix(&root).unwrap().display().to_string();
            snippets(&page, &read_page(&page))
        })
        .collect()
}

/// Spec §11: every YAML snippet is a complete file that CI runs through `validate`.
#[test]
fn every_snippet_produces_exactly_the_diagnostics_it_names() {
    let snippets = book_snippets();
    assert!(!snippets.is_empty(), "the book has no ```yaml snippet");
    let failures: Vec<String> = snippets
        .iter()
        .filter_map(|snippet| {
            let Outcome { names, rendered } = diagnose(snippet);
            (names != snippet.expected)
                .then(|| format!("{}: expected {:?}, got {names:?}\n{rendered}", snippet.location, snippet.expected))
        })
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A `## ... {#<anchor>}` section of a page: the anchor and the text up to the next section.
struct Entry {
    anchor: String,
    body: String,
}

/// The `## ` sections of a page. Each must carry an explicit `{#anchor}`, so anchors never
/// depend on how mdBook turns heading text into ids.
fn entries(markdown: &str) -> Vec<Entry> {
    let mut entries: Vec<Entry> = Vec::new();
    for line in markdown.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            let anchor = heading.rsplit_once("{#").and_then(|(_, id)| id.strip_suffix('}'));
            let anchor = anchor.unwrap_or_else(|| panic!("`{line}` has no explicit {{#anchor}}"));
            entries.push(Entry { anchor: anchor.to_owned(), body: String::new() });
        } else if let Some(entry) = entries.last_mut() {
            entry.body.push_str(line);
            entry.body.push('\n');
        }
    }
    entries
}

/// The page the renderer links to, under `book/src`.
const INDEX_PAGE: &str = "diagnostics.md";

/// Spec §11: the Diagnostics index has one entry per Diagnostic name and vice versa, each with
/// its severity, a snippet that triggers it and how to fix it (or `allow:` it, for a warning).
#[test]
fn the_index_has_one_entry_per_diagnostic_name() {
    let index = entries(&read_page(INDEX_PAGE));
    let mut documented = BTreeSet::new();
    for entry in &index {
        assert!(documented.insert(entry.anchor.as_str()), "`{}` has two entries", entry.anchor);
    }
    let names: BTreeSet<&str> = Name::ALL.iter().map(|n| n.as_str()).collect();
    assert_eq!(documented, names, "the Diagnostics index and the Diagnostic names differ");

    for entry in &index {
        let name =
            Name::from_token(&entry.anchor).unwrap_or_else(|| panic!("no Diagnostic is named `{}`", entry.anchor));
        let token = name.as_str();
        let severity = name.severity().as_str();
        let has_line = |prefix: &str| entry.body.lines().any(|l| l.starts_with(prefix));
        assert!(has_line(&format!("**Severity**: {severity}")), "`{token}` must say `**Severity**: {severity}`");
        assert!(has_line("**Fix**: "), "`{token}` must say how to fix it in a `**Fix**: ` paragraph");
        if name.severity() == Severity::Warning {
            assert!(entry.body.contains("allow:"), "warning `{token}` must say how to `allow:` it");
        }
        let triggering = snippets(token, &entry.body).iter().any(|s| s.expected.contains(token));
        assert!(triggering, "`{token}` has no ```yaml,diagnostic={token} snippet");
    }
}

/// Where GitHub Pages serves the book of the latest release (spec §11).
const PAGES_ROOT: &str = "https://cerclique.github.io/wirdigen/";

/// Spec §6.4: the note ending every rendered Diagnostic links to its entry in the book.
#[test]
fn the_rendered_link_resolves_to_the_index_entry() {
    let summary = read_page("SUMMARY.md");
    let source = Source::new("demo.wirdigen.yaml", "");
    for &name in Name::ALL {
        let rendered = crate::Diagnostic::new(name, 0..0, "message").render(&source, &RenderOptions::default());
        let url = rendered.split_whitespace().find(|w| w.starts_with("https://")).unwrap_or_else(|| {
            panic!("`{}` renders no link:\n{rendered}", name.as_str());
        });
        let (page, anchor) = url
            .strip_prefix(PAGES_ROOT)
            .and_then(|path| path.split_once('#'))
            .unwrap_or_else(|| panic!("`{url}` is not a page of {PAGES_ROOT} with an anchor"));
        let markdown = page.strip_suffix(".html").unwrap_or_else(|| panic!("`{url}` is not an .html page"));
        let markdown = format!("{markdown}.md");
        assert!(summary.contains(&format!("]({markdown})")), "{url}: `{markdown}` is not in SUMMARY.md");
        let text = read_page(&markdown);
        assert!(entries(&text).iter().any(|e| e.anchor == anchor), "{url}: `{markdown}` has no `{{#{anchor}}}` anchor");
        assert_eq!(anchor, name.as_str(), "{url} points at another entry");
    }
}

/// Panics unless `page` has a ` ```yaml ` block identical to
/// `examples/<example>/<example>.wirdigen.yaml`.
fn assert_shows_example_whole(page: &str, example: &str) {
    let file = format!("examples/{example}/{example}.wirdigen.yaml");
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(&file);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let shown = snippets(page, &read_page(page)).iter().any(|s| s.text == text);
    assert!(shown, "{page} has no ```yaml block identical to {file}");
}

/// Spec §11: the tutorial is built on the UDP telemetry example, and shows it whole.
#[test]
fn the_tutorial_shows_the_telemetry_example_whole() {
    assert_shows_example_whole("tutorial.md", "telemetry");
}

/// Spec §11: the TCP request/response example has a page of its own, which shows it whole.
#[test]
fn the_tcp_example_page_shows_the_kvstore_example_whole() {
    assert_shows_example_whole("tcp-example.md", "kvstore");
}

/// Spec §11: the tagged records example has a page of its own, which shows it whole.
#[test]
fn the_records_example_page_shows_the_tracker_example_whole() {
    assert_shows_example_whole("records-example.md", "tracker");
}
