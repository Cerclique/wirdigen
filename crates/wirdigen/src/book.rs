//! Checks of the book in `book/` (spec §11).
//!
//! Every ` ```yaml ` block of the book is a complete Protocol Description run through
//! [`validate`](crate::validate). A plain block must produce no Diagnostic at all; a block marked
//! ` ```yaml,diagnostic=<name> ` must produce exactly the named Diagnostics (the attribute can
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
    /// The Diagnostic names the block is marked as producing.
    expected: BTreeSet<String>,
}

fn book_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../book/src")
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

/// The ` ```yaml ` blocks of one Markdown file. Panics on a block that would escape the check:
/// a `yml` block or an unknown attribute.
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
            .map(|w| match w.strip_prefix("diagnostic=") {
                Some(name) => name.to_owned(),
                None => panic!("{location}: unknown attribute `{w}`"),
            })
            .collect();
        let mut text = body.join("\n");
        text.push('\n');
        snippets.push(Snippet { location, text, expected });
    }
    snippets
}

/// The distinct Diagnostic names a description produces, and their rendering for messages.
fn validate(snippet: &Snippet) -> (BTreeSet<String>, String) {
    let source = Source::new(snippet.location.clone(), snippet.text.clone());
    let diagnostics = match crate::validate(&source) {
        Ok(valid) => valid.warnings().to_vec(),
        Err(diagnostics) => diagnostics.into_vec(),
    };
    let names = diagnostics.iter().map(|d| d.name().to_owned()).collect();
    let rendered = diagnostics.iter().map(|d| d.render(&source, &RenderOptions::default())).collect();
    (names, rendered)
}

fn all_snippets() -> Vec<Snippet> {
    let root = book_src();
    markdown_files(&root)
        .iter()
        .flat_map(|path| {
            let name = path.strip_prefix(&root).unwrap().display().to_string();
            snippets(&name, &fs::read_to_string(path).unwrap())
        })
        .collect()
}

/// Spec §11: every YAML snippet is a complete file that CI runs through `validate`.
#[test]
fn every_snippet_produces_exactly_the_diagnostics_it_names() {
    let snippets = all_snippets();
    assert!(!snippets.is_empty(), "the book has no ```yaml snippet");
    let failures: Vec<String> = snippets
        .iter()
        .filter_map(|snippet| {
            let (actual, rendered) = validate(snippet);
            (actual != snippet.expected)
                .then(|| format!("{}: expected {:?}, got {actual:?}\n{rendered}", snippet.location, snippet.expected))
        })
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// An entry of the Diagnostics index: a `## ... {#<name>}` heading and the text up to the next.
struct Entry {
    name: String,
    body: String,
}

/// The `## ` sections of a page. Each must carry an explicit `{#anchor}`, so anchors never
/// depend on how mdBook turns heading text into ids.
fn entries(markdown: &str) -> Vec<Entry> {
    let mut entries: Vec<Entry> = Vec::new();
    for line in markdown.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            let name = heading.rsplit_once("{#").and_then(|(_, id)| id.strip_suffix('}'));
            let name = name.unwrap_or_else(|| panic!("`{line}` has no explicit {{#anchor}}"));
            entries.push(Entry { name: name.to_owned(), body: String::new() });
        } else if let Some(entry) = entries.last_mut() {
            entry.body.push_str(line);
            entry.body.push('\n');
        }
    }
    entries
}

fn index() -> Vec<Entry> {
    entries(&fs::read_to_string(book_src().join("diagnostics.md")).unwrap())
}

/// Spec §11: the Diagnostics index has one entry per Diagnostic name and vice versa, each with
/// its severity and a snippet that triggers it.
#[test]
fn the_index_has_one_entry_per_diagnostic_name() {
    let index = index();
    let mut documented = BTreeSet::new();
    for entry in &index {
        assert!(documented.insert(entry.name.as_str()), "`{}` has two entries", entry.name);
    }
    let names: BTreeSet<&str> = Name::ALL.iter().map(|n| n.as_str()).collect();
    assert_eq!(documented, names, "the Diagnostics index and the Diagnostic names differ");

    for entry in &index {
        let name = Name::from_token(&entry.name).unwrap();
        let severity = match name.severity() {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        assert!(
            entry.body.lines().any(|l| l == format!("**Severity**: {severity}")),
            "`{}` must say `**Severity**: {severity}`",
            entry.name
        );
        let triggering = snippets(&entry.name, &entry.body).iter().any(|s| s.expected.contains(&entry.name));
        assert!(triggering, "`{}` has no ```yaml,diagnostic={} snippet", entry.name, entry.name);
    }
}

/// Where GitHub Pages serves the book of the latest release (spec §11).
const PAGES_ROOT: &str = "https://cerclique.github.io/wirdigen/";

/// Spec §6.4: the note ending every rendered Diagnostic links to its entry in the book.
#[test]
fn the_rendered_link_resolves_to_the_index_entry() {
    let summary = fs::read_to_string(book_src().join("SUMMARY.md")).unwrap();
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
        let markdown = page.strip_suffix(".html").map(|p| format!("{p}.md")).unwrap();
        assert!(summary.contains(&format!("]({markdown})")), "{url}: `{markdown}` is not in SUMMARY.md");
        let text = fs::read_to_string(book_src().join(&markdown)).unwrap();
        assert!(entries(&text).iter().any(|e| e.name == anchor), "{url}: `{markdown}` has no `{{#{anchor}}}` anchor");
        assert_eq!(anchor, name.as_str(), "{url} points at another entry");
    }
}
