//! The Lua prelude: a hand-written runtime embedded in the library and split into named
//! chunks with declared dependencies (ADR 0010).

use std::sync::OnceLock;

const SOURCE: &str = include_str!("prelude.lua");

const CHUNK_MARKER: &str = "--@chunk ";
const REQUIRES_MARKER: &str = "--@requires ";

/// The chunk every Dissector includes: the Wireshark version guard.
pub(crate) const VERSION: &str = "version";
/// The chunk every Dissector includes: malformed-packet reporting.
pub(crate) const MALFORMED: &str = "malformed";
/// Bounds checking before a read.
pub(crate) const BOUNDS: &str = "bounds";
/// Finding the end of a `terminator:` Field.
pub(crate) const TERMINATED: &str = "terminated";
/// Expression operators (ADR 0007): `+ - *` and negation, wrapping.
pub(crate) const ARITHMETIC: &str = "arithmetic";
/// Expression operators: C's truncating `/` and dividend-signed `%`.
pub(crate) const DIVISION: &str = "division";
/// Expression operators: 64-bit `& | ^ ~ << >>`, `>>` arithmetic.
pub(crate) const BITWISE: &str = "bitwise";
/// Expression operators: comparisons, `!`, and the 1 or 0 of `&&` and `||`.
pub(crate) const LOGIC: &str = "logic";
/// Reporting a size known only when the packet is read that has no value or is negative.
pub(crate) const INVALID: &str = "invalid";
/// Naming a `switch` subject's value from its Field's labels.
pub(crate) const NAMES: &str = "names";
/// Showing the bytes a `switch` with no matching case and no `default` leaves unread.
pub(crate) const UNMATCHED: &str = "unmatched";
/// Reporting a value outside a Field's `expect:`.
pub(crate) const UNEXPECTED: &str = "unexpected";
/// Handing a `bytes` Field's bytes to a Wireshark Dissector by name.
pub(crate) const HANDOFF: &str = "handoff";
/// Registering on the ports of the range preferences, and moving when they change.
pub(crate) const PORTS: &str = "ports";
/// Showing a Field in the Info column as Wireshark displays it.
pub(crate) const INFO: &str = "info";
/// Showing a Field in the Info column by the label of its value.
pub(crate) const INFO_LABEL: &str = "info_label";
/// Keeping the case names of `switch` Fields for the Info column.
pub(crate) const INFO_CASES: &str = "info_cases";

#[derive(Debug)]
struct Chunk {
    name: &'static str,
    requires: Vec<&'static str>,
    lines: Vec<&'static str>,
}

fn chunks() -> &'static [Chunk] {
    static CHUNKS: OnceLock<Vec<Chunk>> = OnceLock::new();
    CHUNKS.get_or_init(|| parse(SOURCE))
}

/// Splits the prelude into chunks. The prelude is embedded, so a malformed one is a bug.
fn parse(source: &'static str) -> Vec<Chunk> {
    let mut chunks: Vec<Chunk> = Vec::new();
    for line in source.lines() {
        if let Some(name) = line.strip_prefix(CHUNK_MARKER) {
            chunks.push(Chunk { name: name.trim(), requires: Vec::new(), lines: Vec::new() });
        } else if let Some(requires) = line.strip_prefix(REQUIRES_MARKER) {
            let chunk = chunks.last_mut().expect("`--@requires` follows a `--@chunk`");
            chunk.requires.extend(requires.split_whitespace());
        } else if let Some(chunk) = chunks.last_mut() {
            chunk.lines.push(line);
        }
    }
    for chunk in &mut chunks {
        while chunk.lines.last().is_some_and(|l| l.trim().is_empty()) {
            chunk.lines.pop();
        }
    }
    chunks
}

/// The lines of the wanted chunks and of the chunks they require, in prelude order.
///
/// Each chunk is followed by a blank line separating it from the next piece of output.
pub(crate) fn select(wanted: &[&str]) -> Vec<&'static str> {
    let chunks = chunks();
    let mut included = vec![false; chunks.len()];
    for name in wanted {
        include(chunks, name, &mut included);
    }
    let mut lines = Vec::new();
    for (chunk, _) in chunks.iter().zip(&included).filter(|(_, included)| **included) {
        lines.extend(&chunk.lines);
        lines.push("");
    }
    lines
}

/// The name and own text of every chunk, in prelude order, for the Lua checks.
#[cfg(test)]
pub(crate) fn chunk_sources() -> impl Iterator<Item = (&'static str, String)> {
    chunks().iter().map(|chunk| (chunk.name, chunk.lines.join("\n") + "\n"))
}

fn include(chunks: &[Chunk], name: &str, included: &mut [bool]) {
    let index =
        chunks.iter().position(|c| c.name == name).unwrap_or_else(|| panic!("the prelude has no chunk `{name}`"));
    if !included[index] {
        included[index] = true;
        for required in &chunks[index].requires {
            include(chunks, required, included);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requirements_name_earlier_chunks() {
        let chunks = chunks();
        for (index, chunk) in chunks.iter().enumerate() {
            assert!(!chunk.lines.is_empty(), "chunk `{}` is empty", chunk.name);
            for required in &chunk.requires {
                let position = chunks.iter().position(|c| c.name == *required);
                assert!(position.is_some_and(|p| p < index), "`{}` requires `{required}`", chunk.name);
            }
        }
    }

    #[test]
    fn always_included_chunks_exist() {
        assert_ne!(select(&[VERSION, MALFORMED, BOUNDS]), Vec::<&str>::new());
    }

    #[test]
    fn selection_keeps_prelude_order() {
        let both = select(&[BOUNDS, VERSION]);
        let version = both.iter().position(|l| l.contains("wd_check_version()")).unwrap();
        let bounds = both.iter().position(|l| l.contains("wd_fits")).unwrap();
        assert!(version < bounds);
        assert!(!both.iter().any(|l| l.contains("wd_truncated")));
    }

    #[test]
    fn chunks_hold_no_marker_lines() {
        assert!(select(&[VERSION, MALFORMED, BOUNDS]).iter().all(|l| !l.starts_with("--@")));
    }
}
