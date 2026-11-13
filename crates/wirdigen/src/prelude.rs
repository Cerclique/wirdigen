//! The Lua prelude: a hand-written runtime embedded in the library and split into named
//! chunks (ADR 0010).
//!
//! Which chunks a Dissector contains is worked out from its Lua: each `wd_` name the emitted
//! code uses brings the chunk that defines it, and each chunk brings the chunks whose names
//! its own text uses. A helper cannot be printed without its chunk.

use std::collections::BTreeSet;
use std::sync::OnceLock;

const SOURCE: &str = include_str!("prelude.lua");

const CHUNK_MARKER: &str = "--@chunk ";

/// The prefix of every name the prelude defines, and of the names the emitter declares.
const PREFIX: &str = "wd_";

/// The chunk every Dissector includes: the Wireshark version guard.
pub(crate) const VERSION: &str = "version";
/// The chunk every Dissector includes: malformed-packet reporting.
pub(crate) const MALFORMED: &str = "malformed";
/// Reporting a size known only when the packet is read that has no value or is negative.
pub(crate) const INVALID: &str = "invalid";
/// Reporting an array Element that reads no bytes.
pub(crate) const EMPTY: &str = "empty";
/// Showing the bytes a `switch` with no matching case and no `default` leaves unread.
pub(crate) const UNMATCHED: &str = "unmatched";
/// Reporting a value outside a Field's `expect:`.
pub(crate) const UNEXPECTED: &str = "unexpected";
/// Handing a `bytes` Field's bytes to a Wireshark dissector by name.
pub(crate) const HANDOFF: &str = "handoff";

#[derive(Debug)]
struct Chunk {
    name: &'static str,
    lines: Vec<&'static str>,
    /// The names it defines at its top level: `local function wd_x`, `local wd_x, wd_y`.
    defines: Vec<&'static str>,
    /// The indices of the chunks whose names its text uses, worked out from that text.
    requires: Vec<usize>,
}

fn chunks() -> &'static [Chunk] {
    static CHUNKS: OnceLock<Vec<Chunk>> = OnceLock::new();
    CHUNKS.get_or_init(|| parse(SOURCE))
}

/// Splits the prelude into chunks and works out their dependencies. The prelude is embedded,
/// so a malformed one is a bug.
fn parse(source: &'static str) -> Vec<Chunk> {
    let mut chunks: Vec<Chunk> = Vec::new();
    for line in source.lines() {
        if let Some(name) = line.strip_prefix(CHUNK_MARKER) {
            chunks.push(Chunk { name: name.trim(), lines: Vec::new(), defines: Vec::new(), requires: Vec::new() });
        } else if let Some(chunk) = chunks.last_mut() {
            chunk.defines.extend(definitions(line));
            chunk.lines.push(line);
        }
    }
    for chunk in &mut chunks {
        while chunk.lines.last().is_some_and(|l| l.trim().is_empty()) {
            chunk.lines.pop();
        }
    }
    let requires: Vec<Vec<usize>> = chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| {
            let mut requires: Vec<usize> = names_used(&chunk.lines.join("\n"))
                .into_iter()
                .filter_map(|name| defining(&chunks, name))
                .filter(|&defining| defining != index)
                .collect();
            requires.sort_unstable();
            requires.dedup();
            requires
        })
        .collect();
    for (chunk, requires) in chunks.iter_mut().zip(requires) {
        chunk.requires = requires;
    }
    chunks
}

/// The `wd_` names a top-level line of a chunk defines: `local function wd_x(...)`,
/// `local wd_x, wd_y` and `local wd_x = ...`.
pub(crate) fn definitions(line: &str) -> Vec<&str> {
    let Some(rest) = line.strip_prefix("local ") else { return Vec::new() };
    if let Some(function) = rest.strip_prefix("function ") {
        let name = function.split('(').next().unwrap_or_default().trim();
        return if name.starts_with(PREFIX) { vec![name] } else { Vec::new() };
    }
    let names = rest.split('=').next().unwrap_or_default();
    names.split(',').map(str::trim).filter(|name| name.starts_with(PREFIX)).collect()
}

/// The index of the chunk defining `name`, if any does.
fn defining(chunks: &[Chunk], name: &str) -> Option<usize> {
    chunks.iter().position(|chunk| chunk.defines.contains(&name))
}

/// The `wd_` names `lua` uses as variables: outside comments and string literals, and not as
/// a table field (`t.wd_x`, `{ wd_x = ... }`), which names nothing the prelude defines.
pub(crate) fn names_used(lua: &str) -> BTreeSet<&str> {
    let bytes = lua.as_bytes();
    let mut names = BTreeSet::new();
    let mut at = 0;
    while at < bytes.len() {
        at = match bytes[at] {
            b'-' if bytes.get(at + 1) == Some(&b'-') => {
                let start = at + 2;
                long_bracket(bytes, start).map_or_else(|| line_end(bytes, start), |level| long_end(bytes, start, level))
            }
            quote @ (b'"' | b'\'') => quoted_end(bytes, at + 1, quote),
            b'[' if long_bracket(bytes, at).is_some() => {
                long_end(bytes, at, long_bracket(bytes, at).expect("checked just above"))
            }
            c if c.is_ascii_alphanumeric() || c == b'_' => {
                let end = at + bytes[at..].iter().take_while(|c| c.is_ascii_alphanumeric() || **c == b'_').count();
                let name = &lua[at..end];
                if name.starts_with(PREFIX) && !is_field(bytes, at, end) {
                    names.insert(name);
                }
                end
            }
            _ => at + 1,
        };
    }
    names
}

/// The level of the long bracket `[[` or `[==[` opening at `at`, if one does.
fn long_bracket(bytes: &[u8], at: usize) -> Option<usize> {
    if bytes.get(at) != Some(&b'[') {
        return None;
    }
    let level = bytes[at + 1..].iter().take_while(|c| **c == b'=').count();
    (bytes.get(at + 1 + level) == Some(&b'[')).then_some(level)
}

/// Where the long string or comment opening at `at` with a bracket of `level` ends.
fn long_end(bytes: &[u8], at: usize, level: usize) -> usize {
    let close: Vec<u8> = std::iter::once(b']').chain(std::iter::repeat_n(b'=', level)).chain(*b"]").collect();
    let body = at + level + 2;
    bytes[body..].windows(close.len()).position(|w| w == close).map_or(bytes.len(), |p| body + p + close.len())
}

/// Where the line holding `at` ends.
fn line_end(bytes: &[u8], at: usize) -> usize {
    bytes[at..].iter().position(|c| *c == b'\n').map_or(bytes.len(), |p| at + p)
}

/// Where the string literal whose text starts at `at`, opened by `quote`, ends.
fn quoted_end(bytes: &[u8], mut at: usize, quote: u8) -> usize {
    while let Some(&c) = bytes.get(at) {
        match c {
            b'\\' => at += 2,
            b'\n' => return at,
            c if c == quote => return at + 1,
            _ => at += 1,
        }
    }
    bytes.len()
}

/// Whether the name from `start` to `end` is a table field: after a single `.`, or a key in a
/// table constructor, after `{` or `,` and before a lone `=`.
fn is_field(bytes: &[u8], start: usize, end: usize) -> bool {
    let before = bytes[..start].iter().rposition(|c| !c.is_ascii_whitespace());
    let after = bytes[end..].iter().position(|c| !c.is_ascii_whitespace()).map(|p| end + p);
    match before {
        Some(b) if bytes[b] == b'.' => b == 0 || bytes[b - 1] != b'.',
        Some(b) if matches!(bytes[b], b'{' | b',') => {
            after.is_some_and(|a| bytes[a] == b'=' && bytes.get(a + 1) != Some(&b'='))
        }
        _ => false,
    }
}

/// The chunks of the prelude a Dissector contains.
pub(crate) struct Chunks {
    included: Vec<bool>,
}

impl Chunks {
    /// The chunks `lua`, Lua printed by the emitter, uses, with the chunks they require and the
    /// chunks every Dissector includes.
    pub(crate) fn used_by(lua: &str) -> Self {
        let chunks = chunks();
        let mut selection = Self::none();
        for name in [VERSION, MALFORMED] {
            selection.include(position(chunks, name));
        }
        for name in names_used(lua) {
            if let Some(index) = defining(chunks, name) {
                selection.include(index);
            }
        }
        selection
    }

    /// The chunks named, with the chunks they require.
    #[cfg(test)]
    pub(crate) fn named(names: &[&str]) -> Self {
        let mut selection = Self::none();
        for name in names {
            selection.include(position(chunks(), name));
        }
        selection
    }

    fn none() -> Self {
        Self { included: vec![false; chunks().len()] }
    }

    fn include(&mut self, index: usize) {
        if !self.included[index] {
            self.included[index] = true;
            for &required in &chunks()[index].requires {
                self.include(required);
            }
        }
    }

    /// Whether the chunk `name` is included.
    pub(crate) fn contains(&self, name: &str) -> bool {
        self.included[position(chunks(), name)]
    }

    /// The lines of the included chunks, in prelude order, each chunk followed by a blank line
    /// separating it from the next piece of output.
    pub(crate) fn lines(&self) -> Vec<&'static str> {
        let mut lines = Vec::new();
        for (chunk, _) in chunks().iter().zip(&self.included).filter(|(_, included)| **included) {
            lines.extend(&chunk.lines);
            lines.push("");
        }
        lines
    }

    /// The names the included chunks define.
    #[cfg(test)]
    pub(crate) fn defined(&self) -> BTreeSet<&'static str> {
        chunks()
            .iter()
            .zip(&self.included)
            .filter(|(_, included)| **included)
            .flat_map(|(chunk, _)| chunk.defines.iter().copied())
            .collect()
    }
}

fn position(chunks: &[Chunk], name: &str) -> usize {
    chunks.iter().position(|c| c.name == name).unwrap_or_else(|| panic!("the prelude has no chunk `{name}`"))
}

/// The name and own text of every chunk, in prelude order, for the Lua checks.
#[cfg(test)]
pub(crate) fn chunk_sources() -> impl Iterator<Item = (&'static str, String)> {
    chunks().iter().map(|chunk| (chunk.name, chunk.lines.join("\n") + "\n"))
}

/// The names of the chunks whose whole text `lua` holds, in prelude order.
#[cfg(test)]
pub(crate) fn chunks_in(lua: &str) -> Vec<&'static str> {
    chunks().iter().filter(|chunk| lua.contains(&chunk.lines.join("\n"))).map(|chunk| chunk.name).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requirements_name_earlier_chunks() {
        let chunks = chunks();
        for (index, chunk) in chunks.iter().enumerate() {
            assert!(!chunk.lines.is_empty(), "chunk `{}` is empty", chunk.name);
            for &required in &chunk.requires {
                assert!(required < index, "`{}` requires `{}`", chunk.name, chunks[required].name);
            }
        }
    }

    /// The dependencies worked out from the chunks' text are those the prelude once declared.
    #[test]
    fn requirements_are_worked_out_from_chunk_text() {
        let edges: Vec<(&str, &str)> =
            chunks().iter().flat_map(|chunk| chunk.requires.iter().map(|&r| (chunk.name, chunks()[r].name))).collect();
        assert_eq!(
            edges,
            [("division", "fault"), ("bitwise", "fault"), ("framing", "invalid"), ("info_label", "info")]
        );
    }

    #[test]
    fn every_name_is_defined_once() {
        let mut seen = BTreeSet::new();
        for chunk in chunks() {
            assert!(!chunk.defines.is_empty(), "chunk `{}` defines nothing", chunk.name);
            for name in &chunk.defines {
                assert!(seen.insert(*name), "`{name}` is defined twice");
            }
        }
    }

    #[test]
    fn definitions_are_found_at_the_top_level() {
        assert_eq!(definitions("local function wd_fits(tvb, offset, size)"), ["wd_fits"]);
        assert_eq!(definitions("local wd_div, wd_mod"), ["wd_div", "wd_mod"]);
        assert_eq!(definitions("local wd_info_cases = {}"), ["wd_info_cases"]);
        assert_eq!(definitions("    local function wd_inner()"), Vec::<&str>::new());
        assert_eq!(definitions("local div, rem = load([["), Vec::<&str>::new());
    }

    #[test]
    fn names_are_found_outside_comments_strings_and_fields() {
        let lua = "-- wd_a\n--[[ wd_b ]] x = \"wd_c\\\"wd_d\" .. 'wd_e' .. [==[ wd_f ]==]\n\
                   t.wd_g = { wd_h = 1, wd_i == 2 } .. wd_j(x_wd_k, wd_l) ..wd_m\n";
        assert_eq!(names_used(lua).into_iter().collect::<Vec<_>>(), ["wd_i", "wd_j", "wd_l", "wd_m"]);
    }

    #[test]
    fn the_lua_used_selects_chunks_and_their_requirements() {
        let chunks = Chunks::used_by("local x = wd_div(1, 2)");
        for name in [VERSION, MALFORMED, "division", "fault"] {
            assert!(chunks.contains(name), "{name}");
        }
        assert!(!chunks.contains("bounds"));
        // A name in a comment or a string selects nothing.
        assert!(!Chunks::used_by("-- wd_fits\nlocal s = \"wd_fits\"").contains("bounds"));
    }

    #[test]
    fn selection_keeps_prelude_order() {
        let both = Chunks::used_by("wd_fits()").lines();
        let version = both.iter().position(|l| l.contains("wd_check_version()")).unwrap();
        let bounds = both.iter().position(|l| l.contains("wd_fits")).unwrap();
        assert!(version < bounds);
    }

    #[test]
    fn chunks_hold_no_marker_lines() {
        assert!(Chunks::named(&[VERSION, MALFORMED, "bounds"]).lines().iter().all(|l| !l.starts_with("--@")));
    }
}
