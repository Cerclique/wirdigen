//! Reading YAML mappings in stage 2: which keys a mapping has, and the kinds of their values.
//!
//! Shared by every part of a Protocol Description that is a mapping (the top level, a Field).

use std::ops::Range;

use crate::diagnostic::{Diagnostic, Name};
use crate::scalar::{Kind, resolve_plain};
use crate::yaml::{Node, Value};

/// A value with the span it came from.
#[derive(Debug, Clone)]
pub(crate) struct Spanned<T> {
    pub(crate) value: T,
    pub(crate) span: Range<usize>,
}

/// The known keys of one mapping, read by [`read_keys`].
pub(crate) struct Keys<'a> {
    /// Each known key found, with its key and value nodes.
    found: Vec<(&'static str, &'a Node, &'a Node)>,
    /// Known keys that some unknown key is probably a misspelling of.
    misspelt: Vec<&'static str>,
}

impl<'a> Keys<'a> {
    /// The value of `key`, if present.
    pub(crate) fn get(&self, key: &str) -> Option<&'a Node> {
        self.found.iter().find(|(k, ..)| *k == key).map(|(_, _, v)| *v)
    }

    /// The key node of `key`, if present.
    pub(crate) fn key_of(&self, key: &str) -> Option<&'a Node> {
        self.found.iter().find(|(k, ..)| *k == key).map(|(_, k, _)| *k)
    }

    /// Whether an unknown key was reported as a likely misspelling of `key`. A missing key that
    /// was misspelt is one mistake, which the unknown-key error already reports.
    pub(crate) fn misspelt(&self, key: &str) -> bool {
        self.misspelt.contains(&key)
    }
}

/// Reads the keys of a mapping: keys must be strings among `known`, each at most once.
pub(crate) fn read_keys<'a>(
    entries: &'a [(Node, Node)],
    known: &[&'static str],
    errors: &mut Vec<Diagnostic>,
) -> Keys<'a> {
    let mut keys = Keys { found: Vec::new(), misspelt: Vec::new() };
    for (key, value) in entries {
        let Value::Scalar { text, .. } = &key.value else {
            errors.push(wrong_type(key.span.clone(), "keys must be strings"));
            continue;
        };
        let Some(name) = known.iter().copied().find(|k| k == text) else {
            let unknown = Diagnostic::new(Name::UnknownKey, key.span.clone(), format!("unknown key `{text}`"));
            errors.push(match closest(text, known) {
                Some(guess) => {
                    keys.misspelt.push(guess);
                    unknown.with_note(format!("did you mean `{guess}`?"), None)
                }
                None => unknown.with_note(format!("the keys are: {}", known.join(", ")), None),
            });
            continue;
        };
        if let Some(first) = keys.key_of(name) {
            errors.push(
                Diagnostic::new(Name::DuplicateKey, key.span.clone(), format!("duplicate key `{name}`"))
                    .with_note("first defined here", Some(first.span.clone())),
            );
        } else {
            keys.found.push((name, key, value));
        }
    }
    keys
}

/// Reads a string value. A scalar that resolves to another kind (`123`, `true`, an empty value)
/// is reported under `invalid`, the key's own error; a list or mapping is a wrong value type.
pub(crate) fn expect_string(node: &Node, key: &str, invalid: Name) -> Result<Spanned<String>, Diagnostic> {
    match &node.value {
        Value::Scalar { text, plain, .. } if !*plain || resolve_plain(text) == Kind::Str => {
            Ok(Spanned { value: text.clone(), span: node.span.clone() })
        }
        Value::Scalar { .. } => Err(Diagnostic::new(invalid, node.span.clone(), format!("`{key}` must be a string"))
            .with_note("quote the value to make it a string", None)),
        _ => Err(wrong_type(node.span.clone(), format!("`{key}` must be a string"))),
    }
}

/// The candidate `word` is most likely a misspelling of, if any is close enough.
pub(crate) fn closest(word: &str, candidates: &[&'static str]) -> Option<&'static str> {
    candidates
        .iter()
        .map(|c| (edit_distance(word, c), *c))
        .filter(|(distance, c)| *distance <= (c.len() / 3).max(1))
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, c)| c)
}

/// Optimal string alignment distance: insertions, deletions, substitutions and adjacent
/// transpositions each cost 1, compared case-insensitively.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.to_lowercase().chars().collect();
    let b: Vec<char> = b.to_lowercase().chars().collect();
    // rows[i][j]: distance between a[..i] and b[..j].
    let mut rows = vec![vec![0; b.len() + 1]; a.len() + 1];
    for (i, row) in rows.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in rows[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (rows[i - 1][j] + 1).min(rows[i][j - 1] + 1).min(rows[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(rows[i - 2][j - 2] + 1);
            }
            rows[i][j] = best;
        }
    }
    rows[a.len()][b.len()]
}

/// Whether `text` holds no line break, counting the Unicode ones YAML and editors break on.
pub(crate) fn is_single_line(text: &str) -> bool {
    !text.contains(['\n', '\r', '\u{85}', '\u{2028}', '\u{2029}'])
}

pub(crate) fn wrong_type(span: Range<usize>, message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(Name::WrongValueType, span, message)
}

/// Reads a key that takes a constant: only a YAML integer, never a float or a bool.
#[cfg_attr(not(test), expect(dead_code, reason = "first used by the Fields ticket"))]
pub(crate) fn expect_integer(node: &Node, key: &str) -> Result<i64, Diagnostic> {
    let wrong = |what: &str| Diagnostic::new(Name::WrongValueType, node.span.clone(), format!("`{key}` {what}"));
    let Value::Scalar { text, plain: true, .. } = &node.value else {
        return Err(wrong("must be an integer"));
    };
    if resolve_plain(text) != Kind::Int {
        return Err(wrong("must be an integer, not a float, a bool or text"));
    }
    let (digits, radix) = if let Some(hex) = text.strip_prefix("0x") {
        (hex, 16)
    } else if let Some(oct) = text.strip_prefix("0o") {
        (oct, 8)
    } else {
        (text.strip_prefix('+').unwrap_or(text), 10)
    };
    i64::from_str_radix(digits, radix).map_err(|_| wrong("is out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yaml;

    const CANDIDATES: [&str; 4] = ["name", "title", "fields", "enums"];

    fn int(text: &str) -> Result<i64, String> {
        let node = yaml::parse(text).unwrap().unwrap();
        expect_integer(&node, "k").map_err(|d| d.name().to_owned())
    }

    #[test]
    fn misspellings_suggest_the_closest_key() {
        assert_eq!(edit_distance("enmu", "enum"), 1, "a transposition costs 1");
        assert_eq!(edit_distance("Name", "name"), 0, "case is ignored");
        assert_eq!(edit_distance("kitten", "sitting"), 3);
        assert_eq!(closest("fieldss", &CANDIDATES), Some("fields"));
        assert_eq!(closest("tilte", &CANDIDATES), Some("title"));
        assert_eq!(closest("bogus", &CANDIDATES), None);
        assert_eq!(closest("x", &CANDIDATES), None);
    }

    #[test]
    fn integer_keys_reject_floats_and_bools() {
        assert_eq!(int("12"), Ok(12));
        assert_eq!(int("0x10"), Ok(16));
        assert_eq!(int("-4"), Ok(-4));
        assert_eq!(int("1.5"), Err("wrong-value-type".into()));
        assert_eq!(int("true"), Err("wrong-value-type".into()));
        assert_eq!(int("'12'"), Err("wrong-value-type".into()));
        assert_eq!(int("99999999999999999999"), Err("wrong-value-type".into()));
    }
}
