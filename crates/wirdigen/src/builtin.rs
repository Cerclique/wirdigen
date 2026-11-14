//! The protocols built into Wireshark, behind the warning `protocol-name-taken` (spec §3.3).
//!
//! `builtin_protocols.tsv` is a `tshark -G protocols` snapshot from the latest stable Wireshark,
//! the union of its builds on Ubuntu 24.04 and 26.04: a `#` header naming the version, then the
//! full name, short name and filter name of each protocol, tab-separated and sorted. The
//! `tshark-stable-24.04` and `tshark-stable-26.04` CI jobs fail when it is out of date
//! (spec §10.9); `make docker-refresh-protocols` rewrites it.

use crate::diagnostic::{Diagnostic, Name};
use crate::keys::Spanned;

/// The snapshot, as committed.
const SNAPSHOT: &str = include_str!("builtin_protocols.tsv");

/// The three Wireshark names of a built-in protocol.
struct Protocol<'a> {
    full: &'a str,
    short: &'a str,
    filter: &'a str,
}

fn protocols() -> impl Iterator<Item = Protocol<'static>> {
    SNAPSHOT.lines().filter(|line| !line.starts_with('#')).filter_map(|line| {
        let mut columns = line.split('\t');
        Some(Protocol { full: columns.next()?, short: columns.next()?, filter: columns.next()? })
    })
}

/// Reports `name:` and `title:` when Wireshark already has a protocol with the same filter
/// name, short name or full name: Wireshark refuses to register a second one.
///
/// The short name is the uppercase of `name:`, and the full name is `title:` or, without one,
/// the short name (spec §3.3), so a clash on the default full name is reported on `name:`.
pub(crate) fn check(name: &Spanned<String>, title: Option<&Spanned<String>>, diagnostics: &mut Vec<Diagnostic>) {
    let short_name = name.value.to_ascii_uppercase();
    let full_name = title.map_or(short_name.as_str(), |t| t.value.as_str());
    let name_clash = protocols().find_map(|protocol| {
        let builtin = protocol.full;
        if protocol.filter == name.value {
            Some(format!("`{}` is already the filter name of Wireshark's `{builtin}`", name.value))
        } else if protocol.short == short_name {
            Some(format!(
                "`{}` makes the short name `{short_name}`, already that of Wireshark's `{builtin}`",
                name.value
            ))
        } else if title.is_none() && protocol.full == full_name {
            Some(format!(
                "`{}` makes the full name `{full_name}`, already that of Wireshark's `{}`",
                name.value, protocol.filter
            ))
        } else {
            None
        }
    });
    let title_clash = title
        .and_then(|_| protocols().find(|protocol| protocol.full == full_name))
        .map(|protocol| format!("`{full_name}` is already the full name of Wireshark's `{}`", protocol.filter));
    let clashes = [(name_clash, &name.span), (title_clash, title.map_or(&name.span, |t| &t.span))];
    for (message, span) in clashes {
        let Some(message) = message else { continue };
        diagnostics.push(
            Diagnostic::new(Name::ProtocolNameTaken, span.clone(), message)
                .with_note("Wireshark refuses to load a Dissector whose protocol names are taken", None)
                .with_note("built-in protocols vary with the Wireshark version and build", None),
        );
    }
}

/// The filter name of every built-in protocol of the snapshot.
#[cfg(test)]
pub(crate) fn filter_names() -> std::collections::BTreeSet<&'static str> {
    protocols().map(|protocol| protocol.filter).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_protocol_of_the_snapshot_has_its_three_names() {
        for line in SNAPSHOT.lines().filter(|line| !line.starts_with('#')) {
            assert_eq!(line.split('\t').count(), 3, "{line:?}");
        }
        assert!(protocols().any(|p| p.filter == "dns"), "the snapshot lists no protocols");
    }
}
