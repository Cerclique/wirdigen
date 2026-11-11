//! `registration:` (spec §3.12): the ports a Dissector claims by default, read in stage 2 and
//! checked in stage 4.
//!
//! Decode As takes no key: every Dissector is offered on both transports whatever it declares,
//! so only the ports are read here.

use std::ops::Range;

use crate::diagnostic::{Diagnostic, Name, record};
use crate::keys::{Spanned, read_keys, wrong_type};
use crate::mapping::{self, Key};
use crate::yaml::{Node, Value};

/// The lowest port a Dissector can claim: port 0 is reserved.
const PORT_MIN: i128 = 1;
/// The highest port number.
const PORT_MAX: i128 = u16::MAX as i128;

/// A transport ports are declared on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    /// Every transport, in the order the keys of `ports:` are documented.
    const ALL: [Transport; 2] = [Transport::Udp, Transport::Tcp];

    /// The key of `ports:` declaring the transport's ports.
    pub(crate) const fn key(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
        }
    }

    /// The Wireshark dissector table of the transport's ports.
    pub(crate) const fn table(self) -> &'static str {
        match self {
            Transport::Udp => "udp.port",
            Transport::Tcp => "tcp.port",
        }
    }

    /// The name of the transport's range preference, under the protocol's filter name.
    pub(crate) const fn preference(self) -> &'static str {
        match self {
            Transport::Udp => "udp_ports",
            Transport::Tcp => "tcp_ports",
        }
    }

    /// How Wireshark's preferences name the transport: `UDP`, `TCP`.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Transport::Udp => "UDP",
            Transport::Tcp => "TCP",
        }
    }
}

/// The ports of one transport, as written.
#[derive(Debug, Clone)]
struct RawPorts {
    transport: Transport,
    /// Where the transport's key is written, where `tcp-without-framing` is reported.
    key: Range<usize>,
    /// The ports, each one port or a range, not yet checked against the port numbers.
    ports: Vec<Spanned<Key>>,
}

/// A `registration:` as written, after stage 2. Leaving it out declares no port.
#[derive(Debug, Clone, Default)]
pub(crate) struct RawRegistration {
    /// The transports with declared ports, in source order.
    transports: Vec<RawPorts>,
}

/// The validated ports of one transport, which the Dissector registers on by default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ports {
    pub(crate) transport: Transport,
    /// The ports in source order, each an inclusive range, `low == high` for a single port.
    pub(crate) ranges: Vec<(u16, u16)>,
}

/// Stage 2: reads `registration:`, pushing its errors.
pub(crate) fn read(node: &Node, errors: &mut Vec<Diagnostic>) -> RawRegistration {
    let Value::Mapping(entries) = &node.value else {
        errors.push(
            wrong_type(node.span.clone(), "`registration` must be a mapping")
                .with_note("write `registration: { ports: { udp: [5000] } }`", None),
        );
        return RawRegistration::default();
    };
    let keys = read_keys(entries, &["ports"], errors);
    let Some(ports) = keys.get("ports") else { return RawRegistration::default() };
    let Value::Mapping(entries) = &ports.value else {
        errors.push(wrong_type(ports.span.clone(), "`ports` must map `udp` or `tcp` to a list of ports"));
        return RawRegistration::default();
    };
    let keys = read_keys(entries, &Transport::ALL.map(Transport::key), errors);
    let transports = Transport::ALL
        .into_iter()
        .filter_map(|transport| {
            let (key, value) = keys.key_of(transport.key()).zip(keys.get(transport.key()))?;
            let ports = read_ports(transport, value, errors)?;
            Some(RawPorts { transport, key: key.span.clone(), ports })
        })
        .collect();
    RawRegistration { transports }
}

/// Reads the ports of `transport`: a non-empty list of ports and `"low-high"` ranges. Every
/// item that is neither is reported; the transport is dropped when any is.
fn read_ports(transport: Transport, node: &Node, errors: &mut Vec<Diagnostic>) -> Option<Vec<Spanned<Key>>> {
    let key = transport.key();
    let items = match &node.value {
        Value::Sequence(items) if !items.is_empty() => items,
        Value::Sequence(_) => {
            errors.push(
                wrong_type(node.span.clone(), format!("`{key}` must list at least one port"))
                    .with_note(format!("remove `{key}`, or write the ports the Dissector claims"), None),
            );
            return None;
        }
        _ => {
            errors.push(
                wrong_type(node.span.clone(), format!("`{key}` must be a list of ports"))
                    .with_note(format!("write `{key}: [5000, \"6000-6010\"]`"), None),
            );
            return None;
        }
    };
    let ports: Vec<Option<Spanned<Key>>> = items
        .iter()
        .map(|item| {
            let port = match &item.value {
                Value::Scalar { .. } => mapping::read_key(item),
                _ => Err(wrong_type(item.span.clone(), "a port must be an integer or a range")),
            };
            record(port, errors).map(|value| Spanned { value, span: item.span.clone() })
        })
        .collect();
    ports.into_iter().collect()
}

/// Stage 4: the ports of each transport. A port outside 1–65535 is `invalid-port`, a port
/// declared twice on one transport `overlapping-ports`; TCP ports without `framing:` are the
/// warning `tcp-without-framing`.
pub(crate) fn check(raw: &RawRegistration, framing: bool, diagnostics: &mut Vec<Diagnostic>) -> Vec<Ports> {
    raw.transports.iter().map(|ports| check_ports(ports, framing, diagnostics)).collect()
}

fn check_ports(raw: &RawPorts, framing: bool, diagnostics: &mut Vec<Diagnostic>) -> Ports {
    if raw.transport == Transport::Tcp && !framing {
        diagnostics.push(
            Diagnostic::new(Name::TcpWithoutFraming, raw.key.clone(), "TCP ports are declared without `framing`")
                .with_note(
                    "each TCP segment is dissected as one message; add `framing:` to find messages in the stream",
                    None,
                ),
        );
    }
    let mut valid: Vec<&Spanned<Key>> = Vec::new();
    for port in &raw.ports {
        let Key { low, high, .. } = port.value;
        if low < PORT_MIN || high > PORT_MAX {
            diagnostics.push(Diagnostic::new(Name::InvalidPort, port.span.clone(), "ports run from 1 to 65535"));
        } else if let Some(first) = valid.iter().find(|v| v.value.low <= high && low <= v.value.high) {
            diagnostics.push(
                Diagnostic::new(
                    Name::OverlappingPorts,
                    port.span.clone(),
                    format!("a port is declared twice on {}", raw.transport.label()),
                )
                .with_note("first declared here", Some(first.span.clone())),
            );
        } else {
            valid.push(port);
        }
    }
    let ranges = valid
        .iter()
        .map(|port| {
            let bound = |value: i128| u16::try_from(value).expect("checked against PORT_MIN and PORT_MAX");
            (bound(port.value.low), bound(port.value.high))
        })
        .collect();
    Ports { transport: raw.transport, ranges }
}
