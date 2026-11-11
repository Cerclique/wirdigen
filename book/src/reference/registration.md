# Registration

**Registration** is how a Dissector attaches to traffic in Wireshark: the ports it claims by
default, and its place in Decode As. `registration:` is optional; leaving it out means Decode As
only.

```yaml
name: demo
registration:
  ports:
    udp: [5000, "6000-6010"]
fields:
  - { name: id, type: uint8 }
```

Here Wireshark decodes UDP port 5000 and ports 6000 to 6010 as `demo` with no setup.

## Ports {#ports}

`ports:` declares the ports per transport, under `udp:`, `tcp:` or both. Each is a list whose
items are a port or a `"low-high"` range, both bounds included, written like the ranges of
[`values:`](fields.md):

- A port is a YAML integer from 1 to 65535: port 0 and larger numbers are
  [`invalid-port`](../diagnostics.md#invalid-port), and so is a range reaching them.
- A range is a string of two integers with the lower one first; `"6010-6000"` is
  [`wrong-value-type`](../diagnostics.md#wrong-value-type), and so is a quoted single port such
  as `"5000"`.
- A port is declared once per transport: a port listed twice, spelt twice (`5000` and
  `0x1388`) or inside a range of the same list is
  [`overlapping-ports`](../diagnostics.md#overlapping-ports). The same port on UDP and on TCP is
  fine.
- A transport is declared with at least one port: `udp: []` is
  [`wrong-value-type`](../diagnostics.md#wrong-value-type). Leave the transport out instead.

```yaml
name: demo
registration:
  ports:
    udp: [5000, "6000-6010"]
    tcp: [5000]
framing:
  header: 2
  length: "len + 2"
fields:
  - { name: len, type: uint16 }
  - { name: body, type: bytes, size: len }
```

## TCP and Framing {#tcp}

On TCP, a message can be split across segments, and a segment can hold several messages.
`framing:` tells the Dissector where each message ends. TCP ports without `framing:` are the
warning [`tcp-without-framing`](../diagnostics.md#tcp-without-framing): each segment is then
dissected as one message, which is right only when every message travels in a segment of its
own.

```yaml,diagnostic=tcp-without-framing
name: demo
registration:
  ports:
    tcp: [5000]
fields:
  - { name: id, type: uint8 }
```

## Port preferences {#preferences}

Each transport with declared ports gets a preference of the protocol, listed in Wireshark's
preferences under the protocol's title, which defaults to the declared ports:

| Transport | Preference | Label |
|---|---|---|
| UDP | `<name>.udp_ports` | UDP port(s) |
| TCP | `<name>.tcp_ports` | TCP port(s) |

Changing a preference moves the Dissector: it stops claiming the old ports and claims the new
ones. From the command line, `tshark -o demo.udp_ports:7000-7005` does the same for one run. A
transport with no declared ports has no preference.

## Decode As {#decode-as}

Every Dissector is offered in Wireshark's Decode As, on both UDP and TCP ports, whether or not it
declares ports. No key controls this. A description without `registration:` is used through
Decode As only, or from the command line:

```text
tshark -X lua_script:demo.lua -d udp.port==5000,demo
```
