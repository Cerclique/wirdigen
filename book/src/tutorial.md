# Tutorial: UDP telemetry

This tutorial writes the Protocol Description of a small protocol from scratch, generates its
Dissector and watches it dissect real packets in tshark, Wireshark's command-line twin. It takes
about fifteen minutes.

You need the `wirdigen` command (see the
[README](https://github.com/Cerclique/wirdigen#install) to install it) and, for the last part,
Wireshark 4.4 or later with its `tshark` and `text2pcap` tools (see
[Installing a Dissector](installing.md#wireshark)). The finished description and its sample
packets are in the repository under
[`examples/telemetry/`](https://github.com/Cerclique/wirdigen/tree/main/examples/telemetry).

## The protocol {#protocol}

*Sensor Telemetry* is an invented protocol. A sensor node measures one quantity, temperature,
humidity or pressure, and sends each reading in a UDP datagram of its own to port 47100. A
datagram is 14 bytes, every number big-endian:

| Bytes | Field | Meaning |
|---|---|---|
| 1 | `version` | Protocol version, 1 |
| 2 | `node` | Identifier of the sending node |
| 4 | `seq` | Counts the node's datagrams from 1 |
| 1 | `sensor` | 1 temperature, 2 humidity, 3 pressure |
| 1 | `status` | Flags: low battery (top bit), calibrated (next bit), a 2-bit priority, 4 unused bits |
| 4 | `reading` | The measurement, an IEEE 754 single-precision float |
| 1 | `battery` | Charge left, in percent |

A first temperature reading of 21.5 from node `0x00a1` looks like this on the wire:

```text
01 00 a1 00 00 00 01 01 50 41 ac 00 00 57
```

## A first description {#first}

Create `telemetry.wirdigen.yaml` with the protocol's name and its first three Fields:

```yaml
name: telemetry
fields:
  - { name: version, type: uint8 }
  - { name: node, type: uint16 }
  - { name: seq, type: uint32 }
```

`name:` is the protocol's filter name in Wireshark, so it is lowercase. `fields:` lists the
payload's Fields in the order they come, each with a `name:` and a [type](reference/fields.md#built-in-types):
there are no offsets to compute. Fields are big-endian unless
[`endian:`](reference/fields.md#byte-order) says otherwise, which is what this protocol needs.

Generate the Dissector:

```text
wirdigen generate telemetry.wirdigen.yaml
```

The command prints nothing on success and writes `telemetry.lua` next to the description. This
is already a working Dissector, showing the first three Fields of every packet. The rest of the
tutorial fills in the other Fields and the details that make it pleasant to read.

## Labels for values {#enum}

A raw `sensor` of 2 means little to a reader of the capture. `values:` gives each value a label.
Here the labels are declared once as an **Enum**, under the top-level `enums:`, so other Fields
could share them later:

```yaml
name: telemetry
fields:
  - { name: version, type: uint8 }
  - { name: node, type: uint16, display: hex }
  - { name: seq, type: uint32 }
  - { name: sensor, type: uint8, values: Sensor }
enums:
  Sensor:
    1: Temperature
    2: Humidity
    3: Pressure
```

Wireshark now shows `Sensor: Humidity (2)`, and `Unknown (9)` for a value without a label. A
filter still matches the number: `telemetry.sensor == 2`. The node also gained
`display: hex`, since node identifiers are usually written in hex. See
[Value mappings](reference/fields.md#value-mappings) and [Display](reference/fields.md#display).

## Flags in a bitfield {#bitfield}

`status` packs two flags and a small number into one byte. A **Bitfield** splits it with
`bits:`, from the most significant bit down. Here is a first attempt:

```yaml,diagnostic=mismatched-bit-widths
name: telemetry
fields:
  - name: status
    type: uint8
    bits:
      - { name: low_battery, width: 1 }
      - { name: calibrated, width: 1 }
      - { name: priority, width: 2 }
```

`wirdigen generate` (or `wirdigen validate`, which checks without writing) refuses it, and
says why:

```text
$ wirdigen validate telemetry.wirdigen.yaml
error[mismatched-bit-widths]: these widths add up to 4 bits, but `uint8` has 8
 --> telemetry.wirdigen.yaml:5:5
  |
5 |     bits:
  |     ^^^^
  |
  = note: name every bit, or cover the gaps with `{ padding: <bits> }` entries
  = note: see https://cerclique.github.io/wirdigen/diagnostics.html#mismatched-bit-widths

error: 1 error in 1 of 1 file
```

Every bit must be accounted for. The four unused bits are `{ padding: 4 }`, and the priority
gets labels of its own, given inline this time since nothing else uses them:

```yaml
name: telemetry
fields:
  - name: status
    type: uint8
    display: hex
    bits:
      - { name: low_battery, width: 1 }
      - { name: calibrated, width: 1 }
      - { name: priority, width: 2, values: { 0: Low, 1: Normal, 2: High, 3: Critical } }
      - { padding: 4 }
```

The one-bit Sub-Fields are shown as `Set` or `Not set`, each with its bits marked as Wireshark
shows the flags of TCP, and can be filtered on their own: `telemetry.status.low_battery == 1`.
See [Bitfields](reference/bitfields.md).

## The reading and the battery {#reading}

The reading is a `float32`. The battery is a percentage, and `unit:` shows it after the value:

```yaml
name: telemetry
fields:
  - { name: reading, type: float32 }
  - { name: battery, type: uint8, unit: "%" }
```

## The Info column {#info}

Wireshark's packet list sums each packet up in its Info column. `info:` fills it from an
**Info Template**, with Fields named in braces:

```yaml
name: telemetry
info: "{sensor} {reading} from node {node}, seq {seq}"
fields:
  - { name: node, type: uint16, display: hex }
  - { name: seq, type: uint32 }
  - { name: sensor, type: uint8, values: { 1: Temperature, 2: Humidity, 3: Pressure } }
  - { name: reading, type: float32 }
```

Each Field shows as in the tree: the sensor's label, the node in hex. The first packet's Info
column reads `Temperature 21.5 from node 0x00a1, seq 1`. See [Info column](reference/info.md).

## Claiming the port {#registration}

So far the Dissector is only offered in Wireshark's *Decode As*: someone has to tell Wireshark
that port 47100 carries Sensor Telemetry. `registration:` claims the port by default:

```yaml
name: telemetry
registration:
  ports:
    udp: [47100]
fields:
  - { name: version, type: uint8 }
```

The port also becomes a preference, `telemetry.udp_ports`, which a user can change without
regenerating anything. See [Registration](reference/registration.md).

## The complete description {#complete}

Put together, with a `title:` for the root of the protocol tree, a `description:` for a few
Fields (Wireshark shows it as help text) and comments documenting the file:

```yaml
# Sensor Telemetry, an invented protocol: the example of the book's tutorial.
#
# A sensor node sends each reading in a UDP datagram of its own to port 47100. A datagram is
# 14 bytes, big-endian:
#
#   version  node  seq  sensor  status  reading  battery
#   1        2     4    1       1       4        1
name: telemetry
title: Sensor Telemetry
registration:
  ports:
    udp: [47100]
info: "{sensor} {reading} from node {node}, seq {seq}"
fields:
  - { name: version, type: uint8 }
  - { name: node, type: uint16, display: hex, description: "Identifier of the sending node" }
  - { name: seq, type: uint32, description: "Counts the node's datagrams from 1" }
  - { name: sensor, type: uint8, values: Sensor }
  - name: status
    type: uint8
    display: hex
    bits:
      - { name: low_battery, width: 1 }
      - { name: calibrated, width: 1 }
      - { name: priority, width: 2, values: { 0: Low, 1: Normal, 2: High, 3: Critical } }
      - { padding: 4 }
  - { name: reading, type: float32 }
  - { name: battery, type: uint8, unit: "%" }
enums:
  Sensor:
    1: Temperature
    2: Humidity
    3: Pressure
```

Generate it again:

```text
wirdigen generate telemetry.wirdigen.yaml
```

## Trying it in tshark {#tshark}

Without a sensor at hand, build a capture from hex. Save the repository's
[`packets.txt`](https://github.com/Cerclique/wirdigen/blob/main/examples/telemetry/packets.txt)
next to the description: five datagrams, each a commented line of hex in the format of
`text2pcap`. The last one is cut short on purpose.

```text
# Node 0x00a1, seq 1: Temperature 21.5, calibrated, Normal priority, battery 87 %.
0000  01 00 a1 00 00 00 01 01 50 41 ac 00 00 57
```

`text2pcap -u` wraps each one in a UDP datagram, here from port 40000 to port 47100:

```text
text2pcap -u 40000,47100 packets.txt telemetry.pcapng
```

`tshark -X lua_script:` loads a Dissector for one run, without installing it. Run it as your
usual user, not root: as root, tshark skips Lua scripts.

```text
$ tshark -X lua_script:telemetry.lua -r telemetry.pcapng
    1 0.000000000     10.1.1.1 → 10.2.2.2     TELEMETRY 60 Temperature 21.5 from node 0x00a1, seq 1
    2 0.000001000     10.1.1.1 → 10.2.2.2     TELEMETRY 60 Humidity 48.25 from node 0x00a1, seq 2
    3 0.000002000     10.1.1.1 → 10.2.2.2     TELEMETRY 60 Pressure 1013.25 from node 0x00b7, seq 7
    4 0.000003000     10.1.1.1 → 10.2.2.2     TELEMETRY 60 9 0 from node 0x00c3, seq 1
    5 0.000004000     10.1.1.1 → 10.2.2.2     TELEMETRY 60 Temperature  from node 0x00c3, seq 2
```

Port 47100 was recognised with no `-d` option: that is the registration at work. `-O telemetry`
prints the protocol tree of each packet:

```text
$ tshark -X lua_script:telemetry.lua -r telemetry.pcapng -O telemetry
...
Sensor Telemetry
    Version: 1
    Node: 0x00b7
    Seq: 7
    Sensor: Pressure (3)
    Status: 0xb0
        1... .... = Low battery: Set
        .0.. .... = Calibrated: Not set
        ..11 .... = Priority: Critical (3)
    Reading: 1013.25
    Battery: 9 %
```

Display filters work on every Field, `-Y` here and the filter bar in Wireshark:

```text
$ tshark -X lua_script:telemetry.lua -r telemetry.pcapng -Y "telemetry.status.low_battery == 1"
    3 0.000002000     10.1.1.1 → 10.2.2.2     TELEMETRY 60 Pressure 1013.25 from node 0x00b7, seq 7
```

The fifth datagram ends after its sensor byte. The Dissector shows what it could read and marks
the packet Malformed, rather than failing:

```text
Sensor Telemetry
    Version: 1
    Node: 0x00c3
    Seq: 2
    Sensor: Temperature (1)
    [Expert Info (Error/Malformed): Malformed: truncated: status]
```

To keep the Dissector in Wireshark for good, copy `telemetry.lua` into its personal Lua plugins
folder: see [Installing a Dissector](installing.md).

## Where next {#next}

[Example: TCP request/response](tcp-example.md) describes a protocol over TCP, with Framing,
a `switch` over Types and strings carrying their length.
[Example: tagged records](records-example.md) reads a list of records to the end of a datagram,
with `if:`, padding, hidden Fields, `expect:` and a handoff to Wireshark's JSON dissector. The
[Format reference](reference/cheat-sheet.md) covers every construct: strings and sizes, arrays,
`if:` and `switch:`, Types, Framing over TCP and Expressions. Every
mistake Wirdigen reports has an entry in the [Diagnostics index](diagnostics.md).
