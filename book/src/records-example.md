# Example: tagged records

The [tutorial](tutorial.md) and the [TCP example](tcp-example.md) described messages whose
layout the header decides once. This example walks through a protocol whose datagrams carry a
list of records, each saying what it is and how long it is: it reads them with an
[array](reference/arrays.md) that runs to the end of the datagram, reads a Field only when a flag
says it is there with [`if:`](reference/conditionals.md#if), skips filler bytes with
[Padding](reference/fields.md#padding), keeps bookkeeping Fields out of the tree with
[`hidden:`](reference/fields.md#hidden), warns about values the protocol never sends with
[`expect:`](reference/fields.md#expect), and makes a Handoff of JSON to Wireshark's own
Dissector with [`dissector:`](reference/fields.md#dissector).

The finished description and its sample packets are in the repository under
[`examples/tracker/`](https://github.com/Cerclique/wirdigen/tree/main/examples/tracker). To run
them you need the same tools as the tutorial: `wirdigen`, and Wireshark 4.4 or later with
`tshark` and `text2pcap`.

## The protocol {#protocol}

*Asset Tracker* is an invented protocol. A tracker fixed to a shipping container sends UDP
datagrams to port 47300. Each datagram starts with a header, every number big-endian:

| Bytes | Field | Meaning |
|---|---|---|
| 2 | `magic` | Always `0x4154`, "AT" in ASCII |
| 1 | `version` | Protocol version, 1 |
| 1 | `flags` | The top bit is set while the container is on a trip; the other bits are 0 |
| 2 | `asset` | Identifier of the container |
| 4 | `trip` | Identifier of the trip, only when the top bit of `flags` is set |

Records follow, up to the end of the datagram. Each record is:

| Bytes | Field | Meaning |
|---|---|---|
| 1 | `tag` | What the record holds: 1 Position, 2 Heading, 3 Note, 4 Manifest |
| 1 | `length` | Size of the value |
| `length` | value | Depends on the tag |
| 0 to 3 | padding | Zero bytes, so the next record starts at a multiple of 4 bytes |

A Position is a latitude and a longitude, each a signed 4-byte number of millionths of a
degree. A Heading is 2 bytes, 0 to 359 degrees. A Note is text. A Manifest is a JSON document
listing what the container holds. A tracker may send tags this description does not know: their
value is skipped by its length.

A Heading of 90 degrees is a record of 4 bytes, with no padding:

```text
02 02 00 5a
```

## A Field that may be absent {#if}

`trip` is in the datagram only when the top bit of `flags` is set. A
[Bitfield](reference/bitfields.md) names that bit, and `if:` reads `trip` only when it is
non-zero:

```yaml
name: tracker
fields:
  - { name: magic, type: uint16, display: hex }
  - { name: version, type: uint8 }
  - name: flags
    type: uint8
    display: hex
    bits:
      - { name: on_trip, width: 1 }
      - { padding: 7 }
  - { name: asset, type: uint16 }
  - { name: trip, type: uint32, if: flags.on_trip }
```

`if:` takes an [Expression](reference/expressions.md): `flags.on_trip` is the sub-Field's value,
0 or 1. When it is 0, `trip` adds nothing to the tree and reads no bytes, so the records start
right after `asset`. See [`if:`](reference/conditionals.md#if).

## Records to the end {#records}

The records are an array of one **Type**, `Record`, read with `repeat: to_end` until no bytes
are left in the datagram. A record's value is a `switch` on its tag, as in the
[TCP example](tcp-example.md#switch), with inline Fields for each case:

```yaml
name: tracker
fields:
  - { name: asset, type: uint16 }
  - { name: records, type: Record, repeat: to_end }
types:
  Record:
    fields:
      - { name: tag, type: uint8, values: Tag }
      - { name: length, type: uint8 }
      - name: value
        switch: tag
        cases:
          1:
            - { name: latitude, type: int32 }
            - { name: longitude, type: int32 }
          2: [ { name: heading, type: uint16, unit: [degree, degrees] } ]
          3: [ { name: note, type: string, size: length } ]
        default:
          - { name: data, type: bytes, size: length }
enums:
  Tag:
    1: Position
    2: Heading
    3: Note
```

Each record is an Element of the array, its own subtree item: `Records [0]`, `Records [1]` and
so on; there is no item for the array as a whole. Every Element shares the same filter names:
`tracker.records.tag == 2` matches every datagram with at least one Heading. See
[Arrays](reference/arrays.md).

The note and the unknown tags take their size from `length`, an earlier Field of the same
record. Position and Heading have a fixed size and do not need it.

Nothing can follow an array that runs to the end, so a Field after it is the warning
[`unreachable-field`](diagnostics.md#unreachable-field):

```yaml,diagnostic=unreachable-field
name: tracker
fields:
  - name: records
    repeat: to_end
    fields:
      - { name: tag, type: uint8 }
  - { name: checksum, type: uint16 }
```

## Padding and hidden Fields {#padding}

Each record ends with zero bytes up to a multiple of 4. A record is 2 bytes of tag and length
plus `length` bytes of value, so the Padding is `(4 - (length + 2) % 4) % 4` bytes.
`{ padding: … }` takes that Expression and skips the bytes as a single "Padding" item, with no
filter name:

```yaml
name: tracker
fields:
  - name: records
    repeat: to_end
    fields:
      - { name: tag, type: uint8 }
      - { name: length, type: uint8, hidden: true }
      - { name: value, type: bytes, size: length }
      - { padding: "(4 - (length + 2) % 4) % 4" }
```

The length matters to the Dissector, not to someone reading the tree: the value's item already
covers its bytes. `hidden: true` reads the Field without showing it. It can still be used in
Expressions, as here, and in display filters: `tracker.records.length > 100` still works. See
[Padding](reference/fields.md#padding) and [Hidden Fields](reference/fields.md#hidden).

## Values the protocol never sends {#expect}

`magic` is always `0x4154` and `version` is always 1, so showing them in every tree tells the
reader nothing. A value that differs, though, is worth knowing about: it may be another protocol
on the same port, or a newer tracker. `expect:` checks a Field's value and adds an expert info
warning when it does not match, and the dissection goes on:

```yaml
name: tracker
fields:
  - { name: magic, type: uint16, display: hex, hidden: true, expect: 0x4154 }
  - { name: version, type: uint8, expect: 1 }
  - { name: heading, type: uint16, unit: [degree, degrees], expect: "0-359" }
```

`expect:` takes a value, a `"low-high"` range or a list of both. It works on hidden Fields too,
so `magic` is hidden and still checked. Every warning is filtered as
`tracker._protocol.unexpected`. See [Expected values](reference/fields.md#expect).

## Handoff to Wireshark's JSON Dissector {#handoff}

A Manifest is JSON, which Wireshark already knows how to show. `dissector:` on a `bytes` Field
makes a Handoff: it passes the Field's bytes to a Dissector by name, here `json`, whose tree
goes right after the Field's item:

```yaml
name: tracker
fields:
  - { name: length, type: uint8 }
  - { name: manifest, type: bytes, size: length, dissector: json }
```

The name is the one Wireshark registers the Dissector under. A name Wireshark does not know is
a warning on the packet, not an error, and the dissection goes on. See
[Handing bytes to another Dissector](reference/fields.md#dissector).

## The complete description {#complete}

Put together, with the Info column showing the asset, the port and a few `description:`s:

```yaml
# Asset Tracker, an invented protocol: the book's tagged records example.
#
# A tracker fixed to a shipping container sends UDP datagrams to port 47300. Each one starts
# with a 6-byte header, big-endian, then a 4-byte trip number when the top bit of `flags` is set:
#
#   magic  version  flags  asset  [trip]
#   2      1        1      2      4
#
# Records follow up to the end of the datagram. Each is a tag, the length of its value, the
# value, then zero bytes up to a multiple of 4. A manifest record is JSON, handed to Wireshark's
# own JSON Dissector.
name: tracker
title: Asset Tracker
registration:
  ports:
    udp: [47300]
info: "Asset {asset}"
fields:
  - { name: magic, type: uint16, display: hex, hidden: true, expect: 0x4154 }
  - { name: version, type: uint8, expect: 1 }
  - name: flags
    type: uint8
    display: hex
    bits:
      - { name: on_trip, width: 1 }
      - { padding: 7 }
  - { name: asset, type: uint16, description: "Identifier of the tracked container" }
  - { name: trip, type: uint32, if: flags.on_trip, description: "Present while on a trip" }
  - { name: records, type: Record, repeat: to_end }
types:
  Record:
    fields:
      - { name: tag, type: uint8, values: Tag }
      - { name: length, type: uint8, hidden: true }
      - name: value
        switch: tag
        cases:
          1:
            - { name: latitude, type: int32, description: "Millionths of a degree" }
            - { name: longitude, type: int32, description: "Millionths of a degree" }
          2: [ { name: heading, type: uint16, unit: [degree, degrees], expect: "0-359" } ]
          3: [ { name: note, type: string, size: length } ]
          4: [ { name: manifest, type: bytes, size: length, dissector: json } ]
        default:
          - { name: data, type: bytes, size: length }
      - { padding: "(4 - (length + 2) % 4) % 4" }
enums:
  Tag:
    1: Position
    2: Heading
    3: Note
    4: Manifest
```

Generate the Dissector:

```text
wirdigen generate tracker.wirdigen.yaml
```

## Trying it in tshark {#tshark}

The repository's
[`packets.txt`](https://github.com/Cerclique/wirdigen/blob/main/examples/tracker/packets.txt)
holds four datagrams, in the hex format of `text2pcap`:

1. asset 7 on trip 42, with a Position, a Heading, a Note and a Manifest;
2. asset 7 off trip, with a record of tag `0x7f`, which the description does not know, and a
   Heading of 400 degrees;
3. asset 9 with a wrong magic and version 2, then a Heading;
4. asset 9 with a Note whose length claims 8 bytes when 2 are left.

```text
text2pcap -u 40000,47300 packets.txt tracker.pcapng
```

```text
$ tshark -X lua_script:tracker.lua -r tracker.pcapng
    1 0.000000000     10.1.1.1 → 10.2.2.2     TRACKER 96 Asset 7
    2 0.000001000     10.1.1.1 → 10.2.2.2     TRACKER 60 Asset 7
    3 0.000002000     10.1.1.1 → 10.2.2.2     TRACKER 60 Asset 9
    4 0.000003000     10.1.1.1 → 10.2.2.2     TRACKER 60 Asset 9
```

The first datagram has every kind of record. `Trip` is there because `On trip` is set, `Magic`
and the lengths are hidden, each record ends with its padding, and the Manifest's bytes are
followed by the JSON Dissector's own tree:

```text
$ tshark -X lua_script:tracker.lua -r tracker.pcapng -O tracker,json
...
Asset Tracker
    Version: 1
    Flags: 0x80
        1... .... = On trip: Set
    Asset: 7
    Trip: 42
    Records [0]
        Tag: Position (1)
        Value: Position
            Latitude: 48858400
            Longitude: 2294500
        Padding
    Records [1]
        Tag: Heading (2)
        Value: Heading
            Heading: 90 degrees
        Padding
    Records [2]
        Tag: Note (3)
        Value: Note
            Note: door open
        Padding
    Records [3]
        Tag: Manifest (4)
        Value: Manifest
            Manifest: 7b2270616c6c657473223a337d
            JavaScript Object Notation
                Object
                    Member: pallets
                        [Path with value: /pallets:3]
                        [Member with value: pallets:3]
                        Number value: 3
                        Key: pallets
                        [Path: /pallets]
        Padding
```

A Heading's padding item covers no byte: it is shown even when the amount is 0.

In the second datagram, `trip` is absent, the unknown tag falls to `default:` and the Heading
gets its warning:

```text
Asset Tracker
    Version: 1
    Flags: 0x00
        0... .... = On trip: Not set
    Asset: 7
    Records [0]
        Tag: Unknown (127)
        Value: 127
            Data: deadbe
        Padding
    Records [1]
        Tag: Heading (2)
        Value: Heading
            Heading: 400 degrees
                [Expert Info (Warning/Protocol): Unexpected value: records.value.heading (expected 0-359)]
                    [Unexpected value: records.value.heading (expected 0-359)]
                    [Severity level: Warning]
                    [Group: Protocol]
        Padding
```

The third datagram has two warnings, but the tree shows only the version's: the magic's is on a
hidden item. It is still in the packet, so a filter finds it, and so do Wireshark's
*Analyze → Expert Information* and tshark's summary of them:

```text
$ tshark -q -X lua_script:tracker.lua -r tracker.pcapng -z expert,warn

Errors (1)
=============
   Frequency      Group           Protocol  Summary
           1  Malformed            TRACKER  Malformed: truncated: records.value.note

Warns (3)
=============
   Frequency      Group           Protocol  Summary
           1   Protocol            TRACKER  Unexpected value: records.value.heading (expected 0-359)
           1   Protocol            TRACKER  Unexpected value: magic (expected 0x4154)
           1   Protocol            TRACKER  Unexpected value: version (expected 1)
```

```text
$ tshark -X lua_script:tracker.lua -r tracker.pcapng -Y tracker._protocol.unexpected
    2 0.000001000     10.1.1.1 → 10.2.2.2     TRACKER 60 Asset 7
    3 0.000002000     10.1.1.1 → 10.2.2.2     TRACKER 60 Asset 9
```

The error above is the fourth datagram's: its Note claims more bytes than are left, so the
record is reported truncated and the packet Malformed, and the array stops there.
