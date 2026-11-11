# Fields and Types

The top-level `fields:` is the layout of the payload: an ordered list of **Fields**, read one
after another from the start of the packet. There are no absolute offsets.

```yaml
name: demo
fields:
  - { name: msg_type, type: uint8 }
  - { name: length, type: uint16 }
  - { name: sender, type: ipv4 }
```

Each Field is shown in the protocol tree and can be filtered as `<protocol>.<name>`, here
`demo.msg_type`, `demo.length` and `demo.sender` (see [Filter names](#filter-names)).

## A Field

A Field is a mapping with a `name:` and exactly one key saying what it is. This chapter covers
`type:` with a built-in type or a [Type](#types), and `fields:` with an
[inline structure](#inline-structures); `switch:` picks a layout among several (see
[`switch:`](conditionals.md#switch)).

- Leaving all of them out is the error
  [`missing-field-kind`](../diagnostics.md#missing-field-kind); giving more than one is
  [`conflicting-field-kind`](../diagnostics.md#conflicting-field-kind).
- `name:` is a lowercase letter, then lowercase letters, digits or `_`: `msg_type`, `v2`.
  Anything else is [`invalid-field-name`](../diagnostics.md#invalid-field-name).
- Two Fields of one structure cannot share a name
  ([`duplicate-field-name`](../diagnostics.md#duplicate-field-name)).
- The only entry of a structure without a `name:` is `{ padding: n }`, bytes to skip (see
  [Padding](#padding)).

The tree shows a Field under a label derived from its name: `_` becomes a space and the first
letter is capitalised, so `msg_type` is shown as "Msg type". `label:` replaces it (see
[Tree text](#tree-text)).

## Built-in types

Built-in names describe the bytes on the wire. Every one in this table has a fixed size, so a
Field of one of them takes no `size:`, `prefix:` or `terminator:`
([`unexpected-length`](../diagnostics.md#unexpected-length)). `string` and `bytes` are as long
as one of those keys says (see [Sizes](sizes.md)), and the timestamps
`abs_time` and `rel_time` as long as their encoding says (see [Timestamps](#timestamps)).

| Type | Bytes | Value |
|---|---|---|
| `uint8` `uint16` `uint24` `uint32` | 1, 2, 3, 4 | unsigned integer |
| `uint40` `uint48` `uint56` `uint64` | 5, 6, 7, 8 | unsigned integer, shown as 64-bit |
| `int8` `int16` `int24` `int32` | 1, 2, 3, 4 | signed integer, two's complement |
| `int40` `int48` `int56` `int64` | 5, 6, 7, 8 | signed integer, shown as 64-bit |
| `bool` | 1 | true when the byte is not zero |
| `float32` `float64` | 4, 8 | IEEE 754 floating point |
| `ipv4` | 4 | IPv4 address |
| `ipv6` | 16 | IPv6 address |
| `ether` | 6 | Ethernet (MAC-48) address |
| `eui64` | 8 | EUI-64 identifier |
| `guid` | 16 | GUID (UUID) |

A `type:` starting with an uppercase letter names a [Type](#types) instead. A lowercase `type:`
naming none of these built-ins is [`unknown-type`](../diagnostics.md#unknown-type).

```yaml
name: sensor
fields:
  - { name: sensor_id, type: uint24 }
  - { name: timestamp_ms, type: uint48 }
  - { name: offset, type: int16 }
  - { name: temperature, type: float32 }
  - { name: calibrated, type: bool }
  - { name: gateway, type: ether }
  - { name: device, type: guid }
```

## Byte order {#byte-order}

Fields are big-endian (network byte order) unless `endian:` says otherwise. The top-level
`endian:` sets the default for the whole description, an
[inline structure](#inline-structures)'s `endian:` the default for the Fields inside it, and a
Field's own `endian:` overrides both. A [Type](#types) is read in its own byte order: its
`endian:`, else the top-level one. The value is `big` or `little`
([`invalid-endian`](../diagnostics.md#invalid-endian)).

```yaml
name: sensor
endian: little
fields:
  - { name: reading, type: int32 }
  - { name: port, type: uint16, endian: big }
  - { name: sample, type: float64 }
```

Byte order applies to the multi-byte integers, `float32`, `float64`, `ipv4`, `eui64` and
`guid`. A little-endian `guid` is the mixed-endian layout Windows uses, with its first three
groups reversed. It also applies to a [`prefix:`](sizes.md#prefix) count, to `utf16` and
`ucs2` text (see [Strings and bytes](#strings-and-bytes)) and to every timestamp encoding (see
[Timestamps](#timestamps)). Single bytes, `ipv6`, `ether` and raw `bytes` have no byte order,
so `endian:` does not change them.

## Strings and bytes {#strings-and-bytes}

`string` is text and `bytes` is raw bytes. Neither has a size of its own: a Field of either
type gives its length with exactly one of `size:`, `prefix:` or `terminator:` (see
[Sizes](sizes.md)).

```yaml
name: chat
fields:
  - { name: room, type: string, size: 8 }
  - { name: nick, type: string, prefix: uint8 }
  - { name: client, type: string, terminator: 0 }
  - { name: digest, type: bytes, size: 16, display: colon }
```

`encoding:` says how a `string`'s bytes become text. Besides `string`, only the timestamps take
it (see [Timestamps](#timestamps)); on any other type it is
[`incompatible-display`](../diagnostics.md#incompatible-display).

| `encoding:` | Text | Default |
|---|---|---|
| `ascii` | 7-bit ASCII | |
| `utf8` | UTF-8 | yes |
| `utf16` | UTF-16, in the Field's byte order | |
| `ucs2` | UCS-2, in the Field's byte order | |
| `latin1` | ISO 8859-1 | |

A `utf16` or `ucs2` string ends at a 2-byte zero aligned on its 2-byte code units, so its
[`terminator:`](sizes.md#terminator) can only be `0`.

```yaml
name: files
endian: little
fields:
  - { name: share, type: string, terminator: 0, encoding: utf16 }
  - { name: host, type: string, size: 16, encoding: ascii }
  - { name: owner, type: string, prefix: uint16, encoding: latin1 }
```

## Timestamps {#timestamps}

`abs_time` is a point in time and `rel_time` a duration. `encoding:` says how the bytes count
time, and so how many bytes the Field reads: a timestamp takes no `size:`, `prefix:` or
`terminator:` ([`unexpected-length`](../diagnostics.md#unexpected-length)).

| `encoding:` | Bytes | `abs_time` | `rel_time` | Default |
|---|---|---|---|---|
| `secs` | 4 | seconds since 1970-01-01 UTC | seconds | yes |
| `secs_nsecs` | 4 + 4 | seconds since 1970, then nanoseconds | seconds, then nanoseconds | |
| `ntp` | 8 | NTP: seconds since 1900, then a 32-bit fraction of a second | not taken | |
| `msecs` | 8 | milliseconds since 1970 | milliseconds | |
| `usecs` | 8 | microseconds since 1970 | microseconds | |
| `nsecs` | 8 | nanoseconds since 1970 | nanoseconds | |

Every encoding follows the Field's [byte order](#byte-order). `ntp` on a `rel_time`, or a text
encoding on a timestamp, is
[`incompatible-display`](../diagnostics.md#incompatible-display).

```yaml
name: clock
fields:
  - { name: sent, type: abs_time }
  - { name: received, type: abs_time, encoding: ntp, display: utc }
  - { name: logged, type: abs_time, encoding: usecs, endian: little }
  - { name: round_trip, type: rel_time, encoding: secs_nsecs }
  - { name: timeout, type: rel_time, encoding: msecs }
```

An `abs_time` is shown in the time zone of whoever views the capture unless `display:` says
otherwise (see [Display](#display)). A `rel_time` takes no `display:`.

## Display {#display}

`display:` says how a value is shown in the tree. Which values it takes depends on the type. For
integers:

| Type | `display:` | Default | Shows 258 as |
|---|---|---|---|
| unsigned integers | `dec` | yes | `258` |
| | `hex` | | `0x0102` |
| | `oct` | | `0402` |
| | `dec_hex` | | `258 (0x0102)` |
| | `hex_dec` | | `0x0102 (258)` |
| signed integers | `dec` | yes | `258` |

Hex digits are padded to the type's width. For `bytes`, `display:` picks the separator between
bytes:

| `display:` | Default | Shows `01 02 03` as |
|---|---|---|
| `plain` | yes | `010203` |
| `dot` | | `01.02.03` |
| `dash` | | `01-02-03` |
| `colon` | | `01:02:03` |
| `space` | | `01 02 03` |

For `abs_time`, `display:` picks the time zone:

| `display:` | Default | Shows 2024-01-01 00:00:00 UTC as |
|---|---|---|
| `local` | yes | in the viewer's time zone, such as `Jan  1, 2024 01:00:00.000000000 CET` |
| `utc` | | `Jan  1, 2024 00:00:00.000000000 UTC` |
| `doy_utc` | | `2024/001:00:00:00.000000000 UTC`, with the day of the year |

`string`, `bool`, `float32`, `float64`, `rel_time` and the address types take no `display:`.
Any other combination is [`incompatible-display`](../diagnostics.md#incompatible-display).

```yaml
name: demo
fields:
  - { name: flags, type: uint8, display: hex }
  - { name: length, type: uint16 }
  - { name: mode, type: uint16, display: oct }
  - { name: session, type: uint32, display: hex_dec }
  - { name: station, type: bytes, size: 6, display: dash }
```

Display changes only what the tree shows: a filter matches the value whichever way it is
written, so `demo.flags == 16` and `demo.flags == 0x10` are the same filter.

## Value mappings {#value-mappings}

Three keys give a value words. Like `display:`, they change only what the tree shows: a filter
still matches the number, so `demo.msg_type == 1` finds every "Request".

| Key | Types | Shows |
|---|---|---|
| `values:` | integers | a label in place of the value, with the value after it: `Request (1)` |
| `true:` / `false:` | `bool` | a label for each state, in place of `True` and `False` |
| `unit:` | integers, `float32`, `float64` | the value, a space, then the unit: `16 bytes` |

On any other type, each of these keys is
[`incompatible-display`](../diagnostics.md#incompatible-display). A Field has `values:` or
`unit:`, not both ([`conflicting-mappings`](../diagnostics.md#conflicting-mappings)).

### Values tables

`values:` maps values to labels. A key is an integer, in decimal or hex, or a range of
integers written as a string `"low-high"`, both bounds included. A value with no key is shown
as `Unknown (7)`.

```yaml
name: demo
fields:
  - name: status
    type: uint16
    display: hex
    values:
      0x0000: OK
      0x0001: Retry
      0xffff: Failed
  - name: delta
    type: int8
    values:
      "-128--1": Behind
      0: Even
      "1-127": Ahead
```

A negative bound keeps its sign, so `"-128--1"` runs from -128 to -1. A key that is neither an
integer nor a range, such as `1.5` or a quoted `"16"`, and a range whose first bound is the
higher, are [`wrong-value-type`](../diagnostics.md#wrong-value-type); a key spelt twice is
[`duplicate-key`](../diagnostics.md#duplicate-key). Two keys matching one value, such as
`5` inside `"0-9"`, are [`overlapping-values`](../diagnostics.md#overlapping-values). A key the
Field's type cannot hold, such as `256` on a `uint8`, is the warning
[`unreachable-value`](../diagnostics.md#unreachable-value); a range is reported only when none
of its values fit. Each label is a non-empty single line
([`invalid-label`](../diagnostics.md#invalid-label)).

### Enums {#enums}

A table several Fields share is declared once as an **Enum**, under the top-level `enums:`, and
named by each Field's `values:`. A request and its response sharing an opcode table is the
typical case.

```yaml
name: demo
fields:
  - { name: msg_type, type: uint8, values: MsgType }
  - { name: reply_to, type: uint8, values: MsgType }
enums:
  MsgType:
    1: Request
    2: Response
    "16-31": Vendor
```

An Enum's name is an uppercase letter then letters or digits
([`invalid-type-name`](../diagnostics.md#invalid-type-name)). A `values:` naming no Enum is
[`unknown-enum`](../diagnostics.md#unknown-enum), and an Enum no Field names is the warning
[`unused-enum`](../diagnostics.md#unused-enum). An Enum's table follows the rules of an inline
one. A key outside the type of one Field using it is reported once, and is left out only for
that Field, so one Enum can serve a `uint8` and a `uint16`.

### States and units

`true:` and `false:` label the two states of a `bool`. Either can be given alone; the other
keeps its default, `True` or `False`.

```yaml
name: demo
fields:
  - { name: enabled, type: bool, true: Enabled, false: Disabled }
  - { name: urgent, type: bool, true: Urgent }
  - { name: length, type: uint16, unit: [byte, bytes] }
  - { name: timeout, type: uint32, unit: ms }
  - { name: distance, type: float32, unit: [metre, metres] }
```

`unit:` is one string, used whatever the value, or a `[singular, plural]` pair: the singular
when the value is 1, the plural otherwise. Here a length of 1 is shown as `1 byte` and a
length of 16 as `16 bytes`. A unit with one form is a plain string: a list holds exactly the
two forms ([`wrong-value-type`](../diagnostics.md#wrong-value-type)). Each form is a non-empty
single line ([`invalid-unit`](../diagnostics.md#invalid-unit)), and a value YAML would read as
a number or a bool needs quotes.

## Tree text {#tree-text}

`label:` is the text the tree shows for the Field, in place of the one derived from its name.
`description:` is a longer explanation, which Wireshark shows in the status bar when the
Field is selected and in its field reference.

```yaml
name: demo
fields:
  - { name: msg_type, type: uint8 }
  - name: seq
    type: uint32
    label: Sequence number
    description: Incremented by the sender for each message
```

Here `msg_type` is shown as "Msg type" and `seq` as "Sequence number". A label is a non-empty
single line ([`invalid-label`](../diagnostics.md#invalid-label)); a description is a single
line ([`invalid-description`](../diagnostics.md#invalid-description)). Both are plain text, so
a value YAML would read as a number or a bool, such as `label: 2` or `label: true`, needs
quotes.

## Inline structures {#inline-structures}

A Field with `fields:` in place of `type:` is an **inline structure**: a group of Fields read
one after another, shown as a subtree that spans the bytes they read. Its `fields:` is written
like the top-level one, a non-empty list of Fields
([`empty-fields`](../diagnostics.md#empty-fields)), and a Field inside it can be a structure
too, to any depth.

```yaml
name: demo
fields:
  - { name: msg_type, type: uint8 }
  - name: header
    label: Fixed header
    endian: little
    fields:
      - { name: length, type: uint16 }
      - name: flags
        fields:
          - { name: urgent, type: bool }
          - { name: priority, type: uint8 }
  - { name: payload, type: bytes, prefix: uint8 }
```

A structure takes `name:`, `label:`, `description:`, `count:` or `repeat:` to make it an
[array](arrays.md), [`if:`](conditionals.md) to read it only under a condition,
[`hidden:`](#hidden), and `endian:`, which is the byte order of the Fields inside it unless they
set their own (see [Byte order](#byte-order)). The keys that
say how a value is read or shown belong on the Fields inside: a length key on a structure is
[`unexpected-length`](../diagnostics.md#unexpected-length), and `display:`, `encoding:`,
`values:`, `true:`, `false:`, `unit:`, [`expect:`](#expect) or [`dissector:`](#dissector) is
[`incompatible-display`](../diagnostics.md#incompatible-display).

Only the Fields of one structure need different names: `header.length` and a top-level
`length` can live side by side.

## Types {#types}

A **Type** is a named group of Fields, declared once under the top-level `types:` and used by
any number of Fields with `type: <Name>`. A Field of a Type is shown like an inline structure: a
subtree holding the Type's Fields.

```yaml
name: demo
fields:
  - { name: req_hdr, type: Header, label: Request header }
  - { name: resp_hdr, type: Header, label: Response header }
types:
  Header:
    fields:
      - { name: length, type: uint16 }
      - { name: sent, type: Stamp }
  Stamp:
    endian: little
    fields:
      - { name: secs, type: uint32 }
      - { name: usecs, type: uint32 }
```

- `types:` maps each Type name to a body with a required `fields:`, written like an inline
  structure's, and an optional `endian:`. Types can be declared in any order and use each
  other.
- A Type name is an uppercase letter, then letters or digits: `Header`, `V2Header`
  ([`invalid-type-name`](../diagnostics.md#invalid-type-name)). Built-in types are all lowercase,
  so the two never clash.
- A Type is read in its own byte order: its `endian:`, else the top-level `endian:`, whatever
  structure the Field using it is in. A Field of a Type takes `name:`, `label:`,
  `description:`, `count:` or `repeat:` to make it an [array](arrays.md),
  [`if:`](conditionals.md) and [`hidden:`](#hidden) only: `endian:`
  on it is [`invalid-endian`](../diagnostics.md#invalid-endian),
  a length key [`unexpected-length`](../diagnostics.md#unexpected-length), and a display or
  value-mapping key, [`expect:`](#expect) or [`dissector:`](#dissector),
  [`incompatible-display`](../diagnostics.md#incompatible-display).
- Using a Type nobody declared is [`unknown-type`](../diagnostics.md#unknown-type), reported
  once however many Fields use it. Declaring a name twice is
  [`duplicate-key`](../diagnostics.md#duplicate-key). A Type that contains itself, directly or
  through other Types, is [`recursive-type`](../diagnostics.md#recursive-type), and a Type no
  Field uses is the warning [`unused-type`](../diagnostics.md#unused-type).

Type names never appear in filter names: each Field of a Type is filtered under the path of the
Field using it, so the example above gives `demo.req_hdr.length`, `demo.req_hdr.sent.secs`,
`demo.resp_hdr.length` and `demo.resp_hdr.sent.secs`, and a request header can be filtered
apart from a response header.

## Padding {#padding}

`{ padding: n }` in place of a Field skips `n` bytes. It can stand anywhere in a structure,
top-level, inline, in a Type or in a `switch` case, and takes no other key: no `name:`, so no
filter name, and nothing an Expression can read. The tree shows the bytes as one item,
"Padding".

```yaml
name: demo
fields:
  - { name: kind, type: uint8 }
  - { padding: 3 }                           # align `length` on 4 bytes
  - { name: length, type: uint16 }
  - { name: text, type: string, size: length }
  - { padding: "(4 - length % 4) % 4" }      # up to the next multiple of 4
  - { name: crc, type: uint32 }
```

`n` is a number of bytes or an [Expression](expressions.md), like a [`size:`](sizes.md#size). A negative
constant is [`invalid-padding`](../diagnostics.md#invalid-padding), and so is a constant
Expression that is negative or has no value. An Expression whose value turns out negative, or
has none, when a packet is read is reported as "Malformed" and the dissection stops; padding
past the end of the packet is "Malformed: truncated". Any key beside `padding:` is
[`unknown-key`](../diagnostics.md#unknown-key).

## Hidden Fields {#hidden}

`hidden: true` reads a Field without adding it to the tree. Expressions can still read it, and
display filters still match it: a hidden Field keeps its [filter name](#filter-names). Hiding a
structure, a Field of a Type, a [`switch`](conditionals.md#switch) Field or an
[array](arrays.md) hides everything in it; for a [bitfield](bitfields.md#hidden), the sub-Fields
can also be hidden one by one. `hidden: false` is the default.

```yaml
name: demo
fields:
  - { name: length, type: uint16, hidden: true }   # shown only through `data`
  - { name: data, type: bytes, size: length }
  - name: reserved
    hidden: true
    fields:
      - { name: a, type: uint32 }
      - { name: b, type: uint32 }
```

## Expected values {#expect}

`expect:` declares the values a Field should hold: one value, a `"low-high"` range string with
both bounds included, or a list mixing both. It goes on integer and `bool` Fields and on
[bitfield](bitfields.md) sub-Fields. A `bool` holds 0 or 1, as [Expressions](expressions.md)
read it.

```yaml
name: demo
fields:
  - { name: magic, type: uint32, display: hex, expect: 0xcafe }
  - { name: version, type: uint8, expect: [1, "5-7"] }
  - { name: ready, type: bool, expect: 1 }
  - name: flags
    type: uint8
    bits:
      - { name: reserved, width: 4, expect: 0 }
      - { name: kind, width: 4 }
```

A value outside it is not a malformed packet: the Dissector adds an expert info **warning** on
the Field, "Unexpected value: version (expected 1, 5-7)", filtered as
`<protocol>._protocol.unexpected`, and goes on reading. A hidden Field is checked too.

Values are written as in a [values table](#values-tables): an entry that is neither an integer
nor a range, a range whose first bound is the higher, and an empty list are
[`wrong-value-type`](../diagnostics.md#wrong-value-type). On any other type, `expect:` is
[`incompatible-display`](../diagnostics.md#incompatible-display). An `expect:` none of whose
values the Field's type can hold, such as `256` on a `uint8`, never matches: it is the warning
[`unreachable-expect`](../diagnostics.md#unreachable-expect), and every packet gets the expert
info.

## Handing bytes to another Dissector {#dissector}

`dissector:` on a `bytes` Field passes its bytes to a Dissector Wireshark already has, by the
name Wireshark registers it under: `json`, `http`, `data`, and so on. The Field is shown as
usual, then the other Dissector's layer right after it, in the same structure.

```yaml
name: demo
fields:
  - { name: length, type: uint16 }
  - { name: payload, type: bytes, size: length, dissector: json }
  - { name: trailer, type: bytes, prefix: uint8, dissector: data, hidden: true }
```

- The other layer is shown even when the Field is [hidden](#hidden): `hidden: true` with
  `dissector:` shows the decoded bytes but not the raw ones.
- A Field with no bytes calls no Dissector. The Protocol column keeps this protocol's name.
- Whether Wireshark has a Dissector by that name is known only when a packet is read. A name it
  does not know adds an expert info **warning**, even when the Field is empty, "Unknown Dissector <name>: payload", filtered
  as `<protocol>._undecoded.dissector`, and the dissection goes on.
- Bytes the other Dissector cannot read are its own malformed packet, shown in its layer; the
  dissection of this protocol goes on.

The name is one word: an empty name, one with a space, or a value that is not a string is
[`invalid-dissector`](../diagnostics.md#invalid-dissector). `dissector:` on any other type is
[`incompatible-display`](../diagnostics.md#incompatible-display).

## Filter names {#filter-names}

Every Field the tree shows, structures included, gets the display filter name
`<protocol>.<path>`, where the path is the chain of Field names from the top level down,
through inline structures and Fields of a [Type](#types), never through Type names. In the
example above they are `demo.msg_type`, `demo.header`, `demo.header.length`,
`demo.header.flags`, `demo.header.flags.urgent`, `demo.header.flags.priority` and
`demo.payload`. A filter on a structure, such as `demo.header.flags`, matches every packet
that has it. The sub-Fields of a [bitfield](bitfields.md) extend their container's name:
`demo.flags.ext`. The cases of a [`switch`](conditionals.md#switch-tree) add no segment, so
Fields of two cases can reach one filter name and share it.

Filter names are part of a Dissector's behaviour: users save filters and colouring rules
against them. Renaming a Field, or moving it into or out of a structure, changes its filter
name, and so breaks those filters. Wirdigen never renames a Field on its own: the filter name
is always the one the description spells.
