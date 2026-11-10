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
`demo.msg_type`, `demo.length` and `demo.sender`.

## A Field

A Field is a mapping with a `name:` and exactly one key saying what it is. This chapter covers
`type:` with a built-in type.

- Leaving all of them out is the error
  [`missing-field-kind`](../diagnostics.md#missing-field-kind); giving more than one is
  [`conflicting-field-kind`](../diagnostics.md#conflicting-field-kind).
- `name:` is a lowercase letter, then lowercase letters, digits or `_`: `msg_type`, `v2`.
  Anything else is [`invalid-field-name`](../diagnostics.md#invalid-field-name).
- Two Fields of one structure cannot share a name
  ([`duplicate-field-name`](../diagnostics.md#duplicate-field-name)).

The tree shows a Field under a label derived from its name: `_` becomes a space and the first
letter is capitalised, so `msg_type` is shown as "Msg type". `label:` replaces it (see
[Tree text](#tree-text)).

## Built-in types

Built-in names describe the bytes on the wire. Every one in this table has a fixed size, so a
Field of one of them takes no `size:`, `prefix:` or `terminator:`
([`unexpected-length`](../diagnostics.md#unexpected-length)). `string` and `bytes` are as long
as one of those keys says (see [Strings and bytes](#strings-and-bytes)).

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

A `type:` naming none of them, nor `string` or `bytes`, is
[`unknown-type`](../diagnostics.md#unknown-type). The timestamps `abs_time` and `rel_time` are
part of the format but not read by this version yet
([`not-supported-yet`](../diagnostics.md#not-supported-yet)).

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
`endian:` sets the default for the whole description, and a Field's own `endian:` overrides
it. The value is `big` or `little`
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
groups reversed. It also applies to a `prefix:` count and to `utf16` and `ucs2` text (see
[Strings and bytes](#strings-and-bytes)). Single bytes, `ipv6`, `ether` and raw `bytes` have
no byte order, so `endian:` does not change them.

## Strings and bytes {#strings-and-bytes}

`string` is text and `bytes` is raw bytes. Neither has a size of its own: a Field of either
type gives its length with exactly one of these keys.

| Key | The value ends |
|---|---|
| `size: <n>` | after `n` bytes, a constant of zero or more |
| `prefix: <type>` | after as many bytes as the unsigned integer just before it says: `uint8` to `uint64`, in the Field's byte order |
| `terminator: <byte>` | before the first byte of that value, from 0 to 255; the terminator is read but not shown |

```yaml
name: chat
fields:
  - { name: room, type: string, size: 8 }
  - { name: nick, type: string, prefix: uint8 }
  - { name: text, type: string, prefix: uint16 }
  - { name: client, type: string, terminator: 0 }
  - { name: digest, type: bytes, size: 16, display: colon }
  - { name: extension, type: bytes, prefix: uint32 }
```

Leaving all three out is [`missing-length`](../diagnostics.md#missing-length), and giving more
than one is [`conflicting-length`](../diagnostics.md#conflicting-length). A negative `size:` is
[`invalid-size`](../diagnostics.md#invalid-size), a `prefix:` that is not an unsigned integer
type is [`invalid-prefix`](../diagnostics.md#invalid-prefix), and a `terminator:` outside 0 to
255 is [`invalid-terminator`](../diagnostics.md#invalid-terminator). This version takes only a
constant `size:`; a size computed from earlier Fields is not read yet
([`not-supported-yet`](../diagnostics.md#not-supported-yet)).

The tree shows the value bytes only: the `prefix:` count and the terminator are read but not
highlighted with the value. When the packet ends before the value does, or before a
terminator is found, the Dissector reports "Malformed: truncated" on that Field and stops.

`encoding:` says how a `string`'s bytes become text. It takes no other type
([`incompatible-display`](../diagnostics.md#incompatible-display)).

| `encoding:` | Text | Default |
|---|---|---|
| `ascii` | 7-bit ASCII | |
| `utf8` | UTF-8 | yes |
| `utf16` | UTF-16, in the Field's byte order | |
| `ucs2` | UCS-2, in the Field's byte order | |
| `latin1` | ISO 8859-1 | |

A `utf16` or `ucs2` string ends at a 2-byte zero aligned on its 2-byte code units, so its
`terminator:` can only be `0`.

```yaml
name: files
endian: little
fields:
  - { name: share, type: string, terminator: 0, encoding: utf16 }
  - { name: host, type: string, size: 16, encoding: ascii }
  - { name: owner, type: string, prefix: uint16, encoding: latin1 }
```

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

`string`, `bool`, `float32`, `float64` and the address types take no `display:`. Any other
combination is [`incompatible-display`](../diagnostics.md#incompatible-display).

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
