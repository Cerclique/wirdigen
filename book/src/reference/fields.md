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
letter is capitalised, so `msg_type` is shown as "Msg type".

## Built-in types

Built-in names describe the bytes on the wire. Every one of these has a fixed size, so a Field
of one of them takes no `size:`, `prefix:` or `terminator:`
([`unexpected-length`](../diagnostics.md#unexpected-length)).

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

A `type:` naming none of them is [`unknown-type`](../diagnostics.md#unknown-type). The
variable-length `string` and `bytes` and the timestamps `abs_time` and `rel_time` are part of
the format but not read by this version yet
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
groups reversed. Single bytes, `ipv6` and `ether` have no byte order, so `endian:` does not
change them.
