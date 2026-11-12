# Sizes

A Field of a fixed-size built-in type (`uint16`, `ipv4`, `abs_time`, …) knows how many bytes it
reads. A `string` or `bytes` Field does not: it says where its value ends with exactly one of
these keys.

| Key | The value ends |
|---|---|
| [`size: <n>`](#size) | after `n` bytes: a constant of zero or more, or an [Expression](expressions.md) |
| [`size: "_remaining"`](#remaining) | at the end of the message |
| [`prefix: <type>`](#prefix) | after as many bytes as the unsigned integer just before it says |
| [`terminator: <byte>`](#terminator) | before the first byte of that value |

```yaml
name: chat
fields:
  - { name: room, type: string, size: 8 }
  - { name: nick, type: string, prefix: uint8 }
  - { name: client, type: string, terminator: 0 }
  - { name: digest, type: bytes, size: 16, display: colon }
  - { name: extension, type: bytes, prefix: uint32 }
```

- Leaving all of them out is [`missing-length`](../diagnostics.md#missing-length), and giving
  more than one is [`conflicting-length`](../diagnostics.md#conflicting-length).
- A fixed-size type takes none of them
  ([`unexpected-length`](../diagnostics.md#unexpected-length)). A timestamp's size follows
  from its `encoding:` (see [Timestamps](fields.md#timestamps)).

## `size:` {#size}

`size:` is a number of bytes: a YAML integer, or an [Expression](expressions.md) written as a
string. An Expression can read Fields read earlier by name (see
[References](expressions.md#references)), so a length carried in a header is written as its
name.

```yaml
name: chat
fields:
  - { name: length, type: uint16 }
  - { name: text, type: string, size: length }
  - { name: padding, type: bytes, size: "(4 - length % 4) % 4" }
  - { name: header, type: bytes, size: "4 * 6 + 2" }
```

A negative constant is [`invalid-size`](../diagnostics.md#invalid-size), and so is a constant
Expression that is negative, divides by zero or shifts by a count outside 0 to 63.

```yaml,diagnostic=invalid-size
name: demo
fields: [ {name: data, type: bytes, size: "2 - 4"} ]
```

A `count:` on an [array](arrays.md#count) and the amount of a [padding](fields.md#padding)
follow the same rules as a `size:`.

## `size: "_remaining"` {#remaining}

`_remaining` is the [built-in](expressions.md#builtins) holding the number of bytes left in the
message, so `size: "_remaining"` reads everything up to its end: a trailing payload, or a
blob the description does not break down.

```yaml
name: demo
fields:
  - { name: kind, type: uint8 }
  - { name: payload, type: bytes, size: "_remaining" }
```

A Field after it, in the same structure or after the structure holding it, can only be empty
or truncated, which is the warning
[`unreachable-field`](../diagnostics.md#unreachable-field).

```yaml,diagnostic=unreachable-field
name: demo
fields:
  - { name: body, type: bytes, size: "_remaining" }
  - { name: checksum, type: uint16 }
```

When the `size: "_remaining"` Field is under [`if:`](conditionals.md), the Field after it is
read whenever the condition is false, so it is not `unreachable-field`.

```yaml
name: demo
fields:
  - { name: flags, type: uint8 }
  - { name: body, type: bytes, size: "_remaining", if: "flags & 1" }
  - { name: checksum, type: uint16 }
```

## `prefix:` {#prefix}

`prefix:` names the unsigned integer type, `uint8` to `uint64`, read just before the value and
giving its length in bytes. The count is read in the Field's [byte order](fields.md#byte-order).

```yaml
name: chat
endian: little
fields:
  - { name: nick, type: string, prefix: uint8 }
  - { name: text, type: string, prefix: uint16 }
```

Any other `prefix:` is [`invalid-prefix`](../diagnostics.md#invalid-prefix).

```yaml,diagnostic=invalid-prefix
name: demo
fields: [ {name: user, type: string, prefix: int16} ]
```

## `terminator:` {#terminator}

`terminator:` is a byte value, 0 to 255: the value runs up to the first byte equal to it. The
terminator is read, but is not part of the value. `terminator: 0` reads a NUL-terminated
string.

```yaml
name: files
fields:
  - { name: path, type: string, terminator: 0 }
  - { name: line, type: string, terminator: 10 }
```

A `utf16` or `ucs2` string (see [Strings and bytes](fields.md#strings-and-bytes)) ends at a
2-byte zero aligned on its 2-byte code units, so its `terminator:` can only be `0`. A
terminator outside 0 to 255, or other than 0 on those encodings, is
[`invalid-terminator`](../diagnostics.md#invalid-terminator).

```yaml,diagnostic=invalid-terminator
name: demo
fields: [ {name: user, type: string, encoding: utf16, terminator: 10} ]
```

## In the packet {#runtime}

- The tree highlights the value bytes only: the `prefix:` count and the terminator are read
  but not highlighted with the value.
- When the packet ends before the value does, or before a terminator is found, the Dissector
  reports "Malformed: truncated" on that Field and stops, filtered as
  `<protocol>._malformed.truncated`.
- A `size:` Expression that is negative, divides by zero or shifts by a count outside 0 to 63
  in a packet is "Malformed", filtered as `<protocol>._malformed.expression` (see
  [In the packet](expressions.md#runtime)).
