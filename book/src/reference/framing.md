# Framing

On TCP, a message can be split across segments, and a segment can hold several messages.
**Framing** tells the Dissector where each message ends: a header of constant size, and the
whole message's length computed from it.

```yaml
name: demo
framing:
  header: 4
  length: "len + 4"
fields:
  - { name: kind, type: uint16 }
  - { name: len, type: uint16 }
  - { name: body, type: bytes, size: len }
```

Here every message starts with 4 bytes, the last 2 of which give the length of what follows.

| Key | Value |
|---|---|
| `header` | the number of bytes the length is computed from: an integer of at least 1 |
| `length` | the whole message's length, its header included: an integer, or an [Expression](expressions.md) |

Both are required. A `header` below 1, or a constant `length` shorter than the header, is
[`invalid-framing`](../diagnostics.md#invalid-framing).

## The header {#header}

The length is computed before the message is read, from its first `header` bytes alone. So
`length` reads only top-level Fields, and the [sub-Fields](bitfields.md) of top-level bitfields,
that lie entirely within those bytes:

```yaml
name: demo
framing:
  header: 2
  length: "flags.size + 2"
fields:
  - name: flags
    type: uint16
    bits:
      - { name: version, width: 4 }
      - { name: size, width: 12 }
  - { name: body, type: bytes, size: "flags.size" }
```

Each of these is [`invalid-framing`](../diagnostics.md#invalid-framing):

- a Field that ends after the header;
- a Field under [`if:`](conditionals.md), or after a Field whose size is known only once it is
  read, whose place in the message is not fixed;
- a Field inside an inline structure or a Type;
- the built-ins `_offset` and `_remaining`.

```yaml,diagnostic=invalid-framing
name: demo
framing:
  header: 2
  length: "len + 4"
fields:
  - { name: kind, type: uint16 }
  - { name: len, type: uint16 }
```

A name that is no top-level Field is [`unknown-field`](../diagnostics.md#unknown-field), and a
Field without an integer value is
[`non-numeric-reference`](../diagnostics.md#non-numeric-reference).

## In the stream {#stream}

Framing applies to TCP, through [Registration](registration.md#tcp) or Decode As. Over UDP, each
datagram is one message, as without `framing:`.

- The Dissector reads the messages of a segment one after another, each under its own tree
  root. [`_offset` and `_remaining`](expressions.md#builtins) count from the start of the
  message, not of the segment.
- A message that goes on past the segment waits for the next ones: Wireshark shows it in the
  packet where its last byte arrives. A segment holding only part of a message shows no
  message of its own.
- When TCP reassembly is off (the TCP preference *Allow subdissector to reassemble TCP
  streams*), the end of the segment ends the last message, which is then reported truncated.
- A length that is negative, below the header, or has no value (a division by zero, a shift
  outside 0 to 63) is a "Malformed" expert info error: the rest of the segment is shown as one
  malformed message.
- With several messages in a packet, the Info column shows the last one's, with only the
  Fields that message read.
