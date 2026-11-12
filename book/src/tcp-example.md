# Example: TCP request/response

The [tutorial](tutorial.md) described a protocol whose every datagram has the same layout. This
example walks through a protocol over TCP, where messages of several kinds follow one another in
a stream: it needs [Framing](reference/framing.md) to find where each message ends, a
[`switch`](reference/conditionals.md#switch) to read the right layout for each kind, named
[Types](reference/fields.md#types) for those layouts, and strings that carry their own length.

The finished description and its sample packets are in the repository under
[`examples/kvstore/`](https://github.com/Cerclique/wirdigen/tree/main/examples/kvstore). To
run them you need the same tools as the tutorial: `wirdigen`, and Wireshark 4.4 or later with
`tshark` and `text2pcap`.

## The protocol {#protocol}

*Key-Value Store* is an invented protocol. A client connects to a server on TCP port 47200 and
sends requests: read a key, write a value under a key, delete a key. The server answers each
request with a reply carrying the same request id.

Every message, request or reply, starts with the same 8-byte header, every number big-endian:

| Bytes | Field | Meaning |
|---|---|---|
| 1 | `version` | Protocol version, 1 |
| 1 | `op` | What the message is: `0x01` Get, `0x02` Put, `0x03` Delete, `0x81` Value, `0x82` Done |
| 2 | `length` | Size of the body, the bytes after the header |
| 4 | `request_id` | Chosen by the client, copied into the reply |

The body depends on `op`:

| `op` | Body |
|---|---|
| Get, Delete | the key |
| Put | the key, then the value |
| Value, the reply to a Get | a status byte, then the value |
| Done, the reply to a Put or a Delete | a status byte |

A key is a string of up to 255 bytes, preceded by its length in one byte. A value is preceded by
its length in two bytes. The status is 0 for Ok, 1 when the key was not found, 2 for an error.

A Get of the key `temp`, with request id 1, looks like this on the wire:

```text
01 01 00 05 00 00 00 01 04 74 65 6d 70
```

## The header {#header}

The header is four plain Fields. `op` takes its labels from an [Enum](reference/fields.md#value-mappings),
since the `switch` below will name its cases after the same operations:

```yaml
name: kvstore
fields:
  - { name: version, type: uint8 }
  - { name: op, type: uint8, display: hex, values: Op }
  - { name: length, type: uint16 }
  - { name: request_id, type: uint32 }
enums:
  Op:
    0x01: Get
    0x02: Put
    0x03: Delete
    0x81: Value
    0x82: Done
```

## Finding each message {#framing}

TCP carries a stream of bytes, not messages. A segment can hold several messages, or only part
of one, as when a client sends requests back to back or a large value spans segments. The
Dissector has to know where a message ends before it reads it, and here the header says: the
message is the 8 header bytes plus `length` bytes of body.

`framing:` gives exactly that, in two parts:

```yaml
name: kvstore
framing:
  header: 4
  length: "length + 8"
fields:
  - { name: version, type: uint8 }
  - { name: op, type: uint8 }
  - { name: length, type: uint16 }
  - { name: request_id, type: uint32 }
  - { name: body, type: bytes, size: length }
```

- `header: 4` is how many bytes the Dissector needs before it can compute the length. `length`
  ends at byte 4, so the first four bytes are enough; `request_id` is not needed.
- `length:` is an [Expression](reference/expressions.md) giving the whole message's size, header
  included, from the Fields of those first bytes.

With this, the Dissector asks Wireshark for more data when a message is cut by the end of a
segment, and reads several messages when a segment holds more than one. Each message gets its
own *Key-Value Store* tree. See [Framing](reference/framing.md).

## One layout per operation {#switch}

The body above is still raw bytes. A `switch` Field reads a different layout depending on a
value, here `op`. Each case names a **Type**, a group of Fields declared once under the
top-level `types:`:

```yaml
name: kvstore
fields:
  - { name: op, type: uint8 }
  - name: body
    switch: op
    cases:
      0x01: Get
      0x02: Put
    default:
      - { name: data, type: bytes, size: "_remaining" }
types:
  Get:
    fields:
      - { name: key, type: string, prefix: uint8 }
  Put:
    fields:
      - { name: key, type: string, prefix: uint8 }
      - { name: value, type: string, prefix: uint16 }
```

`default:` is read when no case matches, so a message of an operation this description does
not know still shows its body, as `data`. Without it, the rest of the message would be shown as
unmatched bytes with an expert note. Under Framing, `_remaining` counts the bytes left in the
current message, not in the segment. See [`switch:`](reference/conditionals.md#switch).

The Fields of a case are filtered by their path from the top: `kvstore.body.key` matches the
key of a Get, a Put and a Delete alike.

## Strings with a length {#strings}

`prefix: uint8` reads a one-byte length, then that many bytes of string. The key `temp` is
`04 74 65 6d 70` on the wire, and Wireshark shows `Key: temp`. The value uses `prefix: uint16`
because it can be longer. The prefix is not a Field of its own: `Key` covers only the string's
bytes, after it. See [`prefix:`](reference/sizes.md#prefix).

A prefix that claims more bytes than the message holds does not throw the Dissector off: it
reports the Field truncated and marks the message Malformed, as below.

## The Info column and the port {#info}

The Info column names the operation and the request, then the key or the status, whichever the
message has:

```yaml
name: kvstore
info: "{op} #{request_id}: {body.key}{body.status}"
fields:
  - { name: op, type: uint8, values: { 1: Get, 0x82: Done } }
  - { name: request_id, type: uint32 }
  - name: body
    switch: op
    cases:
      1: [ { name: key, type: string, prefix: uint8 } ]
      0x82: [ { name: status, type: uint8, values: { 0: Ok, 1: Not found } } ]
```

A Field in a case the message did not read shows nothing, so a Get reads `Get #1: temp` and a
reply `Done #3: Not found`. See [Info column](reference/info.md).

`registration:` claims TCP port 47200 by default, as in the tutorial. Claiming a TCP port
without `framing:` would get the warning
[`tcp-without-framing`](diagnostics.md#tcp-without-framing), since each segment would then be
read as one message.

## The complete description {#complete}

Put together, with the five Types, a second Enum for the status and a few `description:`s:

```yaml
# Key-Value Store, an invented protocol: the book's TCP request/response example.
#
# A client sends requests to a server on TCP port 47200, which answers each one. Every Message,
# request or reply, starts with the same 8-byte header, big-endian:
#
#   version  op  length  request_id
#   1        1   2       4
#
# then `length` bytes of body, whose layout depends on `op`. Strings carry their length before
# them: a uint8 for a key, a uint16 for a value.
name: kvstore
title: Key-Value Store
registration:
  ports:
    tcp: [47200]
framing:
  header: 4
  length: "length + 8"
info: "{op} #{request_id}: {body.key}{body.status}"
fields:
  - { name: version, type: uint8 }
  - { name: op, type: uint8, display: hex, values: Op }
  - { name: length, type: uint16, description: "Size of the body, after the header" }
  - { name: request_id, type: uint32, description: "Pairs a reply with its request" }
  - name: body
    switch: op
    cases:
      0x01: Get
      0x02: Put
      0x03: Delete
      0x81: Value
      0x82: Done
    default:
      - { name: data, type: bytes, size: "_remaining" }
types:
  Get:
    fields:
      - { name: key, type: string, prefix: uint8 }
  Put:
    fields:
      - { name: key, type: string, prefix: uint8 }
      - { name: value, type: string, prefix: uint16 }
  Delete:
    fields:
      - { name: key, type: string, prefix: uint8 }
  Value:
    fields:
      - { name: status, type: uint8, values: Status }
      - { name: value, type: string, prefix: uint16 }
  Done:
    fields:
      - { name: status, type: uint8, values: Status }
enums:
  Op:
    0x01: Get
    0x02: Put
    0x03: Delete
    0x81: Value
    0x82: Done
  Status:
    0: Ok
    1: Not found
    2: Error
```

Generate the Dissector:

```text
wirdigen generate kvstore.wirdigen.yaml
```

## Trying it in tshark {#tshark}

The repository's
[`packets.txt`](https://github.com/Cerclique/wirdigen/blob/main/examples/kvstore/packets.txt)
holds the five segments of one TCP connection, in the hex format of `text2pcap`:

1. Get #1, then the first 10 bytes of the 20 of Put #2;
2. the rest of Put #2, then Delete #3;
3. three replies back to back: Value #1, Done #2 and Done #3;
4. a message with op `0x7f`, which the description does not know;
5. a Get whose key claims 9 bytes in a 4-byte body.

`text2pcap -T` wraps each one in a TCP segment of the same connection, here from port 52000 to
port 47200. It writes every segment in the same direction, so the replies travel the same way
as the requests: the Dissector does not mind, since it reads each message from its own header.

```text
text2pcap -T 52000,47200 packets.txt kvstore.pcapng
```

```text
$ tshark -X lua_script:kvstore.lua -r kvstore.pcapng
    1 0.000000000     10.1.1.1 → 10.2.2.2     KVSTORE 77 Get #1: temp
    2 0.000001000     10.1.1.1 → 10.2.2.2     KVSTORE 77 Put #2: colorDelete #3: temp
    3 0.000002000     10.1.1.1 → 10.2.2.2     KVSTORE 87 Done #3: Not found
    4 0.000003000     10.1.1.1 → 10.2.2.2     KVSTORE 65 127 #4:
    5 0.000004000     10.1.1.1 → 10.2.2.2     KVSTORE 66 Get #5:
```

Put #2 began in the first segment, but Wireshark shows it in the second, where its last byte
arrives, together with Delete #3. In packet 2's Info column, the Put's text comes from the
message reassembled across both segments and the Delete's is added after it. The tree of
packet 2 holds one *Key-Value Store* root per message:

```text
$ tshark -X lua_script:kvstore.lua -r kvstore.pcapng -O kvstore
...
Key-Value Store
    Version: 1
    Op: Put (0x02)
    Length: 12
    Request id: 2
    Body: Put
        Key: color
        Value: teal
Key-Value Store
    Version: 1
    Op: Delete (0x03)
    Length: 5
    Request id: 3
    Body: Delete
        Key: temp
```

The unknown operation of packet 4 falls to `default:`, and the Get of packet 5 reads past its
own body, so its key is reported truncated:

```text
Key-Value Store
    Version: 1
    Op: Unknown (0x7f)
    Length: 3
    Request id: 4
    Body: 127
        Data: deadbe

Key-Value Store
    Version: 1
    Op: Get (0x01)
    Length: 4
    Request id: 5
    Body: Get
        [Expert Info (Error/Malformed): Malformed: truncated: body.key]
```

The truncation stays inside the message: Framing already said where it ends, so a message
after it in the stream would still be read.

A filter on a Field of a Type matches every message that has it, here the two that name the key
`temp`:

```text
$ tshark -X lua_script:kvstore.lua -r kvstore.pcapng -Y 'kvstore.body.key == "temp"'
    1 0.000000000     10.1.1.1 → 10.2.2.2     KVSTORE 77 Get #1: temp
    2 0.000001000     10.1.1.1 → 10.2.2.2     KVSTORE 77 Put #2: colorDelete #3: temp
```
