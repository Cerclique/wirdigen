# Bitfields

A **bitfield** is an unsigned integer Field split into sub-Fields of a few bits each, as protocol
headers pack flags and small numbers into one byte or word. Its `bits:` lists the sub-Fields by
width, most significant bit first, and Wirdigen computes each one's mask.

```yaml
name: demo
fields:
  - name: flags
    type: uint8
    bits:
      - { name: version, width: 3 }
      - { padding: 1 }
      - { name: ext, width: 1 }
      - { name: kind, width: 3 }
```

Here `version` is the top three bits (mask `0xE0`), one bit is unused, `ext` is the next bit
(`0x08`) and `kind` the three lowest bits (`0x07`). The tree shows `flags` as a number with a
subtree holding `version`, `ext` and `kind`, each with its bits marked, as Wireshark shows the
flags of IP or TCP.

## The container {#container}

- `bits:` goes only on a Field of a fixed-size unsigned integer type, `uint8` to `uint64`
  ([`invalid-bits`](../diagnostics.md#invalid-bits)). The container is read and shown like any
  unsigned integer, with its own `display:`, `values:`, `label:` and `endian:`.
- Every bit is accounted for: the widths, padding included, must add up to the bits of the
  container, 8 for a `uint8`, 16 for a `uint16`, and so on
  ([`mismatched-bit-widths`](../diagnostics.md#mismatched-bit-widths)). Each width is at least 1
  ([`invalid-bit-width`](../diagnostics.md#invalid-bit-width)).
- `{ padding: n }` covers `n` bits nothing names. It adds nothing to the tree and has no filter
  name.
- Bits are counted on the container's value, after its byte order: in a little-endian `uint16`,
  the first sub-Field is still the most significant bits of the number.

```yaml
name: demo
fields:
  - name: control
    type: uint16
    endian: little
    display: hex
    bits:
      - { name: channel, width: 4 }
      - { padding: 4 }
      - { name: level, width: 8 }
```

## Sub-Fields {#sub-fields}

A sub-Field takes `name:` and `width:`, both required, and optionally `display:`, `values:`,
`unit:`, `true:`, `false:`, `hidden:`, `label:` and `description:`. Its name follows the rule
of Field names, and two sub-Fields of one bitfield need different names.

- A **1-bit** sub-Field is a boolean, shown as "Set" or "Not set". `true:` and `false:` replace
  those labels.
- A **wider** sub-Field is an unsigned integer of its width. It takes the `display:` of an
  unsigned integer, and `values:` (an inline table or an Enum) or `unit:`, as described in
  [Value mappings](fields.md#value-mappings). A key that does not fit in the sub-Field's
  width is the warning [`unreachable-value`](../diagnostics.md#unreachable-value).
- A 1-bit sub-Field with `values:`, `unit:` or `display:` is an unsigned integer too, holding 0
  or 1.
- There are no signed sub-Fields.

```yaml
name: demo
enums:
  Priority: { 0: Low, 1: Normal, 2: High, 3: Urgent }
fields:
  - name: header
    type: uint16
    bits:
      - { name: ack, width: 1, true: Acknowledged, false: Pending }
      - { name: priority, width: 2, values: Priority }
      - { name: retries, width: 5, unit: [try, tries] }
      - { name: ttl, width: 8, display: hex, label: Time to live }
```

Any other key on a sub-Field is [`unknown-key`](../diagnostics.md#unknown-key), and `expect:`
is not read by this version yet
([`not-supported-yet`](../diagnostics.md#not-supported-yet)).

## Hidden bitfields {#hidden}

`hidden: true` on the container leaves it and all its sub-Fields out of the tree. On a
sub-Field it leaves out that sub-Field only. Hidden items are still read: Expressions can use
them and display filters still match them. Any other Field can be
[hidden](fields.md#hidden) the same way.

```yaml
name: demo
fields:
  - name: options
    type: uint8
    hidden: true
    bits:
      - { name: has_trailer, width: 1 }
      - { name: reserved, width: 7, hidden: true }
  - { name: body, type: bytes, size: "_remaining" }
```

## Filter names and Expressions {#filter-names}

Each sub-Field extends the filter name of its container: the first example gives `demo.flags`,
`demo.flags.version`, `demo.flags.ext` and `demo.flags.kind`. A boolean sub-Field can be
filtered on by name alone (`demo.flags.ext`), or compared to 1 or 0.

[Expressions](expressions.md) read a sub-Field with a dotted path from its container, as they
read into a structure: `flags.ext` is 1 or 0, `flags.kind` the number in its three bits.

```yaml
name: demo
fields:
  - name: flags
    type: uint8
    bits:
      - { name: has_checksum, width: 1 }
      - { name: option_words, width: 7 }
  - { name: options, type: bytes, size: "flags.option_words * 4" }
  - { name: checksum, type: bytes, size: "flags.has_checksum * 2" }
```

A bare sub-Field name such as `option_words` is not a Field of the structure, so it is
[`unknown-field`](../diagnostics.md#unknown-field): always write the container first.
