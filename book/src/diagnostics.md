# Diagnostics index

One entry per Diagnostic, under the name Wirdigen prints in brackets (`error[unknown-key]`) and
links to at the end of each message. See [Diagnostics](reference/diagnostics.md) for how errors,
warnings and `allow:` work.

Errors cannot be silenced: fix the description. Warnings can be fixed, or silenced by adding
their name to the top-level `allow:` list.

## `yaml-syntax` {#yaml-syntax}

**Severity**: error

The file is not well-formed YAML, so nothing else can be checked. The message is the YAML
parser's.

```yaml,diagnostic=yaml-syntax
name: [demo
fields: []
```

**Fix**: correct the YAML at the position shown, here by closing the `[` list or writing
`name: demo`.

## `multiple-documents` {#multiple-documents}

**Severity**: error

A Protocol Description is a single YAML document, but the file holds several, separated by
`---`.

```yaml,diagnostic=multiple-documents
name: a
fields: [ {name: a, type: uint8} ]
---
name: b
```

**Fix**: put each Protocol Description in its own file.

## `yaml-alias` {#yaml-alias}

**Severity**: error

The file uses a YAML alias (`*name`). Aliases are not part of the YAML subset Wirdigen reads,
because a description reuses Fields through Types. An alias always comes with the anchor it
refers to, which is the error [`yaml-anchor`](#yaml-anchor).

```yaml,diagnostic=yaml-alias,diagnostic=yaml-anchor
x: &a demo
name: *a
fields: [ {name: a, type: uint8} ]
```

**Fix**: write the value out, or move repeated Fields into a Type.

## `yaml-anchor` {#yaml-anchor}

**Severity**: error

The file declares a YAML anchor (`&name`). Anchors are not part of the YAML subset Wirdigen
reads, because a description reuses Fields through Types.

```yaml,diagnostic=yaml-anchor
name: &n demo
fields: [ {name: a, type: uint8} ]
```

**Fix**: remove the anchor, and move repeated Fields into a Type.

## `yaml-tag` {#yaml-tag}

**Severity**: error

The file uses a YAML tag (`!foo`, `!!str`). Tags are not part of the YAML subset Wirdigen reads.

```yaml,diagnostic=yaml-tag
name: !foo demo
fields: [ {name: a, type: uint8} ]
```

**Fix**: remove the tag. To keep a value as text, quote it.

## `merge-key` {#merge-key}

**Severity**: error

The file uses a YAML merge key (`<<:`). Merge keys are not part of the YAML subset Wirdigen
reads, because a description reuses Fields through Types.

```yaml,diagnostic=merge-key
name: demo
fields: [ {name: a, type: uint8} ]
<<: {}
```

**Fix**: write the keys out, or move repeated Fields into a Type.

## `missing-key` {#missing-key}

**Severity**: error

A required key is missing: every description needs `name:` and `fields:`. An empty file is
missing both.

```yaml,diagnostic=missing-key
name: demo
```

**Fix**: add the key. When the key is only misspelt, Wirdigen reports the
[`unknown-key`](#unknown-key) instead, with the spelling it expected.

## `wrong-value-type` {#wrong-value-type}

**Severity**: error

A value has the wrong kind: a scalar where a list is expected, a list where a mapping is
expected, a float or a bool where an integer is expected, and so on. The whole description must
be a mapping.

```yaml,diagnostic=wrong-value-type
name: demo
fields: [ {name: a, type: uint8} ]
allow: unknown-allow
```

**Fix**: write the value in the kind the message asks for, here a list:
`allow: [unknown-allow]`.

## `unknown-key` {#unknown-key}

**Severity**: error

A key is not part of the format. When it is close to a known key, the message suggests that
key.

```yaml,diagnostic=unknown-key
name: demo
bogus: 1
fields: [ {name: a, type: uint8} ]
```

**Fix**: correct the spelling, or remove the key. Use a YAML comment to document a description.

## `duplicate-key` {#duplicate-key}

**Severity**: error

A key appears twice in the same mapping, so the description has no single meaning. A note
points at the first occurrence.

```yaml,diagnostic=duplicate-key
name: demo
name: other
fields: [ {name: a, type: uint8} ]
```

**Fix**: keep one of the two.

## `empty-fields` {#empty-fields}

**Severity**: error

The top-level `fields:` list is empty: a protocol must declare at least one Field.

```yaml,diagnostic=empty-fields
name: demo
fields: []
```

**Fix**: declare the Fields of the payload.

## `invalid-protocol-name` {#invalid-protocol-name}

**Severity**: error

`name:` is not a valid filter name. A name is a lowercase letter, then lowercase letters,
digits, `_` or `-`, at most 32 characters. Uppercase is never lowercased silently, and a `.`
is refused because it would blur where the Field path starts in filters such as `demo.id`.

```yaml,diagnostic=invalid-protocol-name
name: Demo
fields: [ {name: a, type: uint8} ]
```

**Fix**: choose a name that follows the rules, here `demo`. The uppercase form is derived for
the Protocol column, and `title:` sets the full name.

## `invalid-protocol-title` {#invalid-protocol-title}

**Severity**: error

`title:` is empty, blank or spans several lines. A title is shown on one line at the root of
the protocol tree.

```yaml,diagnostic=invalid-protocol-title
name: demo
title: ""
fields: [ {name: a, type: uint8} ]
```

**Fix**: write a single-line title, or leave `title:` out to use the uppercase `name:`.

## `invalid-endian` {#invalid-endian}

**Severity**: error

An `endian:` value, at the top level or on a Field, is not a byte order. Byte order is `big` or
`little`, never encoded in a type name.

```yaml,diagnostic=invalid-endian
name: demo
endian: network
fields: [ {name: id, type: uint16} ]
```

**Fix**: write `big` or `little`, or leave `endian:` out for big-endian.

## `missing-field-kind` {#missing-field-kind}

**Severity**: error

A Field says nothing about what it is. A Field needs exactly one of `type:` (a built-in type
or a Type), `fields:` (an inline structure) or `switch:` (a choice of layout).

```yaml,diagnostic=missing-field-kind
name: demo
fields: [ {name: id} ]
```

**Fix**: add the Field's `type:`, here `{name: id, type: uint8}`.

## `conflicting-field-kind` {#conflicting-field-kind}

**Severity**: error

A Field has more than one of `type:`, `fields:` and `switch:`, so it has no single meaning.
A note points at the first of them.

```yaml,diagnostic=conflicting-field-kind
name: demo
fields:
  - { name: id, type: uint8, fields: [ {name: low, type: uint8} ] }
```

**Fix**: keep one. To group Fields under a name, use `fields:` alone.

## `invalid-field-name` {#invalid-field-name}

**Severity**: error

A Field's `name:` is not a lowercase letter followed by lowercase letters, digits or `_`.
Names appear bare in filters and Expressions, so `-` and `.` are refused, and a leading `_` is
kept for Wirdigen's built-ins.

```yaml,diagnostic=invalid-field-name
name: demo
fields: [ {name: msgType, type: uint8} ]
```

**Fix**: rename the Field, here `msg_type`. Its tree label is derived from the name
("Msg type").

## `duplicate-field-name` {#duplicate-field-name}

**Severity**: error

Two Fields of the same structure share a name, so their filter name and any reference to them
would be ambiguous. A note points at the first one.

```yaml,diagnostic=duplicate-field-name
name: demo
fields:
  - { name: id, type: uint8 }
  - { name: id, type: uint16 }
```

**Fix**: rename one of them.

## `unknown-type` {#unknown-type}

**Severity**: error

A Field's `type:` names no built-in type and no Type. When the name is close to a built-in, the
message suggests it.

```yaml,diagnostic=unknown-type
name: demo
fields: [ {name: id, type: unit8} ]
```

**Fix**: correct the spelling, here `uint8`. The built-in types are listed in
[Fields](reference/fields.md#built-in-types).

## `unexpected-length` {#unexpected-length}

**Severity**: error

A Field of a fixed-size type has a length key (`size:`, `prefix:` or `terminator:`). Its size
already follows from its type.

```yaml,diagnostic=unexpected-length
name: demo
fields: [ {name: id, type: uint32, size: 4} ]
```

**Fix**: remove the length key.

## `missing-length` {#missing-length}

**Severity**: error

A `string` or `bytes` Field does not say how long it is. Its length comes from exactly one of
`size:`, `prefix:` or `terminator:`.

```yaml,diagnostic=missing-length
name: demo
fields: [ {name: user, type: string} ]
```

**Fix**: add the length key that matches the wire: `size: 16` for a constant length,
`prefix: uint8` when a count comes just before the value, or `terminator: 0` for a
NUL-terminated string. See [Strings and bytes](reference/fields.md#strings-and-bytes).

## `conflicting-length` {#conflicting-length}

**Severity**: error

A Field has more than one of `size:`, `prefix:` and `terminator:`, so its length has no single
meaning. A note points at the first of them.

```yaml,diagnostic=conflicting-length
name: demo
fields: [ {name: user, type: string, size: 8, terminator: 0} ]
```

**Fix**: keep the one key that says where the value ends.

## `invalid-size` {#invalid-size}

**Severity**: error

A `size:` is a negative number of bytes.

```yaml,diagnostic=invalid-size
name: demo
fields: [ {name: data, type: bytes, size: -4} ]
```

**Fix**: write the length in bytes, zero or more.

## `invalid-prefix` {#invalid-prefix}

**Severity**: error

A `prefix:` does not name an unsigned integer type. The prefix is the count of bytes read just
before the value, so it is one of `uint8` to `uint64`.

```yaml,diagnostic=invalid-prefix
name: demo
fields: [ {name: user, type: string, prefix: int16} ]
```

**Fix**: name the unsigned integer type of the count, here `uint16`.

## `invalid-terminator` {#invalid-terminator}

**Severity**: error

A `terminator:` is not a byte from 0 to 255, or it is not 0 on a `utf16` or `ucs2` string,
which always ends at a 2-byte zero.

```yaml,diagnostic=invalid-terminator
name: demo
fields: [ {name: user, type: string, encoding: utf16, terminator: 10} ]
```

**Fix**: write the byte value of the terminator, such as `0` or `10` for a line feed. A
`utf16` or `ucs2` string takes only `terminator: 0`.

## `incompatible-display` {#incompatible-display}

**Severity**: error

A Field's `display:` or `encoding:` is not one its type takes. Unsigned integers take `dec`,
`hex`, `oct`, `dec_hex` and `hex_dec`; signed integers are shown only as `dec`; `bytes` take
`plain`, `dot`, `dash`, `colon` and `space`; `string`, `bool`, the floats and the address types
take no `display:` at all. Only `string` takes `encoding:`.

```yaml,diagnostic=incompatible-display
name: demo
fields: [ {name: offset, type: int16, display: hex} ]
```

**Fix**: pick a value from the table in [Fields](reference/fields.md#display), or remove
`display:` to use the type's default. A signed value shown in hex needs an unsigned type. The
encodings are listed in [Strings and bytes](reference/fields.md#strings-and-bytes).

## `invalid-label` {#invalid-label}

**Severity**: error

A Field's `label:` is empty, blank, spans several lines or is not a string. The label is the
Field's one-line text in the protocol tree.

```yaml,diagnostic=invalid-label
name: demo
fields: [ {name: id, type: uint8, label: ""} ]
```

**Fix**: write a single-line label, or leave `label:` out to derive it from the name ("Id").

## `invalid-description` {#invalid-description}

**Severity**: error

A Field's `description:` spans several lines or is not a string. Wireshark shows it on one
line, in the status bar and the field reference.

```yaml,diagnostic=invalid-description
name: demo
fields:
  - { name: id, type: uint8, description: "Identifies\nthe request" }
```

**Fix**: write the description on one line, or quote a value YAML reads as a number or a bool.

## `not-supported-yet` {#not-supported-yet}

**Severity**: error

The description uses part of the format that this version of Wirdigen does not read yet: a
Field made of inline `fields:` or a `switch:`, one of the built-in types `abs_time` and
`rel_time`, or a `size:` given as an Expression (including `"_remaining"`) rather than a
constant. A newer Wirdigen will accept it.

```yaml,diagnostic=not-supported-yet
name: demo
fields:
  - { name: header, fields: [ {name: id, type: uint8} ] }
```

**Fix**: upgrade Wirdigen, or describe the layout with what this version supports, here by
listing the Fields at the top level.

## `unknown-allow` {#unknown-allow}

**Severity**: warning

An `allow:` entry names no warning: either no Diagnostic has that name, or it names an error,
which cannot be silenced. It is a warning rather than an error so that a description allowing a
warning added by a newer Wirdigen still works with an older one.

```yaml,diagnostic=unknown-allow
name: demo
fields: [ {name: a, type: uint8} ]
allow: [bogus]
```

**Fix**: correct the name or remove the entry. To keep an entry meant for a newer Wirdigen,
allow this warning too:

```yaml
name: demo
fields: [ {name: a, type: uint8} ]
allow: [unknown-allow, bogus]
```
