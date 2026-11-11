# `if` and `switch`

Some Fields are in a message only sometimes: an extension present when a flag is set, a body
whose layout depends on a message type. `if:` reads a Field only under a condition; `switch:`
is not supported by this version yet.

## `if:` {#if}

`if: <Expression>` reads the Field only when the [Expression](expressions.md) is not zero.
Otherwise the Field is skipped: it reads no bytes and adds nothing to the tree.

```yaml
name: demo
fields:
  - { name: flags, type: uint8 }
  - { name: session, type: uint32, if: "flags & 0x01" }
  - { name: checksum, type: uint16, if: "flags & 0x80 == 0x80" }
  - { name: payload, type: bytes, size: "_remaining" }
```

`session` is in the packet only when the lowest bit of `flags` is set, `checksum` only when the
highest one is.

- **Any Field.** `if:` goes on a Field of a built-in type, an inline structure, a Field of a
  [Type](fields.md#types), an [array](arrays.md), and on the Fields inside a Type. On an array,
  the condition is computed first, and `count:` only when it is true.
- **C truthiness.** Any value other than zero is true, negative values included. Comparisons,
  `!`, `&&` and `||` give 1 or 0, so `if: "len > 4"` and `if: "!(flags & 1)"` read as they
  look.
- **A constant** works too: `if: 0` never reads the Field. A YAML `true` or `false` is
  [`wrong-value-type`](../diagnostics.md#wrong-value-type): write `1` or `0`.
- **In the packet**, a condition that divides by zero or shifts by a count outside 0 to 63
  adds a "Malformed" expert info error on the Field and stops the dissection, as for any
  [Expression](expressions.md#runtime). A negative condition is simply true.
- A Field after a conditional `size: "_remaining"` Field or `repeat: to_end` array is
  reachable when the condition is false, so it is not
  [`unreachable-field`](../diagnostics.md#unreachable-field).

## Conditional scope {#scope}

A Field under `if:` has a value only when its condition was true, so an Expression may read it
only from inside the same **conditional scope**: inside the Field carrying the `if:`. Reading a
conditional Field, or a Field inside a conditional structure or Type, from anywhere else is
[`conditional-reference`](../diagnostics.md#conditional-reference), reported at the reference.

Conditions are never compared: two Fields with the same `if:` are still in two scopes, so the
second cannot read the first.

```yaml,diagnostic=conditional-reference
name: demo
fields:
  - { name: flags, type: uint8 }
  - { name: len, type: uint8, if: "flags & 1" }
  - { name: data, type: bytes, size: len, if: "flags & 1" }
```

The way out is an inline structure carrying the `if:`: inside it, its Fields read each other as
usual, and its own `if:` is computed once.

```yaml
name: demo
fields:
  - { name: flags, type: uint8 }
  - name: ext
    if: "flags & 1"
    fields:
      - { name: len, type: uint8 }
      - { name: data, type: bytes, size: len }
```

The rule follows the path: after `ext` above, `ext.len` is a `conditional-reference` too, and
so is `hdr.len` when `len` is read under an `if:` inside the Type of `hdr`.
