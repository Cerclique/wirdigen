# `if` and `switch`

Some Fields are in a message only sometimes: an extension present when a flag is set, a body
whose layout depends on a Field of the header. `if:` reads a Field only under a condition;
`switch:` picks one layout among several.

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
so is `hdr.len` when `len` is read under an `if:` inside the Type of `hdr`. The Fields of a
[`switch` case](#switch-scope) follow the same rule.

## `switch:` {#switch}

A `switch` Field reads one layout among several, picked by the value of an
[Expression](expressions.md), its **subject**. It is how a protocol with several kinds of message
is described: a header saying which message follows, then a `switch` on it.

```yaml
name: demo
fields:
  - { name: msg_type, type: uint8, values: MsgType }
  - name: body
    switch: msg_type
    cases:
      1: Login
      2:
        - { name: reason, type: uint8 }
      "16-31": Vendor
    default:
      - { name: unknown, type: bytes, size: "_remaining" }
types:
  Login:
    fields:
      - { name: user_id, type: uint32 }
      - { name: name, type: string, prefix: uint8 }
  Vendor:
    fields:
      - { name: code, type: uint16 }
enums:
  MsgType:
    1: Login
    2: Logout
    "16-31": Vendor
```

- **`switch:`** is the subject: an Expression, or a constant, computed once before the cases.
  A subject that divides by zero or shifts out of range is "Malformed", as for any
  [Expression](expressions.md#runtime).
- **`cases:`** maps values to layouts. A key is an integer or a `"low-high"` range string, as in
  a [values table](fields.md#value-mappings), and `cases:` needs at least one. Two cases
  matching a same value are
  [`overlapping-cases`](../diagnostics.md#overlapping-cases): the subject is a 64-bit signed
  value, so `-1` and `18446744073709551615` are the same value there.
- **A case** is the name of a [Type](fields.md#types), or a list of Fields spelled like an
  [inline structure](fields.md#inline-structures). A built-in type is not a case: wrap it in a
  list, `[ { name: value, type: uint8 } ]`.
- **`default:`**, optional, is read when no case matches. It is a Type or a list of Fields too.
- **No match and no `default:`**: the rest of the message is shown raw as "Unmatched bytes"
  (filtered as `<protocol>._unmatched`) with an expert info note "No case for 7: body"
  (`<protocol>._undecoded.unmatched`), and the dissection stops there, since nothing says
  where the unknown layout ends. It is a note, not "Malformed": the packet may be fine, only
  this description does not know it.

A `switch` Field takes `name:`, `label:`, `description:`, `if:`, [`hidden:`](fields.md#hidden),
`switch:`, `cases:` and `default:` only. Any other key is an error under the name the key has
elsewhere: `values:`, `display:` or `expect:` is
[`incompatible-display`](../diagnostics.md#incompatible-display), `size:`
[`unexpected-length`](../diagnostics.md#unexpected-length), `count:` or `repeat:`
[`invalid-array`](../diagnostics.md#invalid-array), `endian:`
[`invalid-endian`](../diagnostics.md#invalid-endian), `bits:`
[`invalid-bits`](../diagnostics.md#invalid-bits). A case is read in the byte order of the
structure the `switch` is in, and a Type case in its own. `cases:` or `default:` without
`switch:` is [`missing-field-kind`](../diagnostics.md#missing-field-kind), or
[`conflicting-field-kind`](../diagnostics.md#conflicting-field-kind) next to `type:` or
`fields:`.

### Tree and filter names {#switch-tree}

The `switch` Field is a subtree, like an inline structure, and the case it reads goes straight
into it: a case adds no level to the tree and no segment to filter names. Above, the Login's
`user_id` is `demo.body.user_id`, not `demo.body.Login.user_id`.

The subtree item is named after the subject's value: "Body: Login". When
the subject is a bare Field path (`msg_type`, `hdr.kind`, `flags.op`) to a Field read in the
same layout or Type, the name is that Field's `values:` label, else the number; any other
Expression (`"kind & 0x0f"`), or a path a [Type](fields.md#types) reads from where it is used,
shows the number: "Body: 7".

Two cases reaching one filter name share its ProtoField when the two Fields have the same type,
`display:`, value mappings, `label:` and `description:`, so `demo.body.user_id` filters both a
Login's `user_id` and another message's. When they differ, it is
[`conflicting-filter-name`](../diagnostics.md#conflicting-filter-name): rename one, or make them
match.

```yaml,diagnostic=conflicting-filter-name
name: demo
fields:
  - { name: msg_type, type: uint8 }
  - name: body
    switch: msg_type
    cases:
      1: [ { name: id, type: uint32 } ]
      2: [ { name: id, type: uint16 } ]
```

### Scope {#switch-scope}

A case is a [conditional scope](#scope): its Fields have a value only when it matched. They
read each other, and the Fields before the `switch`, as usual, but nothing outside the case can
read them: `body.reason` after `body` is
[`conditional-reference`](../diagnostics.md#conditional-reference). What later Fields need
belongs in the header before the `switch`, or inside each case.
