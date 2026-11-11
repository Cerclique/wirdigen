# Expressions

An Expression is a small formula that computes a number from constants and Fields read
earlier: a size, and later a count, a condition or a `switch` subject. It is written as a YAML
string.

```yaml
name: demo
fields:
  - { name: header, type: bytes, size: "4 * 6 + 2" }
  - { name: count, type: uint8 }
  - { name: records, type: bytes, size: "count * 8" }
```

This version reads Expressions in `size:`.

## Writing an Expression in YAML {#yaml}

Quote every Expression with `"..."`. Some unquoted ones would parse as YAML (`4 * 6`), but
others would not: one starting with `*` or `!` means something else in YAML, and `#` starts a
comment. A plain YAML integer such as `size: 16` is a constant, not an Expression.

## Values {#values}

| Value | Example |
|---|---|
| decimal integer | `42`, `1_000` |
| hexadecimal integer, `0x` or `0X` | `0x1F`, `0xFFFF_0000` |
| binary integer, `0b` or `0B` | `0b1010_0001` |
| a Field read earlier, by its path | `length`, `header.length` |
| a built-in | `_offset`, `_remaining` |
| a parenthesized Expression | `(length + 4)` |

- `_` separates digits anywhere after the first one. There are no character literals and no
  strings.
- A literal starting with `0` followed by more digits, such as `010`, is
  [`leading-zero-literal`](../diagnostics.md#leading-zero-literal): it would be octal in C, and
  Expressions have no octal.
- A literal must fit in 64 bits. Above `0x7FFF_FFFF_FFFF_FFFF` it wraps to a negative value, so
  `0xFFFF_FFFF_FFFF_FFFF` is `-1`.
- A name starting with `_` is a built-in, which is why Field names cannot start with `_`.
  `_offset` is the number of bytes from the start of the message, and `_remaining` the number
  of bytes left in it.

## Operators {#operators}

From the tightest binding to the loosest:

| Operators | Meaning |
|---|---|
| `!` `~` `-` (unary) | not (1 for zero, else 0), bitwise complement, negation |
| `*` `/` `%` | multiplication, division, remainder |
| `+` `-` | addition, subtraction |
| `<<` `>>` | shifts |
| `&` | bitwise and |
| `^` | bitwise exclusive or |
| `\|` | bitwise or |
| `==` `!=` `<` `<=` `>` `>=` | comparisons |
| `&&` | logical and |
| `\|\|` | logical or |

Operators of one row group from the left: `a - b - c` is `(a - b) - c`.

The order is Rust's and Python's, **not C's**: bitwise operators bind tighter than comparisons,
so a mask test means what it looks like. `flags & 0x80 == 0x80` is `(flags & 0x80) == 0x80`,
where C would read `flags & (0x80 == 0x80)`.

Comparisons do not chain: `a < b < c` is
[`chained-comparison`](../diagnostics.md#chained-comparison). Write `a < b && b < c`, or
`(a < b) < c` to compare the first result.

Any other mistake, such as a missing value or parenthesis or a character Expressions do not
use, is [`expression-syntax`](../diagnostics.md#expression-syntax), pointing at the token.

```yaml,diagnostic=chained-comparison
name: demo
fields: [ {name: data, type: bytes, size: "1 < 2 < 3"} ]
```

## Arithmetic {#arithmetic}

Every value is a signed 64-bit integer, and the arithmetic is C's:

- `/` truncates toward zero and `%` takes the sign of the left side: `-7 / 2` is `-3` and
  `-7 % 2` is `-1`. Lua's own operators would give `-4` and `1`.
- `>>` is arithmetic: it keeps the sign, so `-8 >> 1` is `-4`.
- Overflow wraps around: `0x7FFF_FFFF_FFFF_FFFF + 1` is the most negative value.
- Comparisons, `!`, `&&` and `||` give 1 or 0, and any value other than 0 counts as true.
- `&&` and `||` stop as soon as the result is known: in `0 && 1 / 0`, the division is never
  done.

```yaml
name: demo
fields:
  - { name: masked, type: bytes, size: "0x1234 & 0xF" }
  - { name: rounded, type: bytes, size: "(13 + 3) / 4 * 4" }
  - { name: either, type: bytes, size: "(2 > 1 || 0) + 1" }
```

A constant `size:` that is negative, divides by zero or shifts by a count outside 0 to 63 is
[`invalid-size`](../diagnostics.md#invalid-size).

```yaml,diagnostic=invalid-size
name: demo
fields: [ {name: data, type: bytes, size: "2 - 4"} ]
```

## References {#references}

A name in an Expression reads the value of a Field read earlier in the packet.

- **Nearest first.** A name is looked up among the earlier Fields of the structure the
  Expression is in, then among the earlier Fields of each enclosing structure, out to the
  top-level `fields:`. The nearest Field of that name wins.
- **Dotted paths** go into a structure or a Field of a Type read earlier: `hdr.len`,
  `request.header.flags`.
- **Only earlier Fields.** A Field read later, or the Field the Expression belongs to, is
  [`forward-reference`](../diagnostics.md#forward-reference). A name that matches nothing is
  [`unknown-field`](../diagnostics.md#unknown-field), and so is a path into the structure still
  being read: inside `hdr`, write `len`, not `hdr.len`.
- **Only numbers.** Integer and `bool` Fields can be read; a `bool` reads as 1 or 0. A
  `string`, `bytes`, float, address, timestamp or structure is
  [`non-numeric-reference`](../diagnostics.md#non-numeric-reference).

```yaml
name: demo
fields:
  - { name: length, type: uint8 }
  - name: header
    fields:
      - { name: length, type: uint16 }
      - { name: compressed, type: bool }
      - { name: options, type: bytes, size: "length - 4" }
  - { name: body, type: bytes, size: "header.length * (header.compressed + 1)" }
  - { name: trailer, type: bytes, size: length }
```

Here `options` reads `header.length`, the nearest `length`, and `trailer` reads the top-level
one.

### Inside a Type {#references-in-types}

A Type can read its own Fields, and also names it does not declare. Those are resolved at each
place the Type is used, in the scope of that use, so one Type can read a different Field at each
use. An error is reported at the use that cannot resolve the name, with a note pointing at the
name in the Type.

```yaml
name: demo
fields:
  - { name: size, type: uint8 }
  - { name: request, type: Block }
  - name: reply
    fields:
      - { name: size, type: uint16 }
      - { name: block, type: Block }
types:
  Block:
    fields:
      - { name: kind, type: uint8 }
      - { name: data, type: bytes, size: "size - 1" }
```

`request.data` reads the top-level `size`, and `reply.block.data` reads `reply.size`.

## Built-ins {#builtins}

| Built-in | Value |
|---|---|
| `_offset` | the number of bytes from the start of the message to the Field being read |
| `_remaining` | the number of bytes left in the message from the Field being read |

`size: "_remaining"` reads everything left. A Field after it in the same structure can only be
empty or truncated, which is the warning
[`unreachable-field`](../diagnostics.md#unreachable-field).

```yaml
name: demo
fields:
  - { name: kind, type: uint8 }
  - { name: align, type: bytes, size: "(4 - _offset % 4) % 4" }
  - { name: payload, type: bytes, size: "_remaining" }
```

## In the packet {#runtime}

An Expression that reads Fields is computed when the packet is read, with the arithmetic above.
A Field value is a signed 64-bit integer, so a `uint64` above `0x7FFF_FFFF_FFFF_FFFF` reads as a
negative number.

When the value cannot be used, the Dissector shows what it read so far, adds a "Malformed"
expert info error on the Field, filtered as `<protocol>._malformed.expression`, and stops:

- a division or remainder by zero;
- a shift by a count outside 0 to 63;
- a negative size.

A size larger than what is left of the packet is a truncation, as for any Field that does not
fit: "Malformed: truncated", filtered as `<protocol>._malformed.truncated`.

