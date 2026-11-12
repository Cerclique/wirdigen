# Arrays

An **array** is a Field read several times in a row: a list of records, each laid out the
same way. Its element is an [inline structure](fields.md#inline-structures) or a Field of a
[Type](fields.md#types), and one of two keys says how many elements there are:

| Key | Elements |
|---|---|
| `count: <Expression>` | as many as the [Expression](expressions.md) gives, or a constant |
| `repeat: to_end` | as many as fit, until the message ends |

```yaml
name: demo
fields:
  - { name: n, type: uint8 }
  - name: items
    count: n
    fields:
      - { name: id, type: uint16 }
      - { name: len, type: uint8 }
      - { name: data, type: bytes, size: len }
  - name: corners
    count: 4
    type: Point
types:
  Point:
    fields:
      - { name: x, type: int16 }
      - { name: y, type: int16 }
```

Here `items` holds `n` records, each with its own length, and `corners` four points.

## Elements in the tree {#tree}

Each element is its own subtree item, labelled with the Field's label and the element's
index from 0: "Items [0]", "Items [1]", and so on. There is no item for the array as a whole.

All the elements share the array's filter names: `demo.items.id` matches the `id` of every
element, as Wireshark matches every occurrence of a field in a packet.

## `count:` {#count}

`count:` is a constant or an Expression over the Fields read before the array, written like a
[`size:`](sizes.md#size). It is computed once, before the first element.

- A constant `count:` that is negative, divides by zero or shifts by a count outside 0 to 63 is
  [`invalid-count`](../diagnostics.md#invalid-count).
- In a packet, a count that is negative or has no value adds a "Malformed" expert info error on
  the array and stops the dissection, filtered as `<protocol>._malformed.expression`.
- A count larger than the packet holds is a truncation: the element that does not fit is
  "Malformed: truncated", as for any Field.

```yaml,diagnostic=invalid-count
name: demo
fields:
  - name: items
    count: "2 - 4"
    fields: [ {name: id, type: uint8} ]
```

## `repeat: to_end` {#repeat}

`repeat: to_end` reads elements until the message ends, as in a list of tag-length-value
records filling the rest of a packet. The last element must end exactly with the message, or
it is truncated.

```yaml
name: demo
fields:
  - { name: version, type: uint8 }
  - name: options
    repeat: to_end
    fields:
      - { name: tag, type: uint8 }
      - { name: len, type: uint8 }
      - { name: value, type: bytes, size: len }
```

A Field after a `repeat: to_end` array, in the same structure or after the structure holding
it, can only be empty or truncated, which is the warning [`unreachable-field`](../diagnostics.md#unreachable-field).

## Elements that read nothing {#empty}

An element that reads no bytes would repeat forever without moving through the packet, so the
Dissector stops the array there with a "Malformed: empty element" expert info error, whatever
the count, filtered as `<protocol>._malformed.empty_element`. It happens only when every Field of
the element can be empty, such as a `bytes` Field whose size is 0 in the packet.

## Rules {#rules}

- `count:` and `repeat:` together are
  [`conflicting-repeat`](../diagnostics.md#conflicting-repeat), and a `repeat:` other than
  `to_end` is [`invalid-repeat`](../diagnostics.md#invalid-repeat).
- Only an inline structure or a Field of a Type repeats: `count:` or `repeat:` on a Field of a
  built-in type is [`invalid-array`](../diagnostics.md#invalid-array). Put the value in a
  one-Field structure instead.
- A Field inside an element can read the Fields before it in the same element, and the Fields
  read before the array. Nothing outside an element can read inside it:
  `items.len` after `items` is [`unknown-field`](../diagnostics.md#unknown-field), since there
  is one `len` per element.

```yaml,diagnostic=invalid-array
name: demo
fields:
  - { name: ids, type: uint16, count: 4 }
```

```yaml
name: demo
fields:
  - name: ids
    count: 4
    fields: [ {name: id, type: uint16} ]
```
