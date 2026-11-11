# Info column

Wireshark's packet list shows a one-line summary of each packet in its Info column. `info:`
fills it from a template naming Fields of the packet:

```yaml
name: demo
info: "{msg_type} id={id}"
fields:
  - { name: msg_type, type: uint8, values: { 1: Request, 2: Response } }
  - { name: id, type: uint16, display: hex }
```

A request with `id` 0x002a shows "Request id=0x002a". The column is set once the Dissector has
read the message, however far it got. The Protocol column always shows the protocol's short
name, the uppercase `name:`.

## Templates {#templates}

A template is text with references in braces:

- **`{path}`** shows a Field. The path is the Field's name, then the names down into
  [inline structures](fields.md#inline-structures), [Types](fields.md#types),
  [`switch` cases](conditionals.md#switch) and [bitfields](bitfields.md), as in its filter name:
  `{msg_type}`, `{header.seq}`, `{flags.ack}`, `{body.user_id}`.
- **`{{` and `}}`** are a literal `{` and `}`: `"{{{id}}}"` shows `{42}`.

A reference is a Field path and nothing more. An Expression (`{len + 4}`), a format specifier
(`{id:04x}`) or an empty `{}` is [`invalid-info`](../diagnostics.md#invalid-info), as is a
brace that pairs with nothing, and a template on several lines. To change how a number looks,
give its Field a [`display:`](fields.md#display).

## What a reference shows {#references}

| The Field | Shows |
|---|---|
| An integer with [`values:`](fields.md#value-mappings), or a sub-Field with them | The label of its value, or the number when no label matches. |
| A `switch` Field | The name of its case, as in its tree item: "Login", or the number. |
| Any other Field | Its value as Wireshark displays it: with its `display:`, its unit, its `true:`/`false:` label, a string's text, an address. |
| A Field that was not read | Nothing. |

Any Field of a built-in type can be referenced, [hidden](fields.md#hidden) ones included, and so
can a bitfield sub-Field and a `switch` Field:

```yaml
name: demo
info: "{kind} {flags.prio} from {source} ({body})"
fields:
  - { name: kind, type: uint8, values: Kind }
  - name: flags
    type: uint8
    bits:
      - { name: prio, width: 2, values: { 0: low, 3: high } }
      - { padding: 6 }
  - { name: source, type: ipv4 }
  - name: body
    switch: kind
    cases:
      1: [ { name: user, type: string, prefix: uint8 } ]
      2: [ { name: code, type: uint16 } ]
enums:
  Kind:
    1: Login
    2: Error
```

Unlike an [Expression](expressions.md#references), a template can reach into an `if:` Field or
a `switch` case: the column is set after the whole message, so a Field that was not read, being
under a false `if:`, in another case, or after the end of a truncated packet, shows nothing.
Above, `{body.code}` would be empty in a Login.

A path is resolved from the top-level `fields:`. One that names no Field is
[`unknown-field`](../diagnostics.md#unknown-field), and so is one going into an
[array](arrays.md): an array has a value per element, and the column shows one. A path ending on
an inline structure, a Field of a Type or an array has no value of its own to show: it is
[`invalid-info`](../diagnostics.md#invalid-info).

```yaml,diagnostic=invalid-info
name: demo
info: "{header}"
fields:
  - name: header
    fields: [ { name: seq, type: uint16 } ]
```

## Without `info:` {#default}

Without `info:`, the Info column shows the case name of the outermost `switch` Field, the way a
protocol with several kinds of message names each one: "Login", "Error". The outermost is the
`switch` Field with the fewest structures and Types around it, the first one in the layout
among equals; a `switch` inside an [array](arrays.md) is never picked. When that `switch` Field
is not read, or there is none, the column keeps what Wireshark's UDP or TCP layer wrote.
