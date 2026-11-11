# Cheat sheet

A Protocol Description has ten top-level keys. They are accepted in any order and listed here
in the order the book and the examples use.

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Filter name of the protocol: a lowercase letter, then lowercase letters, digits, `_` or `-`, at most 32 characters. |
| `title` | no | Full name shown at the root of the protocol tree. Defaults to the uppercase `name`. |
| `registration` | no | Ports claimed by default, and Decode As ([Registration](registration.md)). Leaving it out means Decode As only. |
| `framing` | no | How messages are found in a TCP stream. |
| `endian` | no | Default byte order, `big` (the default) or `little`. |
| `info` | no | Template of the Info column. |
| `fields` | yes | The top-level layout: a non-empty list of Fields. |
| `types` | no | Named Types, reusable groups of Fields. |
| `enums` | no | Named tables of labels for integer values. |
| `allow` | no | Names of warnings to silence. |

The smallest description is `name:` plus `fields:`:

```yaml
name: demo
fields:
  - { name: id, type: uint8 }
```

With a title and a silenced warning:

```yaml
name: demo
title: Demo Protocol
fields:
  - { name: id, type: uint8 }
allow: [unknown-allow]
```

There is no format-version key and no top-level `description:` key: YAML comments document a
file. (A Field's own `description:` is its help text in Wireshark.)
