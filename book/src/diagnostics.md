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
fields: [ {name: a} ]
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
fields: [ {name: a} ]
```

**Fix**: write the value out, or move repeated Fields into a Type.

## `yaml-anchor` {#yaml-anchor}

**Severity**: error

The file declares a YAML anchor (`&name`). Anchors are not part of the YAML subset Wirdigen
reads, because a description reuses Fields through Types.

```yaml,diagnostic=yaml-anchor
name: &n demo
fields: [ {name: a} ]
```

**Fix**: remove the anchor, and move repeated Fields into a Type.

## `yaml-tag` {#yaml-tag}

**Severity**: error

The file uses a YAML tag (`!foo`, `!!str`). Tags are not part of the YAML subset Wirdigen reads.

```yaml,diagnostic=yaml-tag
name: !foo demo
fields: [ {name: a} ]
```

**Fix**: remove the tag. To keep a value as text, quote it.

## `merge-key` {#merge-key}

**Severity**: error

The file uses a YAML merge key (`<<:`). Merge keys are not part of the YAML subset Wirdigen
reads, because a description reuses Fields through Types.

```yaml,diagnostic=merge-key
name: demo
fields: [ {name: a} ]
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
fields: [ {name: a} ]
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
fields: [ {name: a} ]
```

**Fix**: correct the spelling, or remove the key. Use a YAML comment to document a description.

## `duplicate-key` {#duplicate-key}

**Severity**: error

A key appears twice in the same mapping, so the description has no single meaning. A note
points at the first occurrence.

```yaml,diagnostic=duplicate-key
name: demo
name: other
fields: [ {name: a} ]
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
fields: [ {name: a} ]
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
fields: [ {name: a} ]
```

**Fix**: write a single-line title, or leave `title:` out to use the uppercase `name:`.

## `unknown-allow` {#unknown-allow}

**Severity**: warning

An `allow:` entry names no warning: either no Diagnostic has that name, or it names an error,
which cannot be silenced. It is a warning rather than an error so that a description allowing a
warning added by a newer Wirdigen still works with an older one.

```yaml,diagnostic=unknown-allow
name: demo
fields: [ {name: a} ]
allow: [bogus]
```

**Fix**: correct the name or remove the entry. To keep an entry meant for a newer Wirdigen,
allow this warning too:

```yaml
name: demo
fields: [ {name: a} ]
allow: [unknown-allow, bogus]
```
