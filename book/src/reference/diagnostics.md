# Diagnostics

A **Diagnostic** is an error or a warning that Wirdigen reports about a Protocol Description.
Each one has a stable kebab-case name and points at where in the description it applies:

```text
warning[unknown-allow]: there is no warning named `bogus`
 --> demo.wirdigen.yaml:3:9
  |
3 | allow: [bogus]
  |         ^^^^^
  |
  = note: see https://cerclique.github.io/wirdigen/diagnostics.html#unknown-allow
```

The last note links to the Diagnostic's entry in the [Diagnostics index](../diagnostics.md),
which explains what it means and how to fix it.

## Errors and warnings

- An **error** means the description has no single meaning or contradicts itself. No Dissector
  is generated.
- A **warning** means the meaning is clear but probably a mistake. The Dissector is generated
  anyway.

Checks run in stages: YAML parsing, then the keys and the kinds of their values, then the
meaning of the description. Each stage reports all its errors, and the next one runs only if
there were none, so fixing errors can reveal new ones.

## Silencing warnings

The top-level `allow:` lists the names of the warnings to silence for the whole description.
Errors cannot be silenced. Naming something that is not a warning is itself the warning
[`unknown-allow`](../diagnostics.md#unknown-allow), which `allow:` can silence too:

```yaml
name: demo
fields:
  - { name: id, type: uint8 }
allow: [unknown-allow, a-warning-from-a-newer-wirdigen]
```

## Stability

Diagnostic names and severities are stable: a later 1.x release never renames a Diagnostic nor
turns a warning into an error. It can add new warnings, though, so a build that fails on any
warning can start failing after an upgrade. The message wording, the notes and the layout of
the rendered text can change in any release.
