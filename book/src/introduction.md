# Introduction

Wirdigen turns a declarative description of a network protocol into a Wireshark dissector.

You write a **Protocol Description**, a YAML file that names the protocol and lays out the Fields
of its payload. Wirdigen checks it, reports any mistake with a precise location, and generates a
Lua **Dissector** for Wireshark 4.4 and later.

```yaml
name: demo
fields:
  - { name: id, type: uint8 }
  - { name: length, type: uint16 }
```

By convention the file is named `<protocol>.wirdigen.yaml`, here `demo.wirdigen.yaml`.

## About this book

This book is the user guide and the reference of the Protocol Description format. Every YAML
example in it is a complete description checked by Wirdigen's CI, so it is valid unless the text
says which Diagnostic it shows.

Wirdigen v1 is being written: chapters shown greyed out in the table of contents are not written
yet. The book at <https://cerclique.github.io/wirdigen/> follows the latest release; the one at
<https://cerclique.github.io/wirdigen/dev/> follows the development branch.
