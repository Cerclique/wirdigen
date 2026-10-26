# Wirdigen

Wirdigen turns a declarative description of a network protocol into a Wireshark dissector.

## Language

**Protocol Description**:
The document a user writes to describe one protocol: its identity, how Wireshark should recognise its traffic, and the layout of its payload.
_Avoid_: Package, packet description, message description, dissector description

**Field**:
One named element of a Protocol Description's payload layout, with a type and display settings.
_Avoid_: Data chunk, data, attribute

**Dissector**:
The Wireshark Lua plugin generated from a Protocol Description.
_Avoid_: Plugin, LUA file
