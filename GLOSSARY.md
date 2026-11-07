# Wirdigen

Wirdigen turns a declarative description of a network protocol into a Wireshark dissector.

## Language

**Protocol Description**:
The document a user writes to describe one protocol: its identity, its Registration, and the layout of its payload.
_Avoid_: Package, packet description, message description, dissector description

**Registration**:
How a Dissector attaches to traffic in Wireshark: the ports it claims by default, and its availability in Decode As.
_Avoid_: Connection, network information, binding

**Field**:
One named element of a Protocol Description's payload layout, with a built-in type or a Type, and display settings.
_Avoid_: Data chunk, data, attribute

**Type**:
A named, reusable group of Fields, defined once in a Protocol Description and used wherever a layout is needed, including as one kind of message among several.
_Avoid_: Struct, message, template

**Framing**:
How a Dissector finds where each message starts and ends in a TCP stream, so one message split across segments, or several in one segment, are dissected correctly.
_Avoid_: Reassembly, segmentation, PDU splitting

**Expression**:
A formula in a Protocol Description that computes a size, a count, a condition or a switch subject from Fields read earlier.
_Avoid_: Formula, rule, script

**Diagnostic**:
An error or a warning that Wirdigen reports about a Protocol Description, identified by a stable name and pointing at where in the description it applies. An error stops generation; a warning does not.
_Avoid_: Lint, issue, validation message

**Dissector**:
The Wireshark Lua plugin generated from a Protocol Description.
_Avoid_: Plugin, LUA file
