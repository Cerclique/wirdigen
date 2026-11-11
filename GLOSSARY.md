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
One named element of a Protocol Description's payload layout: a single value, or a group of Fields, with its display settings.
_Avoid_: Data chunk, data, attribute

**Structure**:
An ordered list of entries read one after another, each a Field or Padding: the top-level layout, an inline group of Fields, a Type's body or a Case.
_Avoid_: Record, block, section

**Padding**:
Unnamed space that is skipped: bytes between the entries of a Structure, or bits between the Sub-Fields of a Bitfield. It cannot be filtered or referenced.
_Avoid_: Gap, filler, reserved bytes, unused bits, alignment

**Hidden Field**:
A Field read but left out of the protocol tree; it can still be filtered and used in Expressions.
_Avoid_: Invisible field, private field, internal field

**Expected Values**:
The values a Field or Sub-Field should hold. A Message holding another value gets a warning in Wireshark but is still read to the end; it is not Malformed.
_Avoid_: Constraint, assertion, validation, magic value

**Bitfield**:
A Field of an unsigned integer type whose bits are split, most significant first, into Sub-Fields and Padding, every bit accounted for.
_Avoid_: Flags, bitmask, packed field

**Sub-Field**:
A Field of a Bitfield, a few bits wide: a boolean when it is one bit, an unsigned integer otherwise.
_Avoid_: Bit field, flag, bit

**Array**:
A Field whose layout is read several times in a row: as many times as a count gives, or until its enclosing Structure or the Message ends.
_Avoid_: List, sequence, repeated field, vector

**Element**:
One reading of an Array's layout, shown in the tree on its own and numbered from 0, but sharing the Array's name and Filter Names.
_Avoid_: Item, entry, record

**Switch**:
A Field that reads one Case among several, picked by the value of its Subject.
_Avoid_: Union, variant, choice

**Case**:
One layout a Switch can read, a Type or a group of Fields, picked by a set of Subject values or, for the default Case, when no other matches. It adds no level to the tree or to Filter Names.
_Avoid_: Branch, arm, variant, alternative, message type

**Subject**:
The Expression whose value picks a Switch's Case, computed once before any Case is read.
_Avoid_: Selector, discriminant, tag, key

**Conditional Field**:
A Field read only when its condition, an Expression, is not zero; otherwise it reads nothing and adds nothing to the tree.
_Avoid_: Optional field, guarded field

**Conditional Scope**:
A Conditional Field or a Case: the Fields inside it have a value only when it was read, so only Expressions inside it can read them.
_Avoid_: Conditional block, branch

**Type**:
A named, reusable group of Fields, defined once in a Protocol Description and used wherever a layout is needed, including as a Case of a Switch.
_Avoid_: Struct, message, template

**Byte Order**:
Whether a multi-byte value is read most significant byte first (big) or last (little). A Field takes the nearest one set on itself, its enclosing Structures or the Protocol Description; a Type keeps its own, whatever Structure uses it.
_Avoid_: Endianness, endian

**Value Mapping**:
What a Field shows beside or instead of its raw value: labels for values and value ranges, given inline or by naming an Enum, labels for true and false, or a unit.
_Avoid_: Value labels, value string, lookup

**Enum**:
A named table of labels for integer values and value ranges, defined once in a Protocol Description and shared by every Field whose values it names.
_Avoid_: Value string, lookup table, dictionary

**Message**:
One unit of traffic a Dissector reads with the top-level Structure: a packet's payload, or one piece cut out by Framing.
_Avoid_: PDU, frame, packet

**Framing**:
How a Dissector finds where each Message starts and ends in a TCP stream, so one Message split across segments, or several in one segment, are dissected correctly.
_Avoid_: Reassembly, segmentation, PDU splitting

**Expression**:
A formula in a Protocol Description that computes a size, a count, a condition or the Subject of a Switch from Fields read earlier.
_Avoid_: Formula, rule, script

**Field Path**:
The dotted chain of Field names by which an Expression reads an earlier Field, looked up from the nearest enclosing Structure outward.
_Avoid_: Reference, variable, identifier

**Diagnostic**:
An error or a warning that Wirdigen reports about a Protocol Description, identified by a stable name and pointing at where in the description it applies. An error stops generation; a warning does not.
_Avoid_: Lint, issue, validation message

**Dissector**:
The Wireshark Lua plugin generated from a Protocol Description.
_Avoid_: Plugin, LUA file

**Malformed**:
What a Dissector reports when a Message cannot be read as its Protocol Description says, either because a Field does not fit (truncated) or because an Expression's value cannot be used; it shows what it read so far and stops, never failing with a Lua error.
_Avoid_: Invalid packet, corrupt, parse error

**Filter Name**:
The name a Wireshark display filter uses for a Field: the protocol's name, then the Field names from the top-level Structure down to it, never through a Type's name or a Case. Saved filters depend on it, so changing it breaks them.
_Avoid_: Abbreviation, abbrev, field ID, filter path
