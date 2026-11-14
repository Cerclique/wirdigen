# Wirdigen v1 specification

> **Status: complete.** Every part below is decided.

This document describes Wirdigen v1: the Protocol Description format, the Dissectors it produces, the architecture, the library API, the CLI, the test strategy, the documentation and the release process. It is the destination of the [Wirdigen v1 spec](https://github.com/Cerclique/wirdigen/issues/8) map and the input for breaking v1 into implementation tickets.

It decides nothing new. Every rule here comes from a closed ticket of that map or from an ADR in [`docs/adr/`](adr/), which holds the reasoning and the rejected options. Where the two seem to disagree, the ADR is right and this document has a bug. Terms in **bold capitals** (Protocol Description, Field, Type, …) are defined in [`GLOSSARY.md`](GLOSSARY.md).

## Contents

1. [Scope](#1-scope)
2. [Domain model](#2-domain-model)
3. [Protocol Description format](#3-protocol-description-format)
4. [Expressions](#4-expressions)
5. [Dissector behaviour](#5-dissector-behaviour)
6. [Validation and Diagnostics](#6-validation-and-diagnostics)
7. [Architecture and generation](#7-architecture-and-generation)
8. [Library API](#8-library-api)
9. [CLI](#9-cli)
10. [Testing](#10-testing)
11. [Documentation](#11-documentation)
12. [Toolchain, CI and release](#12-toolchain-ci-and-release)
13. [Compatibility](#13-compatibility)
14. [Out of scope and later](#14-out-of-scope-and-later)
15. [Left to implementation](#15-left-to-implementation)
16. [Decision index](#16-decision-index)

## 1. Scope

Wirdigen turns a **Protocol Description**, a YAML file a user writes, into a **Dissector**: one Lua file that Wireshark loads.

v1 is a rewrite with no compatibility with 0.2/0.3: neither the format nor the API carries over, and there is no migration path. The `arise` branch (2024) and the `archive/rework` tag (the 2023 `rework` branch, holding the nesting / sequential-offset idea) are references to salvage ideas from, not code to continue.

v1 delivers:

- the `wirdigen` library crate (validation, generation, JSON Schema, Diagnostic rendering);
- the `wirdigen-cli` crate, whose binary is `wirdigen`;
- an mdBook user guide and format reference, docs.rs API docs and three example protocols.

A WASM/npm surface comes after v1, as a third crate on top of the library (§14).

## 2. Domain model

The domain terms (Protocol Description, Field, Structure, Type, Switch, Case, Message, Framing and the rest) are defined in [`GLOSSARY.md`](GLOSSARY.md), the single source for their meaning; this spec uses them as defined there.

There is no `messages:` key: a protocol with several kinds of Message is a `switch` whose Cases use Types (§3.9).

The flow is: **Source** (description text plus a name) → `validate` → **ValidDescription** (or Diagnostics) → `generate` → Lua text. The CLI adds files around it.

## 3. Protocol Description format

### 3.1 File and syntax

*ADR 0004, ADR 0005.*

- The format is Wirdigen's own. It borrows concepts from Kaitai Struct, PDL and wsgd (sequential layout, size and count references, repetition, `if`/`switch`, enums, bitfields, expected values), but not their keywords or document shape.
- There is one syntax: a **strict subset of YAML 1.2**, read by a YAML 1.2 parser that reports positions (so `no` and `on` stay strings):
  - one Protocol Description per file, no multi-document streams;
  - no custom tags, no merge keys (`<<:`), no anchors or aliases;
  - unknown keys and duplicate keys are errors with line and column;
  - YAML nests at most 256 levels; a deeper node is `yaml-too-deep`, at the node that reaches level 257 ([ADR 0020](adr/0020-field-depth-limit.md)).
- Expressions are YAML strings parsed by Wirdigen's own mini-language (§4).
- By convention a file is named `<protocol>.wirdigen.yaml`. Nothing enforces it.
- Keys that take only a constant accept a YAML integer. Any other numeric value is a YAML string holding an Expression. A YAML float or bool where an integer is required is an error.
- Reuse of Fields goes through Types (§3.5), never YAML anchors.

### 3.2 Top level

*ADR 0014, ADR 0015.*

A Protocol Description has exactly ten top-level keys, accepted in any order. Docs, examples and the JSON Schema list them in this order:

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Filter name of the protocol (§3.3). |
| `title` | no | Full name at the tree root (§3.3). |
| `registration` | no | Ports and Decode As (§3.12). Leaving it out means Decode As only. |
| `framing` | no | TCP Framing (§3.13). |
| `endian` | no | Default byte order, `big` (default) or `little` (§3.11). |
| `info` | no | Info column template (§3.14). |
| `fields` | yes | The top-level layout: a non-empty structure, spelled like an inline structure (§3.4). |
| `types` | no | Named Types (§3.5). |
| `enums` | no | Named value tables (§3.4.7). |
| `allow` | no | Names of warnings to silence (§6.4). |

There is no format-version key: a file without one is 1.x, and a description using a key from a newer minor already fails on that unknown key. A 2.0 can require `wirdigen: 2`. There is no `description:` key; YAML comments document a file. Ordering of top-level keys is never checked.

The minimum description is `name:` plus `fields:`.

### 3.3 Protocol identity

*ADR 0014.*

Wireshark needs three names per protocol. Wirdigen asks for one and derives the rest:

| Wireshark name | Comes from | Rules |
|---|---|---|
| Filter name (`dns`) | `name:` | `[a-z][a-z0-9_-]+`, 2 to 32 characters: Wireshark refuses one-character filter names. Uppercase is an error, never lowercased silently. No `.`, which would blur where the Field Path starts. Error `invalid-protocol-name`. |
| Short name (`DNS`, Protocol column) | uppercase of `name:` | Always derived. A `short_name:` override can come later as a minor release. |
| Full name (tree root) | `title:` | Optional, non-empty, single line, defaults to the short name. Error `invalid-protocol-title`. |

A `name:` or `title:` equal to a protocol built into Wireshark is the warning `protocol-name-taken`, checked against a `tshark -G protocols` snapshot from the latest supported stable Wireshark, the union of the builds CI runs (§10.5), embedded in the library and kept current by a CI job. Each of the three derived names is compared with the same name of every built-in protocol, as Wireshark refuses a second protocol with any of them; a clash on the default full name is reported on `name:`. It is a warning because built-ins vary by Wireshark version and build. Clashes between two Wirdigen Dissectors are not detected.

Changing `name:` renames every filter of the protocol, so it breaks that protocol's users.

### 3.4 Field declaration

*ADR 0015, Field declaration: types, display and value mappings.*

A Field is declared in Wirdigen's own vocabulary: Wireshark's names (`FT_*`, `BASE_*`, `ENC_*`, value string vs range string) never appear in a Protocol Description.

```yaml
fields:
  - name: msg_type
    type: uint8
    values: MsgType            # an Enum (§3.4.7)
  - name: length
    type: uint16
    display: hex
    unit: [byte, bytes]
  - name: user
    type: string
    prefix: uint8
    encoding: utf8
    label: User name
  - { padding: 2 }
  - name: header
    type: Header               # a Type (§3.5)
  - name: options
    fields:                    # an inline structure
      - { name: ttl, type: uint8 }
```

#### 3.4.1 Structures

- A structure is an ordered sequence of Fields read one after another (sequential layout, no absolute offsets). The top-level `fields:`, a Type's body, a Field's inline `fields:` and an inline `switch` case are all structures, spelled the same way.
- A structure is an **ordered YAML list of maps**, each with a required `name:`. The only entries without a name are `{ padding: … }` (§3.10).
- Sibling Field names must be unique (error).
- A Field is at most 64 deep: at most 64 Fields enclose it, counted through every Type it is reached by, a `switch` case adding none, so at most 64 names lie between the protocol's and its own in its filter name (§5.2). A deeper Field is `field-too-deep`, reported once where it is written at each Field that is the first past 64 on its path, naming the filter name that reaches it ([ADR 0020](adr/0020-field-depth-limit.md)).

#### 3.4.2 Names

| Names of | Rule | Error |
|---|---|---|
| Fields and bitfield sub-Fields | `[a-z][a-z0-9_]*` | `invalid-field-name` |
| Types and Enums | `[A-Z][A-Za-z0-9]*` | `invalid-type-name` |

- Every built-in type is lowercase, so `type: Header` is always a Type and `type: uint8` always a built-in, and a built-in added in a 1.x minor can never collide with a Type.
- Field names exclude `-` and `.` because they appear bare in Expressions (§4). The first-character rule already keeps the `_` prefix reserved for built-ins (§4.5).
- There is no length cap.

#### 3.4.3 What a Field is

A Field has exactly one of:

| Key | Field kind |
|---|---|
| `type:` | a built-in type (§3.4.4) or a Type name (§3.5) |
| `fields:` | an inline structure |
| `switch:` | a choice of layout, with `cases:` / `default:` (§3.9) |

None of them is the error `missing-field-kind`; more than one is `conflicting-field-kind`. Arrays add to this (§3.7): `type: Item` plus `count:`, or `fields: [...]` plus `repeat: to_end`. `bits:` goes only with a fixed-size unsigned integer `type:` (§3.8).

Every numeric Field read can be used in later Expressions (§4.3); `hidden: true` reads a Field without showing it (§3.10).

#### 3.4.4 Built-in types

Built-in names describe the wire, not Wireshark's ftypes.

| Built-in | Wire | Wireshark ProtoField |
|---|---|---|
| `uint8` `uint16` `uint24` `uint32` `uint64` | unsigned integer | `uintN` |
| `uint40` `uint48` `uint56` | unsigned integer | `uint64`; generated code reads the bytes itself |
| `int8` `int16` `int24` `int32` `int40` `int48` `int56` `int64` | signed integer | `intN`, or `int64` for 40/48/56 |
| `bool` | 1 byte, non-zero is true | `bool` |
| `float32` `float64` | IEEE 754 | `float` / `double` |
| `string` | text; length from `size:`, `prefix:` or `terminator:` (§3.6) | `string` (`stringz` for `terminator: 0`) |
| `bytes` | raw bytes; same length keys | `bytes` |
| `ipv4` `ipv6` `ether` `eui64` `guid` | fixed size | same names |
| `abs_time` `rel_time` | timestamp; size from `encoding:` (§3.4.5) | `absolute_time` / `relative_time` |

- Fixed-size types reject the length keys; `string` and `bytes` need exactly one of them. `stringz` and `ubytes` are not types.
- Generated code fills Lua's gaps itself: length-prefixed strings, 40/48/56-bit integers, and bitfields (one ProtoField per sub-Field with a mask, since Lua has no `add_bitmask`).
- Not in v1, each addable in a minor release: `char`, `framenum`, `protocol`, `none`, `ipx`, `oid`, `rel_oid`, `systemid`.

#### 3.4.5 `encoding:`

| Type | Values | Default |
|---|---|---|
| `string` | `ascii` `utf8` `utf16` `ucs2` `latin1` | `utf8` |
| `abs_time` | `secs` (4 bytes, Unix epoch), `secs_nsecs` (4 + 4), `ntp` (8), `msecs` / `usecs` / `nsecs` (8, Unix epoch) | `secs` |
| `rel_time` | as `abs_time`, without `ntp` | `secs` |

- `utf16` and `ucs2` follow the Field's `endian:` (§3.11), and their `terminator:` is a 2-byte zero.
- A timestamp's size follows from its encoding, so `size:` on `abs_time`/`rel_time` is rejected.
- `encoding:` on any other type is `incompatible-display`.
- Every `ENC_TIME_*` value works through Lua's `add_packet_field` on 4.4.19 and 4.6.9, in both byte orders (#57); the `timestamps` corpus case covers each value (§10.5).

#### 3.4.6 `display:`

| Type | `display:` values | Default |
|---|---|---|
| unsigned integers, and integer bitfield sub-Fields | `dec` `hex` `oct` `dec_hex` `hex_dec` | `dec` |
| signed integers | `dec` | `dec` |
| `bytes` | `plain` `dot` `dash` `colon` `space` (byte separator) | `plain` |
| `abs_time` | `local` `utc` `doy_utc` | `local` |
| every other type | none | — |

Any value outside this matrix, and an `encoding:` or value-mapping key (§3.4.7) on a type that does not take it, is the error `incompatible-display`.

#### 3.4.7 Value mappings and Enums

| Key | Applies to | Meaning |
|---|---|---|
| `values:` | integer types, integer bitfield sub-Fields | An inline map from an integer or a `"low-high"` range string to a label, or the name of an Enum. |
| `true:` / `false:` | `bool`, boolean bitfield sub-Fields | Labels for the two states; either may be given alone. |
| `unit:` | integer and float types | A string, or a `[singular, plural]` list of exactly two strings (a one-item list is `wrong-value-type`). Each form is a non-empty single line, else the error `invalid-unit`. |

- Overlapping keys in one table are the error `overlapping-values`. A key outside the type's range is the warning `unreachable-value`.
- `unit:` together with `values:` is the error `conflicting-mappings`.
- The generator emits a Wireshark value string, or a range string when any key is a range.
- A top-level `enums:` maps an **Enum** name to a values table, referenced as `values: <EnumName>`. Inline tables stay allowed. An unknown Enum is the error `unknown-enum`; an Enum never used is the warning `unused-enum`.
- A key is a YAML integer, or a string `"low-high"` of two integers with `low <= high` (spaces around the bounds are allowed, so is the unquoted plain scalar `16-31`); anything else, a quoted integer included, is `wrong-value-type`, and a key written twice is `duplicate-key` (YAML keys: `16` and `"16"` differ). A range is `unreachable-value` only when none of its values fit the type, and an Enum's key is reported once, for the first Field that cannot reach it; a Field whose table the type cuts to nothing gets no labels. Labels, including `true:`/`false:`, follow `invalid-label` (§3.4.8). A Field naming an Enum, or misspelling its name, uses it even when the Field has other errors, so those never cascade into `unused-enum`.
- Confirmed on 4.4.19 and 4.6.9 (#55): Wireshark converts each key and range bound to an unsigned integer of the ProtoField's width (32 or 64 bits) and compares range strings unsigned. Generated code therefore leaves out keys the type cannot hold and cuts ranges to it, writes a negative bound of a signed type up to 32 bits as its 32-bit two's complement, and splits a range crossing zero. An Enum is one Lua table per distinct cut. A unit is printed right after the value, so the generator adds the space. `-T json` shows only raw values, so the `values` corpus case checks that the tables load and dissect, not the label text.

```yaml
enums:
  MsgType:
    1: Request
    2: Response
    "16-31": Vendor
```

#### 3.4.8 Tree text

- `label:` is optional, non-empty and single line (error `invalid-label`). It defaults to `name:` with `_` turned into a space and the first letter capitalised (`msg_type` → "Msg type"). Array elements show `<label> [i]`.
- `description:` is optional and single line (error `invalid-description`). It becomes the ProtoField's blurb.

#### 3.4.9 Sharing a ProtoField

Two Fields reaching one filter name (§5.2) share a ProtoField only when type, `display:`, value mappings, `label:` and `description:` all match; two references to the same Enum count as matching. Otherwise it is the error `conflicting-filter-name`.

### 3.5 Types

*Language capabilities in v1, ADR 0009, ADR 0010.*

- `types:` is a map from Type name to `{ fields: [...], endian: … }`: `fields:` is required, `endian:` optional. A Type body is spelled like an inline structure Field without `name:`.
- A Type can be used as a Field's `type:`, as an array element and as a `switch` case.
- Type names are not part of filter names (§5.2): a Field `req_hdr` of Type `Header` with a Field `len` is `myproto.req_hdr.len`.
- `endian:` can be set on a Type (§3.11). A Type is read in its own byte order, else the top level's, whatever structure the Field using it is in: one `dissect_<Type>` serves every use (§7.3). `endian:` on a Field of a Type is therefore `invalid-endian`, and the value keys on it are rejected as on an inline structure (`unexpected-length`, `incompatible-display`).
- A duplicate Type name is `duplicate-key`; an unknown Type is `unknown-type`, reported once at its first use; a Type containing itself, directly or through other Types, is `recursive-type`, reported once per cycle. A Type never used is the warning `unused-type`; a misspelt use counts as using the Type it is closest to, as for Enums.
- Expressions inside a Type are resolved at each place the Type is used (§4.3), and errors point at that use site.
- There is no per-Type `info:` in v1.

### 3.6 Sizes

*Language capabilities in v1, Expression mini-language.*

A variable-length Field (string, bytes, …) states its length with exactly one of these mutually exclusive keys:

| Key | Meaning |
|---|---|
| `size: <expr>` | Byte length from an Expression over earlier Fields, or a constant. |
| `size: "_remaining"` | Up to the end of the innermost enclosing structure with a known size, or of the message. |
| `prefix: <int type>` | Length read from an unsigned integer type (`uint8` … `uint64`) just before the value, in the Field's byte order (`prefix: uint16`). |
| `terminator: <byte>` | Ends at that byte, 0 to 255 (NUL-terminated strings). The terminator is consumed but not part of the value. |

None of them on `string`/`bytes` is `missing-length`, more than one is `conflicting-length`; a negative constant `size:` is `invalid-size`, and so is a constant Expression that is negative, divides by zero or shifts by a count outside 0..63 (#60: rejected when building rather than reported at runtime as in §4.4), any other `prefix:` is `invalid-prefix`, and a `terminator:` outside 0–255, or other than 0 on `utf16`/`ucs2`, is `invalid-terminator`.

A Field placed after a Field that reads to the end of the message is the warning `unreachable-field` (§6.3).

### 3.7 Arrays

| Key | Meaning |
|---|---|
| `count: <expr>` | Fixed or computed number of elements. |
| `repeat: to_end` | Repeat until the enclosing structure or message ends (TLV lists). |

The two are mutually exclusive (`conflicting-repeat`); `repeat:` leaves room for `repeat: { until: <expr> }` after v1, and any value but `to_end` is `invalid-repeat` in v1. The element is an inline structure or a Type: `count:` or `repeat:` on a built-in type is `invalid-array`. A constant `count:` follows the rules of a constant `size:` (§3.6) under `invalid-count`. Each element is its own subtree item, its label followed by its index (`Items [0]`, `Items [1]`, …); there is no item for the array as a whole. Elements share filter names (§5.2). A Field after a Field that reads to the end of the message is the warning `unreachable-field` (§6.3). An element that consumes zero bytes stops the array as malformed, with a "Malformed: empty element" expert info error on the array, filtered `<protocol>._malformed.empty_element` (§5.2). `count:` is evaluated once, before the first element; `repeat: to_end` reads elements while bytes are left in the message (§4.5's `_remaining`).

### 3.8 Bitfields

```yaml
- name: flags
  type: uint8
  bits:
    - { name: version, width: 3 }
    - { padding: 1 }
    - { name: ext, width: 1 }
    - { name: kind, width: 3 }
```

- `bits:` declares sub-Fields by bit width, most significant bit first. Wirdigen computes the masks.
- Widths must add up to the container's size; gaps are named or `{ padding: n }` entries. A mismatch is the error `mismatched-bit-widths`, and a width below 1 is `invalid-bit-width`. Padding bits add no tree item.
- Sub-Fields are usable in Expressions (`flags.ext`) and extend the container's filter name (`myproto.flags.ext`).
- The container must be a fixed-size unsigned integer (else `invalid-bits`). It is shown as an unsigned integer (with its own `display:` and `values:`) whose subtree holds the sub-Fields. `hidden: true` on it hides the subtree, but the sub-Fields stay usable in Expressions and filters.
- A width-1 sub-Field is boolean (Set / Not set, taking `true:`/`false:`) unless it carries `values:`, `unit:` or `display:`, which make it an unsigned integer. Wider sub-Fields are masked unsigned integers. There are no signed sub-Fields in v1.
- Sub-Fields accept only `name`, `width`, `display`, `values`, `unit`, `true`, `false`, `hidden`, `expect`, `label` and `description`.

### 3.9 Conditionals

*Language capabilities in v1, Expression mini-language, ADR 0009.*

- `if: <expr>` on a Field reads it only when the Expression is non-zero. It goes on any Field kind (a built-in, an inline structure, a Field of a Type, an array, where it is evaluated before `count:`) and also takes an integer constant. A condition that faults is malformed at runtime (§4.4), even a constant one; a negative one is true. A Field after a conditional `size: "_remaining"` Field or `repeat: to_end` array is not `unreachable-field`.
- `switch: <expr>` with `cases:` and an optional `default:` picks a layout from a value:
  - the subject is an Expression or an integer constant, computed once; one that faults is malformed at runtime (§4.4);
  - case keys are integers or `"low-high"` range strings, read like `values:` keys (§3.4.7); `cases:` is required and non-empty (`missing-key`, `wrong-value-type`);
  - each case is a Type name or inline Fields; a built-in type name is `wrong-value-type`. Inline Fields are read in the byte order of the structure holding the `switch`, a Type in its own (§3.5);
  - overlapping cases (values or ranges) are the error `overlapping-cases`, comparing values as the subject has them (§4.4), so `-1` and `18446744073709551615` overlap;
  - with no matching case and no `default:`, the rest of the message is shown raw as a bytes item filtered `<protocol>._unmatched`, with an expert info note (group Undecoded) filtered `<protocol>._undecoded.unmatched`, and the dissection stops: nothing says where the unknown layout ends.
- A case adds no tree level either: its Fields go straight into the `switch` Field's subtree item.
- A protocol with several kinds of message is a `switch` whose cases use Types. The `switch` Field's item shows the label of the Subject's value after its own label ("Body: Login"). When the `switch:` subject is a bare Field Path to a Field read by the same dissect function (§7.3), the name (and the default Info column, §3.14) is that Field's `values:` label, or the number if unmatched; any other Expression shows the number, and so does a path a Type resolves at its use site (§4.3), which can name a different Field at each use.
- A `switch` Field accepts only `name`, `label`, `description`, `if`, `hidden`, `switch`, `cases` and `default`, never `values:`. Another key is reported under the name it has elsewhere: a length key `unexpected-length`, `endian` `invalid-endian`, `bits` `invalid-bits`, `count`/`repeat` `invalid-array`, a value key `incompatible-display`. `cases` or `default` without `switch` is `missing-field-kind`, or `conflicting-field-kind` beside `type` or `fields`.
- Fields under `if:` or inside a case can be referenced only from inside the same conditional scope (§4.3). The way out is an inline structure carrying the `if:`.
- `switch` cases add no segment to filter names (`myproto.body.user_id`). Two cases reaching the same path share a ProtoField under the rule of §3.4.9; otherwise it is the error `conflicting-filter-name`. For a Field of a Type, its "type" is the Type: two Fields of different Types at one path conflict.

### 3.10 Padding, hidden Fields, expected values and handoff

| Key | Meaning |
|---|---|
| `{ padding: <n \| expr> }` | A standalone structure entry, shown as one "Padding" item, with no filter name. |
| `hidden: true` | Reads the Field (usable in Expressions, filters and `info:`) without adding it to the tree. |
| `expect: <value \| "low-high" \| list>` | A mismatch adds an expert info **warning** and dissection goes on. A list may mix values and ranges. An `expect:` that can never match is a validation warning (`unreachable-expect`). |
| `dissector: <name>` | On a bytes Field: passes the bytes to an existing Wireshark dissector by name (static handoff). |

- `{ padding: … }` takes no other key. Its amount follows the rules of a `size:` (§3.6): a negative constant, or a constant Expression that is negative or has no value, is `invalid-padding`; at runtime, a negative or faulting Expression is malformed (§4.4).
- A padding after a Field that reads to the end is the warning `unreachable-field`, as a Field would be.
- `expect:` goes on integer and `bool` Fields and on sub-Fields; elsewhere it is `incompatible-display`, like a value-mapping key. Its values are read like `values:` keys (§3.4.7), and an empty list is `wrong-value-type`. A `bool` holds 0 or 1, as Expressions read it (§4.4), and a `uint64` is compared as the unsigned value it is.
- An `expect:` is `unreachable-expect` when none of its values is in the range of the Field's type or the sub-Field's width; it is kept, so every packet gets the warning.
- A mismatch is an expert info warning (group Protocol) on the Field's item, hidden or not: "Unexpected value: <path> (expected <values as written>)", filtered `<protocol>._protocol.unexpected`.
- `dissector:` goes on `bytes` Fields only; elsewhere it is `incompatible-display`, like a value-mapping key. Its value is a one-word string: an empty one, one with whitespace, or a scalar that is not a string is `invalid-dissector`.
- The handed-off dissector's layer goes into the Field's structure, right after the Field's item, hidden or not, and the dissection goes on after it. A Field with no bytes calls no dissector. The Protocol column keeps the short name (§5.5).
- The dissector is looked up by name the first time a packet reads the Field, empty or not. An unknown name is an expert info warning (group Undecoded) on the structure: "Unknown dissector <name>: <path>", filtered `<protocol>._undecoded.dissector`. An error in the handed-off dissector is shown in its own layer and never raises a Lua error.

There is no `align:` in v1.

### 3.11 Byte order

`endian:` is `big` (default) or `little`. It is set at the top level and can be overridden on a Type, an inline structure or a Field. A Type does not inherit the byte order of the structure it is used in (§3.5). It is never encoded in type names.

### 3.12 Registration

*Registration mechanisms in v1.*

```yaml
registration:          # optional; leaving it out means Decode As only
  ports:
    udp: [5000, "6000-6010"]
    tcp: [5000]
```

- Ports are declared per transport, UDP, TCP or both, each as a single number or a `"low-high"` range string.
- Port 0, ports above 65535, inverted ranges, a port repeated within one transport and an empty transport list are errors: a port or range outside 1–65535 is `invalid-port`, a port declared twice on one transport (listed twice, spelt twice, or inside a range of the same list) is `overlapping-ports`, and an inverted range, a quoted single port or an empty list is `wrong-value-type`, as for the keys of a values table (§3.4.7).
- The preferences are named `<name>.udp_ports` and `<name>.tcp_ports`.
- Each declared transport gets a Wireshark range preference ("UDP port(s)" / "TCP port(s)") defaulting to the declared ports. When it changes (`prefs_changed`), the Dissector removes the old ports and adds the new ones. A transport with no declared ports gets no preference.
- Every Dissector is offered in Decode As on both `udp.port` and `tcp.port` (`add_for_decode_as`), whatever it declares. No key controls this.
- TCP Registration without `framing:` is the warning `tcp-without-framing`: each segment is then dissected as one message.
- `ports:` sits under `registration:` so `heuristic:` and `tables:` can join it later.

### 3.13 Framing

*Language capabilities in v1, Expression mini-language.*

```yaml
framing:
  header: 4              # constant
  length: "length + 4"   # total Message length, an Expression
```

- Applies under TCP Registration and TCP Decode As.
- `header` is a constant. `length` may reference only top-level Fields (and their bitfield sub-Fields) lying entirely inside the first `header` bytes; `_offset` and `_remaining` are not allowed. Breaking this rule is an error.
- The Dissector loops over the Messages in a segment and asks for more data through `pinfo.desegment_offset` / `desegment_len`: the exact missing bytes once the header gives the length, `DESEGMENT_ONE_MORE_SEGMENT` while the header is incomplete. Under TCP it is detected by `pinfo.port_type`; over UDP, `framing:` is ignored and each datagram is one Message.
- A computed length below `header`, or negative, is malformed (§5.3).

### 3.14 Info column

- `info:` is a template with `{path}` references, for example `"{msg_type} id={id}"`.
- References only: no Expressions or format specifiers. `{{` and `}}` escape braces.
- A reference renders the Field's `values:` (or `true:`/`false:`) label if it has one (the number if unmatched), otherwise the Field's display form. Any Field type is allowed.
- Conditional Fields may be referenced; an absent one renders as an empty string. Unresolvable paths, array internals and forward references are errors. Paths resolve from the top-level layout once the Message is read, so no reference is forward; one that resolves to no Field or goes into an array is `unknown-field`.
- A reference names a Field of a built-in type, a bitfield sub-Field, or a `switch` Field, which renders the label of its Subject's value as in §3.9. A template that does not parse (a lone brace, an Expression, a format specifier, more than one line) or a reference to an inline structure, a Field of a Type or an array is `invalid-info`.
- The Dissector sets the column once the Message is read, however far it got. With several Messages in a packet (Framing, §3.13), the column shows the last one's, from the values that Message read: a Field another Message of the packet read but it did not shows nothing. Setting the column first clears its fence, so the text also replaces what TCP reassembly fenced off from an earlier Message, and the last Message's text stands alone. Built-in Fields and sub-Fields are rendered from Wireshark's field extractors (`Field.new`), so their display form is Wireshark's own.
- Without `info:`, the Info column shows the label of the outermost `switch` Field's Subject value, as in §3.9: the one fewest structures and Fields of Types from the top level, first in layout order among them, never inside an array. When it is not read, the column keeps the transport's text.
- The Protocol column always shows the short name (§3.3).

## 4. Expressions

*ADR 0007, Expression mini-language.*

### 4.1 Where they appear

`size:`, `count:`, `if:`, `padding:`, the `framing:` `length`, and `switch:` subjects.

### 4.2 Syntax

A small C-like infix language: integer literals, Field Paths, the built-ins `_offset` and `_remaining`, and parentheses. No function calls, assignment, strings or `?:` in v1; each can be added later.

Operators from tightest to loosest binding (Rust/Python order, **not** C):

| Level | Operators |
|---|---|
| unary | `!` `~` `-` |
| multiplicative | `*` `/` `%` |
| additive | `+` `-` |
| shift | `<<` `>>` |
| bitwise and | `&` |
| bitwise xor | `^` |
| bitwise or | `\|` |
| comparison (non-associative) | `==` `!=` `<` `<=` `>` `>=` |
| logical and | `&&` |
| logical or | `\|\|` |

So `flags & 0x80 == 0x80` means `(flags & 0x80) == 0x80`, and `a < b < c` is an error.

An Expression nests at most 64 levels deep; a deeper one is the error `expression-too-deep`, at the token that reaches depth 65, because it would make a Dissector Lua cannot load ([ADR 0018](adr/0018-expression-depth-limit.md)). Depth counts every level the parser enters: a value, a parenthesis, a unary operator, and a binary operator over its operands. A value alone is 1 deep, `-x` and `(x)` are 2 deep, and a flat chain `a + a + … + a` of k operands is k deep, as it groups from the left.

Literals: decimal, `0x` hex (case-insensitive), `0b` binary, with `_` separators. A leading-zero literal such as `010` is an error. No character literals. `"low-high"` ranges are not an operator; they exist only in `switch` cases, `expect:` and `registration: ports:`.

### 4.3 References

1. A bare name resolves **nearest first**: earlier siblings, then the enclosing structure's earlier Fields, outward to the root. The nearest wins, without a shadowing warning.
2. Dotted paths descend into structures already read and into bitfield sub-Fields (`hdr.len`, `flags.ext`). Hidden Fields can be referenced.
3. Only Fields read **earlier** can be referenced. Forward references are errors.
4. Inside a Type, references are resolved at each use site, and errors carry that site's position.
5. Array elements can be referenced only from inside the element. No indexing and no `_index` in v1.
6. Conditional Fields can be referenced only from inside the same conditional scope. Conditions are never proven equivalent.
7. Only integer types, bitfield sub-Fields and `bool` can be referenced. Float, string, bytes, address and structure Fields are errors. There is no comparison against `values:` labels.

### 4.4 Values and runtime semantics

- One value type: signed 64-bit integer (Lua 5.3/5.4 integers). A `uint64` above 2⁶³ reads as negative.
- Truthiness is C's: comparisons and logic give 1 or 0, and any non-zero value is true.
- `/` truncates toward zero and `%` takes the dividend's sign (C, not Lua floor division). `>>` is arithmetic. Overflow wraps.
- Operators compile to prelude helper calls, never native Lua bitwise operators or `//` in the parsed file, so it parses under Lua 5.2 (§5.4); the helpers that need Lua 5.3 operators compile them from strings with `load`, after the version guard.
- Division or modulo by zero, a negative size, count, padding or framing length, and a shift count outside 0..63 are a "Malformed" expert info error on that Field. The Dissector stops cleanly and never raises a Lua error.
- An oversized size or count is a truncation (§5.3).

### 4.5 Built-ins

| Built-in | Value |
|---|---|
| `_offset` | Bytes from the start of the message: the packet, or the Message under Framing. |
| `_remaining` | Bytes left in the innermost enclosing structure with a known size, or else in the message. |

New built-ins can only be added under the `_` prefix, which is why user names may not start with `_`.

## 5. Dissector behaviour

Everything in this section is observable in Wireshark and falls under semver (§13).

### 5.1 Tree

- The tree root shows the full name (§3.3). Each structure Field is a subtree, and each array element is its own subtree item (`Items [0]`).
- Padding is one "Padding" item. Hidden Fields are not shown, but the layer a `dissector:` hands their bytes to is (§3.10). Unmatched `switch` bytes are shown raw with an expert info note (§3.9).

### 5.2 Filter names

*ADR 0009.*

- Every shown Field is filtered as `<protocol>.<path>`. The path is the chain of Field names from the top-level layout down through inline `fields:` and Type-typed Fields. Type names never appear.
- Type reuse registers one set of ProtoFields per use site.
- Array elements share their element's names (`myproto.items.id`).
- Bitfield sub-Fields extend their container's path (`myproto.flags.syn`).
- `switch` cases add no segment.
- Padding has no filter name.
- Expert infos are filtered under a reserved `_` segment, which no Field Path can reach (§3.4.2): a truncated packet is `<protocol>._malformed.truncated`, an Expression with no value (§4.4) `<protocol>._malformed.expression`, an array element that reads no bytes (§3.7) `<protocol>._malformed.empty_element`, a `switch` with no matching case (§3.9) `<protocol>._undecoded.unmatched`, a value outside its `expect:` (§3.10) `<protocol>._protocol.unexpected`, a `dissector:` naming no dissector (§3.10) `<protocol>._undecoded.dissector`. The bytes such a `switch` shows raw are `<protocol>._unmatched`.
- Two Fields reaching one path share a ProtoField when type, display, value mappings, label and description match (§3.4.9). Otherwise validation fails with `conflicting-filter-name`. Wirdigen never renames a Field silently.
- Renaming a Field, or moving it in or out of a nested structure, changes its filter name.

### 5.3 Bad and short packets

- Generated code bounds-checks before every read.
- On a short packet, the Dissector shows what it decoded, adds a "Malformed: truncated" expert info **error** on the Field that did not fit, and stops cleanly.
- Runtime arithmetic faults (§4.4) are reported the same way, as "Malformed".
- `expect:` mismatches are expert info **warnings** and dissection goes on.
- **A generated Dissector never raises a Lua error on any input.**

### 5.4 Versions and loading

*ADR 0006.*

- Lua only; no C plugin.
- Supports Wireshark **≥ 4.4** (Lua 5.3/5.4), with rolling support and no ceiling: misbehaviour on a new upstream release is a bug. Raising the floor is a minor release, and only after upstream end of life.
- At load, the Dissector checks `get_version()`. Below 4.4 it fails with a clear error naming the version it needs.
- For that guard to run, the whole file must **parse under Lua 5.2**: no native bitwise operators, no `//`. Expression operators go through prelude helpers; those needing Lua 5.3 operators are compiled at load with `load`, after the guard. Confirmed on 4.4.19 and 4.6.9 (#60): the bundled `bit` library works on 32 bits (`bit.band(0x100000001, 0x1FFFFFFFF)` is 1), so it cannot give 64-bit Expressions, while `load`ed native operators can.

### 5.5 Columns and preferences

- The Protocol column shows the short name, and the Info column follows §3.14.
- There is one port range preference per declared transport (§3.12).

## 6. Validation and Diagnostics

*ADR 0008, Validation of a Protocol Description.*

### 6.1 Stages

1. YAML parse.
2. Strict deserialization (unknown and duplicate keys, wrong scalar kinds).
3. Expression parsing.
4. Semantic checks.

Each stage reports **all** its errors, and the next stage runs only if the current one found none. Errors that only follow from an earlier one are suppressed: an unknown Type gives one error, not one per use. Validation is written entirely in Rust; the JSON Schema is never used to validate.

### 6.2 Severity

- **Error**: the description has no single meaning or contradicts itself. No Dissector is generated.
- **Warning**: the meaning is clear but probably a mistake. Generation goes ahead.

### 6.3 Checks

Errors:

- `invalid-field-name`, `invalid-type-name` (§3.4.2);
- `missing-field-kind`, `conflicting-field-kind` (§3.4.3); `unexpected-length`: length keys on a fixed-size type; `missing-length`: none on `string`/`bytes`; `size:` on a timestamp; `invalid-bits`: `bits:` on anything but a fixed-size unsigned integer; `invalid-endian`: an `endian:` other than `big` or `little`, or on a Field of a Type or a `switch` Field (§3.5, §3.9, §3.11);
- `incompatible-display`: a `display:` or `encoding:` value outside the matrices of §3.4.5–§3.4.6, or a value-mapping key, `expect:` or `dissector:` on a type that does not take it (§3.10);
- `invalid-label`, `invalid-description` (§3.4.8); `invalid-unit` (§3.4.7);
- `overlapping-values`, `conflicting-mappings`, `unknown-enum` (§3.4.7);
- `mismatched-bit-widths`: bitfield widths not adding up to the container; `invalid-bit-width`: a width below 1;
- `forward-reference`: a reference to a Field read later or to itself; `unknown-field`: a reference that resolves to no Field, or that goes into an array from outside its elements; `non-numeric-reference`: a reference to a Field that is not an integer, a bitfield sub-Field or a `bool`; `conditional-reference`: a Field under `if:` or inside a case, or a Field inside one, used outside its conditional scope (§4.3);
- duplicate sibling Field names; duplicate or unknown Type names; `recursive-type`; `field-too-deep`: a Field more than 64 deep (§3.4.1);
- `overlapping-cases`: overlapping `switch` cases (§3.9);
- mutually exclusive keys together (`size`/`prefix`/`terminator`: `conflicting-length`; `count`/`repeat`: `conflicting-repeat`);
- `invalid-size`, `invalid-prefix`, `invalid-terminator` (§3.6); `invalid-count`, `invalid-repeat`, `invalid-array` (§3.7); `invalid-padding`, `invalid-dissector` (§3.10); `invalid-info` (§3.14);
- `framing:` `length` breaking the header-only rule;
- a YAML float or bool where an integer is required; `leading-zero-literal`; `chained-comparison`: a non-associative comparison chain; `expression-too-deep`: an Expression nested more than 64 levels deep (§4.2); `expression-syntax`: any other Expression that does not parse;
- `invalid-port`, `overlapping-ports`: invalid ports and port ranges (§3.12);
- `invalid-protocol-name`, `invalid-protocol-title`;
- `conflicting-filter-name`: two Fields reaching one filter name whose ProtoFields do not match (§3.4.9, §3.9);
- unknown or duplicate keys, and the YAML subset violations of §3.1, `yaml-too-deep` included.

Warnings:

- `tcp-without-framing`;
- `unused-type`, `unused-enum`;
- `unreachable-value`: a `values:` key outside the Field type's range;
- `unreachable-field`: a Field or padding after a Field that always reads to the end of the message: a `repeat: to_end` array, a `size: "_remaining"` Field, or an inline structure, a Field of a Type or a `switch` Field whose every case always reads one of those. A Field under `if:` or an array with `count:` does not count, as it may read nothing;
- `unreachable-expect`: an `expect:` that can never match (§3.10);
- `protocol-name-taken`;
- `unknown-allow`: an `allow:` entry that names no warning, either an unknown name or an error's (a warning so that a description allowing a warning from a newer minor still works).

### 6.4 Names, silencing and locations

- Every Diagnostic has a stable kebab-case name, the same token used in `allow:`.
- A description silences warnings by name with the top-level `allow: [...]`. The CLI can fail on warnings with `--deny-warnings` (§9.6). Errors cannot be silenced.
- Every Diagnostic carries a precise span. Inside an Expression string it points at the token; for escaped or multi-line YAML strings, at the whole value. It is rendered as a rustc-style snippet.
- Every rendered Diagnostic ends with a note linking to its entry in the book's Diagnostics index (§11).

### 6.5 Stability

Stable under semver:

- which descriptions are accepted: rejecting one that was accepted is major, unless it fixes a documented bug;
- Diagnostic names and severities: warning → error is major; error → warning, or a new warning, is minor;
- the library's Diagnostic structure;
- that the JSON Schema accepts every valid description.

Not stable: message wording, notes, span precision, rendered layout and the schema's exact text. Because a minor release can add a warning, it can break a `--deny-warnings` build after an upgrade; the docs say so (§11).

### 6.6 JSON Schema

A JSON Schema (`.json`) for `*.wirdigen.yaml` is generated from the Rust model, with the model's doc comments as `description`s for editor hover. It is for editor completion only and ships through `json_schema()`, `wirdigen schema`, release assets and a SchemaStore entry.

## 7. Architecture and generation

*ADR 0002, ADR 0010, ADR 0012.*

### 7.1 Crates

There are two crates in one workspace, with one lockstep version:

- `wirdigen`: the library. Parsing, validation, lowering, the emitter, the prelude, the schema and the renderer are all private modules of it.
- `wirdigen-cli`: the CLI, binary `wirdigen`, installed with `cargo install wirdigen-cli`.

Any later crate is named `wirdigen-<part>` (a WASM crate depends on `wirdigen`). A crate that a published crate depends on is published too and documented as an implementation detail.

### 7.2 Pipeline

```
Source ─► YAML parse ─► strict deserialize ─► parse Expressions ─► semantic checks ─► ValidDescription
                                                                                          │
                                                                        lower (private Dissector-shaped model)
                                                                                          │
                                                                        emit (indenting writer) + prelude chunks ─► String
```

- The model keeps source spans for every key and value, Expressions included.
- **Lowering** builds a private model: the ProtoFields and value strings to register, one dissect function per Type, and for each a statement list (bounds-checked read, add to tree, evaluate an Expression into a local, branch, loop, hand off), with every Expression keeping its operators, which the emitter prints as prelude helper calls.
- **Emitting** prints the model through an indenting writer. Placeholder substitution and template engines are rejected.
- **Generation cannot fail** on a validated description. Everything lowering relies on is checked by validation, so a lowering failure is a Wirdigen bug, never a Diagnostic.
- The model and the emitter are not public API.

### 7.3 Generated code

- **Types**: one dissect function `wd.dissect_<Type>` per Type, in dependency order, taking and returning the offset. Each also takes the site table of the use it reads: the ProtoFields registered for that use (§5.2) and its path, for truncation reports. Every dissect function returns `nil` once it stopped on a truncated packet, so its callers stop too. Values are kept, in the function's table `v`, only for Fields some Expression references; the `info:` template reads its Fields through field extractors once the Message is read (§3.14). Outer scopes are reached through a context table.
- **Prelude**: a hand-written Lua runtime embedded with `include_str!`, split into named chunks, each needing the chunks whose names its code uses. It holds the version guard, bounds-checked readers, C-style division and modulo, 64-bit bitwise operators, string readers, the Framing loop and malformed-packet reporting. Only the chunks whose names a Dissector's emitted Lua uses, plus the chunks they need, are emitted, in the prelude's fixed order. The version guard and malformed-packet reporting are always included.
- **Names**: user names are always mangled into keys of the Dissector's table (`wd.f_<name>`, `wd.dissect_<Type>`), and prelude names start with `wd_`, so a Field called `end` or `type` is safe.
- **Size**: however many Fields or Types a description has, and however deep it nests, every generated function stays within Lua's limits of 200 locals, 255 upvalues and 255 registers, and within its parser's nesting limit: the Dissector's declarations are entries of one table, `wd`, the values a function reads are entries of its table `v`, and a statement nested too deep is a function of its own ([ADR 0019](adr/0019-generated-lua-within-lua-function-limits.md)).
- **Format**: 4-space indent, fixed by the emitter (no external formatter). Comments name each Type (`-- Type: X`) and each Field's path, with no source line numbers.
- **Header**: the Wirdigen version, the Source name's last `/`- or `\`-separated component, and "Requires Wireshark >= 4.4".
- **Determinism**: the same description bytes and Wirdigen version give byte-identical Lua on every OS: no timestamps or paths, ordered maps, `\n` line endings, a trailing newline. The Lua text itself is not under semver (§13).

## 8. Library API

*ADR 0012.*

```rust
pub struct Source;                 // Source::new(name, text), owned
pub fn validate(source: &Source) -> Result<ValidDescription, Diagnostics>;

pub struct ValidDescription;       // opaque
impl ValidDescription {
    pub fn warnings(&self) -> &[Diagnostic];
    pub fn generate(&self) -> String;   // infallible
}

pub fn json_schema() -> String;    // pretty, deterministic

pub struct Diagnostics;            // newtype: every error and warning of the run, source order
// impl std::error::Error (one-line summary); has_errors(); render(&Source, &RenderOptions) -> String
// len(); is_empty(); as_slice() -> &[Diagnostic]; iter(); IntoIterator by value and by reference

pub struct Diagnostic;
impl Diagnostic {
    pub fn name(&self) -> &'static str;      // stable name, as in `allow:`
    pub fn severity(&self) -> Severity;
    pub fn span(&self) -> Range<usize>;      // byte offsets into the Source text
    pub fn message(&self) -> &str;
    pub fn notes(&self) -> /* each a message with an optional span */;
    pub fn render(&self, source: &Source, options: &RenderOptions) -> String;
}

pub enum Severity { Error, Warning }         // exhaustive

#[non_exhaustive] #[derive(Default)]
pub struct RenderOptions { pub color: bool, pub deny_warnings: bool }
```

- **No I/O**: the library never touches files or a terminal. `Source`'s name is a label, never resolved. Diagnostics show it whole, and the Lua header keeps its last component.
- **Model private**: there is no public description tree. Accessors on `ValidDescription` can be added in minor releases.
- `Diagnostics` holds warnings already filtered by `allow:`, so `wirdigen::validate(&src)?.generate()` works.
- Line and column are derived from spans, never stored.
- The renderer is built on `annotate-snippets`. Its layout is not stable.
- **No `Serialize`**: no `serde_json` or `schemars` type appears in the API. Each consumer (CLI, WASM) defines its own JSON.
- Every public type is owned, has no lifetime parameters and is `Send + Sync + 'static`, checked by a compile-time test. All public structs have private fields; only `RenderOptions` is `#[non_exhaustive]`.
- Every public item is documented: `missing_docs` comes from the workspace lints table (section 12.1), and CI denies warnings. A writer-based `generate_into` can come later if streaming matters.

## 9. CLI

*ADR 0013, CLI UX.*

### 9.1 Commands

| Command | Does |
|---|---|
| `wirdigen validate <inputs>…` | Validates, writes nothing. |
| `wirdigen generate <inputs>…` | Validates and writes Dissectors. |
| `wirdigen generate --check <inputs>…` | Writes nothing; fails if a Dissector on disk is missing or differs. |
| `wirdigen schema [-o <file>]` | Prints the JSON Schema. |

There is no `check` subcommand. `--version` is clap's default. Completions and man pages are generated at build time (`clap_complete`, `clap_mangen`) into the release archives, so there is no runtime subcommand for them. There is no config file and no `WIRDIGEN_*` environment variable.

### 9.2 Inputs

- One or more paths. `-` reads stdin, at most once, with the `Source` name `<stdin>`.
- No directory walking or implicit search. No inputs is a usage error.
- Any extension is accepted, with no warning off the `.wirdigen.yaml` convention. The `Source` name is the path as typed.

### 9.3 Outputs and writing

- By default the output goes next to the input, named from the file name: `foo.wirdigen.yaml` → `foo.lua`, otherwise the last extension is replaced. It is never named after the protocol's `name:`.
- `-o <file|->` requires exactly one input. `--out-dir <dir>` takes any number. Stdin input goes to stdout unless `-o` is given.
- Two inputs mapping to one output, or an output equal to its input, is a usage error raised before anything runs.
- Writes are atomic (temp file in the same directory, then rename) and overwrite silently. Identical bytes are not rewritten, so the mtime is kept.
- Each input succeeds or fails on its own: valid inputs are written even if another has errors. The exit code is the worst result.

### 9.4 `--check`

- Compares bytes with the path `generate` would write, respecting `-o` and `--out-dir`. A missing file counts as stale.
- Prints one stderr line per stale file (`` `x.lua` is stale ``, or `` stale (missing) ``), without a diff in v1 (`--diff` can come later as a minor release).
- `-o -` is rejected, and so is standard input without `-o <file>`, since neither has a file to compare. Diagnostics and `--deny-warnings` still apply.

### 9.5 Human output

- Diagnostics go to stderr through the library renderer, under the `Source` name as typed. They come per input in argument order, and in source order within a file.
- `--color auto|always|never`: `auto` means stderr is a TTY. `NO_COLOR` and `CLICOLOR_FORCE` apply below an explicit `--color`.
- A summary line (`error: 2 errors, 1 warning in 1 of 3 files`) appears only when there were Diagnostics. Success is silent.
- `-q` hides warnings and the summary. `-v` lists each file as written or unchanged.

### 9.6 `--deny-warnings`

- Applies to `validate` and `generate` (with or without `--check`), not to `schema`.
- Warnings become errors for the run, so a warnings-only file is not written (status `failed`). They are rendered as errors with a note.
- JSON keeps `"severity": "warning"` and adds `"denied": true`.
- All or nothing: there is no `--deny <name>` and no CLI `--allow`. Silencing lives in the description (§6.4).

### 9.7 JSON Lines

`--message-format human|json`. With `json`, stdout carries one JSON object per line. It is incompatible with `-o -`. Each record has a `type`:

| `type` | Fields |
|---|---|
| `diagnostic` | `file`, `name`, `severity`, `message`, `span {start, end, line, column, end_line, end_column}` (byte offsets, 1-based line and column, the column counted in characters), `notes [{message, span?}]`, `rendered` (uncoloured), and `denied: true` when promoted by `--deny-warnings` |
| `file` | `input`, `output` (`null` under `validate`), `status`: `written`, `unchanged`, `stale`, `failed` or `valid` |
| `summary` | counts by severity (`errors`, `warnings`; a denied warning counts as a warning), and the `exit_code` |

Every record is emitted whatever `-q` or `-v` say; stderr then only carries `error:` lines for inputs or outputs that cannot be read or written, and stale files. Adding fields or record types is minor; removing or renaming one is major. Consumers must ignore unknown fields. The CLI alone owns this shape. A `github` annotations format can come after v1 as an additive change.

### 9.8 Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. |
| `1` | Any failure: an error Diagnostic, a denied warning, a stale or missing file under `--check`, an unreadable input or unwritable output. |
| `2` | Usage error (clap), raised before any input is processed. |

A panic (`101`) is a bug, not part of the contract. A finer split can only come later behind an opt-in flag, never by renumbering.

## 10. Testing

*ADR 0011, Testing strategy, CLI UX.*

### 10.1 Principles

- Dissector behaviour is tested **only in real tshark**; there is no mock of the Wireshark Lua API.
- Lua parse and load checks use **real** `lua5.2`, `lua5.3` and `lua5.4` interpreters (`mlua` embeds one version per build).
- Golden files are regression aids, not compatibility promises (§13).

### 10.2 Corpus

`tests/cases/<case>/` holds:

- `<case>.wirdigen.yaml`;
- a golden `<case>.lua`, compared byte for byte;
- `packets.txt`: text2pcap hex, each packet commented;
- a golden `dissected.json`: tshark's `-T json --no-duplicate-keys` output cut down to the Dissector's own layer, the same layer `-J <proto>` keeps. The harness cuts it itself rather than passing `-J`, which could hide a top-level `_ws.lua.error`;
- optionally a golden `info.txt`: the Info column of each packet (§3.14), from tshark's `_ws.col.info` field, which is not in the Dissector's layer.

Both Wireshark versions must produce the same `dissected.json`; a per-version file is a documented exception. Goldens are plain files (no `insta`), rewritten with `WIRDIGEN_BLESS=1`, never in CI. The corpus is `eol=lf` via `.gitattributes`. Each case is its own test. The three book examples (§11) are corpus cases.

### 10.3 Diagnostics corpus

- `tests/diagnostics/<diagnostic-name>/<case>.wirdigen.yaml` plus `<case>.expected`, with one `severity name line:col-line:col` per line and no message text. The whole set must match, so cascades are caught.
- A completeness test checks that every Diagnostic name has a directory, and vice versa.
- Each warning has an `allowed` case with an empty `.expected`.
- A few colour-off renderer goldens (internal) check the rendered layout.
- Every valid description, warning cases included, must pass the generated JSON Schema (`jsonschema` as a dev-dependency).

### 10.4 Lua checks (`WIRDIGEN_LUA=1`)

- Every golden `.lua` and every prelude chunk parses under Lua 5.2 and compiles under 5.3 and 5.4.
- Under 5.3 and 5.4, each chunk plus its declared dependencies runs its top level in a strict environment: the standard library, its dependencies' names and inert placeholders for Wireshark's globals, with `get_version()` returning the 4.4 floor so the version guard runs. Any other global read is an error.

### 10.5 tshark (`WIRDIGEN_TSHARK=1`)

- Two versions:
  - the 4.4 floor, from a `debian:trixie` container, run as a non-root user because tshark skips `-X lua_script` as root;
  - the latest stable, from `ppa:wireshark-dev/stable` on ubuntu-24.04, and again on ubuntu-26.04 so a difference in the newer LTS's build shows up.
- No source builds and no RC or nightly job. Lua 5.3 is covered only by the load check.
- The harness sets `LC_ALL=C`, `TZ=UTC` and a temporary `WIRESHARK_CONFIG_DIR`.
- Large descriptions, generated by the test rather than checked in (thousands of Fields, hundreds of Types in a chain and side by side, Fields nested 50 deep, a value read 160 inline structures deep in a Type), must load and dissect: their Dissectors stay within Lua's per-function limits (§7.3, [ADR 0019](adr/0019-generated-lua-within-lua-function-limits.md)).
- The corpus covers every `encoding:` value of `abs_time` and `rel_time` (§3.4.5) in both byte orders. Because tshark exits 0 on a Lua load error, it checks stderr, `_ws.lua.error` and the packet count rather than the exit code.
- Confirmed on 4.4.19 and 4.6.9 (#51): a Lua load error only prints to stderr and tshark still exits 0; as root, tshark warns on stderr and skips `-X lua_script`; every packet carries a harmless `_ws.lua.fake` item once a script is loaded; UDP never calls a Dissector for an empty payload. Installing tshark takes about 15 s from Debian and 45 s from the PPA.
- Confirmed on 4.4.19 and 4.6.9 (#57): `-T json` prints an `FT_ABSOLUTE_TIME` value as its display text on 4.4 (`Jan  1, 2024 00:00:00.000000000 UTC`) but as ISO 8601 UTC on 4.6, whatever its `display:` (`2024-01-01T00:00:00.000000000Z`). The decoded instants agree, so the `timestamps` case carries the documented exception `dissected-4.6.json`; a new stable version may need its own file.

### 10.6 Bad input

Backs the "never raises a Lua error" promise (§5.3):

- From each valid packet, the harness derives every truncation, seeded mutations (bit flips, a length or count set to 0, max or huge, inserted or removed bytes, garbage) and a few random packets.
- They go into one pcap and one tshark run per case. The test asserts no `_ws.lua.error`, no Lua stderr, and every packet attributed to the protocol.
- TCP cases are also re-split at random segment boundaries: the valid stream, cut at random, must dissect into the same Messages as `dissected.json`, and each bad packet is a stream of its own. A TCP packet whose bytes TCP holds for a Message still incomplete carries no layer of the protocol, which passes.
- PRs use a fixed seed. The weekly run uses a random seed with large counts and reports the seed and the smallest failing packet, which then becomes a `packets.txt` regression.

### 10.7 Generation and validation

These use proptest only, with no cargo-fuzz in v1:

- arbitrary bytes and mutated YAML into `validate` never make it panic;
- for random *valid* descriptions from a strategy over the v1 language: `validate` accepts them, `generate` doesn't panic, two generations are byte-identical, and the output passes the Lua checks;
- weekly, end to end: random descriptions × random and truncated packets in tshark;
- in-crate lowering unit tests cover scoping, the values kept for Expressions and chunk selection;
- cross-OS determinism comes from the golden `.lua` comparison on the 3-OS `test` job.

Shrunk failures become corpus cases.

### 10.8 CLI

- `trycmd` cases in `tests/cli/`, blessed with `TRYCMD=overwrite`, reuse the `tests/cases/` and `tests/diagnostics/` corpus. They cover exit codes, `--deny-warnings`, `--check` fresh/stale/missing, `-o`/`--out-dir`/stdin, JSON Lines and partial failure.
- A few `assert_cmd` tests cover the unchanged mtime and forced-TTY / `CLICOLOR_FORCE` colour.
- They run on all 3 OSes. Dissector behaviour is not re-tested at the CLI level.

### 10.9 CI jobs

| Job | Runs on | Required |
|---|---|---|
| `test`: goldens, Diagnostics, renderer, schema, lowering, proptest, CLI | ubuntu / macos / windows | yes |
| `lua` (`WIRDIGEN_LUA=1`) | ubuntu-24.04 with `lua5.2`/`5.3`/`5.4` | yes |
| `tshark-4.4` (`WIRDIGEN_TSHARK=1`): `dissected.json` + fixed-seed bad packets | `debian:trixie` container, non-root | yes |
| `tshark-stable-24.04` | ubuntu-24.04 + PPA | yes |
| `tshark-stable-26.04` | `ubuntu:26.04` container + PPA, non-root | yes |
| weekly `Refresh protocols` (separate workflow): refreshes the `protocol-name-taken` snapshot | ubuntu-24.04, `tshark-stable-24.04` and `tshark-stable-26.04` images | n/a; a changed snapshot opens or updates one PR |
| weekly `Weekly` (separate workflow): large-count bad packets, high `PROPTEST_CASES`, random descriptions × packets on both versions, the beta toolchain and `cargo deny check advisories` | ubuntu, `tshark-4.4` and `tshark-stable-24.04` images | n/a; a failure opens or updates one issue with the seed |

The gated tests fail rather than skip when their tool is missing. `make test-lua` and `make test-tshark` run them locally. A CI job running real tshark also fails when the `protocol-name-taken` snapshot (§3.3) is out of date: `tshark-stable-24.04` and `tshark-stable-26.04`, whose tshark is at least the snapshot's version, fail when it is newer or lists a protocol the snapshot lacks. Builds of one version differ by distribution (26.04's has the Falco plugin's protocols, #177), so the snapshot is the union of both builds at its version, sorted; a protocol dropped within a version stays until the next version. `make docker-refresh-protocols` rewrites the snapshot from both images. The weekly `Refresh protocols` workflow, early each Monday UTC and on demand, runs it in the two images built as those jobs build them, sharing their weekly caches. A changed snapshot is force-pushed as one commit on `main` to `chore/refresh-protocols`, and one PR titled `chore: refresh built-in protocols for Wireshark <version>` is opened or updated from it; an unchanged one pushes nothing. Pushes and PR calls use a token minted by a GitHub App (secrets `PROTOCOLS_CLIENT_ID` and `PROTOCOLS_APP_PRIVATE_KEY`; installed on this repository only, with Contents and Pull requests read/write) so that CI runs on the PR. The PR is not merged automatically, and the `tshark-stable-24.04` and `tshark-stable-26.04` jobs stay the safety net.

## 11. Documentation

*Documentation set for v1.*

- **Book**: an mdBook in `book/` on GitHub Pages is the user guide and format reference.
  - The release book is served at `/`, built from the latest tag. `main` is served at `/dev/` with a "development version" banner. There is no per-version archive.
  - Until a tag carries `book/`, `/` also serves `main`, so the Diagnostic links rendered by the library resolve before the first v1 release (#52).
  - PR CI builds the book and checks snippets without deploying.
- **README**: a short landing page (what Wirdigen is, install, a ~20-line quickstart, a link to the book). It is also `wirdigen-cli`'s crates.io page.
- **Format reference**: hand-written, one chapter per construct (Fields and Types, sizes, arrays, bitfields, `if`/`switch`, Registration, Framing, Expressions, `info:`, Diagnostics), plus a one-page cheat sheet of the ten top-level keys in §3.2's order.
  - Every YAML snippet is a complete file that CI runs through `validate`. A snippet can be marked as expected to fail with a named Diagnostic.
  - Nothing is generated from the schema.
- **Examples**: three invented protocols in `examples/`, each also a corpus case. None clashes with a built-in protocol.
  1. *UDP telemetry*: fixed Fields, an enum, a bitfield, `info:`, port Registration. This is the book's tutorial.
  2. *TCP request/response*: length-based Framing, `switch` on a header Field, named Types, a length-prefixed string.
  3. *Tagged records*: arrays until end, `if` Fields, padding and hidden Fields, `expect:` warnings, handoff to a built-in dissector.

  The old `example/example_dissector.json` is deleted.
- **Installing a Dissector**: Wireshark's *Help → About → Folders → Personal Lua Plugins* and `tshark -G folders` are the authority; typical per-OS paths are shown only as examples. The chapter covers:
  - trying a Dissector without installing it, with `-X lua_script:foo.lua`;
  - reloading (Ctrl+Shift+L or restart);
  - "Wireshark ≥ 4.4 (Lua 5.3/5.4)", and `ppa:wireshark-dev/stable` for stock Ubuntu 24.04;
  - troubleshooting: the version-guard error, tshark exiting 0 on Lua errors, Lua skipped as root.

  The CLI has no `install` command.
- **CLI chapter**: output placement, `generate --check` in CI, exit codes and the `--deny-warnings` caveat (§6.5), linking to the changelog's "New warnings" group.
  - It holds the normative **JSON Lines contract** (§9.7).
  - Flag detail stays in `--help` and the man pages. The book includes `wirdigen --help` from its `trycmd` case, so CI catches a stale copy.
- **Diagnostics index**: one page with an anchor per Diagnostic name: its severity, meaning, a CI-checked triggering snippet, and how to fix or `allow:` it. A test fails if a Diagnostic lacks an entry or vice versa.
- **docs.rs**: crate docs with a runnable doctest (`Source` → `validate` → `generate`, plus rendering Diagnostics), short notes on semver scope and the I/O-free design, and a link to the book for the format.
- **Changelog**: git-cliff after a hand-written first v1 entry ("rewrite, no compatibility with 0.3"). PRs that add a warning use the commit scope `diagnostics`, grouped under **"New warnings"**.
- **`docs/CONTRIBUTING.md`**, short: test layers and their setup, adding a corpus case and re-blessing goldens, the PR title convention including the `diagnostics` scope, and pointers to `GLOSSARY.md` and `docs/adr/`. It is not part of the book.
- **Repository docs**: `docs/SECURITY.md` (private vulnerability reporting on) and `docs/CODE_OF_CONDUCT.md`.
- **Issue forms**: the bug report asks for the Wirdigen, Wireshark and OS versions and the Protocol Description.

## 12. Toolchain, CI and release

*Toolchain, CI and release policy, ADR 0001–0003.*

### 12.1 Toolchain

- Stable Rust only, pinned in `rust-toolchain.toml` and bumped by hand. A weekly job runs tests and clippy on beta.
- Edition 2024. `rust-version` is declared and checked by an `msrv` job. It rises only when a dependency needs it, and raising it is a minor release.
- `[workspace.lints]`: `unsafe_code = "forbid"`, `missing_docs = "warn"` (off for the CLI), `clippy::pedantic` at warn. `-D warnings` applies in clippy and `cargo doc`.
- Local tooling: prek hooks (`.pre-commit-config.yaml`), a `Makefile` matching CI (`make lint`, `make test`, `make test-lua`, `make test-tshark`), `.editorconfig`, `rustfmt.toml` (120 columns, `use_small_heuristics = "Max"`) and `_typos.toml`.

### 12.2 CI on every PR

- `rust`: fmt, build, test, clippy and doc, all `--locked --all-targets`.
- `test` on ubuntu, macos and windows (`fail-fast: false`).
- `msrv`.
- `deny` (advisories, licenses, bans, sources) plus `cargo machete`.
- `typos`, `links` (lychee, offline), `workflows` (actionlint, zizmor) and `pr-title`.
- A `cargo publish --dry-run --locked` packaging check.
- The `lua`, `tshark-4.4`, `tshark-stable-24.04` and `tshark-stable-26.04` jobs of §10.9.
- The book build and snippet checks.

`semver` (cargo-semver-checks, not required) is added once 1.0.0 is published. There is no coverage job.

Workflow hygiene: actions pinned to commit SHAs, `permissions: contents: read`, `persist-credentials: false`, concurrency cancel, timeouts, Swatinem/rust-cache.

Scheduled weekly: `cargo deny check advisories`, the beta job and the large test runs of §10.9. Dependabot runs weekly with one grouped PR each for cargo (`build(deps)`) and actions (`ci(deps)`) and a 7-day cooldown. `rust-audit.yml` and `rust-ci.yml` are deleted.

### 12.3 Versioning

- v1 ships as `1.0.0-alpha.N` → `-beta.N` → `-rc.N` → `1.0.0`. There is no further 0.x.
- 0.2.x and 0.3.0 stay on crates.io, not yanked. The advisory issues #1 and #2 are closed when v1 lands on `main`.

### 12.4 Release flow

1. On a `release/vX.Y.Z` branch: bump the version, run `git cliff --unreleased --tag vX.Y.Z --prepend CHANGELOG.md`, and open a PR titled `chore: release vX.Y.Z`.
2. Tag the merge commit `vX.Y.Z` and push the tag.
3. `release.yml`:
   1. checks that the tag matches the manifest version and that `CHANGELOG.md` has a dated section;
   2. runs `cargo publish --workspace` with crates.io Trusted Publishing (no build cache);
   3. drafts a GitHub Release from the changelog section (`--prerelease` for `-alpha`/`-beta`/`-rc`);
   4. builds and attaches CLI binaries, completions and man pages, and the JSON Schema;
   5. publishes the Release.

Publishing comes before the GitHub Release because it is the irreversible step and the one most likely to fail.

Binaries are built by a hand-written matrix with `taiki-e/upload-rust-binary-action` for Linux x86_64/aarch64 (musl), macOS aarch64/x86_64 and Windows x86_64. They ship with SHA-256 checksums, `actions/attest-build-provenance` and cargo-binstall metadata. Package managers come after 1.0. Trusted Publishing on crates.io is a one-time manual setup.

### 12.5 Repository

- Squash-merge only, with conventional PR titles as commit messages. Branches are deleted after merge.
- A `main` ruleset: no direct or force pushes, and the PR jobs above as required checks (`semver` and scheduled jobs excluded).
- The `arise` branch stays as a reference until 1.0.0, then is deleted or tagged `archive/arise`. The old `dev` and `rework` branches were already archived as the tags `archive/dev` and `archive/rework` (2026-11-08), and every other branch was deleted, leaving `main` and `arise`.

## 13. Compatibility

*ADR 0001.*

From 1.0.0, a breaking change to any of these is a major release:

1. **The Protocol Description format.** A description valid in 1.x stays valid and means the same in every later 1.y. This covers accepted descriptions, Diagnostic names and severities (§6.5), and the YAML subset: allowing a YAML feature later is minor, banning one is major.
2. **The library's Rust API** (§8).
3. **The CLI**: commands, flags, exit codes and the JSON Lines contract (§9).
4. **Dissector behaviour in Wireshark**: Field names and display filter names, and the protocol tree layout.

Not covered: the generated Lua text, rendered Diagnostic layout and wording, notes, span precision, and the JSON Schema's exact text. Two releases may generate different Lua from one description as long as the Dissector behaves the same.

Dropping a Wireshark version (after upstream end of life) and raising `rust-version` are minor releases. `cargo-semver-checks` guards only the Rust API; the other three surfaces are guarded by tests and review.

## 14. Out of scope and later

Not part of v1. Each item can come later as an additive (minor) change unless noted.

- **WASM / npm surface**: a `wirdigen-wasm` crate on the library API, owning its own JSON shapes, possibly for a web editor. Its own effort after v1.
- **Other targets**: a C plugin or anything but Lua. It would need builds per Wireshark version and OS.
- **Kaitai `.ksy` importer**.
- **A JSON form of the description** for tools, or a second grammar front-end.
- **Registration**: heuristic dissectors (which need recognition constraints first) and arbitrary dissector tables (ethertype, `sctp.ppi`, `ip.proto`, …), under `registration:`.
- **Language**: repeat-until-condition (`repeat: { until: … }`), `align:`, delimiter-based Framing, runtime byte order, telling snaplen truncation apart from malformed packets, value-driven / dissector-table handoff, checksum verification, computed Fields, per-Type `info:`, Expression function calls, strings, `?:` and array indexing.
- **Format keys**: `short_name:`, `description:`.
- **Built-in types**: `char`, `framenum`, `protocol`, `none`, `ipx`, `oid`, `rel_oid`, `systemid`; signed bitfield sub-Fields.
- **CLI**: `--diff` for `--check`, a `github` message format, per-name `--deny`, finer exit codes behind an opt-in flag, `generate_into` in the library, and package-manager distribution.

## 15. Left to implementation

These are not open design questions, but the spec deliberately leaves them to the implementation tickets:

- **The full list of Diagnostic names.** The checks in §6.3 are fixed; most of their kebab-case names are chosen when implemented. Names become stable at 1.0.0, and the completeness tests (§10.3, §11) keep the list, the corpus and the book in sync.
- **The YAML 1.2 parser crate**: `saphyr-parser` (its event API, not serde), chosen in #47. It reports positions for every event, so Wirdigen builds its own span-carrying tree and enforces the strict subset and unknown/duplicate keys itself.
- **The tshark gotchas** (exit code on Lua load errors, install time), confirmed in #51 (§10.5), and the `ENC_TIME_*` timestamp encodings confirmed by the corpus (§3.4.5).
- **Prelude chunk boundaries and helper names**, under the `wd_` prefix.

## 16. Decision index

| Area | Ticket | ADR |
|---|---|---|
| Prior art | [Prior art for declarative protocol descriptions](https://github.com/Cerclique/wirdigen/issues/9) | — |
| Lua API facts | [Wireshark Lua API capabilities and versions](https://github.com/Cerclique/wirdigen/issues/10) | — |
| tshark in CI | [Running Lua Dissectors headless in tshark](https://github.com/Cerclique/wirdigen/issues/11) | — |
| Own format | [Own description format or adopt an existing one](https://github.com/Cerclique/wirdigen/issues/12) | [0004](adr/0004-own-protocol-description-format.md) |
| Target versions | [Wireshark and Lua target versions](https://github.com/Cerclique/wirdigen/issues/13) | [0006](adr/0006-lua-dissectors-for-wireshark-4-4.md) |
| Language | [Language capabilities in v1](https://github.com/Cerclique/wirdigen/issues/14) | — |
| Registration | [Registration mechanisms in v1](https://github.com/Cerclique/wirdigen/issues/15) | — |
| Syntax | [Protocol Description input syntax](https://github.com/Cerclique/wirdigen/issues/16) | [0005](adr/0005-yaml-description-syntax.md) |
| Toolchain and release | [Toolchain, CI and release policy](https://github.com/Cerclique/wirdigen/issues/17) | [0001](adr/0001-semver-scope.md), [0002](adr/0002-crate-names.md), [0003](adr/0003-v1-via-pre-releases.md) |
| Expressions | [Expression mini-language](https://github.com/Cerclique/wirdigen/issues/23) | [0007](adr/0007-expression-semantics.md) |
| Validation | [Validation of a Protocol Description](https://github.com/Cerclique/wirdigen/issues/24) | [0008](adr/0008-diagnostics-and-generated-schema.md) |
| Generation | [Generation technique](https://github.com/Cerclique/wirdigen/issues/25) | [0009](adr/0009-filter-names-follow-field-paths.md), [0010](adr/0010-generation-via-lowered-model-and-prelude.md) |
| Testing | [Testing strategy](https://github.com/Cerclique/wirdigen/issues/26) | [0011](adr/0011-dissectors-tested-in-real-tshark.md) |
| Library API | [Library API and crate layout](https://github.com/Cerclique/wirdigen/issues/31) | [0012](adr/0012-opaque-io-free-library-api.md) |
| CLI | [CLI UX](https://github.com/Cerclique/wirdigen/issues/32) | [0013](adr/0013-cli-contract.md) |
| Identity | [Protocol identity and top-level keys](https://github.com/Cerclique/wirdigen/issues/36) | [0014](adr/0014-protocol-identity-and-no-format-version.md) (amended by 0015) |
| Documentation | [Documentation set for v1](https://github.com/Cerclique/wirdigen/issues/37) | — |
| Field declaration | [Field declaration: types, display and value mappings](https://github.com/Cerclique/wirdigen/issues/41) | [0015](adr/0015-own-field-vocabulary.md) |
| Expression depth | [Deeply nested Expressions or Type chains abort the process](https://github.com/Cerclique/wirdigen/issues/191) | [0018](adr/0018-expression-depth-limit.md) |
| Lua limits | [A Dissector with more than ~200 Fields or ~95 Types fails to load](https://github.com/Cerclique/wirdigen/issues/199) | [0019](adr/0019-generated-lua-within-lua-function-limits.md) |

Research notes behind the first three rows live in [`docs/research/`](research/).
