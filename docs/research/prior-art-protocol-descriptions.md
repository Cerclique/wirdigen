# Prior art for declarative protocol descriptions

Research for issue #9. Question: which declarative formats and tools describe binary protocols or generate Wireshark dissectors, what can they express, how healthy are they, and what should Wirdigen adopt, extend or borrow?

Maintenance facts are as of 2026-11-07, taken from the GitHub/GitLab APIs and project pages unless stated otherwise. Terms (Protocol Description, Field, Dissector) follow `docs/GLOSSARY.md`.

## Baseline: where Wirdigen is today

`example/example_dissector.json` shows the current Protocol Description: a `name`, one global `endianness`, a `connection` (`udp`/`tcp` plus ports), and a flat `data` list of Fields, each with `name`, `format`, `base`, and an absolute `offset` and `size`. There is no nesting, variable length, arrays, bitfields, conditionals or multiple message types. Every tool below goes beyond that.

## Summary table

| Tool / format | Nesting | Variable length | Arrays | Bitfields | Conditionals | Multiple message types | Wireshark output | Maintained? | Licence |
|---|---|---|---|---|---|---|---|---|---|
| Kaitai Struct `.ksy` (YAML) | yes (`types`) | yes (`size` expr, `size-eos`, `terminator`) | yes (`repeat: expr/until/eos`) | yes (`b1`..`b64`) | yes (`if`) | yes (`switch-on`/`cases`) | no upstream target; forks only | yes, 0.11 (2025-09-07), commits Oct 2026 | compiler GPL-3.0+, runtimes MIT |
| KS → Wireshark compiler forks (indivisible, rgbpb) | via KS | via KS | via KS | yes (rgbpb fixed `bN`) | yes | yes | Lua Dissector + forked Lua runtime | active fork (rgbpb, Oct 2026), not merged | GPL-3.0 (compiler) |
| `kaitai-to-wireshark` (joushx, lain3d fork) | `types` only | static/local `size` only | no | no | no | no | Lua Dissector | dead (last push 2022-04) | MIT |
| Wireshark Generic Dissector (wsgd) `.wsgd` + `.fdesc` | yes (`struct`) | yes (expressions) | yes (fixed and variable) | yes (`bool1`, `uint1`..`uint32`) | yes (`if`, `while`, `do while`) | yes (`switch` on message id) | interpreted at runtime by a compiled C++ plugin | yes: binaries for Wireshark 4.6 (2025-11), commits Jan 2026 | GPL-2.0+ |
| Google PDL (`.pdl`) | yes (structs, packet inheritance) | yes (`_size_`, `_payload_`) | yes (fixed, `_count_`, `_size_`) | yes (sub-byte scalars) | limited (`if` on a 1-bit flag) | yes (child packets with constraints) | via third-party `pdl-dissector` | PDL: active (Oct 2026); pdl-dissector: last push 2024-05 | Apache-2.0 / MIT |
| WDissectorGen (YAML) | no | no | no | no | no | no | Lua Dissector | dead (last push 2019-02) | GPL-3.0 |
| Spicy (Zeek) | yes (units) | yes (`&size`, `&until`, `&eod`) | yes (vectors) | yes (`bitfield(N)`) | yes (`if (...)`, `switch`) | yes | none (Zeek / C++ parsers) | active, v1.17.0 (2026-09-14) | BSD-style (Zeek) |
| Wireshark built-in generators (asn2wrs, pidl, idl2wrs) and Protobuf `.proto` loading | per source language | yes | yes | per source | per source | yes | C compiled into Wireshark, or the Protobuf dissector at runtime | yes (in tree) | GPL-2.0+ (Wireshark) |

## Kaitai Struct (`.ksy`)

- **What it is.** A YAML language for binary formats, compiled by `kaitai-struct-compiler` (Scala) into parsers for C++/STL, C#, Go, Java, JavaScript, Lua, Nim, Perl, PHP, Python, Ruby and Rust. <https://kaitai.io/>
- **Expressiveness.** Per the user guide: `seq` for ordered fields; `types` for nested subtypes; `size` (expressions allowed), `size-eos`, `terminator`; `repeat` with `eos`, `expr` or `until`; bit-sized integers `bX` with `meta/bit-endian`; `if`; `switch-on` with `cases`; `enums`; parse instances (`pos`) and value instances (`value`); `params`; `process` (e.g. XOR); `meta/endian` with per-type `le`/`be` suffixes; `encoding` on strings. <https://doc.kaitai.io/user_guide.html>
- **Syntax sketch.**
  ```yaml
  meta: { id: my_proto, endian: be }
  seq:
    - { id: msg_id, type: u2, enum: msg_type }
    - { id: len, type: u2 }
    - id: body
      size: len
      type:
        switch-on: msg_id
        cases: { 'msg_type::hello': hello }
  ```
- **Schema.** A JSON Schema for KSY is maintained at <https://github.com/kaitai-io/ksy_schema> (MIT, last push 2025-09-12).
- **Format gallery.** <https://github.com/kaitai-io/kaitai_struct_formats> holds hundreds of `.ksy` files, including a `network/` folder with 21 entries; each file states its own licence in `meta/license`. Last push 2026-11-07.
- **Maturity and maintenance.** Releases: 0.9 (2021-05-02), 0.10 (2022-07-08), 0.11 (2025-09-07). `kaitai_struct` and `kaitai_struct_compiler` both had commits on 2026-10-26. About 4.7k stars. Still below 1.0. <https://github.com/kaitai-io/kaitai_struct_compiler/releases>
- **Licence.** Compiler and visualiser GPLv3+; runtimes MIT (JavaScript runtime Apache-2.0). <https://kaitai.io/> The home page says nothing about the licence of generated code.
- **Wireshark.** There is no upstream Wireshark target. The umbrella issue "Wireshark dissectors as target language" (#50) has been open since 2016-11-14. <https://github.com/kaitai-io/kaitai_struct/issues/50> See the next section for the forks.

## Kaitai → Wireshark generators

1. **Compiler fork with a `wireshark` target** (indivisible in 2023, continued by rgbpb in 2026). It adds a `WiresharkLuaCompiler` built on the KS Lua backend, plus a forked Lua runtime.
   - In March 2023 indivisible reported that conditionals, switches and loops "seem to work" but called it rudimentary.
   - On 2026-09-20 rgbpb reported fixes: crashes on `value` instances, the mapping of `bN` types onto Wireshark `ftypes`, enum names in the Dissector, and the runtime under Lua 5.3/5.4. Tested with Wireshark 4.4.
   - On 2026-10-26 rgbpb reported a rebase onto upstream, no more need for `--read-pos`, and an `-x-wireshark:` meta extension that generates the `DissectorTable.get(...):add(port, proto)` registration.
   - Not yet a pull request. The open questions are whether the Wireshark runtime can share the regular Lua runtime, and dropping `bit32`.
   - Repos: <https://github.com/rgbpb/kaitai_struct_compiler_wireshark/tree/wireshark-lua-dissector> (GPL-3.0, last push 2026-10-25) and <https://github.com/rgbpb/kaitai_struct_lua_runtime_wireshark/tree/wireshark-lua-runtime>. Discussion: issue #50 above.
2. **`kaitai-to-wireshark`** (joushx; fork lain3d). A Python script (`./convert.py description.ksy > plugin.lua`).
   - The lain3d README feature table supports `size` ("static values and simple references to local fields"), `types`, `contents` (without checking the value), `instances` and `endian`.
   - It does not support `value`, `doc`, `repeat`, `encoding`, `size-eos`, `terminator`, `enums`, `if` or `switch`, nor `fX`, `bX` or `strz`. 64-bit integers are marked "cannot be decoded in Wireshark (Lua uses 32 bit)".
   - MIT licence, 43 stars, last commit 2022-03-31, last push 2022-04-07. <https://github.com/joushx/kaitai-to-wireshark>, <https://github.com/lain3d/kaitai-to-wireshark>

## Wireshark Generic Dissector (wsgd)

- **What it is.** A compiled C++ plugin, built separately for each Wireshark minor version. At startup it reads every `*.wsgd` file it finds (protocol identity and registration) together with the `.fdesc` files they include (the data layout), and interprets them. No Dissector code is generated, and edits need a Wireshark restart. <http://wsgd.free.fr/>, <https://ask.wireshark.org/questions/49322/wsgd-should-wireshark-always-be-restarted-after-changes-in-wsgd-fdesc>
- **Expressiveness** (home page feature list): basic types (integers, float, string); transforms (quantum, expression); display options (hex, oct, bin, printf, expression); min/max constraints that flag bad data; arrays of fixed or variable size; enums; bit fields (`bool1`, `int2`..`int32`, `uint1`..`uint32`, `enum1`..`enum32`); structs; `if`, `while` and `do while`; `switch` and `switch_expr`; functions; global data across messages; sub-protocol calls; decoders (base64, AES, UTF-8/16); heuristic dissectors; "Decode As"; statistics menus. <http://wsgd.free.fr/fdesc_format.html>, <http://wsgd.free.fr/wsgd_format.html>
- **Syntax sketch** (abridged from the official tutorial, <http://wsgd.free.fr/first_proto.html>):
  ```
  # .fdesc
  enum16 T_msg_id { msg_Xxx 1001  msg_Yyy 1002 }
  struct T_header { byte_order big_endian; T_msg_id msg_id; uint16 size_after_header; }
  switch T_msg_switch T_msg_id {
    case T_msg_id::msg_Xxx : T_msg_xxx "";
    default : T_header header; raw(size_after_header) rest;
  }
  # .wsgd
  PROTONAME My First Protocol
  PROTOABBREV my_first
  PARENT_SUBFIELD tcp.port
  PARENT_SUBFIELD_VALUES 20127
  MSG_HEADER_TYPE T_header
  MSG_ID_FIELD_NAME msg_id
  MSG_TOTAL_LENGTH size_after_header + 8
  MSG_MAIN_TYPE T_msg_switch(msg_id)
  PROTO_TYPE_DEFINITIONS
  include my_first_proto.fdesc ;
  ```
  The `.wsgd` header fields (protocol name, short name, abbreviation, parent field and values, message header, ID field, total length) closely match the identity and connection part of a Wirdigen Protocol Description.
- **Maintenance.** The download page lists builds for Wireshark 4.6.X (dated 2025-11-27 on Windows, 2025-10-11 on Linux, and noted as broken with 4.6.1), 4.4.X and 4.2.X. Each has a planned support end ("mid 2028", "mid 2027", "end 2026"). Source is at <https://gitlab.com/wsgd/wsgd>, with the last commit on 2026-01-30 ("Add bitfield tests") and last activity on 2026-05-31. The project is maintained by one person (Olivier Aveline) and has 7 GitLab stars. <http://wsgd.free.fr/download.html>
- **Licence.** GPL-2.0-or-later (GitLab project metadata).
- **Main trade-off.** It is the most expressive Wireshark-specific format, but users must install a native binary that exactly matches their Wireshark version, and that binary can break on point releases (4.6.1 is listed as "KO"). A generated Lua Dissector has neither problem, and that is Wirdigen's main advantage.

## Google PDL and `pdl-dissector`

- **PDL.** The Packet Description Language from Google's Bluetooth stack, with a Rust compiler and derive crates (`pdl-compiler`, `pdl-derive`, `pdl-runtime`). Apache-2.0, last push 2026-10-29, 91 stars. <https://github.com/google/pdl>
- **Expressiveness** (from <https://github.com/google/pdl/blob/main/doc/reference.md>):
  - Endianness is declared once per file.
  - Packets are ordered fields. A child packet inherits from a parent and fixes parent fields through constraints, e.g. `packet ImATeapot: Error(code = 418)`. This is how one file describes multiple message types.
  - Structs and enums (closed by default; `..` makes them open).
  - Arrays can have a fixed count, or be sized by `_size_(f)` or `_count_(f)` fields.
  - Sub-byte scalars are packed up to the next byte boundary.
  - `_padding_`, `_payload_` and `_body_`, and checksums.
  - Optional fields, e.g. `sugar: 16 if want_sugar = 1`. The condition can only test a 1-bit flag in the same declaration.
- **`pdl-dissector`** (mauricelam). A Rust tool that turns a PDL file and the names of its top-level packets into Lua Dissector functions (`pdl_dissector file.pdl PcapFile > out.lua`). It has an integration test that runs the generated Dissector. MIT licence, 52 commits, no releases, last push 2024-05-05. <https://github.com/mauricelam/pdl-dissector>
- **Relevance.** It is the closest prior art to Wirdigen's architecture: a Rust tool, a declarative input, and a Lua Dissector as output. Its handling of PDL size and count fields and of inheritance is worth reading.

## Other declarative-to-Lua generators

- **WDissectorGen** (nocommentlab). Python with a YAML schema. Its schema (`connection.type` udp/tcp, `ports`, `protocol.name`, and `fields` with `type`, `filter`, `base`, `offset`, `size`) is almost the same as Wirdigen's current JSON. It is just as flat: no nesting, arrays or conditionals. GPL-3.0, last push 2019-02-07. <https://github.com/nocommentlab/WDissectorGen>
- **ws_dissector_helper** (prontog). A Lua helper library for writing Dissectors by hand, not a generator. GPL-3.0, last push 2019-03-01. <https://github.com/prontog/ws_dissector_helper>

## Spicy (Zeek)

- A parser-generator language for network protocols that compiles to C++ for Zeek. It has no Wireshark output.
- Constructs: `type X = unit { ... }`; `&size`, `&until`, `&eod`; vectors `T[N]`; `bitfield(N)`; `if ( cond )` on fields; `switch` on an expression or by look-ahead; `&byte-order`; unit parameters `unit(x: T)`; sinks for reassembly. <https://docs.zeek.org/projects/spicy/en/latest/programming/parsing.html>
- Active: v1.17.0 released 2026-09-14, last push 2026-11-05. BSD-style Zeek licence. <https://github.com/zeek/spicy>
- **Relevance.** Spicy is a design reference for stream-oriented features (reassembly, look-ahead switching) that file-format languages such as Kaitai treat as secondary. It is not a format to adopt.

## Wireshark's own declarative paths

- **Generators in the Wireshark source tree.** `tools/dissector_generators/` contains `asn2wrs.py` (ASN.1), `idl2wrs` (CORBA IDL), `eti2wrs.py`, and others. `tools/pidl` handles DCE/RPC IDL, and ASN.1 inputs live in `epan/dissectors/asn1/`. They all produce C that is compiled into Wireshark, so they suit standards bodies, not end users. <https://github.com/wireshark/wireshark/tree/master/tools/dissector_generators>
- **Protobuf.** Wireshark loads `.proto` files at runtime from configured *Protobuf Search Paths*, and the *Protobuf UDP Message Types* preference maps UDP ports to root message types. No code is needed. `.proto` support dates from 3.2.0. <https://wiki.wireshark.org/Protobuf>
- **Relevance.** These show that Wireshark already accepts declarative input in some ecosystems. Wirdigen covers custom fixed-layout binary protocols, which none of them address.

## Other Rust ecosystem references

- **binrw** (Apache-2.0, ~1.4k stars, last push 2026-11-01) and **deku** (Apache-2.0, last push 2026-11-06) are Rust derive-based binary (de)serialisers, not file formats. Their attribute vocabulary is a well-tested naming precedent: count, if, magic, endianness, and bit-level fields in deku. <https://github.com/binrw/binrw>, <https://github.com/sharksforarms/deku>

## Adopt, extend or borrow?

1. **Adopting `.ksy` as the Protocol Description format: not now; keep it as an option to revisit.**
   - For: the most expressive and best-documented format, a JSON Schema already exists, there is a large gallery including network protocols, and it is actively maintained.
   - Against:
     - KSY says nothing about Wireshark concerns that Wirdigen's Protocol Description must carry, such as transport and port registration, display `base`, and filter names. The rgbpb fork has to add a non-standard `-x-wireshark:` extension for exactly this reason.
     - Kaitai is still pre-1.0, which conflicts with ADR 0001's promise that a 1.x Protocol Description stays valid.
     - Implementing even a sizeable subset of KSY expressions in Rust is a large job.
   - The upstream KS Wireshark target is also being revived right now. If it lands, "KSY → Dissector" is covered upstream, and Wirdigen would be competing on KS's own ground.
2. **Extending wsgd: no.** It is a native runtime interpreter with a different delivery model and is GPL-2.0+. Its feature list is still the best checklist of what Wireshark users want from a declarative description: constraints, display transforms, heuristic dissectors, Decode As, and message-ID switching driven by header settings.
3. **Borrowing: yes, from several.**
   - From Kaitai: field-relative layout with `seq` order instead of absolute offsets; sizes from expressions or earlier Fields; `repeat` modes; `if`; `switch-on`; `enums`; `bN` bitfields. Wirdigen should also consider a KSY importer later rather than KSY as the native format.
   - From wsgd: the header settings (`MSG_HEADER_TYPE`, `MSG_ID_FIELD_NAME`, `MSG_TOTAL_LENGTH`) as a model for describing multiple message types and PDU length; value constraints.
   - From PDL: `_size_`/`_count_` linkage, packet inheritance with constraints for message variants, and closed versus open enums.
   - From Wirdigen's JSON-Schema validation: keep it, and look at `ksy_schema` for how a richer schema is structured.
4. **Positioning.** No maintained tool takes a Wireshark-aware declarative description, emits a plain Lua Dissector, and needs no native plugin or compiler fork. joushx/kaitai-to-wireshark and WDissectorGen are abandoned. pdl-dissector is dormant and tied to PDL's Bluetooth-oriented model. wsgd needs a matching binary. The KS fork is promising but unmerged and GPL. That gap is Wirdigen's niche.

## Answer gist

No maintained tool turns a Wireshark-aware declarative description into a plain Lua Dissector. Kaitai `.ksy` (most expressive, pre-1.0, GPL compiler, its Wireshark target only in an unmerged 2026 fork) and wsgd (expressive, but a native per-version plugin under GPL-2.0+) are the closest. Wirdigen should keep its own format, borrow Kaitai/PDL/wsgd constructs (sequential layout, size/count references, repeat, if/switch, enums, bitfields, header-driven message switching), and treat a KSY importer as a later option rather than adopting `.ksy`.
