# Wireshark Lua API: what a generated Dissector can use (as of 2026-11-07)

Research for issue #10. The question: what does the Wireshark Lua API offer a generated Dissector today, which Wireshark and Lua versions are current, and what changed between them.

Method: claims come from the Wireshark source on GitLab (branches `release-4.2`, `release-4.4`, `release-4.6`, `release-5.0`, read on 2026-11-07), the Wireshark release notes and User's/Developer's Guides on wireshark.org, and the Lua reference manuals. When the generated reference docs and the C code disagree, this note goes with the code and says so. Source links use `release-5.0` unless stated. `WSLUA` = `https://gitlab.com/wireshark/wireshark/-/blob/release-5.0/epan/wslua`.

## TL;DR

- **Supported branches today:** 4.6 (current stable, 4.6.9) and 4.4 (old stable, 4.4.19). **5.0 is at release candidate** (`v5.0.0rc1`, tagged 2026-10-21) and is planned for November 2026. When 5.0.0 ships, 4.4 reaches end of life. **There is no LTS branch any more**: the last LTS was 3.6, which reached end of life on 2024-05-22.
- **Lua:** 4.4 and later run Lua **5.3 or 5.4**. 4.2 and earlier ran 5.1 or 5.2. The official installers ship **Lua 5.4.6**. Lua 5.5 is not supported (4.6.5 fixed only a *compile* error against it).
- **The parts of the API a Dissector uses have barely changed across 4.2 to 5.0.** The ProtoField constructors, `TreeItem:add` and `add_le` and `add_packet_field`, `DissectorTable`, `Proto:register_heuristic`, and `Pinfo.desegment_len` and `desegment_offset` are the same set in all four branches. The differences: `base.SPECIAL_VALS` (4.6 and later), read-only `ProtoField` attributes (4.4 and later), more `TvbRange` decompress and decode methods (4.4 and later), tree navigation methods (5.0), and the Lua language move itself.
- **Gaps to plan around:** there is no Lua `add_bitmask` and no `dissect_tcp_pdus`. `ftypes.UINT_STRING`, `STRINGZPAD` and `STRINGZTRUNC` cannot be constructed, and neither can the 40/48/56-bit integer types. Signed integers can only use `base.DEC`. The Dissector must do TCP reassembly itself through `pinfo.desegment_*`.

## 1. Versions and lifecycle

| Branch | Status on 2026-11-07 | Latest | First release | Support ends | Lua |
|---|---|---|---|---|---|
| 5.0 | release candidate | 5.0.0rc1 (tag `v5.0.0rc1`, 2026-10-21) | planned Nov 2026 | when 5.2.0 ships | 5.3 / 5.4 |
| 4.6 | **current stable** | 4.6.9 (2026-09-23) | 2025-10-08 | when 5.1.0 ships (18 months minimum) | 5.3 / 5.4 |
| 4.4 | **old stable** | 4.4.19 (2026-09-23) | 2024-08-28 | **when 5.0.0 ships** | 5.3 / 5.4 |
| 4.2 | EOL 2025-10-08 | | 2023-11-15 | | 5.1 / 5.2 |
| 3.6 | EOL 2024-05-22, **last LTS** | | 2021-11-22 | | 5.1 / 5.2 |

Sources:
- Download page (stable 4.6.9, old stable 4.4.19): https://www.wireshark.org/download.html
- Release life cycle table and policy: https://www.wireshark.org/docs/wsug_html/#ChIntroReleaseLifeCycle. The guide says "Each release shall be supported for a minimum of 18 months", support for X.Y ends at "the end of its minimum lifetime or when version X.Y+4 is released" (whichever is later), and "at least two" branches are supported at a time. Only 2.6 and 3.6 are labelled LTS.
- Tags and branches: GitLab API `projects/wireshark%2Fwireshark/repository/tags` shows `v5.0.0rc1` (2026-10-21), `v5.0.0rc0`, `v4.7.0` to `v4.7.4` (the 4.7.x development series), `v4.6.9` and `v4.4.19`. Branch `release-5.0` exists.
- The 5.0 release notes draft says "This is an experimental release intended to test new features for Wireshark 5.0": https://gitlab.com/wireshark/wireshark/-/blob/release-5.0/doc/Wireshark_Release_Notes.adoc

Implication for Wirdigen: ADR 0001 says Wirdigen may drop a Wireshark version only after its upstream end of life. 4.4 crosses that line within weeks of this note. Support for "4.4+" or "4.6+" costs almost nothing extra in API terms, because of the Lua 5.3/5.4 baseline (section 2).

## 2. Lua version and the 4.x move to Lua 5.3/5.4

- **4.4.0** release notes: "Support for Lua 5.3 and 5.4 has been added, and support for Lua 5.1 and 5.2 has been removed. The Windows and macOS installers now ship with Lua 5.4.6." Also: "different versions of Lua are not guaranteed to be compatible". Plugin `.lua` files are now loaded "via the same internal Lua methods as `require()`", and using globals is deprecated. Source: https://www.wireshark.org/docs/relnotes/wireshark-4.4.0.html
- The build files confirm it: `release-4.2/CMakeLists.txt` uses `LUA_FIND_VERSIONS "5.2;5.1"`, `release-4.4` uses `"5.4;5.3"`, and `release-4.6` and `release-5.0` use `ws_find_package(Lua ... "5.3")` (minimum 5.3). The bundled fetch build, `cmake/external/lua54/Lua54.cmake`, downloads `lua-5.4.6.tar.gz` on `release-5.0`.
- **Lua 5.5:** the 4.6.5 release notes list "Compilation error with Lua-5.5" (wsbug 21060) as fixed. That makes it compile, but no release note claims 5.5 support, and the installers ship 5.4. Source: https://gitlab.com/wireshark/wireshark/-/blob/release-4.6/doc/Wireshark_Release_Notes.adoc
- Developer's Guide (Lua chapter): "Wireshark versions 4.2.x and earlier support Lua 5.1 and 5.2, and newer versions support Lua 5.3 and 5.4". The Lua BitOp library (`bit`) is bundled with every version, and Lua 5.3 and later also have native bitwise operators. Before 5.0, Windows used a patched "lua-unicode" runtime for UTF-8 paths. 5.0 replaces it with a UTF-8 code-page application manifest. Source: https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html
- **4.6.0:** `bit` and `rex_pcre2` are preloaded into `package.loaded`. A `Conversation` object and Libgcrypt symmetric ciphers were added. Source: https://www.wireshark.org/docs/relnotes/wireshark-4.6.0.html

### Lua-language breaking changes a code generator must respect (5.1/5.2 to 5.3/5.4)

From the Lua manuals, §8 "Incompatibilities with the Previous Version" (5.3: https://www.lua.org/manual/5.3/manual.html#8, 5.4: https://www.lua.org/manual/5.4/manual.html#8; read from the `lua/lua` repo's `manual/manual.of` at tags v5.3 and v5.4):

- **5.3** adds an integer subtype for numbers. `/` always returns a float and `//` is floor division. A float that looks like an integer prints with `.0` (`2.0`, not `2`).
- **5.3** deprecates the `bit32` library. Use native `& | ~ << >>`, or Wireshark's bundled `bit` (BitOp).
- **5.3** deprecates `math.pow`, `atan2`, `cosh`, `sinh`, `tanh`, `frexp` and `ldexp`.
- **5.4** removes string-to-number coercion from the core language for arithmetic and bitwise operators. The string library still handles arithmetic, but not bitwise operators. Decimal integer literals that overflow are read as floats.
- **5.4** changes some details of integer `for` loops (the control variable never wraps around).
- **5.2** (already true before Wireshark 4.4) removed `setfenv` and `module()`, and moved `unpack` to `table.unpack`.

**Consequence:** a Dissector for 4.4 and later can rely on Lua 5.3 semantics: native bitwise operators, integer-valued `TvbRange:uint()`, and `//`. It must not use `bit32`. To also run on 4.2 or earlier, it would have to avoid native operators and use `bit.*`, and 4.2 is already end of life.

## 3. Proto, ProtoField types and base options

`Proto(name, description)` / `Proto.new` creates the protocol, and `proto.fields` registers the ProtoFields. The constructor rejects an empty name or description, a duplicate description, and invalid characters in the name (`WSLUA/wslua_proto.c`, `Proto_new`).

### Constructors (identical set in 4.2, 4.4, 4.6, 5.0)

Every constructor below except `ProtoField.new` takes `(abbr, [name], ...)`: filter name first, display name second. `ProtoField.new(name, abbr, type, [valuestring], [base], [mask], [description])` puts the display name first.

| Constructor | ftype | Display (`base`) argument | valuestring | mask |
|---|---|---|---|---|
| `uint8` `uint16` `uint24` `uint32` `uint64` | FT_UINTn | `base.DEC` (default), `HEX`, `OCT`, `DEC_HEX`, `HEX_DEC`; may be ORed with `base.UNIT_STRING`, `base.RANGE_STRING`, `base.SPECIAL_VALS` | yes | yes |
| `int8` `int16` `int24` `int32` `int64` | FT_INTn | **must be `base.DEC`** (plus the same OR flags) | yes | yes |
| `char` | FT_CHAR | `base.NONE` (needs a valuestring), `HEX`, `OCT` (default OCT) | yes | yes |
| `framenum` | FT_FRAMENUM | must be `base.NONE`; the valuestring slot takes `frametype.NONE/REQUEST/RESPONSE/ACK/DUP_ACK` | n/a | no |
| `bool` | FT_BOOLEAN | `base.NONE` when there is no mask, otherwise the parent bitfield width (1 to 64) | `{ "true text", "false text" }` | yes |
| `float`, `double` | FT_FLOAT/DOUBLE | n/a; the 3rd argument is a unit table `{singular[, plural]}` | units only | no |
| `string`, `stringz` | FT_STRING/STRINGZ | **must be `base.NONE`** (see the note below) | no | no |
| `bytes`, `ubytes` | FT_BYTES / FT_UINT_BYTES | `base.NONE`, `DOT`, `DASH`, `COLON`, `SPACE` (separator) | no | no |
| `absolute_time` | FT_ABSOLUTE_TIME | `base.LOCAL`, `UTC`, `DOY_UTC` | no | no |
| `relative_time` | FT_RELATIVE_TIME | none | no | no |
| `ipv4`, `ipv6`, `ether`, `ipx`, `guid`, `oid`, `rel_oid`, `systemid`, `eui64`, `protocol`, `none` | as named | none | no | no |
| `new` | any of the above | as above | as above | as above |

Sources:
- `WSLUA/wslua_proto_field.c`: the `PROTOFIELD_*` macros and `ProtoField_integer`/`_boolean`/`_time`/`_floating`/`_other_display`/`_other`, and the `base_displays` table.
- Reference manual: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoField
- I diffed the constructor list between all four branches: no differences.

Code-vs-doc discrepancies and restrictions, from the source:

- **`string`/`stringz` display.** The docs say "One of `base.ASCII` or `base.UNICODE`". The code rejects anything but `base.NONE` ("Display must be base.NONE"). Also, `base.ASCII` and `base.UNICODE` do not exist in the Lua `base` table: it is filled only from the C `BASE_*`, `SEP_*` and `ABSOLUTE_TIME_*` enums (`WSLUA/init_wslua.c`, `wslua_add_introspection`), so both evaluate to `nil` and fall back to NONE. Character encoding is chosen when the Field is added (`ENC_ASCII`, `ENC_UTF_8`, `ENC_UTF_16`, ...), not on the ProtoField.
- **Rejected types.** `ProtoField.new` lists `ftypes.UINT_STRING` as a valid type, but the code rejects it with "Unsupported ProtoField field type". It also rejects `UINT40/48/56`, `INT40/48/56`, `STRINGZPAD`, `STRINGZTRUNC`, `AX25` and the IEEE 11073 floats (`ProtoField_new`, "TODO: not handled yet"). The same holds on all four branches.
- **Masks** may be a Lua integer, a numeric string or `UInt64` (`get_mask`). `base.UNIT_STRING` cannot be combined with `RANGE_STRING` or `SPECIAL_VALS`.
- **Field names.** A field abbreviation (filter name) that already exists with an incompatible ftype is rejected ("A field of an incompatible ftype with this abbrev already exists").

### What changed

- **4.6:** `base.SPECIAL_VALS` added (absent in `release-4.4/wslua_proto_field.c`, present in `release-4.6`). It shows the value_string text without the raw number.
- **4.4 (marked `@since 4.3.0`):** read-only `ProtoField` attributes `type`, `abbr`, `name`, `base`, `valuestring`, `mask`, `description`.
- **4.4 and later:** `range_string`s for `char` and integers, and unit strings, are present from 4.2. Nothing was removed.

## 4. value_string-style mappings

All of these are plain Lua tables passed in the valuestring slot (`WSLUA/wslua_proto_field.c`: `value_string_from_table`, `val64_string_from_table`, `range_string_from_table`, `true_false_string_from_table`, `unit_name_string_from_table`):

- **value_string:** `{ [0] = "Request", [1] = "Reply" }`. Keys must be integers and values strings. 64-bit types automatically use `val64_string`.
- **range_string:** `{ {0, 9, "low"}, {10, 255, "high"} }`, with `base.X + base.RANGE_STRING`.
- **true_false_string** (bool): `{ "Set", "Not set" }`.
- **unit string:** `{ "byte", "bytes" }` (singular required, plural optional), with `base.X + base.UNIT_STRING`. For `float` and `double` it is the third argument.
- **`base.SPECIAL_VALS`** (4.6 and later): ORed in, and requires a value/range table.

## 5. Tree building: subtrees, bitmask fields, variable-length and string fields

`TreeItem` methods, which are the same in 4.2, 4.4 and 4.6: `add`, `add_le`, `add_packet_field`, `set_text`, `append_text`, `prepend_text`, `add_expert_info`, `add_proto_expert_info`, `add_tvb_expert_info`, `set_generated`, `set_hidden`, `set_len`, `referenced`, plus attributes `text`, `len`, `visible`, `generated`, `hidden`. **5.0 adds** `get_child_count`, `get_parent`, `get_child`, `children` and `get_field_info` (all `@since 4.7.0`), which a generator does not need. Source: `WSLUA/wslua_tree.c`, https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html

- **Subtrees.** Every `add`/`add_le`/`add_packet_field` returns the new child `TreeItem`, already turned into a subtree. Wireshark assigns each ProtoField its own `ett` automatically (`proto_item_add_subtree(item, ett > 0 ? ett : wslua_ett)`), so `local sub = tree:add(proto, tvb(0, n))` and then `sub:add(field, ...)` is all it takes. Expand/collapse state is kept per field.
- **Endianness.** `add` treats numbers as big-endian and `add_le` as little-endian. `add_packet_field(field, tvbrange, encoding, ...)` takes an explicit `ENC_*` and handles both.
- **Bitmask fields.** There is **no Lua wrapper for `proto_tree_add_bitmask`** (there is no `bitmask` in `wslua_tree.c`). The idiom is to declare each sub-field with a `mask` (for example `ProtoField.uint8("p.flags.syn", "SYN", base.HEX, nil, 0x02)`, or `ProtoField.bool(..., 8, nil, 0x02)`) and `add` each one over the **same** `TvbRange`. Wireshark shifts and masks the value and draws the bit pattern. `TvbRange:bitfield(pos, len)` can read bits for script logic.
- **Variable-length fields.** `add_packet_field` returns `(child, value, next_offset)`. For strings it uses `proto_tree_add_item_ret_string_and_length`, so `next_offset` reflects the real length consumed. That suits `stringz` with a range that runs to the end of the buffer, or a length-prefixed string where the Dissector first reads the length (for example `tvb(off,2):uint()`) and then builds `tvb(off+2, len)`. `TvbRange:strsize()` gives the length of a NUL-terminated string. `tvb(offset)` with no length means "rest of buffer". Because `UINT_STRING` cannot be constructed (section 3), **length-prefixed strings must be decoded by script logic, not by the ftype.**
- **Strings and encodings.** `ProtoField.string` plus an `ENC_*` on `add_packet_field` (for example `ENC_UTF_8`, `ENC_ASCII`, `ENC_UTF_16 + ENC_LITTLE_ENDIAN`). `TvbRange:string([encoding])`, `ustring`, `le_ustring`, `stringz`, `ustringz` and `le_ustringz` read values in script. `add_packet_field` can also parse ASCII-hex into `ftypes.BYTES` (`ENC_STR_HEX + ENC_SEP_*`) and ISO-8601 into `ABSOLUTE_TIME`.
- **TvbRange additions:** 4.4 added `uncompress_zlib`, `_brotli`, `_snappy`, `_zstd`, `_lz77`, `_lz77huff`, `_lznt1` and `_hpack_huff`, plus `decode_base64` and `decode_base64url` (all `@since 4.3.0`). `uncompress()` was deprecated in 4.4 but is still present in 5.0.

## 6. Registration: dissector tables, heuristics, Decode As

Source: `WSLUA/wslua_dissector.c`, `WSLUA/wslua_proto.c`, https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html. The method set is identical on 4.2 to 5.0, apart from `Dissector:decrypt` (4.6 and later, not relevant here).

- **Port and other tables.** `DissectorTable.get("udp.port"):add(7777, proto)`. The pattern may be an integer, a range string (`"7000-7010,8000"`) or a string for string-keyed tables. `set` replaces existing entries, and `remove`, `remove_all`, `try`, `get_dissector` and `DissectorTable.list()` are also available. `udp.port` and `tcp.port` are `FT_UINT16, BASE_DEC` tables (`epan/dissectors/packet-udp.c` line 1516, `packet-tcp.c` line 11822). Other commonly used tables include `sctp.ppi`, `sctp.port`, `ethertype`, `ip.proto`, `wtap_encap`, `tls.port` and `dtls.port`. The full list on a given install is `tshark -G dissector-tables`.
- **Locale fix (4.4.2).** On 4.4.1 and earlier, `add` and `set` with a range string like `"10,11"` misparsed in locales that use a decimal comma (wsbug 20216). Since then, strings are always parsed as ranges (`wslua_dissector.c` comments around `range_convert_str`).
- **Decode As.** `dissector_add_uint` also adds the handle to the table's "Decode As" candidate list (`epan/packet.c`, `dissector_add_uint`: "if this table supports 'Decode As', add this handle to the list of handles that could be used"). So `add()` alone makes the protocol choosable in Decode As for that table. `DissectorTable:add_for_decode_as(proto)` puts it in the list **without** binding a port. That fits a Protocol Description with no fixed port.
- **No automatic port preference.** C dissectors use `dissector_add_uint_with_preference` to get a user-editable "port" preference. Lua has no equivalent. A Dissector that wants one must declare `proto.prefs.port = Pref.uint(...)` or `Pref.range(...)`, then re-register in `proto.prefs_changed`.
- **Own tables.** `DissectorTable.new(name, [ui_name], [ftypes.UINT8/16/24/32/STRING/NONE/GUID], [base], [proto])` creates a sub-dissector table, for example one keyed on a message-type Field. `DissectorTable.heuristic_new(name, proto)` creates a heuristic list, and `try_heuristics` runs it.
- **Heuristic dissectors.** `proto:register_heuristic("udp", fn)`. The list must exist (`has_heur_dissector_list`), for example `udp`, `tcp`, `sctp` or `infiniband.payload`. The function returns `true` or `false`, or, when a `Dissector` object is passed, a byte count where 0 means "not mine". Lua heuristics are always registered `HEURISTIC_ENABLE` (`wslua_proto.c` line 335). Each protocol and list pair can be registered only once.
- **TCP port selection changed in 4.4.2.** TCP no longer falls back to the *client* port to choose a payload dissector once the server port is known (from the SYN/SYN-ACK), except for ports in the new "Client port dissectors" preference (default 20). A table entry whose port matches only the client side therefore does not fire. Sources: the 4.4.2 notes in `release-4.4/doc/release-notes.adoc`, and `packet-tcp.c` `decode_tcp_ports` (around line 8716).
- **Return value.** If the Lua dissector function returns a number, that is the byte count consumed. Otherwise the whole buffer counts as consumed (`init_wslua.c`, `dissect_lua`).

## 7. TCP reassembly (`desegment_len` / `desegment_offset`)

Source: `WSLUA/wslua_pinfo.c`, https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Pinfo.html

- **Pinfo attributes.** `pinfo.desegment_len` (RW, "Estimated number of additional bytes required for completing the PDU"), `pinfo.desegment_offset` (RW, the offset at which processing resumes), `pinfo.can_desegment` (RW) and `pinfo.saved_can_desegment` (RO, `@since 4.3.0`, for proxy protocols). The global constant `DESEGMENT_ONE_MORE_SEGMENT` is defined; `DESEGMENT_UNTIL_FIN` is **not** exported to Lua (`init_wslua.c`; registered as a number in 4.2 and as an integer from 4.4).
- **No `dissect_tcp_pdus` binding.** The Dissector writes the loop itself:

  ```lua
  function p.dissector(tvb, pinfo, tree)
    local off = 0
    while off < tvb:len() do
      local avail = tvb:len() - off
      if avail < HDR then
        pinfo.desegment_offset = off
        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
        return
      end
      local pdu_len = header_len(tvb, off)
      if avail < pdu_len then
        pinfo.desegment_offset = off
        pinfo.desegment_len = pdu_len - avail
        return
      end
      dissect_pdu(tvb(off, pdu_len):tvb(), pinfo, tree)
      off = off + pdu_len
    end
    return off
  end
  ```

  This only works when TCP's "Allow subdissector to reassemble TCP streams" preference (`tcp.desegment_tcp_streams`, default on) is set. `packet-tcp.c` handles the request: when `desegment_offset == 0`, nothing was dissected and the data source is dropped; otherwise the multi-segment PDU (MSP) is split at the offset (around lines 5840 to 5890). UDP has no equivalent mechanism.
- **Version history.** These attributes are unchanged from 4.2 to 5.0, apart from `saved_can_desegment` (4.4 and later).

## 8. Changes by version, for a generated Dissector

| Version | Change |
|---|---|
| 4.4.0 | Lua 5.3/5.4 replace 5.1/5.2 (bundled 5.4.6). Plugins load via `require()` semantics. `ProtoField` RO attributes. `TvbRange` decompressors and base64. `uncompress()` deprecated. `Pinfo.saved_can_desegment`. |
| 4.4.2 | `DissectorTable` range strings parse correctly in decimal-comma locales. TCP stops selecting dissectors by client port. |
| 4.6.0 | `base.SPECIAL_VALS`. `bit` and `rex_pcre2` preloaded. `Conversation` object. gcrypt ciphers. `Dissector:decrypt`. |
| 4.6.5 | Builds against Lua 5.5 (compile fix only). |
| 5.0 (rc) | Built-in Lua debugger (Tools > Lua Debugger). `TreeItem` navigation methods. `DissectorTable` RO introspection attributes. Windows drops the patched lua-unicode runtime for a UTF-8 manifest. No removals affecting dissectors were found in the release-notes draft. |

## Open points / not verified

- I could not confirm which Lua patch version the 4.6.x and 5.0 Windows and macOS installers actually bundle. The 4.4.0 notes say 5.4.6, and `Lua54.cmake` still fetches 5.4.6 on `release-5.0`, but the installers may come from separate dependency bundles.
- I did not check `tshark -G dissector-tables` or `heuristic-decodes` on a live install (no tshark available). The list of tables in section 6 beyond `udp.port` and `tcp.port` is from general knowledge of the dissector set, not verified per version.
- lua.org was unreachable during this research. The Lua incompatibility lists were read from the official `lua/lua` repository's `manual/manual.of` (tags v5.3 and v5.4), which is the source of the published manual.
