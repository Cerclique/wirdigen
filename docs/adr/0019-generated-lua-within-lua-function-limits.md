# Generated Lua stays within Lua's per-function limits, however large the description

Lua allows a function at most 200 locals, 255 upvalues and 255 registers, and its parser at most about 200 levels of nested blocks, statements and expressions. The emitter of ADR 0010 used to declare every ProtoField, value table, site table, field extractor and dissect function as a `local` of the main chunk, every value an Expression reads as a `local` of its dissect function, and each nested Field as a `do` block inside its parent. A description with about 200 Fields, about 95 Types, or 25 nested inline Structures produced a Dissector that tshark refused to load (#199). The goal is to remove those limits, not to report them: no Diagnostic caps a description's size.

- **The Dissector's own declarations** go in one table, `local wd = {}`: `wd.f_<path>` for ProtoFields, `wd.enum_<Enum>`, `wd.names_<path>`, `wd.site_<path>`, `wd.x_<path>`, and `function wd.dissect_<Type>` and `wd.dissect_top`. The main chunk's locals are then the prelude's, `wd_proto`, the expert infos and `wd`, a fixed set, and each function reaches every declaration through one upvalue.
- **Site tables never nest.** A site table holding the site table of a Type used inside its Type refers to it (`t_next = wd.site_t__next`), declared before it, rather than holding a nested table constructor, which would take a register per level of a chain of Types.
- **The values Expressions read** are kept in one table per dissect function, `local v = {}`, under the Field's path (`v.hdr__len`), instead of one local each.
- **Deep nesting is split into parts.** A statement holding statements (`if:`, `switch`, an inline Structure, an array) four such statements deep in a function becomes a part: `function wd.part_<n>(tvb, pinfo, tree, offset[, site[, ctx]][, v])`, defined before the dissect function, called as `offset = wd.part_<n>(...)`, returning the offset or `nil` like a dissect function. No statement reads a local of the statements around it, so the part needs only what its dissect function takes and `v`. Each function then holds at most about 50 locals and about 20 levels of blocks, whatever the depth of the description.

## Consequences

- A description of 1,000 Fields, 500 Types in a chain, 500 Types used side by side, and 50 levels of nested inline Structures, in a Type or not, loads and dissects in tshark; the tshark suite generates these descriptions and checks them.
- An Expression as deep as ADR 0018 allows loads however deeply it is nested in the description, since a function never holds more than a few levels of blocks around it.
- Filter names, labels and dissection trees do not change. The Lua does: declarations read `wd.f_x` rather than `f_x`, values `v.x` rather than `v_x`. Per ADR 0001 the Lua text is not under semver.
- A dissect function that reads any value allocates its `v` table on each call, and each part is one more call. Both are small next to the tree items Wireshark builds.
- Wireshark itself limits a tree to 500 levels (`gui.max_tree_depth`), so a chain of 500 Types needs that preference raised to show its last level. That is a limit of Wireshark's, not of the Dissector.

## Considered Options

- **A Diagnostic past a size limit**: rejected; real protocols with hundreds of Fields are plausible, and the limits are the emitter's to avoid.
- **One table per kind of declaration** (`wd_f.len`, `wd_site.req`): rejected; more names for no gain, since the mangled keys already tell kinds apart.
- **Closures written in place for deep nesting**: rejected; they reset the locals and registers, but Lua's parser counts the nesting of the source, so 50 levels still fail with `C stack overflow`.
- **Grouping declarations in `do` blocks**: rejected; the main chunk still needs to reach every declaration after the block ends.
