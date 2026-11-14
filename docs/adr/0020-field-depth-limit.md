# Fields are limited to depth 64, and YAML to 256 levels, so every pass can recurse

A Protocol Description nested too deeply aborts Wirdigen with a stack overflow (#207). The YAML reader, deserialization, the filter-name walk, framing sizes, the read-to-end checks, lowering's site tables, emit and `Drop` all recurse once per level of nesting. ADR 0018 caps Expressions; nothing caps Fields. Measured at 66aa62d, with the default 2 MB stack of a spawned Rust thread, which is where a library caller or `cargo test` runs:

| Description | Debug build | Release build |
|---|---|---|
| Nested inline Structures | overflows between 150 and 200 levels, in the YAML reader | overflows between 400 and 600 |
| A chain of Types (`T0` → `T1` → …) | overflows between 800 and 1,000, in lowering | — |

The CLI's 8 MB main thread goes about four times further, and still overflows: 800 nested inline Structures, 5,000 chained Types.

Two limits now apply, both checked before any recursive pass sees the description:

- **A Field is at most 64 deep.** Its Depth is how many Fields enclose it, through every Type it is reached by: the number of names in its Filter Name, less the protocol's and its own. A Case adds none, an Array, a Bitfield, a Switch, an inline Structure and a Field of a Type add one each. A deeper Field is the error `field-too-deep`, reported once at each Field that is the first past 64 on its path, where it is written, with the Filter Name that reaches it in the message; the Fields under it are not reported. A Field of a Type can have a different Depth through each use of the Type, so the check runs once Types are resolved, after the Type dependency walk, which is iterative (ADR 0018). If it reports anything, the checks that walk through every use of a Type do not run, as for any error before them (spec §6.1).
- **YAML nests at most 256 levels.** The YAML reader recurses before any Field exists, and nesting anywhere (`info: [[[[…]]]]`) reaches it. A deeper node is the error `yaml-too-deep`, at the node that reaches level 257. A Field level takes two YAML levels inline (a map, then its `fields:` list) and at most three through a Switch's Cases, so a description within the Field limit is at most about 64 × 3 + 2 = 194 levels deep and never meets this one.

## Consequences

- Every pass after these checks can stay recursive, now and in the future, as ADR 0018 allows for Expressions.
- At 64, the worst case measured, nested inline Structures in a debug build on a 2 MB stack, has more than twice the headroom it needs, for Field shapes that take more stack per level than the ones measured.
- ADR 0019 removed the limits on a description's *size*, and keeps them removed: any number of Fields and Types is accepted. Depth is a different axis. No hand-written protocol nests near 64, recursive Types are already rejected, and a deep chain costs output that grows with the square of its length, since every Filter Name spells its whole path: a chain of 2,000 Types generates 122 MB of Lua. Wireshark itself stops showing a tree at 500 levels (`gui.max_tree_depth`).
- The large-description tshark tests of ADR 0019 that nest past 64 (a chain of 500 Types, a value read 160 Structures deep) shrink to the limit; a description exactly at it must load and dissect in tshark.
- Raising either limit later is a minor change; lowering one rejects descriptions that used to be accepted, which is a major change from 1.0.0 (ADR 0008). Descriptions between 65 and about 500 deep load today; they are rejected while v1 is a pre-release (ADR 0003).

## Considered Options

- **Iterative passes with no limit**: rejected, as for Expressions in ADR 0018. Every pass, and every future one, would need an explicit stack, `Drop` included, for nesting no real protocol has.
- **Counting Structures, Cases included**: rejected. It is closer to what the passes recurse over, but a Switch would count twice and the number would match neither the Filter Name nor the tree users see.
- **Limiting only chains of Types**: rejected. Nested inline Structures overflow on their own, in the YAML reader.
- **128**: rejected. 150 levels pass in a debug build on a 2 MB stack, too little margin for heavier Field shapes.
- **500, Wireshark's tree depth**: rejected. It overflows on a 2 MB stack unless the YAML reader and every per-level pass are made cheaper or iterative, which is the first option again.
- **Reporting only the first too-deep Field, or the Field holding it**: rejected. The Field past the limit is the one to move, and the Filter Name in the message says which use of a Type took it there.
- **Making the YAML reader iterative and relying on `field-too-deep` alone**: rejected. Deep YAML outside `fields:` would still overflow when its nodes are deserialized or dropped.
- **Reporting deep YAML as `yaml-syntax`, or a deep Field as `recursive-type`**: rejected. Neither is malformed or recursive, and tools matching on those names would be misled.
