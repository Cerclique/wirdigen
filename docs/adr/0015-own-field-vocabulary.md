# Fields are declared in Wirdigen's own vocabulary, not Wireshark's

A Field says what it is with one `type:` key holding either a built-in type or a Type, and how it is shown with `encoding:`, `display:`, `values:`, `true:`/`false:`, `unit:`, `label:` and `description:`. The built-in type names describe the wire, not Wireshark's ftypes: `uint8` … `uint64` and `int8` … `int64` at every byte width from 8 to 64 bits (40, 48 and 56 included, though Lua cannot create those ftypes; generated code reads them itself), `bool`, `float32`/`float64`, `string`, `bytes`, `ipv4`, `ipv6`, `ether`, `eui64`, `guid`, `abs_time`, `rel_time`. `stringz` and `ubytes` are not types: `string` and `bytes` take their length from `size:`, `prefix:` or `terminator:` like every variable-length Field.

**Names are split by case.** Field names (and bitfield sub-Field names) match `[a-z][a-z0-9_]*`, Type and Enum names match `[A-Z][A-Za-z0-9]*`, and every built-in is lowercase. `type: Header` is therefore always a Type and `type: uint8` always a built-in, and a built-in added in a 1.x minor can never collide with a user's Type, which ADR 0001's compatibility promise would otherwise forbid. Field names exclude `-` and `.` because they appear bare in Expressions (ADR 0007), where `-` is subtraction and `.` separates path segments.

**Value tables can be named and shared.** A top-level `enums:` key maps an Enum name to a `values:` table (integer or `"low-high"` keys), and a Field writes either an inline table or `values: <EnumName>`. This amends ADR 0014: the top level has ten keys, `enums` listed after `types`. YAML anchors stay banned (ADR 0005), and a request and a response sharing an opcode table are too common to make users copy it.

## Consequences

- One key, `display:`, carries the integer base, the bytes separator and the time zone, and one key, `encoding:`, carries both the text encoding and the timestamp wire format. The valid values depend on the type, and everything outside the matrix in the spec is the single error `incompatible-display`.
- Two Fields reaching one filter path share a ProtoField only when type, display, value mappings, label and description all match (ADR 0009's `conflicting-filter-name`); two references to the same Enum count as matching.
- Wireshark's names (`FT_*`, `BASE_*`, `ENC_*`, value string vs range string) never appear in a Protocol Description. The generator chooses a value string or a range string from the table's keys.
- New built-ins and new `display:`/`encoding:` values are minor releases; renaming one is a 2.0.

## Considered Options

- **Wireshark's names (`float`/`double`, `absolute_time`, `stringz`, `ubytes`, `base:` with `BASE_*` spellings)**: rejected; they leak Lua API details and duplicate what the length keys already say.
- **One name rule for Fields and Types, with Type names checked against the built-in list**: rejected; a new built-in would break descriptions that already use that name as a Type.
- **Separate keys for built-ins and Types (`type:` / `use:`)**: rejected; the case rule already tells them apart.
- **Fields as a YAML map keyed by name**: rejected; YAML map order carries no meaning, and `{ padding: n }` entries have no name.
- **No shared value tables in v1**: rejected; copied tables drift apart and then fail `conflicting-filter-name`.
- **Enums as a kind of Type**: rejected; a Type is a group of Fields, not a table of labels.
