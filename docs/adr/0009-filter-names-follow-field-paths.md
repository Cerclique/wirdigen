# Display filter names follow Field Paths, not Type names

Every Field a Dissector shows gets the display filter name `<protocol>.<path>`, where the path is the chain of Field names from the top-level layout down through inline `fields:` and Type-typed Fields. The name of a Type never appears. A Field `req_hdr` of Type `Header` with a Field `len` is filtered as `myproto.req_hdr.len`; the same Type used as `resp_hdr` gives `myproto.resp_hdr.len`. Filter names are Dissector behaviour under ADR 0001, so this rule is stable: users save filters and colouring rules against them.

- **Type reuse** registers one set of ProtoFields per place the Type is used, not per occurrence in a packet.
- **Array elements** share their element's names (`myproto.items.id`); Wireshark matches every occurrence.
- **Bitfield sub-Fields** extend their container's path (`myproto.flags.syn`).
- **`switch` cases** add no segment: their Fields sit under the switch Field (`myproto.body.user_id`).
- **Padding** has no filter name.

When two Fields reach the same path (typically two `switch` cases each with a Field `id`), they share one ProtoField if their type, display and value strings match. If not, validation fails with the error `conflicting-filter-name`; Wirdigen never renames a Field silently.

## Consequences

- A user can predict every filter name from the description alone by following Field names.
- Renaming a Field, or moving it into or out of a nested structure, changes its filter name, so it is a breaking change for that protocol's users even though the Type is unchanged.
- `conflicting-filter-name` joins the Diagnostics of ADR 0008, so a clash that would otherwise surface as a Wireshark registration error at load time is caught by `validate`.
- A large protocol that reuses a Type in many places registers many ProtoFields; registration is cheap, and per-site names are what makes request and response headers filterable apart.

## Considered Options

- **Type-based names** (`myproto.Header.len`, one ProtoField per Type Field shared by every use, as hand-written C dissectors share an `hf_`): rejected; a request header and a response header could not be filtered apart, and user-chosen, often CamelCase, Type names would leak into filters.
- **A segment per `switch` case** (such as `myproto.body.case_1.user_id`): rejected; cases have no names, so the segment would have to be invented from a value or an index and would change whenever cases are reordered or merged.
- **Silently suffixing colliding names** (`id`, `id_2`): rejected; which Field gets the suffix would depend on case order, and filters would break when cases are edited.
