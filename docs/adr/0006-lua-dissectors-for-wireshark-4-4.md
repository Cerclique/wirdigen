# Dissectors are Lua only and target Wireshark 4.4 and later

Wirdigen generates a Dissector as a single Lua file, nothing else: no C plugin and no other target in v1. A Lua Dissector needs no compiler: users drop it into Wireshark's plugins folder or pass it with `-X lua_script:`, it behaves the same on every OS, and CI can test it headlessly in tshark. A C plugin is faster and fills some Lua API gaps (TCP PDU splitting, `add_bitmask`, 40/48/56-bit integers), but has to be compiled against each Wireshark minor version's ABI on each OS. The gaps can all be filled in generated Lua.

A Dissector supports Wireshark 4.4 and every later release, so generated code targets Lua 5.3 and 5.4. Wireshark 4.2 (Lua 5.2), which stock Ubuntu 24.04 still ships, is not supported. Support is rolling: there is no upper bound, and a Dissector that misbehaves on a new upstream release is a bug.

Loaded into Wireshark older than 4.4, a Dissector fails at load time with an error that names the version it requires, instead of a cryptic Lua error.

## Consequences

- **The generated file must parse under Lua 5.2**, even though 5.2 is unsupported. Lua compiles the whole file before running the version guard, so a single native bitwise operator (`&`, `|`, `~`, `<<`, `>>`) or integer division (`//`) turns the guard's clear error back into a syntax error. Use the bundled `bit` library and `math.floor` instead. A test should load generated Dissectors with a Lua 5.2 parser to catch regressions.
- Per ADR 0001, raising the floor is a minor release, and only once that version has reached upstream end of life.
- The user documentation states "Wireshark ≥ 4.4 (Lua 5.3/5.4)", explains the guard's error, and points stock Ubuntu 24.04 users at `ppa:wireshark-dev/stable`.
- Which Wireshark versions CI tests is decided with the test strategy, not here.

## Considered Options

- **Lua plus a C plugin**: rejected for v1; it doubles the generator and test surface and turns installing a Dissector into a build matrix.
- **Wireshark 4.2 as the floor**: rejected; it reaches stock Ubuntu 24.04, but costs a second Lua dialect (no native integers or bitwise operators) for a release upstream no longer supports.
- **Wireshark 4.6 as the floor**: rejected; the Dissector API is the same as 4.4, so it gains almost nothing.
- **A fixed, listed range of supported versions**: rejected; the API a Dissector uses has barely changed since 4.2, so a ceiling would mostly mean paperwork.
- **No version guard, documentation only**: rejected; a cryptic syntax error is the first thing a stock Ubuntu 24.04 user would hit, and tshark still exits 0.
