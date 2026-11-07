# Research notes

Findings gathered while charting the [Wirdigen v1 spec](https://github.com/Cerclique/wirdigen/issues/8). Each note is a snapshot of its sources on the date it states and is not kept up to date. Where a note's recommendation differs from an ADR in `docs/adr/`, the ADR is the decision (for example, ADR 0008 rejects the JSON Schema validation that the prior-art note suggests keeping).

- [Prior art for declarative protocol descriptions](prior-art-protocol-descriptions.md) ([issue](https://github.com/Cerclique/wirdigen/issues/9)): Kaitai, wsgd, PDL and others; led to ADR 0004.
- [Wireshark Lua API capabilities and versions](wireshark-lua-api.md) ([issue](https://github.com/Cerclique/wirdigen/issues/10)): branches, Lua versions, ProtoField types, registration and TCP reassembly; led to ADR 0006.
- [Running Lua Dissectors headless in tshark](tshark-headless-lua.md) ([issue](https://github.com/Cerclique/wirdigen/issues/11)): `-X lua_script:`, `text2pcap` and CI gotchas; led to ADR 0011.
