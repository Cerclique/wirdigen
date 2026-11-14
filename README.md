# Wirdigen

[![CI](https://github.com/Cerclique/wirdigen/actions/workflows/ci.yml/badge.svg)](https://github.com/Cerclique/wirdigen/actions/workflows/ci.yml)

**Wirdigen** (*Wir*eshark *Di*ssector *Gen*erator) turns a declarative description of a
network protocol into a Wireshark dissector.

You write a **Protocol Description**: a YAML file that names the protocol, the ports it uses
and the Fields of its payload. Wirdigen checks it, reports every mistake with its exact
location, and generates a Lua **Dissector** for Wireshark 4.4 and later. The Dissector shows
each Field in the protocol tree, makes it filterable, and marks a short packet Malformed
instead of failing.

## Install

The `wirdigen` command comes from the `wirdigen-cli` crate, built with
[Rust](https://rustup.rs/):

```sh
cargo install --locked wirdigen-cli
```

Wirdigen 1.0 is in pre-release: name one to install it, as in
`--version 1.0.0-alpha.1`.

Each [GitHub Release](https://github.com/Cerclique/wirdigen/releases) also has
prebuilt binaries for Linux (x86_64, aarch64), macOS (Apple silicon, Intel) and
Windows (x86_64). Each archive includes shell completions and man pages, and
`cargo binstall wirdigen-cli` installs from them. The JSON Schema for
`*.wirdigen.yaml` is attached as `wirdigen.schema.json`.

To use the generated Dissectors you need
[Wireshark](https://www.wireshark.org/) 4.4 or later.

## Quickstart

Describe the protocol in `demo.wirdigen.yaml`:

```yaml
name: demo
registration:
  ports:
    udp: [5000]
info: "{msg_type} id={id}"
fields:
  - { name: msg_type, type: uint8, values: { 1: Request, 2: Response } }
  - { name: id, type: uint16, display: hex }
  - { name: sender, type: ipv4 }
```

Generate `demo.lua` next to it, and load it into tshark or Wireshark for a capture:

```sh
wirdigen generate demo.wirdigen.yaml
tshark -X lua_script:demo.lua -r capture.pcapng -Y "demo.msg_type == 1"
```

UDP port 5000 now decodes as `demo`, with an Info column such as `Request id=0x002a`. To load
the Dissector every time, copy it into Wireshark's personal Lua plugins folder.

## Documentation

- [The Wirdigen book](https://cerclique.github.io/wirdigen/): a tutorial, installing a
  Dissector, and the reference of the Protocol Description format with every Diagnostic.
- [`wirdigen` on docs.rs](https://docs.rs/wirdigen): the Rust library behind the command, to
  validate descriptions and generate Dissectors from your own program.
- [`examples/`](https://github.com/Cerclique/wirdigen/tree/main/examples): complete
  descriptions with sample packets.

## License

See [LICENSE](https://github.com/Cerclique/wirdigen/blob/main/LICENSE).
