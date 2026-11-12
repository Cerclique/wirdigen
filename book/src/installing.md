# Installing a Dissector

A generated Dissector is a single Lua file, such as `telemetry.lua`. Wireshark loads it from its
personal Lua plugins folder at startup; tshark can also load it for one run, with nothing
installed. Wirdigen has no `install` command: copying the file is all there is to it.

## Wireshark 4.4 or later {#wireshark}

Dissectors need **Wireshark 4.4 or later**, whose Lua is 5.3 or 5.4. `tshark --version` or
*Help → About Wireshark* shows the version you have. Loaded into an older Wireshark, a
Dissector stops with an error naming the version it found (see
[Troubleshooting](#version-guard)).

Most platforms' current packages are recent enough. Ubuntu 24.04 ships 4.2: install a newer
release from the Wireshark developers' PPA instead.

```text
sudo add-apt-repository ppa:wireshark-dev/stable
sudo apt update
sudo apt install wireshark tshark
```

## Trying a Dissector without installing it {#try}

`-X lua_script:<file>` loads a Lua file for one run of tshark or Wireshark, on top of the
installed plugins. It is the quickest way to check a Dissector on a capture:

```text
tshark -X lua_script:telemetry.lua -r capture.pcapng
wireshark -X lua_script:telemetry.lua capture.pcapng
```

A Dissector that does not claim ports by default (no [`registration:`](reference/registration.md))
is reached through Decode As, which `-d` gives on the command line:

```text
tshark -X lua_script:demo.lua -d udp.port==5000,demo -r capture.pcapng
```

## Finding the plugins folder {#folder}

Where Wireshark looks for Lua plugins depends on the platform, the version and how Wireshark
was installed, so ask Wireshark rather than guessing:

- In Wireshark, *Help → About Wireshark → Folders*: the **Personal Lua Plugins** row.
- From the command line, `tshark -G folders`:

  ```text
  $ tshark -G folders | grep "Personal Lua"
  Personal Lua Plugins:	/home/alice/.local/lib/wireshark/plugins
  ```

Typical answers look like these, but only the two above are authoritative:

| Platform | Personal Lua plugins folder, for example |
|---|---|
| Linux, macOS | `~/.local/lib/wireshark/plugins` |
| Windows | `%APPDATA%\Wireshark\plugins` |

The folder may not exist yet: create it. Copy the Dissector into it, and Wireshark loads it at
its next start:

```text
mkdir -p ~/.local/lib/wireshark/plugins
cp telemetry.lua ~/.local/lib/wireshark/plugins/
```

A *Global Lua Plugins* folder also exists, for every user of the machine; it usually needs
administrator rights.

## Reloading {#reload}

Wireshark reads Lua plugins when it starts. After regenerating a Dissector, either restart
Wireshark or reload the plugins with *Analyze → Reload Lua Plugins* (Ctrl+Shift+L). tshark
reads them afresh on every run.

## Troubleshooting {#troubleshooting}

### "This Dissector requires Wireshark >= 4.4" {#version-guard}

Every Dissector checks the Wireshark version as it loads, and refuses an older one with a clear
message instead of failing later on a missing Lua function:

```text
tshark: Lua: Error during loading:
telemetry.lua:9: This Dissector requires Wireshark >= 4.4, found 4.2.2
```

Upgrade Wireshark (see [above](#wireshark)); regenerating does not help.

### tshark exits 0 although the Dissector failed {#exit-status}

When a Lua file fails to load, tshark prints `Lua: Error during loading:` on stderr, then reads
the capture without that Dissector and still exits with status 0. A script, or a CI job, that
runs tshark must not trust the exit status alone: check that stderr is empty, and that the
packets show the protocol. Wireshark itself shows the same error in a dialog at startup.

### Nothing happens when running as root {#root}

tshark and Wireshark do not run Lua plugins as root: they print
`Running as user "root" and group "root". This could be dangerous.` and dissect the capture as
if the Dissector did not exist, so the packets show as plain UDP or TCP. Run them as your usual
user; capture permissions are granted through the `wireshark` group (or your platform's
equivalent), not by running as root. Containers often run as root by default: pass a user, as
in `docker run --user "$(id -u):$(id -g)"`.

### The packets show as plain UDP or TCP {#not-claimed}

If the Dissector loaded (no error above) but its packets are not decoded:

- Check that the Dissector claims the traffic's port: its `registration:` ports, or the
  `<name>.udp_ports` and `<name>.tcp_ports` preferences that start from them. Without
  `registration:`, use *Analyze → Decode As* (or `-d` with tshark).
- In Wireshark, check *Help → About Wireshark → Plugins* lists the file, then reload
  (Ctrl+Shift+L).
