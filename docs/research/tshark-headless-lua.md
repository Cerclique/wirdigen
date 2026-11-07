# Running Lua Dissectors headless in tshark

Research for [#11](https://github.com/Cerclique/wirdigen/issues/11). Researched 2026-11-07.

**Question:** Can `tshark` load a generated **Dissector** headlessly against a pcap and produce output we can assert on in automated tests on GitHub Actions (Linux)? What are the gotchas?

**Short answer:** Yes. `tshark -X lua_script:<dissector>.lua -r <file>.pcap -T json|pdml|fields` works without a display. `text2pcap -u <port>,<port>` wraps raw payload bytes in fake Ethernet/IPv4/UDP headers, so a Dissector registered on `udp.port` picks them up. There are three traps to plan around:

1. A Lua load error **does not change tshark's exit code**. The test has to check stderr and/or `-G protocols` itself.
2. When tshark runs as **root**, it **silently skips** `-X lua_script` and the personal plugin directory.
3. The Lua version depends on which tshark gets installed. Ubuntu 24.04's stock package is Wireshark 4.2.2 with **Lua 5.2**. The Wireshark PPA ships 4.6.9 with **Lua 5.4**.

## Provenance

- **Read, not run.** tshark is not installed on the research machine, and Docker was unavailable there. Every claim below comes from the cited docs or Wireshark source code. None of it was checked by running tshark. Treat the commands in "Suggested test recipe" as the first thing to confirm in a CI spike.
- Wireshark source was read on `master` (GitHub mirror `wireshark/wireshark`, the same code as gitlab.com/wireshark/wireshark), 2026-11-07. The loading and root-check logic shown has existed for many releases, but I did not diff it against the 4.2.2 tag.

## 1. Loading a Dissector headless

- `-X lua_script:<file>` "tells TShark to load the given script in addition to the default Lua scripts". `-X lua_scriptN:<arg>` passes an argument to the Nth script. ([tshark(1), 4.6.9](https://www.wireshark.org/docs/man-pages/tshark.html); also in the [noble 4.2.2 man page](https://manpages.ubuntu.com/manpages/noble/man1/tshark.1.html))
- tshark also auto-loads `*.lua` from the global plugin dir (`INSTALLDIR/lib/wireshark/plugins`) and the personal plugin dir `~/.local/lib/wireshark/plugins`. The legacy `$XDG_CONFIG_HOME/wireshark/plugins` still works for Lua. ([WSUG: Plugin folders](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html); [Lua reference: loading](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html)) For tests, prefer `-X lua_script:`, which is explicit and needs no `$HOME` changes.
- Lua is on by default. It can be turned off only with `enable_lua = false` in an `init.lua` ([wsluarm](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html)). Both Ubuntu builds link Lua: noble's `libwireshark17t64` 4.2.2-1.1build3 depends on `liblua5.2-0` ([packages.ubuntu.com](https://packages.ubuntu.com/noble/libwireshark17t64)), and resolute's `libwireshark19` 4.6.4-1 depends on `liblua5.4-0` ([packages.ubuntu.com](https://packages.ubuntu.com/resolute/libwireshark19)).
- To confirm a script loaded, use `tshark -G plugins` (lists Lua scripts with their path) or `tshark -G protocols` (lists registered protocols) ([tshark(1)](https://www.wireshark.org/docs/man-pages/tshark.html)).

## 2. Assertable output

All of these come from [tshark(1)](https://www.wireshark.org/docs/man-pages/tshark.html):

| Option | Use for tests |
|---|---|
| `-T json` (+ `-j`/`-J` protocol filters, `-x` raw hex) | Full tree as JSON. Add `--no-duplicate-keys` so a key that appears more than once becomes one key holding a JSON array, instead of invalid-ish JSON with duplicate keys ([WSUG tshark help](https://www.wireshark.org/docs/wsug_html_chunked/AppToolstshark.html)). |
| `-T ek` | One JSON object per line. |
| `-T pdml` | XML tree, with each field's `name`/`show`/`value`/`pos`/`size`. Easiest way to check offsets and sizes. |
| `-T fields -e <proto>.<field> ...` | Tab-separated values for chosen fields. Smallest and most stable output for golden comparisons. |
| `-V` / `-O <proto>` | Text tree. Readable, but brittle as a golden file. |
| `-Y <display filter>` | Single-pass filter, e.g. `-Y <proto>` to check the Dissector claimed the packet. |
| `-d udp.port==N,<proto>` | Decode As, for forcing a port. |
| `-o pref:value`, `-C profile` | Pin preferences. The man page calls `-C` "useful in … automated testing setups". |

**Detecting dissection-time Lua errors.** If the dissector function throws while a packet is being dissected, wslua adds an expert item `_ws.lua.error` ("Lua Error: …", severity error) to the tree. tshark does not fail. ([init_wslua.c](https://github.com/wireshark/wireshark/blob/master/epan/wslua/init_wslua.c), `ei_lua_error` registration). A test can assert that `tshark … -Y _ws.lua.error` prints nothing, or search the JSON/PDML for `_ws.lua.error`.

## 3. Gotchas

### 3.1 Load errors do not affect the exit code
In `init_wslua.c`, syntax and runtime errors at load time go through `report_failure("Lua: syntax error: …")` / `report_failure("Lua: Error during loading:\n…")`, and loading then moves on to the next script. tshark wires `report_failure` to `failure_message` → `vcmdarg_err`, which only prints `tshark: …` to stderr ([ui/failure_message.c](https://github.com/wireshark/wireshark/blob/master/ui/failure_message.c), [wsutil/report_message.c](https://github.com/wireshark/wireshark/blob/master/wsutil/report_message.c)). So a broken Dissector gives exit 0 and packets that decode as plain UDP "data". **Tests must assert one of these:** stderr has no `Lua:` lines, the protocol shows up in `-G protocols`, or `-Y <proto>` matches the expected number of packets.

### 3.2 Root silently skips `-X lua_script` and personal plugins
In `wslua_init()`, global plugins load unconditionally. Personal plugins and every `-X lua_script` load only `if (!started_with_special_privs() || run_anyway)`. `run_anyway` is set only when a global `run_user_scripts_when_superuser = true` exists, i.e. it was set by an `init.lua` ([init_wslua.c](https://github.com/wireshark/wireshark/blob/master/epan/wslua/init_wslua.c)). On Linux, `started_with_special_privs()` is true when the real or effective uid/gid is 0 ([wsutil/privileges.c](https://github.com/wireshark/wireshark/blob/master/wsutil/privileges.c)). No message is printed when the scripts are skipped.
- GitHub-hosted runners run steps as the non-root `runner` user, so plain steps are fine. **Do not wrap tshark in `sudo`**, and watch out for `container:` jobs or Docker images that run as root. If tshark must run as root, either copy the Dissector into the global plugin dir or set `run_user_scripts_when_superuser = true` in the global `init.lua`.

### 3.3 Versions and Lua dialect on runners
- Runner labels ([actions/runner-images README](https://github.com/actions/runner-images/blob/main/README.md)): `ubuntu-latest` = **ubuntu-24.04**. `ubuntu-26.04` and `ubuntu-22.04` (plus `-arm` variants) are also available. The 24.04 image readme (image 20261101.360.1) does **not** list Wireshark or tshark ([Ubuntu2404-Readme](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md)), so CI has to `apt-get install` it.
- Stock Ubuntu packages ([Launchpad wireshark](https://launchpad.net/ubuntu/+source/wireshark)):

  | Runner | Stock tshark | Lua |
  |---|---|---|
  | ubuntu-22.04 | 3.6.2 | 5.2 (≤4.2 supports 5.1/5.2) |
  | ubuntu-24.04 (`ubuntu-latest`) | 4.2.2-1.1build3 (no newer version in updates/security per Launchpad) | 5.2 |
  | ubuntu-26.04 | 4.6.4-1 | 5.4 |

- The [Wireshark PPA `ppa:wireshark-dev/stable`](https://launchpad.net/~wireshark-dev/+archive/ubuntu/stable) ("Latest stable Wireshark releases back-ported from Debian package versions") currently has **4.6.9-1 for jammy, noble and resolute**. Upstream current stable is **4.6.9**, old-stable is **4.4.19**, and **5.0.0rc1** is in development ([download page](https://www.wireshark.org/download.html)).
- **Lua dialect break:** Wireshark 4.4 "added Lua 5.3 and 5.4 support, and removed Lua 5.1 and 5.2 support" ([4.4.0 release notes](https://www.wireshark.org/docs/relnotes/wireshark-4.4.0.html); [wsluarm](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html)). So stock tshark on ubuntu-24.04 runs the Dissector under Lua 5.2, while the PPA and ubuntu-26.04 run it under Lua 5.4. The current `src/template.rs` uses only basic API calls (`Proto`, `ProtoField`, `tree:add`, `DissectorTable.get(...):add`) and no `bit32`/`unpack`/`setfenv`, so it should be portable. Still, testing two tshark versions (e.g. stock 24.04 plus PPA, or 24.04 plus 26.04) is the cheapest way to catch dialect drift.

### 3.4 Installing non-interactively
`wireshark-common` asks the debconf question `wireshark-common/install-setuid` ("Should non-superusers be able to capture packets?", default false) ([Debian templates](https://salsa.debian.org/debian/wireshark/-/raw/debian/master/debian/templates)). Use `DEBIAN_FRONTEND=noninteractive`. We only read files and never capture, so the default is fine. `text2pcap` ships in `wireshark-common`, which `tshark` pulls in ([noble text2pcap(1)](https://manpages.ubuntu.com/manpages/noble/man1/text2pcap.1.html), "Provided by: wireshark-common").

### 3.5 Locale
[wireshark#20216](https://gitlab.com/wireshark/wireshark/-/issues/20216): in locales where the decimal separator is a comma, `DissectorTable:set("10,11")` fails with "Lua: Error during loading" (reproduced on 4.4.1). Pin `LC_ALL=C` (or `C.UTF-8`) in the test environment.

### 3.6 Output stability
`-T json`/`-V` include frame timestamps, frame numbers, the interface and all lower layers. Restrict output with `-J <proto>` / `-j`, or better, `-T fields -e …`, so the golden files depend only on the Dissector. Debug/info noise goes to stderr and can be controlled with `--log-level` / `WIRESHARK_LOG_LEVEL`. `WIRESHARK_CONFIG_DIR` can point personal config at a temp dir so the developer's own preferences or plugins don't leak into local runs ([tshark(1)](https://www.wireshark.org/docs/man-pages/tshark.html)).

## 4. Generating pcaps from raw bytes: text2pcap

From [text2pcap(1) 4.6.9](https://www.wireshark.org/docs/man-pages/text2pcap.html) and [noble 4.2.2](https://manpages.ubuntu.com/manpages/noble/man1/text2pcap.1.html):

- Input is an `od -Ax -tx1 -v`-style hexdump. Each line starts with an offset, followed by space-separated hex byte pairs. Each packet starts at offset 0, and text after the bytes is ignored. `-o none` gives single-packet mode with no offsets. `-o hex|oct|dec` sets the offset radix.
- `-u <srcport>,<dstport>` adds dummy Ethernet + IPv4 + UDP headers in front of the payload. `-T` does the same with TCP, `-s` with SCTP. `-4`/`-6 <src>,<dst>` set the IP addresses. `-e <ethertype>` adds only an Ethernet header. `-l <linktype>` sets the encapsulation.
- `-F pcap|pcapng`: the default output is **pcapng** in both 4.2.2 and 4.6.9. tshark reads either.
- This matches Wirdigen's model directly. A Protocol Description's `connection` (e.g. `udp`, ports `[60001, 60002]`) becomes `text2pcap -u 60001,60001`, and the payload bytes become the hexdump. A Rust test can build the hexdump string from a `Vec<u8>` (`format!("{:06x} {}", offset, bytes…)`), or write a pcap directly with no text2pcap at all. A classic pcap is a 24-byte global header plus a 16-byte record header per packet, and could use linktype 147 (`USER0`) with `-o uat:user_dlts:…`, or linktype 1 with hand-built Eth/IP/UDP headers. text2pcap is simpler.

## 5. Suggested test recipe (unverified; confirm in a CI spike)

```bash
# CI setup (ubuntu-24.04; add `sudo add-apt-repository -y ppa:wireshark-dev/stable` first for 4.6.x / Lua 5.4)
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark
tshark --version

# Per test (as the non-root runner user)
export LC_ALL=C WIRESHARK_CONFIG_DIR="$(mktemp -d)"
printf '000000 01 02 03 04 05 06 07 08\n' > payload.txt
text2pcap -q -u 60001,60001 payload.txt test.pcap      # -q: quiet

# 1. Dissector registered? (catches load errors that exit 0)
tshark -X lua_script:test.lua -G protocols 2>err.txt | grep -qw test
! grep -q '^tshark: Lua' err.txt

# 2. Decoded fields
tshark -X lua_script:test.lua -r test.pcap -Y test -T fields -e test.bool_NONE -e test.char_HEX
#   (or: -T json --no-duplicate-keys -J test   /   -T pdml)

# 3. No dissection-time Lua errors
test -z "$(tshark -X lua_script:test.lua -r test.pcap -Y _ws.lua.error)"
```

Field filter names follow the abbreviations the generator passes to `ProtoField` (check `src/generator.rs`). The names above are placeholders.

## Open points for the spike

- Confirm on a real runner that a load error gives exit code 0 (read from source, not observed).
- Measure apt install time for `tshark` on ubuntu-24.04 (and with the PPA) to decide whether to cache it.
- Decide which version(s) to support: stock 24.04 (4.2/Lua 5.2), PPA (4.6/Lua 5.4), or ubuntu-26.04 stock (4.6.4/Lua 5.4).
