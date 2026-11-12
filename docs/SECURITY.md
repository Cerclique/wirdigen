# Security policy

## Reporting a vulnerability

Please do not report a vulnerability in a public issue. Report it privately through GitHub instead:
on the repository's **Security** tab, choose
[**Report a vulnerability**](https://github.com/Cerclique/wirdigen/security/advisories/new).

Include what you can of:

- the Wirdigen version (`wirdigen --version`), and the Wireshark version if a Dissector is
  involved;
- the Protocol Description and, for a Dissector issue, a capture or the packet bytes that
  trigger it;
- what happens and what an attacker gains.

The report stays private between you and the maintainers. The fix is developed in a private
advisory and released, then the advisory is published. It credits you unless you ask otherwise.

## Scope

Wirdigen generates Lua Dissectors that Wireshark runs on captured traffic, which an attacker
may control. A vulnerability includes:

- a generated Dissector that lets crafted packets run code, read or write files, or do anything
  beyond adding items to the protocol tree;
- a Protocol Description that makes Wirdigen generate Lua it does not describe, for example by
  escaping a string into code;
- the `wirdigen` command reading or writing files other than its inputs and outputs.

A Dissector that raises a Lua error on a packet, or a Protocol Description that makes Wirdigen
panic, is a bug. Report it in an ordinary issue.

## Supported versions

Fixes go into the latest release only.
