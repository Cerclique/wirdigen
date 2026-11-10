# Test containers

Two test layers need tools a workstation often lacks: the Lua checks need `lua5.2`, `lua5.3`
and `lua5.4` (spec §10.4), and the tshark corpus needs Wireshark 4.4 and the latest stable
(spec §10.5). These images give both, matching the CI jobs:

| Image | Base | Has | CI jobs |
|---|---|---|---|
| `tshark-4.4` | `debian:trixie` | tshark 4.4 | `tshark-4.4` |
| `tshark-stable` | `ubuntu:24.04` | tshark from `ppa:wireshark-dev/stable`, Lua 5.2, 5.3, 5.4 | `tshark-stable`, `lua` |

Each image also has the Rust toolchain pinned by `rust-toolchain.toml`.

## Use

With Docker installed and running:

```sh
make docker-test-lua       # make test-lua in tshark-stable
make docker-test-tshark    # make test-tshark in tshark-4.4, then in tshark-stable
make docker-bless-tshark   # rewrite dissected.json in tshark-4.4, then check tshark-stable agrees
```

Each target builds the images it needs first; an unchanged image builds from Docker's cache
in a second. The repository is mounted at `/work`, so goldens are written to your checkout.
Builds and downloaded crates go to `target/docker/`.

## Notes

- The containers run as the calling user, because tshark skips `-X lua_script` as root.
  Run the targets as a normal user, not with `sudo`.
- The images follow the moving tags `debian:trixie`, `ubuntu:24.04` and the stable PPA, as CI
  does. After a Wireshark release, rebuild the stable image to pick it up:
  `docker build --no-cache -t wirdigen-tshark-stable -f docker/tshark-stable/Dockerfile .`
- When the CI jobs' setup changes, change these Dockerfiles with them.
