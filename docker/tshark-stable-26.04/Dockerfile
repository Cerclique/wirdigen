# The latest stable Wireshark on Ubuntu 26.04 (spec §10.5), where the `tshark-stable-26.04` CI
# job runs its tests: the same PPA as tshark-stable-24.04, built against the newer LTS's libraries.
# Built and run by `make docker-test-tshark-stable-26.04`; see docker/README.md.
FROM ubuntu:26.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        software-properties-common gpg-agent ca-certificates curl gcc libc6-dev make \
    && add-apt-repository -y ppa:wireshark-dev/stable \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*

# The toolchain of rust-toolchain.toml, readable by any user: the container runs as the
# calling user, never root, because tshark skips `-X lua_script` as root.
ENV RUSTUP_HOME=/opt/rustup PATH=/opt/cargo/bin:$PATH
COPY rust-toolchain.toml /opt/toolchain/
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | CARGO_HOME=/opt/cargo sh -s -- -y --profile minimal --default-toolchain none --no-modify-path \
    && cd /opt/toolchain && CARGO_HOME=/opt/cargo rustup toolchain install \
    && chmod -R a+rX /opt/rustup /opt/cargo
