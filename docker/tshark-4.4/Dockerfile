# The Wireshark 4.4 floor (spec §10.5), as in the `tshark-4.4` CI job.
# Built and run by `make docker-test-tshark`; see docker/README.md.
FROM debian:trixie

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        tshark ca-certificates curl gcc libc6-dev make \
    && rm -rf /var/lib/apt/lists/*

# The toolchain of rust-toolchain.toml, readable by any user: the container runs as the
# calling user, never root, because tshark skips `-X lua_script` as root.
ENV RUSTUP_HOME=/opt/rustup PATH=/opt/cargo/bin:$PATH
COPY rust-toolchain.toml /opt/toolchain/
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | CARGO_HOME=/opt/cargo sh -s -- -y --profile minimal --default-toolchain none --no-modify-path \
    && cd /opt/toolchain && CARGO_HOME=/opt/cargo rustup toolchain install \
    && chmod -R a+rX /opt/rustup /opt/cargo
