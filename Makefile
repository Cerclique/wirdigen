CARGO_FLAGS := --locked --all-targets
export RUSTFLAGS := -D warnings
export RUSTDOCFLAGS := -D warnings

.PHONY: lint test test-lua test-tshark book

lint:
	cargo fmt --all --check
	cargo clippy --workspace $(CARGO_FLAGS) -- -D warnings
	cargo doc --workspace --no-deps --locked

test:
	cargo build --workspace $(CARGO_FLAGS)
	cargo test --workspace $(CARGO_FLAGS)

# Needs lua5.2, lua5.3 and lua5.4 on PATH (spec §10.4); fails when one is missing.
test-lua:
	WIRDIGEN_LUA=1 cargo test -p wirdigen --locked --lib lua_check::

# Needs tshark and text2pcap (Wireshark >= 4.4) on PATH, run as a non-root user since tshark
# skips -X lua_script as root (spec §10.5); fails when one is missing.
test-tshark:
	WIRDIGEN_TSHARK=1 cargo test -p wirdigen --locked --test tshark

# Needs mdbook 0.5.4 (the version CI uses). Snippets are checked by `make test`.
book:
	mdbook build book
