CARGO_FLAGS := --locked --all-targets
export RUSTFLAGS := -D warnings
export RUSTDOCFLAGS := -D warnings

.PHONY: lint test test-lua

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
