CARGO_FLAGS := --locked --all-targets
export RUSTFLAGS := -D warnings
export RUSTDOCFLAGS := -D warnings

.PHONY: lint test test-lua test-tshark book docker-test-lua docker-test-tshark \
	docker-test-tshark-4.4 docker-test-tshark-stable docker-bless-tshark \
	refresh-protocols docker-refresh-protocols

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

# Rewrites src/builtin_protocols.tsv, the snapshot behind `protocol-name-taken`, from the tshark
# on PATH, which must be the latest stable Wireshark (spec §3.3, §10.9).
refresh-protocols:
	WIRDIGEN_TSHARK=1 WIRDIGEN_BLESS=1 cargo test -p wirdigen --locked --test tshark builtin_protocols::

# Needs mdbook 0.5.4 (the version CI uses). Snippets are checked by `make test`.
book:
	mdbook build book

# The Lua and tshark layers in the containers of docker/, for a machine without the tools.
# Needs Docker; see docker/README.md. Builds go to target/docker/<image>.
# DOCKER_PREBUILT=1 skips building the images and uses the wirdigen-<name> images already
# loaded; CI sets it after building them with a layer cache across runs.
docker-image-%:
	$(if $(DOCKER_PREBUILT),@echo "Using the prebuilt wirdigen-$* image",docker build -q -t wirdigen-$* -f docker/$*/Dockerfile .)

# Runs $(2) in image $(1) as the calling user, with the repository mounted at /work.
docker_run = mkdir -p target/docker/$(1) target/docker/cargo-home && \
	docker run --rm --user "$$(id -u):$$(id -g)" -v "$(CURDIR):/work" -w /work -e HOME=/tmp \
		-e CARGO_HOME=/work/target/docker/cargo-home -e CARGO_TARGET_DIR=/work/target/docker/$(1) \
		wirdigen-$(1) $(2)

docker-test-lua: docker-image-tshark-stable
	$(call docker_run,tshark-stable,make test-lua)

docker-test-tshark: docker-test-tshark-4.4 docker-test-tshark-stable

docker-test-tshark-4.4 docker-test-tshark-stable: docker-test-tshark-%: docker-image-tshark-%
	$(call docker_run,tshark-$*,tshark --version)
	$(call docker_run,tshark-$*,make test-tshark)

# Rewrites the dissected.json goldens from the 4.4 floor, then checks the latest stable agrees.
docker-bless-tshark: docker-image-tshark-4.4 docker-image-tshark-stable
	$(call docker_run,tshark-4.4,env WIRDIGEN_BLESS=1 make test-tshark)
	$(call docker_run,tshark-stable,make test-tshark)

# Rewrites the built-in protocols snapshot from the tshark-stable image.
docker-refresh-protocols: docker-image-tshark-stable
	$(call docker_run,tshark-stable,tshark --version)
	$(call docker_run,tshark-stable,make refresh-protocols)
