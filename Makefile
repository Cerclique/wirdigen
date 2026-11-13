CARGO_FLAGS := --locked --all-targets
export RUSTFLAGS := -D warnings
export RUSTDOCFLAGS := -D warnings

.PHONY: lint test test-lua test-tshark test-tshark-random book docker-test-lua docker-test-tshark \
	docker-test-tshark-4.4 docker-test-tshark-stable docker-test-tshark-stable-26.04 \
	docker-test-tshark-random-4.4 \
	docker-test-tshark-random-stable docker-bless-tshark \
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
# The bad-input tests (spec §10.6) use a fixed seed; WIRDIGEN_BAD_SEED (a number or `random`),
# WIRDIGEN_BAD_MUTATIONS and WIRDIGEN_BAD_RANDOM override it and their counts.
test-tshark:
	WIRDIGEN_TSHARK=1 cargo test -p wirdigen --locked --test tshark

# Random descriptions x random and truncated packets (spec §10.7), for the weekly run: it takes
# PROPTEST_CASES descriptions, PROPTEST_RNG_SEED fixes the run and WIRDIGEN_RANDOM_PACKETS sets
# the packets per description. Needs the same tools as test-tshark.
test-tshark-random:
	WIRDIGEN_TSHARK=1 cargo test -p wirdigen --locked --lib tshark_random::

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
		-e CARGO_HOME=/work/target/docker/cargo-home \
		-e PROPTEST_CASES -e PROPTEST_RNG_SEED -e WIRDIGEN_RANDOM_PACKETS \
		-e WIRDIGEN_BAD_SEED -e WIRDIGEN_BAD_MUTATIONS -e WIRDIGEN_BAD_RANDOM \
		-e CARGO_TARGET_DIR=/work/target/docker/$(1) \
		wirdigen-$(1) $(2)

docker-test-lua: docker-image-tshark-stable
	$(call docker_run,tshark-stable,make test-lua)

docker-test-tshark: docker-test-tshark-4.4 docker-test-tshark-stable docker-test-tshark-stable-26.04

# stable-26.04 is the latest stable again, from the same PPA on Ubuntu 26.04.
docker-test-tshark-4.4 docker-test-tshark-stable docker-test-tshark-stable-26.04: docker-test-tshark-%: docker-image-tshark-%
	$(call docker_run,tshark-$*,tshark --version)
	$(call docker_run,tshark-$*,make test-tshark)

# The weekly random-description run in one image; the variables it reads are passed through.
docker-test-tshark-random-4.4 docker-test-tshark-random-stable: docker-test-tshark-random-%: docker-image-tshark-%
	$(call docker_run,tshark-$*,tshark --version)
	$(call docker_run,tshark-$*,make test-tshark-random)

# Rewrites the dissected.json goldens from the 4.4 floor, then checks the latest stable agrees,
# on Ubuntu 24.04 and 26.04.
docker-bless-tshark: docker-image-tshark-4.4 docker-image-tshark-stable docker-image-tshark-stable-26.04
	$(call docker_run,tshark-4.4,env WIRDIGEN_BLESS=1 make test-tshark)
	$(call docker_run,tshark-stable,make test-tshark)
	$(call docker_run,tshark-stable-26.04,make test-tshark)

# Rewrites the built-in protocols snapshot from the tshark-stable image.
docker-refresh-protocols: docker-image-tshark-stable
	$(call docker_run,tshark-stable,tshark --version)
	$(call docker_run,tshark-stable,make refresh-protocols)
