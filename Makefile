CARGO_FLAGS := --locked --all-targets
export RUSTFLAGS := -D warnings
export RUSTDOCFLAGS := -D warnings

.PHONY: lint test test-lua test-tshark test-tshark-random book docker-test-lua docker-test-tshark \
	docker-test-tshark-4.4 docker-test-tshark-stable-24.04 docker-test-tshark-stable-26.04 \
	docker-test-tshark-random-4.4 \
	docker-test-tshark-random-stable-24.04 docker-bless-tshark \
	refresh-protocols docker-refresh-protocols refresh-stress profile profile-mem profiling-build

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

# Adds the protocols of the tshark on PATH, which must be the latest stable Wireshark, to
# src/builtin_protocols.tsv, the snapshot behind `protocol-name-taken` (spec §3.3, §10.9); a
# newer Wireshark than the snapshot's replaces it instead.
refresh-protocols:
	WIRDIGEN_TSHARK=1 WIRDIGEN_BLESS=1 cargo test -p wirdigen --locked --test tshark builtin_protocols::

# Rewrites the stress Descriptions of crates/wirdigen/tests/stress/ from tests/stress.rs; `make test`
# fails when they drift.
refresh-stress:
	WIRDIGEN_BLESS=1 cargo test -p wirdigen --locked --test stress

# What `make profile` and `make profile-mem` run: the real `wirdigen generate`, built with the
# `profiling` profile, over the stress Descriptions or DESC="<files>", writing into target/profile/.
DESC ?= $(wildcard crates/wirdigen/tests/stress/*.wirdigen.yaml)
PROFILE_DIR := target/profile
PROFILE_RUN := target/profiling/wirdigen generate --quiet --out-dir $(PROFILE_DIR) $(DESC)

profiling-build:
	cargo build -p wirdigen-cli --profile profiling --locked
	mkdir -p $(PROFILE_DIR)

# CPU profile with samply, opened in the Firefox Profiler; NO_OPEN=1 only saves it. Checks its
# prerequisites first and never installs anything.
profile:
	@command -v samply >/dev/null || { \
		echo "make profile needs samply on PATH. Install it with:"; \
		echo "  cargo install --locked samply"; exit 1; }
	@if [ -r /proc/sys/kernel/perf_event_paranoid ] && [ "$$(cat /proc/sys/kernel/perf_event_paranoid)" -gt 1 ]; then \
		echo "make profile needs kernel.perf_event_paranoid at 1 or less, it is $$(cat /proc/sys/kernel/perf_event_paranoid). Lower it until the next reboot with:"; \
		echo "  sudo sysctl kernel.perf_event_paranoid=1"; exit 1; fi
	@$(MAKE) --no-print-directory profiling-build
	@out=$(PROFILE_DIR)/cpu-$$(date +%Y%m%d-%H%M%S).json.gz && \
		samply record --save-only -o "$$out" -- $(PROFILE_RUN) && \
		if [ -n "$(NO_OPEN)" ]; then echo "Saved $$out. Open it with:"; echo "  samply load $$out"; \
		else samply load "$$out"; fi

# Allocation profile with heaptrack: a summary here, the full view in heaptrack_gui.
profile-mem:
	@command -v heaptrack >/dev/null && command -v heaptrack_print >/dev/null || { \
		echo "make profile-mem needs heaptrack and heaptrack_print on PATH. Install heaptrack with your"; \
		echo "package manager, for example:"; \
		echo "  sudo apt install heaptrack    # Debian, Ubuntu"; \
		echo "  sudo pacman -S heaptrack      # Arch"; \
		echo "  sudo dnf install heaptrack    # Fedora"; exit 1; }
	@$(MAKE) --no-print-directory profiling-build
	@out=$(PROFILE_DIR)/mem-$$(date +%Y%m%d-%H%M%S) && \
		{ heaptrack --record-only -o "$$out" $(PROFILE_RUN) >"$$out.log" 2>&1 || { cat "$$out.log"; exit 1; }; } && rm "$$out.log" && \
		heaptrack_print -f "$$out.zst" -m 0 -p 1 -a 1 -T 1 -n 5 2>/dev/null | awk -f scripts/heaptrack-summary.awk && \
		echo && echo "Saved $$out.zst. See every backtrace with:" && echo "  heaptrack_gui $$out.zst"

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

docker-test-lua: docker-image-tshark-stable-24.04
	$(call docker_run,tshark-stable-24.04,make test-lua)

docker-test-tshark: docker-test-tshark-4.4 docker-test-tshark-stable-24.04 docker-test-tshark-stable-26.04

# stable-26.04 is the latest stable again, from the same PPA on Ubuntu 26.04.
docker-test-tshark-4.4 docker-test-tshark-stable-24.04 docker-test-tshark-stable-26.04: docker-test-tshark-%: docker-image-tshark-%
	$(call docker_run,tshark-$*,tshark --version)
	$(call docker_run,tshark-$*,make test-tshark)

# The weekly random-description run in one image; the variables it reads are passed through.
docker-test-tshark-random-4.4 docker-test-tshark-random-stable-24.04: docker-test-tshark-random-%: docker-image-tshark-%
	$(call docker_run,tshark-$*,tshark --version)
	$(call docker_run,tshark-$*,make test-tshark-random)

# Rewrites the dissected.json goldens from the 4.4 floor, then checks the latest stable agrees,
# on Ubuntu 24.04 and 26.04.
docker-bless-tshark: docker-image-tshark-4.4 docker-image-tshark-stable-24.04 docker-image-tshark-stable-26.04
	$(call docker_run,tshark-4.4,env WIRDIGEN_BLESS=1 make test-tshark)
	$(call docker_run,tshark-stable-24.04,make test-tshark)
	$(call docker_run,tshark-stable-26.04,make test-tshark)

# Rewrites the built-in protocols snapshot from the latest stable, as the union of its builds on
# Ubuntu 24.04 and 26.04.
docker-refresh-protocols: docker-image-tshark-stable-24.04 docker-image-tshark-stable-26.04
	$(call docker_run,tshark-stable-24.04,tshark --version)
	$(call docker_run,tshark-stable-24.04,make refresh-protocols)
	$(call docker_run,tshark-stable-26.04,tshark --version)
	$(call docker_run,tshark-stable-26.04,make refresh-protocols)
