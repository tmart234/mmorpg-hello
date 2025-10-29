# Makefile at repo root

# Detect Windows vs Unix-y environments for clean steps
ifeq ($(OS),Windows_NT)
	CLEAN_CMD = cargo clean && cmd /C del /F /Q Cargo.lock 2>nul || true
else
	CLEAN_CMD = cargo clean && rm -f Cargo.lock || true
endif

.PHONY: clean-lock-build
clean-lock-build:
	@echo "Cleaning target/ and Cargo.lock (DEV-ONLY destructive clean)..."
	$(CLEAN_CMD)
	cargo fmt --all
	cargo build --workspace --all-targets

.PHONY: clean-build
clean-build:
	@echo "Cleaning target/ (non-destructive: keeps Cargo.lock)..."
	cargo clean
	cargo fmt --all
	cargo build --workspace --all-targets

.PHONY: check
check:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings

# Run tests AND the smoke test (VS <-> gs-sim <-> client-sim happy path)
.PHONY: test-stage
test-stage:
	@echo "Running cargo test..."
	cargo test --workspace --all-targets
	@echo "Running smoke test (\`vs\` + \`gs-sim --test-once\` + \`client-sim --smoke-test\`)..."
	cargo run -p tools --bin gen_keys
	cargo run -p tools --bin smoke

# Quick local sanity (gen keys + run smoke only)
.PHONY: sim-positive
sim-positive:
	cargo run -p tools --bin gen_keys
	cargo run -p tools --bin smoke

# CI-lite: lint, build, test, smoke
# This is what GitHub Actions should run.
.PHONY: ci
ci:
	@echo "Lint (fmt + clippy)..."
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	@echo "Build all targets..."
	cargo build --workspace --all-targets
	@echo "Run tests + smoke..."
	$(MAKE) test-stage
	@echo "CI-lite completed ✅"
