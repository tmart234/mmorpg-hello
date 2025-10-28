# Makefile at repo root (Windows-friendly)

.PHONY: clean-lock-build
clean-lock-build:
	@echo Cleaning target/ and Cargo.lock...
	cargo clean
	-@cmd /C del /F /Q Cargo.lock 2>nul
	cargo fmt --all
	cargo build --workspace --all-targets

.PHONY: check
check:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings

# Run tests AND then run the smoke test (VS <-> gs-sim happy path)
.PHONY: test-stage
test-stage:
	@echo Running cargo test...
	cargo test --workspace --all-targets
	@echo Running smoke test \(\`vs\` + \`gs-sim --test-once\`\)...
	cargo run -p tools --bin smoke

# One-shot "does matchmaking loop work" helper if you want to just try it
.PHONY: sim-positive
sim-positive:
	cargo run -p tools --bin gen_keys
	cargo run -p tools --bin smoke

# CI-lite: build from clean, lint, run tests, run smoke
.PHONY: ci
ci: clean-lock-build check test-stage
	@echo CI-lite completed ✅
