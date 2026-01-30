.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z0-9_\-]+:.*##/ {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build debug binary
	cargo build

.PHONY: release
release: ## Build release binary
	cargo build --release

.PHONY: run
run: ## Run the CLI (defaults to --help)
	cargo run -- --help

.PHONY: test
test: ## Run tests
	cargo test

.PHONY: fmt
fmt: ## Format code (rustfmt)
	cargo fmt

.PHONY: fmt-check
fmt-check: ## Check formatting (rustfmt)
	cargo fmt -- --check

.PHONY: clippy
clippy: ## Lint (clippy)
	cargo clippy --all-targets --all-features -- -D warnings

.PHONY: check
check: fmt-check clippy test ## Run fmt-check + clippy + tests

.PHONY: clean
clean: ## Clean build artifacts
	cargo clean

.PHONY: doc
doc: ## Build docs
	cargo doc --no-deps

.PHONY: audit
audit: ## Run cargo-audit if installed
	@command -v cargo-audit >/dev/null 2>&1 && cargo audit || (echo "cargo-audit not installed" && exit 1)
