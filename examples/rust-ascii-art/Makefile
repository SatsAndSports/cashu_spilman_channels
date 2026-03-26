# Rust ASCII Art Server - Standalone Makefile
#
# For Rust developers using Spilman channels:
#   make build             - Build the server
#   make test              - Run unit tests (no mint required)
#   make test-integration  - Run integration tests (requires mint at MINT_URL)
#
# Running the server:
#   make run-server        - Start the server (requires mint at MINT_URL)

# Configuration
MINT_URL ?= http://localhost:3338
PORT ?= 5003

.PHONY: build build-debug test-integration run-server clean help

# Default target
help:
	@echo "Rust ASCII Art Server - Spilman Payment Channel Demo"
	@echo ""
	@echo "Usage:"
	@echo "  make build             Build the server (release)"
	@echo "  make build-debug       Build the server (debug)"
	@echo "  make test-integration  Run integration tests (requires mint at MINT_URL)"
	@echo "  make run-server        Start the server"
	@echo ""
	@echo "Environment variables:"
	@echo "  MINT_URL    Mint URL (default: $(MINT_URL))"
	@echo "  PORT        Server port (default: $(PORT))"

# ============================================================================
# Build
# ============================================================================

build:
	cargo build -p rust-ascii-art --release

build-debug:
	cargo build -p rust-ascii-art

# ============================================================================
# Tests
# ============================================================================

# Integration tests (requires mint running at MINT_URL)
test-integration:
	MINT_URL=$(MINT_URL) cargo test -p rust-ascii-art --test integration -- --nocapture

# ============================================================================
# Run
# ============================================================================

run-server: build-debug
	MINT_URL=$(MINT_URL) PORT=$(PORT) cargo run -p rust-ascii-art

# ============================================================================
# Clean
# ============================================================================

clean:
	cargo clean -p rust-ascii-art
