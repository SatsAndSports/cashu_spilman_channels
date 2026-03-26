# Spilman Go Bindings Makefile
#
# For Go developers using this package:
#   make test              - Run unit tests (uses packaged static libs)
#   make test-integration  - Run integration tests (requires mint at MINT_URL)
#
# For CDK contributors building from Rust source:
#   make build-lib         - Build Rust library (requires cargo)
#   make test-dev          - Run unit tests with local debug build

# Configuration
MINT_URL ?= http://localhost:3338
SERVER_URL ?= http://localhost:5001

# Project root
PROJECT_ROOT ?= ../..

# Directories (relative to this Makefile)
SPILMAN_PKG := ./spilman
EXAMPLE_DIR := $(PROJECT_ROOT)/examples/go-ascii-art

# Project target dir
PROJECT_TARGET := ../../target

.PHONY: test test-dev test-integration test-integration-dev \
        build-lib build-lib-release \
        build-example run-server run-client clean help

# Default target
help:
	@echo "Spilman Go Bindings"
	@echo ""
	@echo "Usage:"
	@echo "  make test              Run unit tests (no mint required)"
	@echo "  make test-integration  Run integration tests (requires mint at MINT_URL)"
	@echo ""
	@echo "Development (requires Rust/Cargo):"
	@echo "  make build-lib         Build Rust library (debug)"
	@echo "  make test-dev          Run unit tests with local debug build"
	@echo ""
	@echo "Example server:"
	@echo "  make build-example     Build the ascii-art example"
	@echo "  make run-server        Run example server (requires mint)"
	@echo "  make run-client        Run example client"
	@echo ""
	@echo "Environment variables:"
	@echo "  MINT_URL       Mint URL (default: $(MINT_URL))"
	@echo "  SERVER_URL     Server URL for client (default: $(SERVER_URL))"
	@echo "  PROJECT_ROOT   Project root (default: $(PROJECT_ROOT))"

# ============================================================================
# Unit Tests (uses packaged static libs)
# ============================================================================

test:
	cd $(SPILMAN_PKG) && go test -v ./...

# ============================================================================
# Integration Tests (requires mint running at MINT_URL)
# ============================================================================

test-integration:
	cd $(SPILMAN_PKG) && MINT_URL=$(MINT_URL) go test -v -tags integration -count=1 ./...

# ============================================================================
# Development (for CDK contributors)
# ============================================================================

# Build the Rust library (debug) using the project workspace manifest
build-lib:
	cargo build -p cdk-spilman-go --manifest-path ../../Cargo.toml

# Build the Rust library (release, stripped)
build-lib-release:
	cargo build -p cdk-spilman-go --manifest-path ../../Cargo.toml --release
	strip $(PROJECT_TARGET)/release/libcdk_spilman_go.so 2>/dev/null || \
	strip $(PROJECT_TARGET)/release/libcdk_spilman_go.dylib 2>/dev/null || true

# Run unit tests with local debug build (for development)
test-dev: build-lib
	cd $(SPILMAN_PKG) && LD_LIBRARY_PATH=$(abspath $(PROJECT_TARGET)/debug) go test -v -tags spilman_dev ./...

# Run integration tests with local debug build
test-integration-dev: build-lib
	cd $(SPILMAN_PKG) && LD_LIBRARY_PATH=$(abspath $(PROJECT_TARGET)/debug) MINT_URL=$(MINT_URL) \
		go test -v -tags 'spilman_dev integration' -count=1 ./...

# ============================================================================
# Example
# ============================================================================

build-example:
	cd $(EXAMPLE_DIR) && go build -o ascii-art .

run-server: build-example
	cd $(EXAMPLE_DIR) && MINT_URL=$(MINT_URL) ./ascii-art

run-client:
	cd $(EXAMPLE_DIR) && SERVER_URL=$(SERVER_URL) ./ascii-art client Hello World

# ============================================================================
# Clean
# ============================================================================

clean:
	cd $(SPILMAN_PKG) && go clean -testcache
	rm -f $(EXAMPLE_DIR)/ascii-art
