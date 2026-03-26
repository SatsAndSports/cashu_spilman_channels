# CDK WASM Bindings Makefile
#
# For TypeScript/JavaScript developers using this package:
#   make build             - Build WASM using wasm-pack
#   make test-integration  - Run integration tests (requires mint at MINT_URL)
#
# Example server:
#   make run-server        - Start the ASCII art server
#   make run-client        - Run the client

# Configuration
MINT_URL ?= http://localhost:3338
PORT ?= 5001

# Project root
PROJECT_ROOT ?= ../..

# Directories
EXAMPLE_DIR := $(PROJECT_ROOT)/examples/ts-ascii-art
KIT_DIR := $(PROJECT_ROOT)/integration-kits/ts
WASM_OUT_DIR := $(KIT_DIR)/wasm

# WASM build mode: set WASM_DEV=1 for fast dev builds (skips wasm-opt)
WASM_DEV ?= 0
ifeq ($(WASM_DEV),1)
  WASM_PROFILE := --dev
else
  WASM_PROFILE := --release
endif

.PHONY: build build-wasm install test-integration run-server run-client clean help

# Default target
help:
	@echo "CDK WASM Bindings"
	@echo ""
	@echo "Usage:"
	@echo "  make build             Build WASM (requires Rust + wasm-pack)"
	@echo "  make install           Install example dependencies"
	@echo "  make test-integration  Run integration tests (requires mint at MINT_URL)"
	@echo "  make run-server        Start the ASCII art example server"
	@echo "  make run-client        Run the example client"
	@echo ""
	@echo "Environment variables:"
	@echo "  MINT_URL       Mint URL (default: $(MINT_URL))"
	@echo "  PORT           Server port (default: $(PORT))"
	@echo "  PROJECT_ROOT   Project root (default: $(PROJECT_ROOT))"

# ============================================================================
# Build
# ============================================================================

# Build WASM for Node.js into the TS integration kit's wasm/ directory.
# Always invoke wasm-pack so Cargo can decide incrementally whether anything
# actually needs rebuilding. This avoids stale generated JS/WASM when source
# files changed but old artifacts still exist.
build: build-wasm

build-wasm:
	@if ! command -v wasm-pack >/dev/null 2>&1; then \
		echo "wasm-pack is required to build WASM bindings but was not found in PATH."; \
		echo "Please install wasm-pack and re-run:"; \
		echo "  cargo install wasm-pack"; \
		exit 1; \
	fi
	@echo "Building WASM for Node.js ($(if $(filter 1,$(WASM_DEV)),dev,release) mode)..."
	wasm-pack build $(WASM_PROFILE) --target nodejs --out-dir $(WASM_OUT_DIR)
	@echo "WASM build complete (output: $(WASM_OUT_DIR))"

rebuild-wasm:
	@echo "Rebuilding WASM for Node.js ($(if $(filter 1,$(WASM_DEV)),dev,release) mode)..."
	wasm-pack build $(WASM_PROFILE) --target nodejs --out-dir $(WASM_OUT_DIR)
	@echo "WASM build complete (output: $(WASM_OUT_DIR))"

# Build TS kit (compile TypeScript to dist/) and install example dependencies
install: build-wasm
	cd $(KIT_DIR) && npm install --no-package-lock --no-fund --no-audit
	@echo "Building TS kit (incremental when unchanged)..."
	cd $(KIT_DIR) && npm run build
	cd $(KIT_DIR) && npm link
	rm -rf $(EXAMPLE_DIR)/node_modules/cdk-spilman-kit
	cd $(EXAMPLE_DIR) && npm install --no-package-lock --no-fund --no-audit && npm link cdk-spilman-kit

# ============================================================================
# Tests
# ============================================================================

# Integration tests (requires mint running at MINT_URL)
test-integration: install
	cd $(EXAMPLE_DIR) && MINT_URL=$(MINT_URL) npm test

# ============================================================================
# Example
# ============================================================================

run-server: install
	cd $(EXAMPLE_DIR) && MINT_URL=$(MINT_URL) PORT=$(PORT) npm run server

run-client: install
	cd $(EXAMPLE_DIR) && MINT_URL=$(MINT_URL) SERVER_URL=http://localhost:$(PORT) npm run client -- "Hello TypeScript"

# ============================================================================
# Clean
# ============================================================================

clean:
	rm -rf $(EXAMPLE_DIR)/node_modules
	rm -rf $(WASM_OUT_DIR)/*.js $(WASM_OUT_DIR)/*.wasm $(WASM_OUT_DIR)/*.d.ts
