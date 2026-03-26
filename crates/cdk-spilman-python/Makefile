# CDK Spilman Python Bindings Makefile
#
# For Python developers using this package:
#   make build             - Build and install using maturin
#   make test-integration  - Run integration tests (requires mint at MINT_URL)
#
# Example server:
#   make run-server        - Start the ASCII art server
#   make run-client        - Run the client

# Configuration
MINT_URL ?= http://localhost:3338
PORT ?= 5002

# Project root
PROJECT_ROOT ?= ../..

# Directories
EXAMPLE_DIR := $(PROJECT_ROOT)/examples/python-ascii-art
INTEGRATION_KIT_DIR := $(PROJECT_ROOT)/integration-kits/python
VENV_DIR := .venv
PYTHON := $(VENV_DIR)/bin/python
PIP := $(VENV_DIR)/bin/pip

.PHONY: check-venv build sync-env venv test-integration run-server run-client clean help

# Default target
help:
	@echo "CDK Spilman Python Bindings"
	@echo ""
	@echo "Usage:"
	@echo "  make build             Build and install using maturin"
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

# Create virtual environment (auto-recreates if stale from a different path/container)
check-venv:
	@if [ -d "$(VENV_DIR)" ]; then \
		expected=$$(cd "$(VENV_DIR)" && pwd); \
		actual=$$(. $(VENV_DIR)/bin/activate 2>/dev/null && echo "$$VIRTUAL_ENV"); \
		if [ "$$actual" = "$$expected" ]; then \
			echo "Found existing Python .venv"; \
		else \
			echo "Stale Python .venv detected (expected $$expected, got $$actual), removing..."; \
			rm -rf $(VENV_DIR); \
		fi; \
	fi
	@if [ ! -d "$(VENV_DIR)" ]; then \
		echo "(Re-)building Python .venv..."; \
		python3 -m venv $(VENV_DIR); \
		$(PIP) install --upgrade pip; \
		$(PIP) install maturin patchelf pytest requests; \
		$(PIP) install -r $(EXAMPLE_DIR)/requirements.txt; \
		$(PIP) install -e $(INTEGRATION_KIT_DIR); \
	fi

venv: check-venv

# Refresh editable installs for local Python sources.
sync-env: venv
	$(PIP) install -e $(INTEGRATION_KIT_DIR)

# Build and install the package into the local venv
build: sync-env
	. $(VENV_DIR)/bin/activate && maturin develop

# ============================================================================
# Tests
# ============================================================================

# Unit tests (no mint required)
test-unit: build
	$(PYTHON) -m pytest tests/keysets_cache_test.py -v

# Integration tests (requires mint running at MINT_URL)
test-integration: build
	MINT_URL=$(MINT_URL) $(PYTHON) -m pytest tests/ -v

# ============================================================================
# Example
# ============================================================================

run-server: build
	MINT_URL=$(MINT_URL) PORT=$(PORT) $(PYTHON) $(EXAMPLE_DIR)/server.py

run-client: build
	MINT_URL=$(MINT_URL) SERVER_URL=http://localhost:$(PORT) $(PYTHON) $(EXAMPLE_DIR)/client.py "Hello Python"

# ============================================================================
# Clean
# ============================================================================

clean:
	rm -rf $(VENV_DIR)
	rm -rf target/
	rm -rf *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
