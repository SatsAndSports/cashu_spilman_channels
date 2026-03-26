# Spilman Channels Development Guide

This guide covers setting up the development environment for Spilman payment channels.

## Quick Start

From the repository root:

```bash
# Run the Spilman test suite
make test-suite
```

## Native Development (Recommended for Pi)

For environments like **Raspiblitz/Raspberry Pi** where containerization is restricted, we recommend a native Rust installation.

### User-Only Rust Installation

If your system has a locked-down system-wide Rust (like `/opt/rust` on Raspiblitz), you can install a private copy for your user:

```bash
# Set install locations to your home directory
export RUSTUP_HOME="$HOME/.rustup"
export CARGO_HOME="$HOME/.cargo"

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Add to your PATH
source "$HOME/.cargo/env"
```

Then run tests as usual:
```bash
make test-rust-only
```

## Container Builds

For reproducible builds without installing Rust locally (works with both `podman` and `docker`):

```bash
# Run Rust-only tests in a container (uses podman by default)
make container-test

# Use docker instead of podman
make container-test CONTAINER_CMD=docker

# Interactive shell for debugging
podman run --rm -it spilman-test-rust bash
```

The container build uses `git archive` to ensure layer caching is based on git state rather than filesystem timestamps, and excludes untracked files. Uncommitted changes are included in the build.

## Running a Mint

The demos and tests require a Cashu mint. Choose one of:

### Standalone Test Mint (Recommended)

The easiest option with the standalone fakewallet+sqlite test mint:

```bash
# Build the standalone mint
cargo build -p cdk-spilman-test-mint --manifest-path Cargo.toml

# Start the mint on the default test port
./target/debug/cdk-spilman-test-mintd --listen-port 3338 --base-url http://127.0.0.1:3338
```

When it is ready, it prints a one-line summary like:

```text
MINT_READY source=spawned url=http://127.0.0.1:3338 name="Spilman Test Mint" version="cdk-spilman-test-mintd/0.15.1" units=[sat,msat,usd]
```

The standalone mint uses a fixed mnemonic for reproducible keyset IDs:
- **sat keyset:** `01e5ccf902614063af576888a30d8c93220bf663f4de8b43edcdd1ced8a45c2f65`
- **msat keyset:** `01f4bb1e9a93272802cbecb0e4609ea6b9ac080faa4d483fcf0c0ed36c60793677`
- **usd keyset:** `01e96c7f95d941041f444a99b69f8030b5a9d1f6c6591eb0df388366a065df37c5`

For test commands that should auto-spawn a mint, prefer `scripts/run_with_mint.sh`.

### Testing Against an External Mint

By default, all test targets auto-spawn the standalone test mint. To test
against a different mint implementation (e.g. NutMix, Nutshell, or a remote
mint), start it yourself and set `MINT_URL`:

```bash
# Run integration and demo tests against your external mint
MINT_URL=http://localhost:3338 make test-integration-all test-demo-all
```

**Important:** The server integration tests (`test-server-*`) always spawn
their own standalone test mint internally because the Rust harness controls
the mint lifecycle. `MINT_URL` is respected by the integration and demo
targets that go through `scripts/run_with_mint.sh`.

---

## Building WASM

The WASM bindings are used by both browser clients and Node.js servers. The root Makefile uses sentinel-based dependency tracking for fast builds.

```bash
# Build and test the workspace
make test-suite
make test-all
```

### Fast Development Builds

For faster iteration during development, use `WASM_DEV=1` to skip `wasm-opt`:

```bash
# Fast dev build (~2.5s incremental vs ~40s with wasm-opt)
WASM_DEV=1 make build-wasm

# Explicit release build (default, includes wasm-opt)
make build-wasm
```

Test targets automatically use dev mode for speed:
```bash
make test-integration-ts  # Uses WASM_DEV=1 internally
make test-demo-ts         # Uses WASM_DEV=1 internally
```

---

## Running Tests

### Rust Tests

```bash
# Rust-side suite
make test-suite

# All tests (includes live mint integration)
make test-all
```

### Server Integration Tests (Rust)

The `cdk-spilman-server-integration-tests` crate validates all four server implementations (TypeScript, Rust, Python, Go).

```bash
# Test individual servers
make test-server-ts
make test-server-rust
make test-server-python
make test-server-go

# Test all servers sequentially
make test-server-all
```

### NUT-00 Error Handling Tests

Tests for selective retry behavior based on NUT-00 error codes:

```bash
# Run selective retry tests (no external mint needed)
make test-selective-retry

# Run all retry-related tests
cargo test -p cdk-spilman-interop-tests retry -- --nocapture

# NUT-00 compliance test against real mint (requires mint)
make test-nut00-errors
```

These tests verify that:
- Keyset errors (12xxx) trigger retry after keysets refresh
- Token-spent errors (11001) fail immediately without retry
- Unparseable errors fail immediately without retry

---

## Directory Structure

```
repo/
├── crates/
│   ├── cdk-spilman/                          # Core Rust implementation
│   ├── cdk-spilman-test-mint/                # Standalone fakewallet+sqlite test mint
│   ├── cdk-spilman-server-integration-tests/ # Test client for all servers
│   ├── cdk-wasm/                             # WASM bindings (JS/TS)
│   ├── cdk-spilman-python/                   # Python bindings
│   └── cdk-spilman-go/                       # Go bindings
├── integration-kits/
│   ├── ts/                                   # TypeScript kit (Express)
│   ├── python/                               # Python integration kit
│   └── go/                                   # Go integration kit
├── examples/
│   ├── rust-ascii-art/                       # Rust server (native)
│   ├── ts-ascii-art/                         # TypeScript server + client
│   ├── python-ascii-art/                     # Python server + client
│   └── go-ascii-art/                         # Go server + client
├── web/
│   └── wasm-nodejs/               # Node.js WASM output
```

## Troubleshooting

### Orphaned Test Processes

If tests are interrupted, server and mint processes may be left running:
```bash
make kill-orphans
```

### HTTP 431 / Request Header Fields Too Large

Usually caused by high-capacity `msat` channels with many small proofs.
**Workaround**: Use a larger `maximum_amount` (e.g., 8192) when funding to reduce the proof count.
