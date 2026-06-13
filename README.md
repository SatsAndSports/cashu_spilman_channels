# Spilman Channels for Cashu

> Unidirectional payment channels for Cashu ecash — enabling instant, off-chain micropayments.

This repository contains the reference implementation of Spilman-style payment channels for the [Cashu](https://cashu.space) protocol. It enables services to accept streaming micropayments without round-trip latency or on-chain settlement for every request.

The primary Rust implementation lives in the `cdk-spilman` crate in this workspace.
Active demos, test harnesses, and the local test mint now live directly at repo root.

**Status: Early Alpha**
Experimental protocol. APIs and data models are subject to breaking changes.

## Key Features

- **Efficiency**: Unlimited micropayments via a single funding transaction.
- **Privacy**: Uses P2BK (Pay-to-Blinded-Key) to prevent mint correlation.
- **Portability**: Core protocol in Rust with bindings for WASM (JS/TS), Python, and Go.
- **Deterministic**: Both parties independently compute commitment outputs using a common `_channel secret_`.

---

## Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Cryptographic protocol and system design |
| [INTEGRATION.md](INTEGRATION.md) | Server and Client integration guide |
| [SPILMAN_DEVELOPMENT.md](SPILMAN_DEVELOPMENT.md) | Contributor guide and environment setup |

---

## Quick Start (Rust)

1. **Add Dependency**:
   ```toml
   cdk-spilman = { version = "0.16.0-rc.1", default-features = false, features = ["spilman-axum", "configurable-host-reqwest"] }
   ```

2. **Run ASCII Art Server**:
   ```bash
   cd examples/rust-ascii-art
   cargo run
   ```

3. **Run TypeScript Demo**:
   ```bash
   cd examples/ts-ascii-art
   npm install && npm start
   ```

## Project Structure

```
repo/
├── crates/
│   ├── cdk-spilman/                # Canonical core Rust protocol implementation
│   ├── cdk-spilman-test-mint/      # Standalone local test mint
│   ├── cdk-wasm/                   # WASM bindings
│   ├── cdk-spilman-python/         # Python bindings (PyO3)
│   ├── cdk-spilman-go/             # Go bindings (CGO)
│   └── cdk-spilman-server-integration-tests/ # Multi-server test client
├── integration-kits/
│   ├── ts/                         # TypeScript/Express integration kit
│   ├── python/                     # Python integration kit
│   └── go/                         # Go integration kit
├── examples/
│   ├── rust-ascii-art/             # Rust demo (native)
│   ├── ts-ascii-art/               # TypeScript demo
│   ├── python-ascii-art/           # Python demo
│   └── go-ascii-art/               # Go demo
```

## License

Code is licensed under MIT.
