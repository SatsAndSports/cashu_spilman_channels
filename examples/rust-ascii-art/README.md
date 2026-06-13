# Rust ASCII Art Server

A demo server implementing Spilman payment channels in Rust using Axum.

This example demonstrates how to build a Spilman channel server using the `cdk-spilman` crate directly.

## Features

- Pay-per-character ASCII art generation
- Spilman payment channels (unidirectional, sender-to-receiver)
- Cooperative and unilateral channel closing
- Multi-unit support (sat, msat, usd)

## Usage

### Using the Makefile

```bash
# Show available commands
make help

# Build the server
make build

# Run the server (requires mint at localhost:3338)
make run-server

# Run with custom mint URL
MINT_URL=http://my-mint:3338 make run-server
```

### Manual Commands

```bash
# Build
cargo build -p rust-ascii-art --release

# Run
MINT_URL=http://localhost:3338 PORT=5003 cargo run -p rust-ascii-art
```

## Testing

Integration tests require a Cashu mint running:

```bash
# Start the standalone test mint (from repo root)
cargo run -p cdk-spilman-test-mint --manifest-path Cargo.toml -- --listen-port 3338 --base-url http://127.0.0.1:3338

# In another terminal, run integration tests
make test-integration

# Or with custom mint URL
MINT_URL=http://my-mint:3338 make test-integration
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/channel/params` | GET | Get server pubkey and pricing info |
| `/channel/register` | POST | Pre-register a channel (balance=0) |
| `/ascii` | POST | Generate ASCII art (requires `X-Cashu-Channel` header) |
| `/ascii/preflight` | POST | Preflight payment check (no side effects) |
| `/channel/:id/status` | GET | Get channel status and amount due |
| `/channel/:id/close` | POST | Close channel cooperatively |
| `/channel/:id/unilateral-close` | POST | Server-initiated close |

## Minimal Dependencies

This example uses `cdk-spilman` with `default-features = false` and the `spilman-axum` + `configurable-host-reqwest` features, which provides the host implementation, the networking battery, and the pre-built management router:

```toml
[dependencies]
cdk-spilman = { version = "0.16.0-rc.1", default-features = false, features = ["spilman-axum", "configurable-host-reqwest"] }
```

This pulls in the Spilman implementation, Axum router, YAML config support, SQLite persistence, and `reqwest` for mint communication.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MINT_URL` | `http://localhost:3338` | Cashu mint URL |
| `PORT` | `5003` | Server port |
| `SERVER_SECRET_KEY` | fixed dev key | Server's secret key (hex) |

## Protocol

See [NUT-XX: Spilman Channels](https://github.com/cashubtc/nuts/pull/296) for the full protocol specification.
