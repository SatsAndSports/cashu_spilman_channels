# TypeScript ASCII Art - Spilman Payment Channel Demo

This example demonstrates Spilman unidirectional payment channels using TypeScript/Node.js with the CDK WASM bindings.

## Overview

- **Server**: Express server that generates ASCII art (pay per character)
- **Client**: Opens a channel, pays per request, and optionally closes the channel

## Prerequisites

1. Build WASM bindings (from repo root):
   ```bash
   make build-wasm
   ```

2. Run a Cashu mint (default `http://localhost:3338`):
   ```bash
   cargo run -p cdk-spilman-test-mint --manifest-path Cargo.toml -- --listen-port 3338 --base-url http://127.0.0.1:3338
   ```

## Quick Start

```bash
# Install dependencies
npm install

# Terminal 1: Start the server
npm run server

# Terminal 2: Run the client
npm run client -- Hello World Cashu --close
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MINT_URL` | `http://localhost:3338` | Cashu mint URL |
| `SERVER_URL` | `http://localhost:5001` | ASCII art server URL |
| `PORT` | `5001` | Server listen port |
| `SERVER_SECRET_KEY` | Random | Server's 32-byte secret key (hex) |

## API Endpoints

### `GET /channel/params`

Returns server configuration for channel setup.

```json
{
  "receiver_pubkey": "02abc...",
  "pricing": { "sat": { "variables": { "chars": 1 }, "min_capacity": 10 } },
  "mints_units_keysets": { "http://localhost:3338": { "sat": ["001b..."] } },
  "pricing_scale": 1,
  "min_expiry_in_seconds": 3600
}
```

### `POST /ascii`

Generate ASCII art. Requires `X-Cashu-Channel` header with base64-encoded payment.

### `POST /ascii/preflight`

Check whether the payment covers the current amount due without recording usage.
Returns `{ ok: true, amount_due }` when sufficient, or `{ ok: false }` when not.

## Payment Flow

1. Client fetches `/channel/params` and generates a keypair.
2. Client funds a channel and stores it locally.
3. Each request includes an incrementing balance + signature in `X-Cashu-Channel`.
4. Optional: client closes the channel via `/channel/:id/close` (`--close` flag).

## File Structure

```
examples/ts-ascii-art/
├── package.json
├── src/
│   ├── index.ts    # CLI entry point
│   ├── server.ts   # Express server using ConfigurableSpilman
│   └── client.ts   # Client using SpilmanClientBridge
└── tests/
    ├── integration.test.ts
    └── retry-close.test.ts
```

## Testing

```bash
make test-demo-ts
```
