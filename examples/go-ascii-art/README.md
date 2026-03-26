# Go ASCII Art - Spilman Payment Channel Demo

This example demonstrates a Go server and client using the Go integration kit.

## Overview

- **Server**: Standard library HTTP server + `RegisterManagementRoutes`
- **Client**: Uses `ClientBridge` to build payment headers and close the channel

## Prerequisites

1. A running Cashu mint (default `http://localhost:3338`)
2. Go toolchain and Rust bindings built (see repo root)

## Run the Demo

```bash
# Start the server
go run -tags spilman_dev . server

# In another terminal
go run -tags spilman_dev . client "Hello World" --close
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MINT_URL` | `http://localhost:3338` | Cashu mint URL |
| `PORT` | `5001` | Server port |
| `SERVER_URL` | `http://localhost:5001` | Client target URL |
| `SERVER_SECRET_KEY` | `00..01` | Server secret key |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/channel/params` | GET | Server parameters (pubkey, pricing, keysets) |
| `/channel/register` | POST | Pre-register a channel |
| `/channel/{id}/status` | GET | Channel status |
| `/channel/{id}/close` | POST | Cooperative close |
| `/channel/{id}/unilateral-close` | POST | Unilateral close |
| `/ascii` | POST | Paid ASCII art endpoint |
| `/ascii/preflight` | POST | Preflight payment check (no side effects) |

## Notes

- The demo uses `spilmankit.DemoFetchActiveKeysetInfo` and `DemoMintFundingToken`.
- Add `--close` to cooperatively close the channel at the end of the run.
- `pricing_scale` is optional in `config.yaml` (default `1`).
