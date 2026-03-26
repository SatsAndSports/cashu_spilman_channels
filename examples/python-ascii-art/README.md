# Python ASCII Art - Spilman Payment Channel Demo

This example shows a minimal server and client using the Python integration kit.

## Overview

- **Server**: Flask server using `ConfigurableSpilman` (YAML config)
- **Client**: Uses `SpilmanClient` to pay per request and optionally close the channel

## Prerequisites

1. Build Python bindings (from repo root):
   ```bash
   make -C crates/cdk-spilman-python build
   ```

2. Run a Cashu mint (default `http://localhost:3338`):
   ```bash
   cargo run -p cdk-spilman-test-mint --manifest-path Cargo.toml -- --listen-port 3338 --base-url http://127.0.0.1:3338
   ```

## Setup

```bash
cd examples/python-ascii-art
pip install -r requirements.txt
pip install -e ../../integration-kits/python
```

## Run the Demo

Terminal 1:

```bash
python server.py
```

Terminal 2:

```bash
python client.py Hello World Cashu --close
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ascii` | POST | Paid ASCII art endpoint |
| `/ascii/preflight` | POST | Preflight payment check (no side effects) |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_SECRET_KEY` | Random | Server's secret key (hex) |
| `MINT_URL` | `http://localhost:3338` | Cashu mint URL |
| `PORT` | `5000` | Server port |
| `SERVER_URL` | `http://localhost:5000` | Client target URL |

## Notes

- The client prints the full channel ID and uses `--close` to cooperatively close.
- The server exposes `/channel/*` management endpoints via the kit's Flask helper.
- `pricing_scale` is optional in `config.yaml` (default `1`).
