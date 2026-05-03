# CDK Spilman Python Integration Kit

Standard components for integrating Spilman payment channels into Python web applications.

## Features

- **Management Routes**: Pre-built endpoints for `/params`, `/register`, `/close`, etc.
- **Flask & FastAPI Support**: Built-in helpers for common frameworks.
- **ConfigurableSpilman**: YAML-driven configuration and storage selection.
- **Client Bridge Wrapper**: `SpilmanClient` for building payment headers and cooperative close.

## Installation

```bash
pip install cdk-spilman-kit[flask]  # or [fastapi]
```

## Configuration

```yaml
min_expiry_seconds: 3600
pricing_scale: 1        # Optional divisor: ceil(total / pricing_scale)
pricing:
  sat:
    min_capacity: 10
    variables:
      chars: 1
```

## Usage (Flask)

```python
from flask import Flask, request, jsonify
from cdk_spilman_kit import ConfigurableSpilman
from cdk_spilman_kit.ext.flask import normalize_bridge_error

app = Flask(__name__)
ctx = ConfigurableSpilman.from_yaml("config.yaml", SECRET_KEY)
spilman = ctx.init_flask(app)

@app.route("/ascii", methods=["POST"])
def ascii_art():
    data = request.get_json() or {}
    msg = data.get("message", "")
    try:
        payment = spilman.process_request_payment({"chars": len(msg)})
        resp = jsonify({"art": msg, "payment": payment.__dict__})
        return spilman.attach_payment_header(resp, payment)
    except Exception as e:
        status, reason = normalize_bridge_error(str(e))
        return jsonify({"error": "Payment failed", "reason": reason}), status
```

## Usage (FastAPI)

```python
from fastapi import FastAPI, Depends
from cdk_spilman_kit import ConfigurableSpilman
from cdk_spilman_kit.ext.fastapi import Spilman

ctx = ConfigurableSpilman.from_yaml("config.yaml", SECRET_KEY)
spilman = Spilman(ctx)

app = FastAPI()
app.include_router(spilman.router)

@app.post("/ascii")
async def ascii_art(payment=Depends(spilman.payment_required)):
    return {"ok": True}
```

## Client usage

```python
from cdk_spilman_kit import SpilmanClient, InMemoryClientHost

host = InMemoryClientHost(alice_secret_hex)
client = SpilmanClient(host)

# Simplified channel opening
result = client.open_channel_from_token(
    token, receiver_pubkey, sender_pubkey, expiry, keyset_info, max_amount
)

header = client.build_payment_header(result.channel_id, balance, include_funding=True)
close_req = client.create_cooperative_close_request(result.channel_id, final_balance)
client.process_cooperative_close_response(close_response_json)
```
