# CDK Spilman Python Bindings

Python bindings for Spilman payment channels, compiled from the core Rust implementation using PyO3.

## Installation

```bash
pip install cdk-spilman
```

## Usage

### Server-Side: SpilmanBridge

The `SpilmanBridge` handles payment validation and channel registration. It delegates storage and policy to a host object.

```python
from cdk_spilman import SpilmanBridge

class MyHost:
    def get_amount_due(self, channel_id: str, context: str | None) -> int:
        return 10  # Your pricing logic
    
    def save_funding(self, channel_id: str, funding: str, payment: str):
        pass  # Persist funding data
    
    # ... see Architecture docs for full list

# Create bridge with your host
bridge = SpilmanBridge(MyHost())

# Process a payment
try:
    result = bridge.process_payment(payment_json, context_json)
    print(f"Payment accepted. New balance: {result.balance}")
except RuntimeError as e:
    import json
    err = json.loads(str(e))
    print(err["status"], err["reason"]) # Structured JSON error
```

### Client-Side: Setup

```python
from cdk_spilman import (
    generate_keypair,
    compute_channel_secret,
    create_funding_outputs,
    create_signed_balance_update,
)

# Derive `_channel secret_` with receiver
channel_secret = compute_channel_secret(sender_secret, receiver_pubkey)

# Create funding outputs for minting
funding = create_funding_outputs(params_json, sender_secret, keyset_json)

# Sign a payment
payment = create_signed_balance_update(params_json, keyset_json, sender_secret, proofs_json, balance)
```

## API Reference

### Classes
- `SpilmanBridge` - Main bridge for server-side payment validation

### Core Functions
- `generate_keypair()` - Generate a new secp256k1 keypair
- `compute_channel_secret(secret, pubkey)` - Derive `_channel secret_`
- `create_funding_outputs(params, secret, keyset)` - Create blinded outputs for funding
- `create_signed_balance_update(...)` - Sign a payment
