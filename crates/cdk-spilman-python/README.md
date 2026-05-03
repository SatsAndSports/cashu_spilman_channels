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
from cdk_spilman import ClientBridge
from cdk_spilman_kit import InMemoryClientHost

host = InMemoryClientHost(alice_secret_hex)
bridge = ClientBridge(host)

# Simplified channel opening
result = bridge.open_channel_from_token(
    token, receiver_pubkey, sender_pubkey, expiry, keyset_info, max_amount
)

# Sign a payment
payment = bridge.create_payment(result.channel_id, balance)
```

## API Reference

### Classes
- `SpilmanBridge` - Server-side bridge
- `ClientBridge` - Client-side bridge

### Core Functions
- `generate_keypair()` - secp256k1 keypair generation
- `compute_channel_secret(secret, pubkey)` - ECDH derivation
- `build_cashu_b_token(mint, proofs)` - Token builder
