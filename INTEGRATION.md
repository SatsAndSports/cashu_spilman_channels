# Spilman Channel Integration Guide

This guide is for developers who want to accept or send Cashu micropayments via Spilman channels.

**Prerequisites**: Basic familiarity with [Cashu](https://cashu.space/) ecash (tokens, mints, proofs).

**Technical Reference**: For cryptographic details, state transitions, and the YAML data model, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Overview

Spilman channels enable **streaming micropayments** between a client (payer) and a server (payee). Instead of paying per-request with individual tokens, the client opens a channel with a set capacity and then makes many small payments by signing incremental balance updates.

### How It Works

1.  **Funding**: The client creates a 2-of-2 multisig Cashu token. Both the client and server must sign to spend the funds cooperatively.
2.  **Payments**: The client signs a "balance update" message (e.g., "The server is now owed 150 sats").
3.  **Closing**: Either party can close the channel. The server submits the latest balance update to the mint, receiving its share while the client gets the remaining change.

---

## Integration Paths (Server-Side)

### Path 1: Rust (Standard)

The Rust server implementation lives in the `cdk-spilman` crate. The easiest way to build a Rust server is using `ConfigurableHost` and the library-provided Axum router.

1.  **Define Pricing**: Create a `config.yaml` file (see schema in [ARCHITECTURE.md](ARCHITECTURE.md)).
2.  **Setup Host & Bridge**:
    ```rust
    let host = Arc::new(ConfigurableHost::from_yaml(&yaml, secret_key_hex)?);
    let bridge = SpilmanBridge::new((*host).clone());
    ```
3.  **Use Axum Router**:
    ```rust
    let app = Router::new()
        .nest("/channel", configurable_management_router(spilman_state));
    ```

### Path 2: TypeScript (Standard)

Use the [TypeScript Integration Kit](integration-kits/ts/) for Express applications.

1.  **Setup Kit**:
    ```typescript
    const sp = await ConfigurableSpilman.fromYaml("config.yaml", secretKeyHex);
    ```
2.  **Use Management Router**:
    ```typescript
    app.use("/channel", sp.router);
    ```

### Path 3: Python

Use the [Python Integration Kit](integration-kits/python/) for Flask or FastAPI applications. See `examples/python-ascii-art/` for a working demo.

### Path 4: Go

Use the [Go Integration Kit](integration-kits/go/) for Go HTTP servers. See `examples/go-ascii-art/` for a working demo.

### Path 5: Custom Implementation

For other stacks, implement the `SpilmanHost` interface defined in [ARCHITECTURE.md](ARCHITECTURE.md).

*   **Policy**: Implement hooks to check if mints, keysets, and pubkeys are acceptable.
*   **Pricing**: Implement `get_amount_due` based on your service's usage metrics.
*   **Storage**: Implement persistent stores for funding data, balances, usage, and keyset cache.

---

## Technical Guidelines

### HTTP Protocol (Reference)

The reference implementations use HTTP headers to transport payments.

#### Request: X-Cashu-Channel Header
The client sends a **base64-encoded JSON** header:
```http
X-Cashu-Channel: eyJjaGFubmVsX2lkIjoiYWJjLi4uIiwiYmFsYW5jZSI6MTUwLC4uLn0=
```

#### Response: Success (200 OK)
On success, return a confirmation header (plain JSON):
```http
X-Cashu-Channel: {"channel_id":"abc...","balance":150,"amount_due":145,"capacity":1000}
```

#### Response: Payment Required (402)
When payment is insufficient, return a structured error:
```json
{
  "error": "insufficient balance",
  "channel_id": "abc...",
  "balance": 100,
  "amount_due": 150
}
```

### Transport Constraints

The Spilman protocol typically transmits the `X-Cashu-Channel` header. Standard web servers often impose a **16KB limit** on total header size.

A single funding proof occupies ~400 bytes when encoded. A funding token containing more than **~40 proofs** (common for high-capacity msat channels) will likely exceed the header limit. 

**Workaround**: Use a larger `maximum_amount` (e.g., 8192) during funding to reduce the proof count, or transmit the funding token in a `POST` request body.

---

## Two-Phase Payment (Deferred Usage)

When the precise usage isn't known until after request processing, use a
two-phase pattern:

1. **Accept payment without usage** — validates the payment against *prior*
   accumulated usage and records the latest balance and signature, but does
   **not** increment any usage counters.
2. **Record usage after work completes** — applies the actual usage increments.

This accepts the payment up front; it just defers usage accounting.

All integration kits provide helpers for this:

| Language | Accept payment (no usage) | Record usage |
|----------|---------------------------|--------------|
| **Python (Flask)** | `spilman.process_request_payment_no_usage()` | `spilman.record_usage({"chars": n})` |
| **Python (FastAPI)** | `await spilman.process_request_payment_no_usage(request)` | `await spilman.record_usage(request, {"chars": n})` |
| **TypeScript** | `spilman.processRequestPaymentNoUsage(req)` | `spilman.recordUsage(req, { chars: n })` |
| **Go** | `ctx.ProcessRequestPaymentNoUsage(r)` | `ctx.RecordUsage(r, map[string]int{"chars": n})` |

**Rust** does not have a dedicated wrapper; use the core API directly:

```rust
// Accept payment with empty context (no usage increment)
let payment = bridge.process_payment_via_json(payment_json, "{}")?;

// ... do work ...

// Record actual usage
host.record_payment(channel_id, PaymentProof { balance, signature }, &serde_json::to_string(&increments)?);
```

**Behavior**: The first call validates that the payment covers **prior** accumulated
usage and will reject (402) if insufficient. It does not reserve the new usage.
If actual usage exceeds balance, it will be recorded and the **next** request
will be rejected until topped up.

---

## State Management

| Store | Purpose |
|-------|---------|
| **Funding** | Store params, proofs, and `_channel secret_` for validation and closing. |
| **Balance** | Track the highest payment signature seen (monotonic). |
| **Usage** | Store monotonic counters (e.g., requests, bytes) to compute `amount_due`. |
| **Closing** | Temporary storage for swap data during the closing transition. |
| **Closed** | Final audit trail of closed channels and their proofs. |

---

## Working Examples

| Component | Location |
|-----------|----------|
| **ASCII Art** | `examples/rust-ascii-art/` (Standard Rust server) |
| **Python Demo** | `examples/python-ascii-art/` |
| **TypeScript Demo** | `examples/ts-ascii-art/` (TypeScript/Node.js server) |
| **Go Demo** | `examples/go-ascii-art/` |

---

## Further Reading

- [ARCHITECTURE.md](ARCHITECTURE.md) - Cryptographic protocol details and Trait definitions
- [NUT-XX: Spilman Channels](https://github.com/cashubtc/nuts/pull/296) - Protocol specification
