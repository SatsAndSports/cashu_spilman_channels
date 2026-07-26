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
*   **Keyset cache presence**: Implement `has_keysets_for_unit(mint, unit)` as an inactive-inclusive cache check. It should return true when any keyset is cached for that mint/unit, not only when an active output keyset is available.

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
| **OpeningFromSwap** | (Client-only) Temporary storage for params and input token before funding completes. |
| **Funding** | Store params, proofs, and `_channel secret_` for validation and closing. |
| **Balance** | Track the highest payment signature seen (monotonic). |
| **Usage** | Store monotonic counters (e.g., requests, bytes) to compute `amount_due`. |
| **Closing** | Temporary storage for swap data during the closing transition. |
| **Closed** | Final audit trail of closed channels and their proofs. |

---

## Client-Side Recovery (NUT-09)

The client-side implementation uses a two-phase opening process to prevent fund loss. If a network failure occurs after the funding swap is submitted, the channel may be stuck in the `OpeningFromSwap` state.

For applications that need to own async runtime behavior, persistence, retries, or proof reservations, the Rust client bridge exposes a Sans-IO-style opening flow:

1. **Prepare** with `prepare_open_channel_from_token` or `prepare_open_channel_from_proofs_with_input_keysets`. This builds channel parameters, the opening record, and the mint swap request without network I/O or storage mutation.
2. **Persist** the opening record before submitting the swap.
3. **Submit** the prepared swap request to the mint using application-owned networking.
4. **Complete** the swap response with `complete_prepared_open_channel`.
5. **Verify/recover** with `funding_restore_request_for_prepared_open` and `complete_funding_restore_for_prepared_open` when desired.
6. **Commit** the result with `mark_completed_open`.

The high-level `open_channel_from_*` methods remain convenience wrappers around this same sequence.

Use the `restore_funding_proofs` method to recover:

1. **Attempt Restore**: Re-fetches the signatures from the mint via NUT-09.
2. **Success**: If the swap had succeeded on the mint, you get the funding proofs and the channel transitions to `Open`.
3. **Failure**: If the mint has no record of the swap, the original `input_token` remains unspent. You can retrieve it from the opening store and retry or reclaim.

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
