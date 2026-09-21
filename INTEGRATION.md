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

### Exact Close Completion

Durable hosts implement the `SpilmanStorage` close-journal methods:
`freeze_close` atomically compares the accepted payment, enters Closing, and
inserts the application's opaque secret-bearing journal; `advance_close` uses
exact journal compare-and-swap and can atomically install Closed plus payout.
`get_close_journal` propagates storage errors rather than treating them as absence.
Memory and SQLite stores implement this contract. Balance updates reject Closing
and Closed, and legacy lifecycle setters cannot bypass an installed journal.
No old close authorization is converted into a journal automatically.

Before restore or replay, `verify_prepared_close` authenticates the saved request
against separately persisted funding, payment, and expected receiver. It verifies
the receiver signature instead of regenerating its random signature bytes, and
checks exact inputs and outputs against the authorized commitment without using
current time, lifecycle state, or active keysets. Journal schema and replay policy
remain application-owned.

`PreparedClose`, `PreparedCloseTransition`, and `CompletedClose` implement Serde
serialization. Their serialized forms contain secrets or spendable proofs; protect
them as wallet data and never log them. Their `Debug` implementations are redacted.

`complete_prepared_close` checks the channel/mint/unit binding, deterministic
commitment secrets and role/index metadata, exact request outputs, signature
count/amount/keyset, and DLEQ using the preparation's historical output keyset.
It does not consult active keysets or the clock and does not mutate storage.

For NUT-09, send the saved swap's `outputs` as the restore request, then call
`complete_prepared_close_restore(response_json, &prepared)`. A valid response may
reorder output/signature pairs; completion returns them in prepared order.
Unknown, duplicate, missing, partial, or invalid results are errors. Only two
empty arrays return `None`; this is not a zero-value close, proof that funding
was spent, or permission to change outputs or replay a request.

These are completion primitives, not a recovery protocol. The application must
bind the saved preparation to the receiver, funding and accepted payment, persist
execution uncertainty before HTTP, serialize payment/close transitions, validate
input state before any replay, and journal finalization before installing the
closed state. In particular, `mark_prepared_close_closing` still stores only
expiry/payment authorization, not the exact preparation. The convenience close
wrappers do not implement this application-owned journal.

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

For applications that need to separate validation from persistence, use
`validate_new_channel_funding` to check first-use channel funding without
mutating storage, then call `record_validated_new_channel` once the host is ready
to commit it. `validate_payment` itself is side-effect-free and only validates
channels that are already recorded; high-level `fund_channel` and
`process_payment` remain validate-and-record convenience wrappers.

Server close execution can also be split into caller-owned steps. Use
`prepare_cooperative_close_transition` or `prepare_unilateral_close_transition`
to build the close swap and pending closing-state update without mutating state,
then call `mark_prepared_close_closing` before submitting the swap to the mint.
After the mint responds, call `complete_prepared_close` to verify and unblind the
response without marking the channel closed, then `mark_completed_close` to
persist the final closed state. The high-level `execute_*_close` methods still
perform the full sequence for simple integrations.

---

## State Management

| Store | Purpose |
|-------|---------|
| **OpeningFromSwap** | (Client-only) Durable parameters and serialized funding input saved before submission; the swap may be unsubmitted or ambiguous. |
| **OpeningFailed** | (Client-only) Explicit mint rejection retained with opening/failure metadata. |
| **Funding** | Store params, proofs, and `_channel secret_` for validation and closing. |
| **Balance** | Track the highest payment signature seen (monotonic). |
| **Usage** | Store monotonic counters (e.g., requests, bytes) to compute `amount_due`. |
| **Closing** | Durable expiry/payment authorization used to reconstruct close execution; the prepared mint swap itself is not stored by the core host contract. |
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

The Rust `wallet`-feature method `restore_funding_proofs` is a checked query, not
a state transition. These recovery methods are not currently exposed by the
Python, Go, or WASM bridges.

1. **Attempt Restore**: Re-fetches the signatures from the mint via NUT-09.
2. **Success**: If the swap succeeded, it returns validated funding-proof JSON and leaves the channel in `OpeningFromSwap`.
3. **Commit recovery**: Use `recover_open_channel_from_swap`, or the explicit `prepare_open_channel_recovery` / `complete_prepared_open_recovery` / `mark_completed_open_recovery` phases, to restore funding plus any expected plain change and persist `Open`.
4. **Empty restore**: This establishes only that no outputs were observed. The stored funding input (Cashu token or raw proof JSON) must not be retried or reclaimed until the application has safely resolved whether an earlier submission can still execute.

---

## Post-Expiry Sender Refunds (Rust)

These `cdk-spilman` APIs are available without the `wallet` feature. This is a
breaking prepared-refund schema/API: old serialized attempts are not supported.

1. Reconstruct the trusted `EstablishedChannel` from stored funding, for example
   with `EstablishedChannel::from_client_channel_funding(&funding)`.
2. Select a currently active output `KeysetInfo` for that channel's mint and unit.
   Do not replace `channel.params.keyset_info`: it describes the funding inputs
   and their fees. `KeysetInfo` itself has no mint URL or active flag; the
   application must associate its keyset cache and connection with the right mint.
3. Prepare only at a caller-supplied Unix time strictly greater than expiry.
   Use a fresh random 32-byte context (or a durable unique 32-byte attempt ID)
   for a new request. The output keyset may differ in keys, denominations, format,
   and fees from funding. The funding input fees alone determine refund value.
4. Persist the complete prepared JSON atomically before any submission. Treat it
   as immutable and secret-bearing. Keep previous attempts while unresolved.
5. Submit that exact request once. Validate before network I/O and import only
   proofs returned by checked completion. Persist proof custody and completion
   together, deduplicating replayed proofs.

```rust,ignore
let prepared = channel.prepare_sender_refund_after_expiry(
    sender_secret.clone(), now_seconds, output_keyset, attempt_context,
)?;
let durable_json = prepared.to_json()?;
// Application persists durable_json before any network request.
let prepared = PreparedSenderRefund::from_json(&durable_json)?;
prepared.verify(&channel, &sender_secret)?; // pure, no clock/network/signing

let proofs = channel.submit_prepared_sender_refund(
    &prepared, &sender_secret, now_seconds, &mint_connection,
).await?;
```

For application-owned networking, submit `prepared.swap_request.clone()` to
`prepared.mint`, then pass the response's `Vec<BlindSignature>` to:

```rust,ignore
let proofs = channel.complete_prepared_sender_refund(
    &prepared, &sender_secret, response.signatures,
)?;
```

Following a lost/invalid response, or on restart, restore the immutable attempt:

```rust,ignore
let outcome: Option<Vec<Proof>> = channel.restore_prepared_sender_refund_outputs(
    &prepared, &sender_secret, &mint_connection,
).await?;
```

For application-owned NUT-09 networking, build `RestoreRequest { outputs }` from
`prepared.outputs.iter().map(|o| o.blinded_message.clone()).collect()` and call
`channel.complete_prepared_sender_refund_restore(&prepared, &sender_secret, response)`
with the complete `RestoreResponse`, not just its signatures.

- `Ok(Some(proofs))` means all expected outputs were validated. Proof order is
  canonicalized to prepared order even if the restore response was reordered.
- `Ok(None)` means both response arrays were empty. It does **not** prove a
  previous request failed or cannot still execute. Keep reservations and resolve
  ambiguity before creating a changed request.
- `Err` includes partial, duplicate, unknown, or mismatched restore outputs,
  incorrect counts/amounts/keysets/totals, and missing/invalid DLEQ. Never import
  partial results or treat these errors as absence.

All completion uses `prepared.output_keyset.active_keys`. Despite that historical
field name, the keys need not still be active; never substitute current mint keys.
Pure verification checks channel/mint/unit binding, keyset identity and metadata,
version/context-derived outputs, exact funding inputs, net value, sender identity,
and the single refund SIG_ALL signature. Deserialization alone is not validation.
Completion and restore do not consult wall-clock time or reject historical keys.

Refund derivation requires the sender private key, not just the shared channel
secret. The private key is not serialized in `PreparedSenderRefund`, but the
record contains confidential output secrets and blindings. Protect the record
and never log it or the derivation preimages, which contain the sender private
key. Send only the swap/restore request to the mint, not the prepared record.

Preparation and checked submission return downcastable `SenderRefundError::NotExpired`
at/before expiry; zero net value returns `SenderRefundError::ZeroNetValue` without
building an empty swap. Overflow and fees exceeding funding value are errors.
`MintConnection` still returns `anyhow::Result`: its errors propagate unchanged,
preserving concrete error types and source chains where the adapter provides them.
The library cannot recover structured NUT-00 data already flattened by an adapter.

There is **no hidden retry or refresh**. After a conclusive retryable keyset
rejection, the application may refresh/select another output keyset, prepare a
successor with a fresh context, persist it, and submit it under its own retry
budget. Do not mutate the old attempt or use a changed-request retry on an
ambiguous timeout, empty restore, or invalid response.

If funding was already spent, `channel.check_funding_token_state(&connection)`
checks exactly the first funding proof's Y and rejects missing, extra, or
mismatched states. Supported generated close/refund transactions spend all
funding inputs atomically, so one representative suffices under that assumption;
this is not a guarantee about arbitrary transactions. The first proof is used
specifically because generated SIG_ALL transactions attach the witness only to
the first input.

`EstablishedChannel::classify_funding_spend_witness(&state)` is only an advisory
witness-shape hint: one signature suggests a generated refund and two suggest a
generated receiver close. An honest pinned mint can accept an unrelated extra
signature on a valid receiver close, causing the exact-count classifier to return
`Unknown`. The hint is neither cryptographic settlement proof nor a prerequisite
for checked recovery. After exact persisted-refund restore, callers may fall back
to checked sender-close discovery for `Unknown` as well as `RelayClose`. Do not
convert invalid/partial restore errors to absence, infer failure from an empty
restore, or import proofs solely from witness classification. Validated output
recovery, not a recognized witness shape, is the basis for importing proofs.

For a receiver close, `SpilmanChannelSender::new(sender_secret, channel)` exposes
`restore_sender_proofs(&connection)`. Its existing ascending-denomination,
per-denomination-index discovery algorithm now validates every NUT-09 pair and
DLEQ before signing the restored sender proof. Only a fully empty response ends
one denomination's search; any malformed response or network error aborts the
entire discovery with no partial proof result.

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
