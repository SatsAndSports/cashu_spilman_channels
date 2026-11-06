# Spilman Channel Integration Guide

This guide is for developers who want to accept or send Cashu micropayments via Spilman channels.

**Prerequisites**: Basic familiarity with [Cashu](https://cashu.space/) ecash (tokens, mints, proofs).

**Technical Reference**: For cryptographic details, state transitions, and the YAML data model, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Typed mint outcomes

This is a coordinated breaking API change within unreleased 0.3.0. Rebuild all
bindings and update custom networking implementations together. There is no
automatic fallback to parsing old exception/error strings as mint responses.

Rust mint networking traits return `Result<String, MintRequestError>`. The success
string is the complete response body, still subject to JSON, output and signature
verification. Use `MintResponse { status, body }.into_result()` to classify a
complete HTTP response, and `MintRequestError::transport(message)` for failures
to send or fully read/decode one. A string converted into `MintRequestError`
always becomes a transport failure, even if its contents look like NUT-00 JSON.

Python, Go/C and WASM/TypeScript mint callbacks return a **serialized JSON
envelope**, for both successful and unsuccessful HTTP statuses:

```json
{"status":400,"body":"{\"code\":12002,\"detail\":\"Inactive Keyset\"}"}
```

Use `json.dumps({"status": resp.status_code, "body": resp.content.decode("utf-8")})`
in Python, `MintResponseEnvelope(resp)` in Go, or serialize `{status, body}` after
strict UTF-8 decoding in TypeScript. Exceptions, rejected promises and callback
failure returns represent transport/read failures; never throw a raw
HTTP error body. The Go/C callback success flag now means a complete response
envelope was returned, not that the HTTP status was successful. This contract
applies to swap, restore and keyset callbacks, not the separate demo minting
`http_call` callback. Callback providers are trusted to report actual status and
complete bodies; an envelope is evidence provenance, not mint authentication.

Only HTTP 400 with a numeric `u32` NUT-00 `code` and string `detail` is classified
as `Rejected`. Duplicate known fields, overflow, malformed JSON, and other HTTP
statuses become `Http` failures. Read failures become `Transport`; both preserve
submission uncertainty. Only known codes **12001 and 12002** can permit keyset
reselection. The former blanket 12xxx rule and 99999 workaround are removed.

Rejection does not mean inputs are spendable: 11001 explicitly reports spent
inputs. Opening helpers only mark a fresh attempt `OpeningFailed` for a qualifying
keyset rejection; other submission failures retain `OpeningFromSwap` with
`input_may_be_spent=true`. An existing opening record requires recovery, rather
than another fresh high-level submission. Applications must serialize channel
operations and retain earlier uncertainty in their own journals; evidence from
a later rejection cannot erase an earlier possibly successful submission.

`OpenChannelError.mint_error` preserves structured evidence separately from its
display message. Python/Go opening exceptions carry serialized `OpenChannelError`;
WASM rejects with its structured object. Close transport/unclassified failures use
`mint_request_failed` with evidence and any preceding rejection, instead of being
misreported as `mint_rejected`. No failed submission finalizes a close or releases
application-owned reservations. Durable replay and exact restore remain the
application's responsibility; the typed evidence is not a settlement journal.

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

`compare_payment` atomically accepts a new payment only against the exact previous
Open-channel authorization. Applications computing credit deltas must use this
CAS rather than treating a monotonic no-op as newly accepted funds.

Before restore or replay, `verify_prepared_close` authenticates the saved request
against separately persisted funding, payment, and expected receiver. It verifies
the receiver signature instead of regenerating its random signature bytes, and
checks exact inputs and outputs against the authorized commitment without using
current time, lifecycle state, or active keysets. Journal schema and replay policy
remain application-owned.

Receiver close output-keyset rotation preserves the nominal split fixed by the
payment authorization, even when the new output keyset charges different fees
on subsequent spends. Sender discovery can use
`SpilmanChannelSender::restore_sender_proofs_with_keysets` with same-unit historical
keys without changing channel derivation. `SenderCloseKeysetMissing` requests a
metadata refresh; invalid cryptographic evidence remains an error, never partial
success. This discovery API is distinct from exact prepared-request restoration.

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

**Workaround**: Use a larger `maximum_amount_for_one_output` (e.g., 8192) during funding to reduce the proof count, or transmit the funding token in a `POST` request body.

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

## State-First Channel Recovery (Rust)

Use these additive Rust APIs when the mint outcome is uncertain, when Alice
checks whether Charlie closed, or when resuming a retained close/refund. They
require no new feature flag, storage schema, daemon option, or reset. They are
not yet exposed through the Python/Go/WASM bridges. MONAD's existing orchestration
is not changed by this library PR; it must explicitly adopt this contract later.

`EstablishedChannel::inspect_funding(&mint).await` queries every funding Y in one
NUT-07 request. It validates the local funding model and exact response identity
coverage (no missing, duplicate, or unrelated Ys; response ordering is immaterial).
The returned `FundingInspection` retains the complete response and reports
`Unspent`, `Pending`, `Spent`, or `Mixed`. Generated close/refund requests normally
spend the whole funding token atomically. Mixed states can represent a partial
post-expiry refund and are left to the host rather than classified.

For Alice:

```rust,ignore
let recovery = sender.recover_funds(
    &mint_connection,
    &retained_refund_attempts,
    &historical_close_output_keysets,
).await?;
```

Each refund must belong to this sender/channel and be authenticated before I/O.
If funding is spent, all valid empty refund restores permit discovery of Alice's
deterministic close outputs. A possibly submitted refund never excludes the
possibility that Charlie won the race. A verified refund returns
`SenderRecoverySource::Refund { attempt_index }`; verified close outputs return
`ReceiverClose`. Close outputs carry Alice's second-stage authorization but still
need the ordinary second-stage swap; refund outputs are already loose proofs.
Supply cached same-unit historical close output keys, not merely today's active
keys; missing keys remain a recoverable error (`SenderCloseKeysetMissing`). The
library does not silently refresh or reselect keys.

For Charlie:

```rust,ignore
let recovery = bridge.recover_close(
    &channel_id,
    &retained_close_attempts,
    &mint_connection,
).await?;
```

The host must already be `Closing`, with stored funding and a fixed closing
payment. Every supplied attempt is authenticated against those records before
I/O; retained historical output-keyset attempts can be recovered independently.
The returned payout is a verified `CompletedClose`, not a storage transition.
Persist the completion before finalizing/importing it according to your journal.
Use a mint connection bound to the channel's mint for either party.

Both operations return `ChannelRecovery<T>`:

| Outcome | Meaning / host action |
|---|---|
| `Unspent` | No committed spend observed. Apply existing expiry and immutable-request replay rules; this is not a reservation or permission to replace an uncertain request. |
| `Pending` | Wait and retain the unresolved operation. No NUT-09 call is made. |
| `Mixed` | Partial/mixed funding state. No NUT-09 call or inferred refund classification is made. |
| `Recovered { funding, payout }` | Verified payout to durably persist/import. No host state is mutated. |
| `SpentNoKnownPayout` | Valid empty restores found no known payout; not proof of refund, zero entitlement, or successful settlement. |

Transport errors and invalid/nonempty restore responses return errors, never
absence. Another retained exact attempt may positively recover the payout despite
a response invalid for an earlier attempt (for example, a different output keyset).
Otherwise, any invalid refund restore prevents Alice from treating the refund as
absent and falling through to discovery. Discovery errors return no partial proof
set. Neither witness signature count nor failure to match a known signature routes
these recovery operations.

These methods inspect/recover only: they never submit/replay, inspect time, refresh
keys, release reservations, or install terminal states. They are explicit calls,
not background polling. Already verified responses or saved completions can still
be completed/finalized without requiring a fresh online NUT-07 query. Charlie's
host can abandon further collection after expiry, but must distinguish that policy
from a factual claim that Alice refunded; first recover any known earlier close.
Raw NUT-09 helpers and pure response-completion APIs retain their narrower contracts
and do not themselves enforce the new orchestration order. Ordinary channels only:
this PR does not add rerandomized signing or restore-point derivation.

Run `cargo test -p cdk-spilman-client-integration-tests --test recovery` for direct
and loopback HTTP real-mint races, lost successful replies, independently spendable
payouts, partial post-expiry spend, historical keysets, and injected bad evidence.

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

Use `channel.inspect_funding(&connection)` for full-token NUT-07 evidence, or
`sender.recover_funds(...)` for the state-first refund/close fallback sequence.
These validate every funding identity. Generated transactions normally spend all
funding inputs atomically, but a partial post-expiry refund can produce mixed
states. No witness-count or known-signature classification is used. Invalid restore
responses remain errors, and verified expected outputs establish recovered value.

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

## Receiver channel-state lookup (breaking API update)

Receiver `SpilmanStorage::get_state` and `SpilmanHost::get_channel_state` return
`Result<Option<ChannelState>, String>`. `Ok(None)` means the channel is unknown;
`Ok(Some(state))` means it exists; `Err` means lookup failed or stored state is
invalid. Never substitute `Open` for missing or unreadable state. First-time
registration accepts unknown channels only through validation of supplied funding;
existing-channel payment validation rejects them as `UnknownChannel`.

Receiver callback contracts:

- Python: return `None` for unknown, a state string for known, or raise on failure.
- JavaScript/WASM: return `null` for unknown, a state string for known, or throw
  on failure. `undefined`, empty strings and invalid types are errors.
- Go: `GetChannelState(channelID string) (string, error)`; `("", nil)` means
  unknown. The C callback returns JSON `{"Ok":null}`, `{"Ok":"open"}`, or
  `{"Err":"..."}`; a null pointer is an error, not an unknown channel.

Known callback strings are `open`, `closing`, and `closed`. Other strings, including
the removed `sender_refunded_after_expiry`, are errors. SQLite preserves its
existing state representation and schema, but rejects unrecognized stored states
and propagates query errors rather than treating them as `Open`.

The inferred refund terminal state and `SpilmanStorage::finish_sender_refund` have
been removed. Existing `SenderRefundedAfterExpiry` database rows are unsupported:
state lookup fails explicitly and leaves the data intact. There is no automatic
conversion to `Closed` or `Closing`, migration, or deletion. Hosts abandoning
collection should keep the channel `Closing` and record their policy in the
application-owned close journal using the existing compare-and-swap operations.
Retained attempts remain available for later explicit recovery.

Update custom receiver hosts and rebuild bindings together. There is no database
migration or reset. Client payment signing/recording, including cooperative balance
decreases, is unchanged. Client-host state callbacks are a separate API.
## Keyset discovery and selection

Since 0.2.0, keep library capabilities separate from per-operation output policy.
The library understands V1 (`00`) and V2 (`01`). Unknown first bytes are skipped
only while enumerating metadata; explicitly supplied unsupported funding/proofs
remain errors. Discovery validates all supported metadata, retains inactive entries,
and never clears unrelated cache records. It does not apply output-version policy.

Rust automatic opening and active-keyset fetch APIs require `KeysetSelectionPolicy`:

```rust
use cdk_spilman::{KeysetSelectionPolicy, KeysetVersion, KeysetVersions};
let policy = KeysetSelectionPolicy {
    allowed_versions: KeysetVersions::from([KeysetVersion::V2]),
};
// Equivalently: KeysetVersions::V2. Also available: V1 and V1_AND_V2.
```

Policy applies to every selection, including refresh/retry. Explicit-ID and
explicit-keyset-info opening APIs use the caller's already-selected keyset: those
callers own application policy. Close/refund/recovery are independent and can use
all implemented versions. `cached_active_keyset_ids` enumerates the cache without
an application filter; apply `allowed_versions.allows(id)` before selecting.

`KeysetDiscovery` carries supported `keysets`, `skipped` entries (version byte,
optional unit, active flag), and `unsupported_active_units`. A null unit indicates
unknown metadata whose unit could not be read. Built-in Rust networking emits a
warning per affected unit. Successful discovery may yield no supported keysets;
selection then returns a no-compatible-active-keyset error. HTTP or malformed
supported metadata/key failures remain errors.

Python and WASM expose `discover_keysets_json`, `select_active_keyset_json`, and
`build_keyset_info_from_responses`. The selection policy JSON is
`{"allowed_versions":["v1","v2"]}`; no field default and no numeric min/max range.
The response builder matches the requested ID and verifies supported key material.
For example, Python:

```python
import json
from cdk_spilman import KEYSET_VERSIONS_V1_AND_V2, select_active_keyset_json
id = select_active_keyset_json(listing_json, "sat", json.dumps({
    "allowed_versions": KEYSET_VERSIONS_V1_AND_V2,
}))
```

The TS kit exports immutable `KEYSET_VERSIONS_V1`, `KEYSET_VERSIONS_V2`, and
`KEYSET_VERSIONS_V1_AND_V2` arrays. Pass one as the third argument to
`demoFetchActiveKeysetInfo`; Python's demo fetcher takes `allowed_versions=`.
These demo helpers default to exactly V1 and V2, not an expanding capability set.

Go exposes `DiscoverKeysets`, `KeysetDiscovery.SelectActive`, and
`KeysetSelectionPolicy{AllowedVersions: spilman.KeysetVersionsV1AndV2()}`.
`KeysetVersionsV1()` and `KeysetVersionsV2()` are also available. Preset functions
return fresh slices. Pass a policy as the third argument to
`spilmankit.DemoFetchActiveKeysetInfo`. Go metadata helpers classify/choose entries;
actual channel construction and verification still use the Rust core.

Neither successful discovery nor policy selection grants support for unknown
cryptography. Fixed presets never gain V3 when the library is upgraded. Rust's
`KeysetVersions::library_supported()` and Go's `LibrarySupportedKeysetVersions()`
are explicit opt-ins to following future implemented versions.
## Keyset-only sender refund candidates

`PreparedSenderRefund::with_output_keyset(&channel, &sender_secret, keys)` creates
a validated replacement candidate without signing or submitting. It retains the
original funding inputs, witnesses, output amounts, secrets, blindings, and blinded
points. Only output keyset IDs and signing-key metadata change. SIG_ALL excludes
keyset IDs, so Alice's existing signature remains valid. Replacement keys must
have the same unit and support every retained denomination; the host selects
active keys and owns refresh, rejection authority, candidate limits and retries.

Prepared refunds now require `derivation_keyset`, the original full keyset metadata
used for deterministic secret/blinding and denomination derivation. `output_keyset`
is the current candidate's signing keyset. Initial preparations set both alike;
successors retain the derivation metadata. This is a breaking Rust/JSON format
change: records missing the field reject, with no migration or automatic deletion.
The secret derivation algorithm remains version 1.

Pass retained candidates to `SpilmanChannelSender::recover_funds`. Recovery checks
all funding identities with NUT-07 first, then routes NUT-09 issuance by signature
keyset IDs and verifies the complete payout against a retained candidate. Echoed
query IDs can differ from issued signature IDs for shared blinded points. The
returned refund source identifies the winning attempt index. Valid empty refund
restores still permit receiver-close discovery; invalid or unavailable evidence
remains unresolved unless another retained refund verifies. Preserve finalization
and candidate history durably before exposing recovered funds.

## Checked swap completion primitives

The Rust-only `cdk_spilman::swap_completion` module provides:

- `swap_authorization_digest(&SwapRequest) -> [u8; 32]`: Cashu's canonical digest,
  selected by the request's rerandomization flag. Sign directly using BIP-340;
  do not SHA-256 the returned bytes again. This does not validate authorization.
- `PreparedSwapOutput`: the original blinded message, secret and blinding factor.
  `Debug` is redacted. Treat these values as confidential journal material.
- `complete_swap_response(request, prepared_outputs, response, historical_keyset)`:
  verifies exact output count/order, amount/keyset, original secret/point binding,
  derived-point DLEQ, and resulting proof DLEQ. Returns a complete proof batch or
  an error, never a partial payout.
- `swap_restore_request(request, committed_r)`: constructs ordinary or derived
  NUT-09 points. The request must have nonempty, unique output points.
- `complete_swap_restore(request, prepared_outputs, committed_r, response, keys)`:
  validates and canonicalizes complete output/signature pairs. Only paired empty
  arrays mean absence. Partial, duplicate or unknown outputs reject.

Ordinary requests require absent `R`; rerandomized requests require `R`. Derived
outputs use `B' = B + t(R)G`; unblinding uses the effective scalar `r + t(R)` modulo
the curve order. Degenerate points/scalars reject without panicking. Returned
proofs keep the original secret; their DLEQ `r` is the effective scalar, not the
original one. For fixed secret and mint key the unblinded `C` is unchanged, but the
full proof serialization (including DLEQ) need not match an ordinary issuance.

The primitives assume one authenticated historical output keyset for the batch.
They do not check mint activity/current expiry, contact the mint, inspect input
states, choose candidates, persist records, or attach channel-specific stage-2
witnesses. The host authenticates its retained request and obtains `R` from a
successful response or validated committed funding evidence. `R` alone never
proves a receiver close. Missing DLEQ is an error, including on restored signatures.
Host recovery must retain custody on errors/absence according to its own journal.

The workspace pin includes [CDK fork PR #6](https://github.com/SatsAndSports/cdk/pull/6),
an additive digest API atop the existing v0.18.1 backport. All CDK/Cashu crates use
that same source. This does not enable rerandomized channels or choose a default
channel mode; no parameter encoding, channel ID, journal format or binding API is
changed by this milestone.
