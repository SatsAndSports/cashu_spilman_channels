# Spilman Channel Architecture

This document describes the technical design and cryptographic protocol of Spilman-style unidirectional payment channels for Cashu ecash.

## Overview

A Spilman channel is a unidirectional payment channel between:
- **Alice (sender)**: The payer (e.g., video viewer)
- **Charlie (receiver)**: The payee (e.g., video server)

Alice funds the channel by locking ecash in a 2-of-2 multisig with a time-locked refund path. She then signs off-chain balance updates—effectively 'commitment transactions'—that incrementally transfer value to Charlie. Charlie can settle the channel at any time by submitting the latest update to the mint.

This settlement process is known as **'Stage 1'**. It spends the shared funding token and generates two sets of individual P2PK proofs: one for Charlie's earned balance and another for Alice's remaining change. This ensures both parties can independently reclaim their respective shares in **'Stage 2'**.

---

## Technical Protocol

### 1. 2-of-2 Multisig Funding

The channel is funded by Alice with a Cashu token that requires **both** Alice and Charlie to spend cooperatively. The funding token's spending conditions are:

```
P2PK: (Alice AND Charlie) OR (Alice after expiry)
```

This is implemented using Cashu's NUT-11 spending conditions:
- `pubkeys`: [Charlie's pubkey] - requires Charlie's signature
- `data`: Alice's pubkey - requires Alice's signature  
- `refund_keys`: [Alice's refund pubkey] - allows Alice to reclaim after expiry
- `locktime`: Unix timestamp when refund becomes valid (the channel's `expiry_timestamp`)

### 2. Deterministic Outputs

Both parties compute the **same** blinded outputs for the commitment transaction using a common `_channel secret_`. This eliminates round trips during payment:

1. Alice and Charlie derive the `_channel secret_` from an ECDH shared secret (hashed with a domain separator).
2. Both use the `_channel secret_` to deterministically generate blinding factors
3. Both can independently compute the same `BlindedMessage` outputs

### 3. Balance Updates

Alice authorizes balance updates by signing a Cashu **commitment swap**. This swap spends the funding token and creates deterministic Stage 1 outputs for both Charlie (his earned balance) and Alice (her remaining change).

Alice signs the request using the **`SIG_ALL`** flag, ensuring the signature commits to the specific inputs and outputs. She sends Charlie a `BalanceUpdateMessage`:

```json
{
  "channel_id": "abc123...",
  "amount": 150,
  "signature": "schnorr_sig_hex"
}
```

Charlie verifies the signature by reconstructing the same swap request.

### 4. Channel ID

The channel ID is a SHA256 hash of all canonical channel parameters, using pipe-delimited decimal text:

```
channel_id = SHA256(
  mint_url | unit | capacity | funding_token_amount |
  keyset_id | input_fee_ppk | maximum_amount |
  setup_timestamp | sender_pubkey | receiver_pubkey |
  expiry_timestamp | channel_secret_hex
)
```

All fields are pipe-delimited decimal text for cross-platform consistency. `channel_secret_hex` (the hex-encoded `_channel secret_`) ensures that only the two parties who know the secret can compute the channel ID.

`funding_token_amount` is an explicit channel parameter. Use `compute_funding_token_amount()` when constructing a channel; do not recompute it from capacity.

### 5. Funding Verification

When Charlie receives the channel parameters and funding proofs, he performs a full verification:

1. **Deterministic Construction**: He re-derives the expected blinded messages using the `_channel secret_` and ensures the funding proofs match exactly.
2. **DLEQ Verification**: He verifies the DLEQ proofs to ensure the mint actually signed these proofs and no token inflation is possible.
3. **Policy Check**: He confirms the mint, unit, and keyset are acceptable.

---

## P2BK (Pay-to-Blinded-Key) Privacy

The channel uses **blinded pubkeys** in the funding token and in the per-user proofs created at channel closing, so the mint cannot correlate channels to real identities.

### Why Blinding?

Without blinding, the mint sees:
- Alice's real pubkey in multiple funding tokens
- Charlie's real pubkey as recipient
- Pattern: "Alice pays Charlie repeatedly"

With P2BK:
- Each channel uses fresh blinded pubkeys
- Mint sees uncorrelated random-looking keys
- No pattern linking channels to identities

### Loose Sender Refund Security

Post-expiry loose refund outputs are bearer proofs, unlike the key-locked channel
outputs. Their secret and blinding derivations must both include the sender's
private key bytes: the receiver also knows the channel secret and could otherwise
derive the outputs and recover spendable proofs through mint restore.

This fix changes newly prepared outputs without migrating existing records.
Legacy prepared attempts cannot be made private retrospectively, and upgrading
does not protect outputs already submitted using the shared-only derivation.
Do not rewrite an ambiguous submitted attempt or assume its funds are unspent;
retain its exact recovery data. Prepared records contain bearer secrets and
blindings and must be protected; never log them or derivation preimages.

### Blinding Derivation

The stage-1/stage-2 channel-secret derivations below use **pipe-delimited decimal
text** for hash inputs. The versioned loose sender-refund derivation described
under Keyset Rotation Handling additionally uses binary secret/context prefixes
and serialized output-keyset metadata.

#### Stage 1 (Funding / Refund)

Stage 1 uses a shared blinding scalar `r` per role. Distinct `context` strings (e.g., `sender_stage1`, `sender_stage1_refund`) ensure that Alice's refund blinded key is uncorrelated from her 2-of-2 payment key.

```
r = SHA256("Cashu_Spilman_P2BK_v1" || channel_secret || "{channel_id}|{context}|{retry_counter}")
```

Blinded keys are derived using standard BIP-340 parity handling.

#### Stage 2 (Per-Output)

Stage 2 uses a deterministic ephemeral keypair and follows the [NUT-28](https://github.com/cashubtc/nuts/blob/main/28.md) (P2BK) specification. Each output is locked to a unique blinded pubkey derived from its amount and index.

The ephemeral secret `e` is derived deterministically:

```
e = SHA256("Cashu_Spilman_P2BK_ephemeral_v1" || channel_secret || "{channel_id}|{context}|{amount}|{index}|{retry_counter}")
```


---

## State and Pricing

The protocol handles cryptographic signing and verification, but a functional service also requires **state management** and **business logic**. These requirements motivate the Bridge and Host architecture described below.

- **Service Tracking**: Charlie must track how much service has been delivered per channel (e.g., bytes, requests) to ensure each payment covers the accumulated cost.
- **Payment Persistence**: Charlie must store the highest-balance update received per channel. This is his proof for settlement and prevents rollback attempts.
- **Pricing Function**: The developer defines how usage maps to `amount_due`. The server only fulfills a request if `balance >= amount_due`. Some clients will sometimes overpay a little, as it's not always obvious in advance what the cost of a given request will be.

By delegating these concerns to a "Host" while keeping the protocol logic in the "Bridge," Spilman channels can be integrated into any service.

### Channel Lifecycle (Server Perspective)

```
               payment
                ┌───┐
                ▼   │
       fund ──► Open ──► Closing ──► Closed
                         cooperative
                         or unilateral
```

- **Open**: Created when a client registers a funded channel. The server accepts payments, tracks usage, and persists the highest-balance update.
- **Closing**: Close authorization has been durably recorded before mint I/O. The swap may be unsubmitted, in flight, or awaiting completion. No further payments are accepted.
- **Closed**: The mint has processed the swap. Receiver and sender proofs have been unblinded and stored. The channel is settled.

### Channel Lifecycle (Client Perspective)

```
 OpeningFromSwap ───────► Open ───────────────────► Closed
       │                   │                          ▲
       ▼                   └─► Closing (optional) ───┘
 OpeningFailed
       │
       └─ identical re-save ──► OpeningFromSwap
```

- **OpeningFromSwap**: The channel parameters and serialized funding input are persisted *before* the funding swap is submitted. The swap may still be unsubmitted, may be in flight, or may have an ambiguous outcome.
- **OpeningFailed**: The mint explicitly rejected this opening. Opening and failure metadata remain available for audit; an identical opening re-save clears the failure and returns to `OpeningFromSwap`.
- **Open**: The funding swap has succeeded and the 2-of-2 multisig funding proofs are stored. The channel is ready for payments.
- **Closing**: An optional caller-controlled local state for retaining the channel while making it unusable for new payments. Client cooperative-close response processing can also transition directly from `Open` to `Closed`.
- **Closed**: The channel has been closed (cooperatively or unilaterally).

A channel stuck in `OpeningFromSwap` can query NUT-09 with the Rust `wallet`-feature method `restore_funding_proofs`. That method validates and returns restored funding proofs but does not mutate channel state. To persist the transition to `Open`, use `recover_open_channel_from_swap`, or run `prepare_open_channel_recovery`, `complete_prepared_open_recovery`, and `mark_completed_open_recovery`. Recovery must also account for expected plain change outputs. These recovery methods are not currently exposed by the Python, Go, or WASM bridges. The stored `input_token` field may contain a Cashu token or raw input-proofs JSON; an application must resolve submission ambiguity before treating those inputs as reclaimable.

Client opening is also available as a Sans-IO-style prepare/complete flow. `prepare_open_channel_from_token` and `prepare_open_channel_from_proofs_with_input_keysets` construct the deterministic channel parameters, opening record, and mint swap request without performing network I/O or storage mutation. The caller then persists the opening record, submits the swap to the mint, completes the mint response, optionally verifies NUT-09 restore, and explicitly marks the channel open. The high-level bridge methods are convenience wrappers around this sequence.

Transitions:
- `→ Open`: Client funds a channel and registers it via the funding endpoint.
- `Open → Open`: Normal payment — balance increases, usage is recorded.
- `Open → Closing`: Cooperative close requested, where the server accepts payment for only what's actually due, allowing the client to 'undo' any earlier overpayment.
- `Closing → Closed`: Mint swap succeeds and proofs are unblinded.
- `Open → Closing → Closed`: Unilateral close follows the same durable closing boundary as cooperative close.

---

## Universal Bridge Architecture

To make Spilman channels adoptable across different tech stacks, the library uses a **"Pure Brain + Language Bridges"** model.

### The Protocol Bridge

The Spilman logic is implemented as a structured **Protocol Bridge** (`SpilmanBridge`):
- **Input**: Typed params + request context
- **Output**: Typed success or error
- **Portability**: Compiles to WASM (JS/TS) and FFI (Python/Go)

### The SpilmanHost Interface

The bridge is **keyless and stateless**. It delegates policy decisions (pricing, storage) and cryptographic operations (ECDH, signing) to the host application via the `SpilmanHost` trait. The host owns the private key; the bridge remains keyless.

Server-side funding validation is available as an explicit validate/record flow. `validate_new_channel_funding` checks channel parameters, funding proofs, policy, and the sender signature without mutating storage. `record_validated_new_channel` commits that validated funding through the host. High-level entry points such as `fund_channel` and `process_payment` remain convenience wrappers that validate then record when they receive first-use funding. Low-level `validate_payment` is side-effect-free and only validates already recorded channels.

Server-side closing is likewise exposed as explicit steps. `prepare_cooperative_close_transition` and `prepare_unilateral_close_transition` build a signed `PreparedClose` and the pending closing-state transition without marking the channel closing. `mark_prepared_close_closing` commits that transition before mint I/O. After the caller submits the prepared swap to the mint, `complete_prepared_close` verifies and unblinds the mint response without marking the channel closed, and `mark_completed_close` commits the final closed state. High-level `execute_*_close` methods remain convenience wrappers around this sequence.

```rust
trait SpilmanHost<C = String> {
    // Policy
    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool;
    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &Id) -> bool;
    fn get_amount_due(&self, channel_id: &str, context: Option<&C>) -> u64;
    fn get_channel_policy(&self, unit: &str) -> Option<ChannelPolicy>;
    fn now_seconds(&self) -> u64;

    // Storage: funding and payments
    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding>;
    fn save_funding(&self, channel_id: &str, funding: ChannelFunding, initial_payment: PaymentProof);
    fn record_payment(&self, channel_id: &str, payment: PaymentProof, context: &C);
    fn get_balance_and_signature_for_unilateral_exit(&self, channel_id: &str) -> Option<PaymentProof>;

    // Channel state transitions
    fn get_channel_state(&self, channel_id: &str) -> ChannelState;
    fn mark_channel_closing(&self, channel_id: &str, expiry_timestamp: u64, payment: PaymentProof) -> Result<(), String>;
    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData>;
    fn mark_channel_closed(
        &self,
        channel_id: &str,
        expiry_timestamp: u64,
        balance: u64,
        receiver_proofs_json: &str,
        sender_proofs_json: &str,
        receiver_sum: u64,
        sender_sum: u64,
    ) -> Result<(), String>;

    // Keyset cache
    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id>;
    fn has_keysets_for_unit(&self, mint: &str, unit: &CurrencyUnit) -> bool;
    fn get_keyset_info(&self, mint: &str, keyset_id: &Id) -> Option<String>;

    // Cryptographic operations (host owns the secret key)
    fn compute_channel_secret(&self, receiver_pubkey_hex: &str, sender_pubkey_hex: &str) -> Result<String, String>;
    fn sign_with_tweaked_key(&self, signer_pubkey_hex: &str, message_hex: &str, tweak_scalar_hex: &str) -> Result<String, String>;
}
```

### Client-Side: SpilmanClientBridge

The `SpilmanClientBridge` mirrors this pattern, enabling external signers and custom storage for client applications. It uses a two-phase opening process to ensure funds are never lost even if the process crashes or the network fails during funding.

```rust
trait SpilmanClientHost {
    // Channel Opening (two-phase)
    fn save_opening_from_swap_channel(&self, channel_id: &str, opening: ClientChannelOpeningFromSwap) -> Result<(), String>;
    fn mark_channel_open(&self, channel_id: &str, funding_proofs_json: &str) -> Result<(), String>;
    fn get_channel_opening_from_swap(&self, channel_id: &str) -> Result<Option<ClientChannelOpeningFromSwap>, String>;
    fn mark_channel_opening_failed(&self, channel_id: &str, failure: ClientOpeningFailure) -> Result<(), String>;
    fn get_channel_funding(&self, channel_id: &str) -> Option<ClientChannelFunding>;

    // Payment State (mutable)
    fn get_payment_state(&self, channel_id: &str) -> Option<ClientPaymentState>;
    fn record_payment(&self, channel_id: &str, state: ClientPaymentState) -> Result<(), String>;

    // Lifecycle
    fn get_channel_state(&self, channel_id: &str) -> Option<ClientChannelState>;
    fn mark_channel_closing(&self, channel_id: &str) -> Result<(), String>;
    fn mark_channel_closed(&self, channel_id: &str) -> Result<(), String>;
    fn list_channel_ids(&self) -> Vec<String>;
    fn delete_channel(&self, channel_id: &str) -> Result<(), String>;

    // Persistent keyset cache (default implementations may be unsupported/empty)
    fn get_keyset(&self, mint: &str, keyset_id: &Id) -> Option<ClientKeysetCacheEntry>;
    fn set_keyset(&self, mint: &str, keyset_id: Id, entry: ClientKeysetCacheEntry) -> Result<(), String>;
    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id>;
    fn list_keysets_for_unit(&self, mint: &str, unit: &CurrencyUnit) -> Vec<(Id, ClientKeysetCacheEntry)>;

    // Time & Crypto
    fn now_seconds(&self) -> u64;
    fn compute_channel_secret(&self, sender_pubkey_hex: &str, receiver_pubkey_hex: &str) -> Result<String, String>;
    fn sign_with_tweaked_key(&self, signer_pubkey_hex: &str, message_hex: &str, tweak_scalar_hex: &str) -> Result<String, String>;
}
```

Opening persistence is insert-or-verify: an identical retry is accepted, while
different opening data or an existing funded channel is never replaced.
Completion is likewise complete-or-verify, so replaying the same funding proofs
is safe and preserves payment and lifecycle state. Recovery reads distinguish a
missing opening from storage or deserialization failure. SQLite clients may use
`SqliteClientStorage::open_read_only` to inspect an existing database without
creating it, enabling WAL, initializing schema, or running migrations.

---

### Integration Kits

The Bridge and Host traits are deliberately flexible, but most services follow the same pattern: load pricing from config, track usage in a database, and expose management endpoints. To avoid reimplementing this boilerplate, the library provides **integration kits** — ready-made `SpilmanHost` and `SpilmanClientHost` implementations.

Integration kits are available for Rust (`ConfigurableHost`, `ConfigurableClientHost`), TypeScript (`cdk-spilman-kit`), Python, and Go. See [INTEGRATION.md](INTEGRATION.md) for setup guides.

## Data Model: YAML Configuration

The integration kits use a standardized YAML schema for pricing and policy:

```yaml
# Trusted mints and the units they support
mints:
  "http://localhost:3338": [sat, msat, usd]

# Optional scaling divisor: amount_due = ceil(raw_total / pricing_scale)
pricing_scale: 1000

# Per-unit pricing and capacity policies
pricing:
  sat:
    min_capacity: 100
    variables:
      blobs: 500    # 0.5 sat per blob
      bytes: 10     # 0.01 sat per byte
  usd:
    min_capacity: 10
    max_amount_per_output: 64
    variables:
      blobs: 100
      bytes: 2
```

---

## System Behavior

### Keyset Rotation Handling

Post-expiry sender refunds deliberately do not use the automatic retry helpers
below. The application selects a separate output keyset and persists one immutable
`PreparedSenderRefund` containing channel ID, mint/unit, complete output keyset
metadata, net amount, deterministic output secrets/blindings, and the signed
all-funding-input swap. The old funding keyset still determines input fees;
output-keyset fees are not fees for this transaction's inputs. Time eligibility
is strict (`now > expiry`); fee multiplication, totals and subtraction are checked,
and zero-net refunds are rejected explicitly.

Refund output derivation version 1 domain-separates loose outputs with
`sender_refund_loose`. Secret and blinding preimages begin with the channel
secret, sender's 32-byte private key, caller-owned 32-byte attempt context,
canonical serialized output `KeysetInfo`, and big-endian `u32` version 1; they end
with
`channel_id|sender_refund_loose|amount|per_amount_index|secret` or `|blinding`.
Amounts use the existing largest-first decomposition, limited by the channel's
maximum output amount. A new context produces distinct successor outputs even
on the same keyset. Binding to the sender's private key prevents the receiver,
who also knows the shared channel secret, from deriving loose refund proofs even
if the context is known. Derivation preimages contain the sender private key and
must never be logged or exposed. The prepared record does not serialize that key,
but its output secrets and blindings are confidential too; protect storage and
do not log the record or send it to the mint. The entire prepared record is
re-derived and compared during pure verification, and the actual refund SIG_ALL
authorization is checked against the channel's sender refund pubkey. Verification
neither signs nor performs I/O.

Opening, refund completion, and sender-close discovery share exact signature
validation: count, per-output amount and keyset, checked totals, mandatory DLEQ
against the expected blinded point, and unblinding with persisted denomination
keys. NUT-09 matching rejects unknown/duplicate/missing outputs and canonicalizes
complete responses into request order. Only two empty arrays mean absent, never
a partial or invalid response. Existing sender-close discovery retains its
ascending-denomination/index algorithm and returns no partial results on errors.
Prepared refund recovery works with historical inactive output keys, not today's
active keyset. Empty restore cannot resolve submission ambiguity by itself.

Supported generated close/refund transactions spend all funding inputs atomically;
under that assumption one representative suffices for NUT-07 state checks. This
is not a guarantee about arbitrary transactions. Exactly the first funding proof's
Y must be returned: the first proof is selected specifically because generated
SIG_ALL transactions attach the witness only to the first input.

Witness-shape classification is advisory, not cryptographic settlement proof or
a prerequisite for checked recovery. A valid receiver close accepted by an honest
mint may contain unrelated extra signatures and thus classify as `Unknown` under
the exact-count heuristic. After exact persisted-refund restore, checked
sender-close discovery remains available for `Unknown`; neither malformed restore
responses nor an unrecognized witness justify skipping validation or importing
partial results. Applications own retry budgets, keyset refresh, ambiguous-attempt
reconciliation, proof custody, and persistence. See the
[integration guide](INTEGRATION.md#post-expiry-sender-refunds-rust).

The implementation handles mint keyset rotation using a **Persistent Cache** strategy:

1.  **Retention**: When the keyset cache is refreshed, existing keysets are never removed from the local store, even if they are no longer returned by the mint's `/v1/keysets` endpoint.
2.  **Validation**: Channels opened while a keyset was active remain valid and closable after the mint deactivates that keyset.
3.  **Active Flag**: The bridge uses an `active` flag to select output keysets for *new* swap outputs, while input proofs and existing channels may reference old or inactive keysets if the mint still accepts them.
4.  **Cache-First Retry**: Auto-open and close helpers ensure the cache has at least one keyset for the relevant `(mint, unit)` before entering the retry helper. Selection inside the helper is cache-only. If the mint explicitly rejects the first swap with a retryable keyset error, the helper refreshes, reselects, and retries once only if the selected output keyset changed. Auto-open persists the rejected first record as `OpeningFailed`; a changed-keyset retry creates a distinct opening and may leave that audit record in storage. Ambiguous submission failures are not retried and remain `OpeningFromSwap`.

Custom `SpilmanHost` implementations expose this cache preflight through
`has_keysets_for_unit(mint, unit)`. Its intended meaning is inactive-inclusive:
return true when the host has any cached keyset for that mint/unit, not only an
active output keyset.

### Channel Closing Flow

There are two server close orchestration styles.

**Explicit Sans-IO flow:**

1. `prepare_*_close_transition` validates and returns a pending transition containing the exact `PreparedClose`, without storage mutation.
2. `mark_prepared_close_closing` durably stores expiry/payment authorization and enters `Closing` before mint I/O.
3. The caller submits `transition.prepared_close.swap_request`.
4. `complete_prepared_close` verifies and unblinds without storage mutation.
5. `mark_completed_close` persists proofs and enters `Closed`.

The preparation, transition, and completion are serializable secret-bearing
values with redacted `Debug`. Applications can persist them as immutable journal
payloads. Completion validates the deterministic output commitment and exact
signature amounts/keysets/DLEQ with historical keys, using the same checked
signature primitive as opening and refund completion. NUT-09 completion through
`complete_prepared_close_restore` matches exact output identities and canonicalizes
reordered pairs; two empty arrays are absence, while partial results are errors.
Neither this API nor the core host's `Closing` marker implements execution
history, funding/payment journal binding, replay authorization, or atomic
payment-versus-close coordination. Those remain application responsibilities.

**Convenience/replay flow:** after `Closing` is durable,
`execute_close_for_closing_channel` selects an active output keyset, reconstructs
and submits the close swap, handles completion, and persists `Closed`. It permits
at most one retry after a recognized rejection when refresh selects a changed
keyset. An empty-cache preflight refresh failure is returned. Post-rejection
refresh is best-effort; if it fails or does not produce a changed keyset, the
first mint rejection is returned without another submission.

### NUT-00 Error Handling

The bridge implements intelligent error handling based on [NUT-00](https://github.com/cashubtc/nuts/blob/main/00.md) error codes returned by the mint.

#### Error Code Categories

| Code Range | Category | Retry Behavior |
|------------|----------|----------------|
| 10xxx | Proof/Token verification | Fail immediately |
| 11xxx | Input/Output errors (e.g., spent proofs) | Fail immediately |
| 12000..13000 | Keyset errors (not found, inactive) | Retry after refresh |
| 99999 | Unknown keyset (NutMix workaround) | Retry after refresh |
| 20xxx+ | Quote/Payment/Auth errors | Fail immediately |

#### Selective Retry Logic

When a swap fails during channel closing:

1. **Parse the NUT-00 error code** from the mint's JSON response (`{"code": 12001, "detail": "..."}`)
2. **Check if retryable**: Only keyset errors (`12000..13000`) and the NutMix unknown-keyset workaround (`99999`) trigger retry
3. **If retryable**: refresh keysets from the mint, reselect the active output keyset from cache, and rebuild the swap request
4. **Skip unchanged retry**: if refresh selects the same output keyset id, fail with the first mint rejection instead of resubmitting the same stale swap
5. **If changed**: submit one rebuilt swap attempt
6. **If not retryable**: fail immediately without refresh or retry

This prevents wasted retries on errors that can't be fixed by refreshing keysets (e.g., proofs already spent, signature invalid). The error code is preserved in the `CloseError` for callers to inspect.

#### WASM Error Boundary

Errors crossing the WASM-JS boundary must preserve their string content. The `js_error_to_string()` helper extracts string values from `JsValue` errors, ensuring NUT-00 JSON is passed through cleanly rather than being wrapped as `JsValue("...")`.
