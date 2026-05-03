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

### Blinding Derivation

Channel-secret based derivations use **pipe-delimited decimal text** for hash inputs to ensure 100% cross-platform consistency.

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
                 │                    ▲
                 │    (unilateral)    │
                 └────────────────────┘
```

- **Open**: Created when a client registers a funded channel. The server accepts payments, tracks usage, and persists the highest-balance update.
- **Closing**: A cooperative close has been initiated. The swap request is prepared but not yet submitted to the mint. No further payments are accepted.
- **Closed**: The mint has processed the swap. Receiver and sender proofs have been unblinded and stored. The channel is settled.

### Channel Lifecycle (Client Perspective)

```
      open_channel_from_token
                 │
                 ▼
        OpeningFromSwap ──► Open ──► Closed
                 │           ▲
                 └───────────┘
                    restore
```

- **OpeningFromSwap**: Initial state when `open_channel_from_token` starts. The channel parameters and input token are persisted *before* the funding swap is submitted. This ensures that if the process crashes or the mint times out, the user doesn't lose their input ecash.
- **Open**: The funding swap has succeeded and the 2-of-2 multisig funding proofs are stored. The channel is ready for payments.
- **Closed**: The channel has been closed (cooperatively or unilaterally).

A channel stuck in `OpeningFromSwap` can be recovered using the `restore_funding_proofs` method, which uses NUT-09 to fetch the signatures if the swap actually succeeded on the mint's side. If the swap never reached the mint, the original `input_token` remains unspent and can be reclaimed.

Transitions:
- `→ Open`: Client funds a channel and registers it via the funding endpoint.
- `Open → Open`: Normal payment — balance increases, usage is recorded.
- `Open → Closing`: Cooperative close requested, where the server accepts payment for only what's actually due, allowing the client to 'undo' any earlier overpayment.
- `Closing → Closed`: Mint swap succeeds and proofs are unblinded.
- `Open → Closed`: Unilateral close (server submits the latest payment directly).

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
    fn save_opening_from_swap_channel(&self, channel_id: &str, opening: ClientChannelOpeningFromSwap);
    fn mark_channel_open(&self, channel_id: &str, funding_proofs_json: &str);
    fn get_channel_opening_from_swap(&self, channel_id: &str) -> Option<ClientChannelOpeningFromSwap>;
    fn get_channel_funding(&self, channel_id: &str) -> Option<ClientChannelFunding>;

    // Payment State (mutable)
    fn get_payment_state(&self, channel_id: &str) -> Option<ClientPaymentState>;
    fn record_payment(&self, channel_id: &str, state: ClientPaymentState);

    // Lifecycle
    fn get_channel_state(&self, channel_id: &str) -> ClientChannelState;
    fn mark_channel_closed(&self, channel_id: &str);
    fn list_channel_ids(&self) -> Vec<String>;
    fn delete_channel(&self, channel_id: &str);

    // Time & Crypto
    fn now_seconds(&self) -> u64;
    fn compute_channel_secret(&self, sender_pubkey_hex: &str, receiver_pubkey_hex: &str) -> Result<String, String>;
    fn sign_with_tweaked_key(&self, signer_pubkey_hex: &str, message_hex: &str, tweak_scalar_hex: &str) -> Result<String, String>;
}
```

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

The implementation handles mint keyset rotation using a **Persistent Cache** strategy:

1.  **Retention**: When the keyset cache is refreshed, existing keysets are never removed from the local store, even if they are no longer returned by the mint's `/v1/keysets` endpoint.
2.  **Validation**: Channels opened while a keyset was active remain valid and closable after the mint deactivates that keyset.
3.  **Active Flag**: The bridge uses an `active` flag to decide which keysets are acceptable for *new* channels, while allowing *existing* channels to use their original keysets.

### Channel Closing Flow

Closing is orchestrated by the bridge in two stages:

1. **Sync stage** (`prepare_cooperative_close_for_execution`): Validates signatures, verifies balance, and creates the swap request.
2. **Async stage**: Submits the swap to the mint, retries on keyset error, unblinds signatures, verifies DLEQ, and calls the `mark_channel_closed` host hook.

### NUT-00 Error Handling

The bridge implements intelligent error handling based on [NUT-00](https://github.com/cashubtc/nuts/blob/main/00.md) error codes returned by the mint.

#### Error Code Categories

| Code Range | Category | Retry Behavior |
|------------|----------|----------------|
| 10xxx | Proof/Token verification | Fail immediately |
| 11xxx | Input/Output errors (e.g., spent proofs) | Fail immediately |
| 12xxx | Keyset errors (not found, inactive) | Retry after refresh |
| 99999 | Unknown keyset (NutMix workaround) | Retry after refresh |
| 20xxx+ | Quote/Payment/Auth errors | Fail immediately |

#### Selective Retry Logic

When a swap fails during channel closing:

1. **Parse the NUT-00 error code** from the mint's JSON response (`{"code": 12001, "detail": "..."}`)
2. **Check if retryable**: Only keyset errors (12xxx range) trigger retry
3. **If retryable**: Refresh keysets from mint, rebuild swap request, retry once
4. **If not retryable**: Fail immediately without refresh or retry

This prevents wasted retries on errors that can't be fixed by refreshing keysets (e.g., proofs already spent, signature invalid). The error code is preserved in the `CloseError` for callers to inspect.

#### WASM Error Boundary

Errors crossing the WASM-JS boundary must preserve their string content. The `js_error_to_string()` helper extracts string values from `JsValue` errors, ensuring NUT-00 JSON is passed through cleanly rather than being wrapped as `JsValue("...")`.
