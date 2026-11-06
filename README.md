# Spilman Channels for Cashu

> Unidirectional payment channels for Cashu ecash — enabling instant, off-chain micropayments.

This repository contains the reference implementation of Spilman-style payment channels for the [Cashu](https://cashu.space) protocol. It enables services to accept streaming micropayments without round-trip latency or on-chain settlement for every request.

The primary Rust implementation lives in the `cdk-spilman` crate in this workspace.
Active demos, test harnesses, and the local test mint now live directly at repo root.

**Status: Early Alpha**
Experimental protocol. APIs and data models are subject to breaking changes.

The development version is **0.3.0** (early alpha). Breaking pre-1.0 API or protocol
changes increment the minor version; compatible fixes increment the patch version.
A version bump does not imply a published package or release tag.

### Upgrading from 0.2.x

**0.3.0 changes channel-ID derivation and is cryptographically incompatible with
existing 0.2.x channels.** Coordinate the upgrade across both channel participants
and rebuild the matching Rust, Python, Go, and WASM/TypeScript bindings and kits.
Settle or recover outstanding 0.2.x channels with compatible 0.2.x software before
switching. Preserve that software, keys, and wallet/channel data until recovery is
complete; do not delete or reset funded state. There is no automatic migration or
legacy derivation mode. Create new channels with 0.3.0 after upgrading.
See [CHANGELOG.md](CHANGELOG.md) for details.

### Choosing keyset versions

```rust
use cdk_spilman::{KeysetSelectionPolicy, KeysetVersions};

let policy = KeysetSelectionPolicy {
    allowed_versions: KeysetVersions::V1_AND_V2,
};
// Pass policy to auto-opening or active-keyset selection APIs.
```

`V1`, `V2`, and `V1_AND_V2` are fixed sets; `library_supported()` deliberately
follows future library capabilities. Discovery understands prefixes `00` and `01`
and skips unknown versions, reporting diagnostics instead of failing the entire
mint refresh. Selection restrictions do not discard old proofs or cached metadata.
See [INTEGRATION.md](INTEGRATION.md#keyset-discovery-and-selection) for bindings.

Durable receiver integrations can authenticate exact close preparations and use
atomic `SpilmanStorage` close-journal CAS operations. Custom storage implementations
must implement the new journal methods; see [INTEGRATION.md](INTEGRATION.md#exact-close-completion).

## Key Features

- **Efficiency**: Unlimited micropayments via a single funding transaction.
- **Privacy**: Uses P2BK (Pay-to-Blinded-Key) to prevent mint correlation.
- **Portability**: Core protocol in Rust with bindings for WASM (JS/TS), Python, and Go.
- **Deterministic**: Both parties independently compute commitment outputs using a common `_channel secret_`.
- **Sans-IO Primitives**: Client channel opening, server funding validation, and server close completion expose explicit prepare/validate/complete/record steps so applications can own networking, persistence, retry, and recovery policy.
- **Exact Close Completion**: Serializable close preparations and completions support application-owned journals. `complete_prepared_close_restore` matches NUT-09 outputs in prepared order and checks signatures against persisted historical output keys. These primitives do not provide a durable close journal or authorize replay by themselves; see [INTEGRATION.md](INTEGRATION.md#exact-close-completion).

---

## Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Cryptographic protocol and system design |
| [INTEGRATION.md](INTEGRATION.md) | Server and Client integration guide |
| [SPILMAN_DEVELOPMENT.md](SPILMAN_DEVELOPMENT.md) | Contributor guide and environment setup |

---

## Quick Start (Rust)

1. **Add Dependency**:
   ```toml
   cdk-spilman = { version = "0.3", default-features = false, features = ["spilman-axum", "configurable-host-reqwest"] }
   ```

2. **Run ASCII Art Server**:
   ```bash
   cd examples/rust-ascii-art
   cargo run
   ```

3. **Run TypeScript Demo**:
   ```bash
   cd examples/ts-ascii-art
   npm install && npm start
   ```

## Experimental test-mint rerandomization

The Rust `cdk_spilman::swap_completion` module now supplies pure checked completion
and restore-point derivation for ordinary and rerandomized swaps, plus a canonical
external-signer digest. It verifies both blind-signature and unblinded-proof DLEQs.
The Rust channel core also accepts
`params.with_commitment_mode(CommitmentMode::Rerandomized)` before funding derivation.
Use `CommitmentOutputs::complete_swap_response` with the full mint response to
retain mint randomness during completion. Existing constructors select ordinary
mode. To open new rerandomized channels with the Rust client bridge, construct it
with `.with_commitment_mode(CommitmentMode::Rerandomized)`. See
[channel-mode integration](INTEGRATION.md#channel-commitment-mode) for opening,
binding and recovery APIs.
See [primitive API](INTEGRATION.md#checked-swap-completion-primitives) and the
[dual-mode design](ARCHITECTURE.md#dual-mode-channels).

The test mint now supports the opt-in V2 swap primitive proposed in
[NUT PR #463](https://github.com/cashubtc/nuts/pull/463), alongside ordinary swaps.
This is mint-side test infrastructure; existing Spilman channels still use their
ordinary mode and unchanged channel-ID vectors. See the
[test-mint guide](crates/cdk-spilman-test-mint/README.md) for the exact CDK backport,
direct-call, HTTP lost-response recovery, and backend tests. The exact CDK fork
pin applies workspace-wide, including the library, rather than only to tests.

## Rust HTTP adapter limits

Mint networking now returns typed failure evidence (`MintRequestError`) rather
than raw error strings. Custom Rust implementations and Python/Go/WASM networking
callbacks must adopt the new contract and rebuild matching bindings. See
[typed mint outcomes](INTEGRATION.md#typed-mint-outcomes) for the callback envelope,
retry rules, and handling of uncertain submissions.

With `configurable-host-reqwest`, mint response bodies are limited to **4 MiB of
decoded bytes**, including compressed responses. Mint JSON must be valid UTF-8.
`ReqwestNetworking` applies a **30-second total deadline per settlement swap
request**, including reading the body. `ReqwestClientNetworking::new(timeout)`
uses the caller's nonzero total request timeout for swaps, restores, and keyset
queries; server-side keyset discovery uses 15 seconds per request.

Oversized, malformed, truncated, or timed-out responses are transport/read failures,
not evidence that a submitted swap was rejected or unspent. Preserve the prepared
operation and use the existing recovery flow to resolve an ambiguous outcome.

## Ordinary Channel Recovery (Rust)

When a close/refund outcome is uncertain, use the state-first recovery APIs:

- Alice: `sender.recover_funds(&mint, &refund_attempts, &close_output_keysets).await`.
- Charlie: `bridge.recover_close(&channel_id, &close_attempts, &mint).await`.

Both query NUT-07 before NUT-09. Alice tries retained maybe-submitted refunds
first, then discovers her share of Charlie's close if those restores are empty.
Charlie restores his retained close attempts. Verified payouts are returned for
the host to persist/import; neither method submits swaps or mutates storage.
Spent funding without a recovered payout stays unresolved, not a classified refund
or a zero-value close. See [the recovery contract](INTEGRATION.md#state-first-channel-recovery-rust)
for outcomes, historical keys, and host responsibilities. These additive APIs are
Rust-only; existing raw restore/completion primitives remain available.

The obsolete first-proof check, `FundingSpendKind`, signature-based classifiers,
and inferred receiver refund terminal state have been removed. Custom hosts must
use `open`/`closing`/`closed`; unsupported stored refund states fail lookup without
changing or deleting data. See the [state lookup contract](INTEGRATION.md#receiver-channel-state-lookup-breaking-api-update).

## Sender Refunds (Rust)

After `now_seconds > expiry_timestamp`, use
`EstablishedChannel::prepare_sender_refund_after_expiry(sender_secret, now_seconds, output_keyset, derivation_context)`.
Choose an active `KeysetInfo` for the channel's mint/unit independently of the
funding keyset, and use a fresh `[u8; 32]` context for each successor attempt.
Persist the entire `PreparedSenderRefund::to_json()` result before submitting.
It contains confidential output secrets and blindings: protect it and do not log
it. Derivation requires the sender private key; never expose derivation preimages.
Checked submission and NUT-09 recovery use the persisted output keys, including
after rotation; there is no automatic keyset selection or changed-request retry.
See [the refund integration guide](INTEGRATION.md#post-expiry-sender-refunds-rust)
for exact completion APIs and ambiguity handling. These APIs require no feature
flag and are currently Rust-only.

## Project Structure

```
repo/
├── crates/
│   ├── cdk-spilman/                # Canonical core Rust protocol implementation
│   ├── cdk-spilman-test-mint/      # Standalone local test mint
│   ├── cdk-wasm/                   # WASM bindings
│   ├── cdk-spilman-python/         # Python bindings (PyO3)
│   ├── cdk-spilman-go/             # Go bindings (CGO)
│   └── cdk-spilman-server-integration-tests/ # Multi-server test client
├── integration-kits/
│   ├── ts/                         # TypeScript/Express integration kit
│   ├── python/                     # Python integration kit
│   └── go/                         # Go integration kit
├── examples/
│   ├── rust-ascii-art/             # Rust demo (native)
│   ├── ts-ascii-art/               # TypeScript demo
│   ├── python-ascii-art/           # Python demo
│   └── go-ascii-art/               # Go demo
```

## License

Code is licensed under MIT.
