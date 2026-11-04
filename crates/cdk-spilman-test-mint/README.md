# Spilman test mint: experimental rerandomized V2 swaps

Milestone 1 implements the **mint swap primitive** from
[cashubtc/nuts#463](https://github.com/cashubtc/nuts/pull/463), while ordinary
swaps and the existing Spilman channel construction remain supported. Channel
mode TLVs, channel payment-signing changes, direct payout redesign, and channel
close/recovery APIs are later milestones.

## Exact implementation baseline

- Draft specification: `1d528eb2a5a2487e02b3a55989f160cedabd312c`.
- Upstream implementation proposal: cashubtc/cdk#2735,
  `365959807dd93703abc65597fba73eac7d41ef57`.
- Base CDK release: v0.18.1 (`a056e0f0`).
- Backport: [SatsAndSports/cdk at
  `da5cf282dd070772af830fa5215630f059e5f1ad`](https://github.com/SatsAndSports/cdk/commit/da5cf282dd070772af830fa5215630f059e5f1ad).

All workspace CDK/Cashu crates use that same immutable fork revision. The
pin applies to the library as well as its tests; it is not a test-only override.
The backport imports only the primitive's mint, protocol models, SQLite/common SQL
storage, tests, and wallet initializer adjustments. It does not move to CDK
development main or update the underlying package versions. The fork includes
`SPILMAN_RERANDOMIZATION_BACKPORT.md` with provenance and validation commands.
Its second commit adds deterministic derived-collision retry/exhaustion tests.
PostgreSQL and upstream-generated FFI packages are not validated targets of this
milestone; the test mint uses SQLite.

## Run

The normal daemon and its options are unchanged:

```sh
cargo run -p cdk-spilman-test-mint -- --listen-port 3338
```

The daemon uses a **public fixed test seed** and fake Lightning: never fund it
with real money. Existing callers can still select persistent storage through
`build_persistent_test_mint(config, path)`; this milestone adds no persistence API
or CLI options. The CDK backport adds spent-input recovery storage, so existing
persistent test databases should remain paired with their matching mint version.

Check `/v1/info` for `nuts["3"].rerandomize == true`. SQLite supports atomic
signature/spent-input randomness commits.
Each request still opts in explicitly with `rerandomize: true`; absent or false
uses ordinary signing/issuance. Opted-in authorization never falls back to an
ordinary signature. The wire primitive is V2 secp256k1, not BLS/V3.

## Test

```sh
make test-mint-rerandomization
make test-mint-rerandomization-backend
```

The first command runs independent fixed transcript/digest/scalar/point/signature
vectors, direct real-CDK-mint calls, and a real mint router over loopback
HTTP/WebSocket. Both mint scenarios use the existing `create_test_mint()` builder
with in-memory SQLite and **explicit zero fees**. It checks:

- Ordinary absent/false flags, no randomness in ordinary responses/states, and
  ordinary NUT-09 restore.
- Rejection of non-SIG_ALL inputs; two-party P2PK thresholds; HTLC receiver/refund
  authorization; rejection of ordinary and obsolete raw-point mode signatures.
- Previously signed original points do not block opted-in issuance.
- Duplicate originals, changed order, points and amounts reject without spending
  the inputs or disclosing randomness.
- Both inputs of a two-input/two-output swap expose one shared committed `R`.
- The HTTP test retains original outputs/secrets/blindings in memory, discards
  the response body, obtains `R` from NUT-07, restores derived outputs through NUT-09,
  verifies mint and transferable DLEQs, and spends the recovered ordinary proofs.
- NUT-17 live spent updates and new-subscription snapshots retain the same `R`; any
  observed pending/unspent notification omits it. The HTTP test does not require
  observing a transient pending notification.
- Recovery rejects pending, incomplete, wrong-identity, inconsistent-R and
  noncanonical-R state sets.

The direct-call test also spends each of two rerandomized outputs separately,
verifying their value and transferable DLEQs. These tests cover the mint primitive,
not the actual Alice/Charlie channel APIs, which require later channel integration.
No subprocess, crash/restart harness, or disk-backed recovery fixture is added.

The backend command discovers the exact CDK source from Cargo metadata and runs
its focused tests. It covers deterministic infinity/collision retries, bounded
retry exhaustion without spending, pending/precommit nondisclosure, incomplete
saga cleanup, backend recovery, capability gates, and SQLite
migration/reopen behavior. No production randomness injection hook is exposed.
Both layers run in Rust CI; ordinary channel regressions retain their normal fees
and published channel vectors.
