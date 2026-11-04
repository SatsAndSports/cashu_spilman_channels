# Changelog

## 0.3.0 — Unreleased

### Breaking networking API

- Rust mint traits return `MintRequestError` evidence instead of string errors.
  Python/Go/WASM callbacks return complete `{status, body}` JSON envelopes;
  ordinary exceptions remain transport failures. Rebuild bindings and update
  custom adapters together; see [the integration guide](INTEGRATION.md#typed-mint-outcomes).
- Retry decisions use validated HTTP 400 rejections with known code 12001/12002,
  not display-message parsing, all 12xxx codes, or the historical 99999 workaround.
  Uncertain opening outcomes retain their pending records; high-level opening
  cannot resubmit an existing record. No storage migration or automatic reset.

### Breaking protocol change

- Replace the ad hoc pipe-delimited channel-ID preimage with a versioned,
  canonical Lightning-style TLV stream. Types and lengths use `BigSize`,
  unsigned integers use minimal big-endian `tu64`, byte values are no longer
  hex-encoded inside the preimage, and all current parameter types are required
  even records.
- Derive the channel ID with tagged SHA-256 under
  `Cashu_Spilman_channel_id`. The external channel ID remains 32 lowercase
  bytes, represented as 64 lowercase hexadecimal characters.
- Regenerate the independent NUT-XX compatibility vectors and every downstream
  deterministic funding, commitment, key-tweak, mint-signature, and `SIG_ALL`
  fixture.
- Existing channels are cryptographically incompatible because the channel ID
  participates in their deterministic key and output derivations. There is no
  automatic migration or legacy derivation mode. Settle or recover outstanding
  0.2.x channels with compatible 0.2.x software before switching. Preserve the old
  software, keys, and wallet/channel data until completion; resetting funded state
  is not an upgrade procedure. Coordinate both participants and rebuild all
  bindings/kits together, then create new 0.3.0 channels.

### Runtime and maintenance

- Require Python 3.11 or newer; Python 3.9 and 3.10 are no longer supported.
- Await initial TypeScript keyset discovery before returning configured servers.
- Bound Rust reqwest mint responses to 4 MiB of decoded UTF-8 bytes and async
  settlement swaps to 30 seconds per request; retain ambiguous-outcome recovery.
- Include the dependency refreshes and security fixes merged since 0.2.0.

## 0.2.0 — 2026-10-07

### Breaking API changes

- Rust `open_channel_from_token_auto`, `open_channel_from_proofs_auto`, and
  `fetch_active_keyset_info` now require a `KeysetSelectionPolicy`. Use
  `KeysetVersions::V1_AND_V2` to explicitly retain the previous selection range.
- `refresh_keysets_response` returns `KeysetDiscovery` rather than a raw response
  string. `fetch_all_keysets_from_mint` returns `MintKeysetDiscovery`; use `.keysets`
  for verified key material and `.report` for metadata/diagnostics.
- Go's demo active-keyset fetcher requires a selection policy. Python/TS demo
  helpers accept allowed versions and default to the fixed V1-and-V2 set.
- Rebuild/install the matching 0.2.0 Python, Go, and WASM/TS bindings and kits.
  Workspace Rust crates inherit the shared version. No database/schema migration
  or cryptographic channel-ID change is introduced by this release.

### Discovery and selection

- Identify versions by the first decoded byte: 00 is V1, 01 is V2. Skip other
  prefixes before interpreting unknown metadata or requesting their keys. Missing
  or non-hex prefixes and malformed supported IDs remain errors.
- Preserve inactive supported keysets and existing cached records. Selection
  policy never filters input proofs or recovery metadata.
- Match requested key material by ID instead of accepting the first key map.
  Rust/Python/WASM fetching verifies the keyset commitment and response metadata.
- Expose skipped-version diagnostics and warn when a unit advertises unsupported
  active entries without any supported active entry. Empty/future-only listings
  are successful discovery, followed by a no-compatible-keyset selection result.
- Add fixed V1, V2, and V1-and-V2 presets; arbitrary supported-version sets are
  accepted. Unknown policy versions fail rather than enabling unimplemented use.

## Versioning policy

Before 1.0, breaking public API or protocol changes increment the minor version;
compatible fixes increment the patch version. Coordinate binding/kit releases
with the Rust library. Version numbers describe library releases, not Cashu
keyset versions or the Spilman wire protocol. A version bump in a PR is not a
published release/tag.
