# Changelog

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

Before 1.0, breaking public API changes increment the minor version; compatible
fixes increment the patch version. Coordinate binding/kit releases with the Rust
library. Version numbers describe library releases, not Cashu keyset versions or
the Spilman wire protocol. A version bump in a PR is not a published release/tag.
