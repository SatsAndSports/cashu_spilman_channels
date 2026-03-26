# AGENTS.md - Spilman / Root Workspace

This repo now has one active role:

- repo root is the canonical home of Spilman code, bindings, demos, shared test harnesses, and the standalone test mint.

## Common Commands

```bash
# Standalone test mint
cargo build -p cdk-spilman-test-mint --manifest-path Cargo.toml

# Auto-spawn mint for a command
scripts/run_with_mint.sh <command...>

# Lint / format
cargo fmt --manifest-path Cargo.toml --all -- --check
cargo clippy --manifest-path Cargo.toml --workspace --all-targets -- -D warnings

# Test suites
make test-suite
make test-all

# Common delegated top-level targets
make test-unit-spilman

# WASM builds
make build-wasm              # Release (with wasm-opt)
WASM_DEV=1 make build-wasm   # Dev (fast, no wasm-opt)

# NUT-00 error handling tests
make test-selective-retry
make test-nut00-errors
```

## Important Paths

| Path | Purpose |
|---|---|
| `crates/cdk-spilman/` | Canonical Rust Spilman implementation |
| `crates/cdk-spilman-test-mint/` | Standalone fakewallet+sqlite test mint |
| `crates/cdk-spilman-interop-tests/` | Upstream `cdk` interoperability tests |
| `crates/cdk-spilman-server-integration-tests/` | Shared multi-server harness |
| `crates/cdk-wasm/` | WASM bindings |
| `integration-kits/` | Python / Go / TS integration kits |
| `examples/` | Demo servers |

## Mint Infrastructure

- Prefer `MINT_URL` when an external mint is available.
- Otherwise, test flows auto-build and spawn `cdk-spilman-test-mintd`.
- The standalone test mint is intentionally minimal: `fakewallet` + in-memory sqlite + mint/swap coverage.

## Rust Workspace Conventions

- edition 2021, MSRV 1.85.0, toolchain pinned to 1.93.0
- no `unsafe`
- no `.unwrap()` in non-test code
- prefer `Self` over repeating the type name in impls
- prefer bounds in `where` clauses instead of inline generic bounds
- use full-path tracing macros (`tracing::info!`, not imported macros)
- prefer `.to_string()` / `.to_owned()` over `.into()` / `String::from()`
- use `match` when both branches contain logic
- use `mod x;` in separate files; only inline test/bench modules
- import `core::fmt` / `std::fmt` module, not individual items

## Project Notes

- if you need live-mint integration for tests, start with `scripts/run_with_mint.sh`
- active tests should use the standalone test mint by default

## Commit Style

Use conventional commits: `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`.

## Useful Docs

| Document | Path |
|---|---|
| Contributor guide | `SPILMAN_DEVELOPMENT.md` |
| Integration guide | `INTEGRATION.md` |
| Architecture notes | `ARCHITECTURE.md` |
