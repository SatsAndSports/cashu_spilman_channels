#!/usr/bin/env bash
set -euo pipefail

# Run deterministic saga/collision tests in the exact CDK checkout selected by
# this workspace's lockfile. No branch-head lookup or independent dependency pin.
root="$(git rev-parse --show-toplevel)"
manifest="$(cargo metadata --locked --format-version 1 --manifest-path "$root/Cargo.toml" | python3 -c '
import json, sys
packages = json.load(sys.stdin)["packages"]
matches = [p["manifest_path"] for p in packages if p["name"] == "cdk" and p.get("source", "").startswith("git+https://github.com/SatsAndSports/cdk.git?")]
if len(matches) != 1:
    raise SystemExit("expected exactly one pinned CDK fork")
print(matches[0])
')"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}"
cargo test --locked --manifest-path "$manifest" -p cashu --features mint,wallet --lib rerandom
cargo test --locked --manifest-path "$manifest" -p cdk --no-default-features --features mint,wallet --lib rerandom
cargo test --locked --manifest-path "$manifest" -p cdk-sqlite --features mint,wallet --lib rerandom
