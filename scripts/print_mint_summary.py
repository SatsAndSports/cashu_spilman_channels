#!/usr/bin/env python3
"""Fetch and print a one-line mint summary."""

from __future__ import annotations

import json
import sys
import urllib.request


def preferred_units(units: list[str]) -> list[str]:
    order = {"sat": 0, "msat": 1, "usd": 2}
    unique = sorted(set(units), key=lambda unit: (order.get(unit, 99), unit))
    return unique


def fetch_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as response:
        return json.load(response)


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "Usage: print_mint_summary.py <source> <mint_url>",
            file=sys.stderr,
        )
        return 1

    source = sys.argv[1]
    mint_url = sys.argv[2].rstrip("/")

    try:
        info = fetch_json(f"{mint_url}/v1/info")
        keysets = fetch_json(f"{mint_url}/v1/keysets")
    except Exception as exc:  # pragma: no cover - best-effort CLI helper
        print(f"mint summary fetch failed for {mint_url}: {exc}", file=sys.stderr)
        return 1

    name = info.get("name") or "unknown"
    version = info.get("version") or "unknown"
    units = preferred_units(
        [entry.get("unit", "unknown") for entry in keysets.get("keysets", [])]
    )

    print(
        "MINT_READY "
        f"source={source} "
        f"url={mint_url} "
        f"name={json.dumps(name, ensure_ascii=True)} "
        f"version={json.dumps(version, ensure_ascii=True)} "
        f"units=[{','.join(units)}]"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
