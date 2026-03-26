import sys
from pathlib import Path


KIT_DIR = Path(__file__).resolve().parents[3] / "integration-kits" / "python"
sys.path.insert(0, str(KIT_DIR))

from cdk_spilman_kit import SpilmanStores  # noqa: E402
from cdk_spilman_kit.keysets import refresh_keyset_cache  # noqa: E402
from cdk_spilman_kit.stores import KeysetCacheEntry  # noqa: E402
import cdk_spilman_kit.keysets as keysets  # noqa: E402


def test_refresh_retains_inactive(monkeypatch):
    stores = SpilmanStores()
    mint_url = "http://mint.test"
    stores.keyset_cache[(mint_url, "A")] = KeysetCacheEntry(
        info_json="infoA",
        active=True,
        unit="sat",
    )

    entries = [
        {"id": "A", "unit": "sat", "active": False, "info_json": "infoA"},
        {"id": "B", "unit": "sat", "active": True, "info_json": "infoB"},
    ]

    monkeypatch.setattr(keysets, "fetch_all_keysets_from_mint", lambda _url, _units: entries)

    refresh_keyset_cache(stores, mint_url, ["sat"])

    assert stores.keyset_cache[(mint_url, "A")].active is False
    assert (mint_url, "B") in stores.keyset_cache


def test_refresh_does_not_drop_missing(monkeypatch):
    stores = SpilmanStores()
    mint_url = "http://mint.test"
    stores.keyset_cache[(mint_url, "A")] = KeysetCacheEntry(
        info_json="infoA",
        active=True,
        unit="sat",
    )

    entries = [
        {"id": "B", "unit": "sat", "active": True, "info_json": "infoB"},
    ]

    monkeypatch.setattr(keysets, "fetch_all_keysets_from_mint", lambda _url, _units: entries)

    refresh_keyset_cache(stores, mint_url, ["sat"])

    assert (mint_url, "A") in stores.keyset_cache
    assert (mint_url, "B") in stores.keyset_cache
