import requests
import json
from .stores import SpilmanStores, KeysetCacheEntry

DEFAULT_TIMEOUT = 10

def build_keyset_info_json(keyset_id: str, unit: str, keys_data: dict, input_fee_ppk: int) -> str:
    keyset_info = {
        "keysetId": keyset_id,
        "unit": unit,
        "keys": keys_data,
        "inputFeePpk": input_fee_ppk,
        "amounts": sorted([int(k) for k in keys_data.keys()], reverse=True),
    }
    return json.dumps(keyset_info)

def fetch_all_keysets_from_mint(mint_url: str, supported_units: list):
    resp = requests.get(f"{mint_url}/v1/keysets", timeout=DEFAULT_TIMEOUT)
    resp.raise_for_status()
    keysets = resp.json()["keysets"]

    result = []
    for k in keysets:
        if k.get("unit") not in supported_units:
            continue
        keys_resp = requests.get(f"{mint_url}/v1/keys/{k['id']}", timeout=DEFAULT_TIMEOUT)
        keys_resp.raise_for_status()
        keys_data = keys_resp.json()["keysets"][0]["keys"]
        info_json = build_keyset_info_json(k["id"], k["unit"], keys_data, k.get("input_fee_ppk", 0))
        result.append({
            "id": k["id"],
            "unit": k["unit"],
            "active": k.get("active", False),
            "info_json": info_json,
        })
    return result

def refresh_keyset_cache(stores: SpilmanStores, mint_url: str, supported_units: list):
    try:
        keysets = fetch_all_keysets_from_mint(mint_url, supported_units)
        for k in keysets:
            stores.keyset_cache[(mint_url, k["id"])] = KeysetCacheEntry(
                info_json=k["info_json"],
                active=k["active"],
                unit=k["unit"]
            )
    except Exception as e:
        print(f"  [Spilman] Failed to refresh keysets from {mint_url}: {e}")
