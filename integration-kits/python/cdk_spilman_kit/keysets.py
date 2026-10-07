import requests
import json
import warnings
from cdk_spilman import discover_keysets_json, build_keyset_info_from_responses
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
    report = json.loads(discover_keysets_json(resp.text))
    keysets = report["keysets"]
    for unit in report["unsupported_active_units"]:
        warnings.warn(f"Mint {mint_url} has only unsupported active keysets for unit {unit}; supported: V1 (00), V2 (01)", stacklevel=2)

    result = []
    for k in keysets:
        if k.get("unit") not in supported_units:
            continue
        keys_resp = requests.get(f"{mint_url}/v1/keys/{k['id']}", timeout=DEFAULT_TIMEOUT)
        keys_resp.raise_for_status()
        info_json = build_keyset_info_from_responses(resp.text, keys_resp.text, k["id"])
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
