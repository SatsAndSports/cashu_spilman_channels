import hashlib
import json
import pytest
from cdk_spilman import (
    discover_keysets_json, select_active_keyset_json, build_keyset_info_from_responses,
    KEYSET_VERSIONS_V1_AND_V2,
)

PUBKEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
V1 = "00" + hashlib.sha256(bytes.fromhex(PUBKEY)).hexdigest()[:14]
V2 = "01" + hashlib.sha256(f"1:{PUBKEY}|unit:sat".encode()).hexdigest()
FUTURE = {"id": "02opaque", "unit": "sat", "active": True, "keys": False}


@pytest.mark.parametrize("position", [0, 1, 2])
def test_bindings_and_network_discovery(monkeypatch, position):
    from cdk_spilman_kit.keysets import fetch_all_keysets_from_mint
    entries = [
        {"id": V1, "unit": "sat", "active": False},
        {"id": V2, "unit": "sat", "active": True},
    ]
    entries.insert(position, FUTURE)
    listing = json.dumps({"keysets": entries})
    report = json.loads(discover_keysets_json(listing))
    assert len(report["keysets"]) == 2
    assert len(report["skipped"]) == 1
    assert report["unsupported_active_units"] == []
    assert select_active_keyset_json(listing, "sat", json.dumps({"allowed_versions": KEYSET_VERSIONS_V1_AND_V2})) == V2
    with pytest.raises(ValueError, match="compatible"):
        select_active_keyset_json(listing, "sat", '{"allowed_versions":["v1"]}')

    calls = []

    class Response:
        def __init__(self, text):
            self.text = text
        def raise_for_status(self):
            pass

    def get(url, **kwargs):
        calls.append(url)
        if url.endswith("/v1/keysets"):
            return Response(listing)
        id = url.rsplit("/", 1)[1]
        assert id in [V1, V2]
        return Response(json.dumps({"keysets": [FUTURE, {"id": id, "unit": "sat", "keys": {"1": PUBKEY}}]}))

    monkeypatch.setattr("requests.get", get)
    result = fetch_all_keysets_from_mint("https://mint.test", ["sat"])
    assert len(calls) == 3
    assert [k["active"] for k in result] == [False, True]


def test_future_only_warning_and_strict_errors(monkeypatch):
    from cdk_spilman_kit.demo import fetch_active_keyset_info
    class Response:
        text = json.dumps({"keysets": [FUTURE]})
        def raise_for_status(self):
            pass
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: Response())
    with pytest.warns(UserWarning, match="unsupported active"), pytest.raises(ValueError, match="compatible"):
        fetch_active_keyset_info("https://mint.test")
    for id in ["00bad", "01bad", "xx", "+0"]:
        with pytest.raises(ValueError):
            discover_keysets_json(json.dumps({"keysets": [{"id": id}]}))
    listing = json.dumps({"keysets": [{"id": V2, "unit": "sat", "active": True}]})
    with pytest.raises(ValueError):
        build_keyset_info_from_responses(listing, json.dumps({"keysets": [{"id": V1, "unit": "sat", "keys": {"1": PUBKEY}}]}), V2)
