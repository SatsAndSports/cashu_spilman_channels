"""Integration tests for demo helpers.

These tests require a running mint and will be skipped if MINT_URL is not set.
"""

import json
import os
import pytest

from cdk_spilman_kit.demo import fetch_active_keyset_info, mint_plain_proofs


MINT_URL = os.environ.get("MINT_URL")


@pytest.mark.skipif(not MINT_URL, reason="MINT_URL not set")
class TestDemoHelpers:
    """Integration tests for demo helpers."""

    def test_fetch_active_keyset_info(self):
        """Test fetching active keyset info from mint."""
        ki = fetch_active_keyset_info(MINT_URL, "sat")

        # Verify required fields
        assert "keysetId" in ki
        assert "unit" in ki
        assert "keys" in ki
        assert "inputFeePpk" in ki

        # Check types
        assert isinstance(ki["keysetId"], str)
        assert len(ki["keysetId"]) > 0
        assert ki["unit"] == "sat"
        assert isinstance(ki["keys"], dict)
        assert len(ki["keys"]) > 0

        print(f"Keyset ID: {ki['keysetId']}")
        print(f"Number of keys: {len(ki['keys'])}")

    def test_mint_plain_proofs(self):
        """Test minting plain proofs from mint."""
        # 1. Fetch keyset info
        ki = fetch_active_keyset_info(MINT_URL, "sat")
        ki_json = json.dumps(ki)

        # 2. Mint plain proofs
        amount = 100
        proofs_json = mint_plain_proofs(MINT_URL, amount, ki_json, "sat")

        # 3. Parse result as JSON array
        proofs = json.loads(proofs_json)

        assert isinstance(proofs, list)
        assert len(proofs) > 0
        print(f"Minted {len(proofs)} proofs")

        # 4. Verify proofs have expected fields
        total_amount = 0
        for proof in proofs:
            assert "amount" in proof
            assert "id" in proof
            assert "secret" in proof
            assert "C" in proof

            total_amount += proof["amount"]

        # Total should be at least the requested amount
        assert total_amount >= amount
        print(f"Total proof amount: {total_amount} sat")
