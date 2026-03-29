"""
Integration tests for CDK Spilman Python bindings.

These tests require a Cashu mint running at MINT_URL (default: http://localhost:3338).

Run with: MINT_URL=http://localhost:3338 pytest tests/ -v
"""

import base64
import json
import os
import time

import pytest
import requests

import cdk_spilman


def get_mint_url():
    return os.environ.get("MINT_URL", "http://localhost:3338")


def fetch_active_keyset(mint_url: str, unit: str) -> dict | None:
    """Fetch the active keyset for a unit from the mint."""
    try:
        # Get keysets
        resp = requests.get(f"{mint_url}/v1/keysets")
        resp.raise_for_status()
        keysets = resp.json()["keysets"]

        # Find active keyset for unit
        active_keyset = None
        for k in keysets:
            if k["unit"] == unit and k["active"]:
                active_keyset = k
                break

        if not active_keyset:
            return None

        keyset_id = active_keyset["id"]
        input_fee_ppk = active_keyset.get("input_fee_ppk", 0)

        # Get keys for this keyset
        resp = requests.get(f"{mint_url}/v1/keys/{keyset_id}")
        resp.raise_for_status()
        keys = resp.json()["keysets"][0]["keys"]

        return {
            "keysetId": keyset_id,
            "unit": unit,
            "keys": keys,
            "inputFeePpk": input_fee_ppk,
        }
    except Exception as e:
        print(f"Failed to fetch keyset: {e}")
        return None


class TestMintConnectivity:
    """Test that we can connect to the mint."""

    def test_mint_connectivity(self):
        """Verify mint is reachable and returns info."""
        mint_url = get_mint_url()
        resp = requests.get(f"{mint_url}/v1/info")
        assert resp.status_code == 200, f"Mint returned status {resp.status_code}"

        info = resp.json()
        print(f"Connected to mint: {info.get('name', 'unknown')} (version {info.get('version', 'unknown')})")


class TestChannelSetup:
    """Test the client-side channel setup flow."""

    def test_generate_keypair(self):
        """Test keypair generation."""
        secret, pubkey = cdk_spilman.generate_keypair()

        assert len(secret) == 64, f"Secret should be 64 hex chars, got {len(secret)}"
        assert len(pubkey) == 66, f"Pubkey should be 66 hex chars (compressed), got {len(pubkey)}"
        assert pubkey.startswith("02") or pubkey.startswith("03"), "Pubkey should be compressed format"

        print(f"Generated keypair: pubkey={pubkey[:16]}...")

    def test_secret_key_to_pubkey(self):
        """Test deriving pubkey from secret."""
        secret, expected_pubkey = cdk_spilman.generate_keypair()
        derived_pubkey = cdk_spilman.secret_key_to_pubkey(secret)

        assert derived_pubkey == expected_pubkey, "Derived pubkey should match"

    def test_compute_channel_secret(self):
        """Test ECDH shared secret computation."""
        alice_secret, sender_pubkey = cdk_spilman.generate_keypair()
        bob_secret, bob_pubkey = cdk_spilman.generate_keypair()

        # Both parties should compute the same shared secret
        shared_alice = cdk_spilman.compute_channel_secret(alice_secret, bob_pubkey)
        shared_bob = cdk_spilman.compute_channel_secret(bob_secret, sender_pubkey)

        assert shared_alice == shared_bob, "Shared secrets should match"
        assert len(shared_alice) == 64, f"Shared secret should be 64 hex chars, got {len(shared_alice)}"

        print(f"Computed shared secret: {shared_alice[:16]}...")

    def test_funding_outputs_and_channel_id(self):
        """Test the full channel setup flow with keyset from mint."""
        mint_url = get_mint_url()

        # Generate keypairs
        alice_secret, sender_pubkey = cdk_spilman.generate_keypair()
        _, receiver_pubkey = cdk_spilman.generate_keypair()

        print(f"Generated sender pubkey: {sender_pubkey[:16]}...")
        print(f"Generated receiver pubkey: {receiver_pubkey[:16]}...")

        # Fetch active keyset from mint
        keyset_info = fetch_active_keyset(mint_url, "sat")
        assert keyset_info is not None, "Failed to fetch keyset from mint"
        keyset_json = json.dumps(keyset_info)
        print(f"Fetched keyset: {keyset_info['keysetId']}")

        # Compute shared secret
        channel_secret = cdk_spilman.compute_channel_secret(alice_secret, receiver_pubkey)
        print(f"Computed shared secret: {channel_secret[:16]}...")

        # Build channel parameters
        now = int(time.time())
        funding_token_amount = cdk_spilman.compute_funding_token_amount(100, keyset_json, 64)
        params = {
            "sender_pubkey": sender_pubkey,
            "receiver_pubkey": receiver_pubkey,
            "mint": mint_url,
            "unit": "sat",
            "capacity": 100,
            "funding_token_amount": funding_token_amount,
            "maximum_amount": 64,
            "expiry_timestamp": now + 7200,
            "setup_timestamp": now,
            "keyset_id": keyset_info["keysetId"],
            "input_fee_ppk": keyset_info["inputFeePpk"],
        }
        params_json = json.dumps(params)

        # Get channel ID
        channel_id = cdk_spilman.channel_parameters_get_channel_id(params_json, channel_secret, keyset_json)
        assert len(channel_id) == 64, f"Channel ID should be 64 hex chars, got {len(channel_id)}"
        print(f"Channel ID: {channel_id}")

        # Create funding outputs
        funding_json = cdk_spilman.create_funding_outputs(params_json, alice_secret, keyset_json)
        funding = json.loads(funding_json)

        funding_nominal = funding["funding_token_nominal"]
        blinded_messages = funding["blinded_messages"]

        print(f"Funding nominal: {funding_nominal} sat, outputs: {len(blinded_messages)}")

        # Verify we got reasonable outputs
        assert funding_nominal >= 100, f"Expected funding >= 100, got {funding_nominal}"
        assert len(blinded_messages) > 0, "Expected at least one blinded message"

    def test_channel_id_deterministic(self):
        """Test that channel ID computation is deterministic."""
        mint_url = get_mint_url()

        alice_secret, sender_pubkey = cdk_spilman.generate_keypair()
        _, receiver_pubkey = cdk_spilman.generate_keypair()

        keyset_info = fetch_active_keyset(mint_url, "sat")
        assert keyset_info is not None, "Failed to fetch keyset from mint"
        keyset_json = json.dumps(keyset_info)

        channel_secret = cdk_spilman.compute_channel_secret(alice_secret, receiver_pubkey)

        now = int(time.time())
        funding_token_amount = cdk_spilman.compute_funding_token_amount(100, keyset_json, 64)
        params = {
            "sender_pubkey": sender_pubkey,
            "receiver_pubkey": receiver_pubkey,
            "mint": mint_url,
            "unit": "sat",
            "capacity": 100,
            "funding_token_amount": funding_token_amount,
            "maximum_amount": 64,
            "expiry_timestamp": now + 7200,
            "setup_timestamp": now,
            "keyset_id": keyset_info["keysetId"],
            "input_fee_ppk": keyset_info["inputFeePpk"],
        }
        params_json = json.dumps(params)

        # Compute channel ID twice
        channel_id_1 = cdk_spilman.channel_parameters_get_channel_id(params_json, channel_secret, keyset_json)
        channel_id_2 = cdk_spilman.channel_parameters_get_channel_id(params_json, channel_secret, keyset_json)

        assert channel_id_1 == channel_id_2, "Channel ID should be deterministic"
        print(f"Channel ID is deterministic: {channel_id_1}")


# ============================================================================
# Helpers for TestClientBridge
# ============================================================================


class MockClientHost:
    """Mock implementation of SpilmanClientHost for integration tests."""

    def __init__(self, mint_url: str):
        self.mint_url = mint_url
        self.funding: dict[str, str] = {}  # channel_id -> funding_json
        self.payment_state: dict[str, str] = {}  # channel_id -> payment_state_json
        self.channel_state: dict[str, str] = {}  # channel_id -> "open" or "closed"
        self.keys: dict[str, str] = {}  # pubkey_hex -> secret_hex

    def register_key(self, secret_hex: str, pubkey_hex: str):
        """Store a keypair so the host can sign on behalf of this key."""
        self.keys[pubkey_hex] = secret_hex

    # ========================================================================
    # Networking
    # ========================================================================

    def call_mint_swap(self, mint_url: str, swap_request_json: str) -> str:
        resp = requests.post(
            f"{mint_url}/v1/swap",
            data=swap_request_json,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code != 200:
            raise RuntimeError(resp.text or f"swap failed with status {resp.status_code}")
        return resp.text

    def call_mint_restore(self, mint_url: str, restore_request_json: str) -> str:
        resp = requests.post(
            f"{mint_url}/v1/restore",
            data=restore_request_json,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code != 200:
            raise RuntimeError(resp.text or f"restore failed with status {resp.status_code}")
        return resp.text

    # ========================================================================
    # Funding Data (immutable after creation)
    # ========================================================================

    def save_opening_channel(self, channel_id: str, funding_json: str):
        self.funding[channel_id] = funding_json
        self.channel_state[channel_id] = "opening"

    def mark_channel_open(self, channel_id: str, funding_proofs_json: str):
        if channel_id in self.funding:
            import json
            try:
                funding = json.loads(self.funding[channel_id])
                funding["funding_proofs_json"] = funding_proofs_json
                self.funding[channel_id] = json.dumps(funding)
            except (json.JSONDecodeError, TypeError):
                pass
        self.channel_state[channel_id] = "open"

    def get_channel_funding(self, channel_id: str) -> str | None:
        return self.funding.get(channel_id)

    # ========================================================================
    # Payment State (mutable)
    # ========================================================================

    def get_payment_state(self, channel_id: str) -> str | None:
        return self.payment_state.get(channel_id)

    def record_payment(self, channel_id: str, state_json: str):
        self.payment_state[channel_id] = state_json

    # ========================================================================
    # Channel Lifecycle
    # ========================================================================

    def get_channel_state(self, channel_id: str) -> str:
        return self.channel_state.get(channel_id, "open")

    def mark_channel_closed(self, channel_id: str):
        self.channel_state[channel_id] = "closed"

    def list_channel_ids(self) -> list[str]:
        return list(self.funding.keys())

    def delete_channel(self, channel_id: str):
        self.funding.pop(channel_id, None)
        self.payment_state.pop(channel_id, None)
        self.channel_state.pop(channel_id, None)

    # ========================================================================
    # Time
    # ========================================================================

    def now_seconds(self) -> int:
        return int(time.time())

    # ========================================================================
    # Crypto
    # ========================================================================

    def sign_with_tweaked_key(self, signer_pubkey_hex: str, message_hex: str, tweak_scalar_hex: str) -> str:
        secret_hex = self.keys.get(signer_pubkey_hex)
        if secret_hex is None:
            raise RuntimeError(f"No key registered for pubkey: {signer_pubkey_hex}")
        return cdk_spilman.sign_with_tweaked_key_util(secret_hex, message_hex, tweak_scalar_hex)

    def compute_channel_secret(self, sender_pubkey_hex: str, receiver_pubkey_hex: str) -> str:
        secret_hex = self.keys.get(sender_pubkey_hex)
        if secret_hex is None:
            raise RuntimeError(f"No key registered for pubkey: {sender_pubkey_hex}")
        return cdk_spilman.compute_channel_secret(secret_hex, receiver_pubkey_hex)


class MockServerHost:
    """Mock implementation of SpilmanHost for server-side validation in tests."""

    def __init__(self, keyset_id: str, keyset_info_json: str, secret_key_hex: str):
        self.keyset_id = keyset_id
        self.keyset_info_json = keyset_info_json
        self.secret_key_hex = secret_key_hex
        self.funding_data: dict[str, tuple] = {}
        self.payments: dict[str, tuple] = {}

    def receiver_key_is_acceptable(self, pubkey_hex: str) -> bool:
        return True

    def mint_and_keyset_is_acceptable(self, mint: str, keyset_id: str) -> bool:
        return True

    def get_funding_and_params(self, channel_id: str) -> tuple | None:
        data = self.funding_data.get(channel_id)
        if data is None:
            return None
        return data  # (params_json, proofs_json, channel_secret_hex, keyset_info_json)

    def save_funding(
        self,
        channel_id: str,
        params_json: str,
        proofs_json: str,
        channel_secret_hex: str,
        keyset_info_json: str,
        initial_balance: int,
        initial_signature: str,
    ):
        self.funding_data[channel_id] = (
            params_json,
            proofs_json,
            channel_secret_hex,
            keyset_info_json,
        )

    def get_amount_due(self, channel_id: str, context_json: str | None) -> int:
        return 0

    def record_payment(
        self, channel_id: str, balance: int, signature: str, context_json: str
    ):
        self.payments[channel_id] = (balance, signature)

    def get_channel_state(self, channel_id: str) -> str:
        return "open"

    def mark_channel_closing(
        self, channel_id: str, expiry_timestamp: int, balance: int, signature: str
    ):
        pass

    def get_closing_data(self, channel_id: str):
        return None

    def get_channel_policy(self, unit: str):
        if unit == "sat":
            return (3600, 10, None)
        return None

    def now_seconds(self) -> int:
        return int(time.time())

    def get_balance_and_signature_for_unilateral_exit(
        self, channel_id: str
    ) -> tuple | None:
        data = self.payments.get(channel_id)
        if data is None:
            return None
        return data  # (balance, signature)

    def get_active_keyset_ids(self, mint: str, unit: str) -> list[str]:
        return [self.keyset_id]

    def get_keyset_info(self, mint: str, keyset_id: str) -> str | None:
        if keyset_id == self.keyset_id:
            return self.keyset_info_json
        return None

    def call_mint_swap(self, mint_url: str, swap_request_json: str) -> str:
        raise RuntimeError("not used in this test")

    def compute_channel_secret(self, receiver_pubkey_hex: str, sender_pubkey_hex: str) -> str:
        return cdk_spilman.compute_channel_secret(self.secret_key_hex, sender_pubkey_hex)

    def sign_with_tweaked_key(self, signer_pubkey_hex: str, message_hex: str, tweak_scalar_hex: str) -> str:
        return cdk_spilman.sign_with_tweaked_key_util(self.secret_key_hex, message_hex, tweak_scalar_hex)

    def refresh_all_keysets(self, mint: str):
        pass

    def mark_channel_closed(
        self,
        channel_id: str,
        expiry_timestamp: int,
        balance: int,
        receiver_proofs_json: str,
        sender_proofs_json: str,
        receiver_sum: int,
        sender_sum: int,
    ):
        pass


class TestClientBridge:
    """End-to-end test of SpilmanClientBridge + server-side SpilmanBridge."""

    def test_client_bridge(self):
        """Full round-trip: mint proofs -> open channel -> sign payments -> server validates."""
        mint_url = get_mint_url()

        # ================================================================
        # Setup: fetch keyset, generate keypairs
        # ================================================================

        keyset_info = fetch_active_keyset(mint_url, "sat")
        assert keyset_info is not None, "Failed to fetch keyset from mint"
        keyset_json = json.dumps(keyset_info)
        keyset_id = keyset_info["keysetId"]
        print(f"Using keyset: {keyset_id}")

        # Generate Charlie (server/receiver) keypair
        charlie_secret, receiver_pubkey = cdk_spilman.generate_keypair()
        print(f"Charlie pubkey: {receiver_pubkey[:16]}...")

        # ================================================================
        # Step 1: Mint plain proofs and build cashuA token
        # ================================================================

        def http_call(method, url, body):
            if method == "GET":
                r = requests.get(url)
            else:
                r = requests.post(url, data=body, headers={"Content-Type": "application/json"})
            return r.text

        proofs_json = cdk_spilman.mint_proofs_from_mint(mint_url, 100, keyset_json, http_call)
        token = cdk_spilman.build_cashu_a_token(mint_url, proofs_json)
        print(f"Built cashuA token: {token[:20]}...{token[-10:]}")

        # ================================================================
        # Step 2: Create client bridge and open channel
        # ================================================================

        # Generate Alice keypair externally and register with host
        alice_secret, sender_pubkey = cdk_spilman.generate_keypair()

        client_host = MockClientHost(mint_url)
        client_host.register_key(alice_secret, sender_pubkey)

        client_bridge = cdk_spilman.ClientBridge(client_host)
        print(f"Client bridge created, sender_pubkey: {sender_pubkey[:16]}...")

        expiry_timestamp = int(time.time()) + 7200  # 2 hours
        max_amount = 64

        result = client_bridge.open_channel_from_token(
            token, receiver_pubkey, sender_pubkey, expiry_timestamp, keyset_json, max_amount
        )

        print(
            f"Channel opened: id={result.channel_id}, "
            f"capacity={result.capacity}, funding={result.funding_token_amount}"
        )

        assert result.capacity > 0, "Capacity should be positive"
        assert result.capacity <= 100, f"Capacity should not exceed input value, got {result.capacity}"

        # Verify channel is stored
        channels = client_bridge.list_channels()
        assert len(channels) == 1, f"Expected 1 channel, got {len(channels)}"
        assert channels[0] == result.channel_id

        info = client_bridge.get_channel_info(result.channel_id)
        assert info is not None, "get_channel_info returned None"
        assert info.capacity == result.capacity
        print("Channel stored and retrievable")

        # ================================================================
        # Step 3: Create payments
        # ================================================================

        payment_json = client_bridge.create_payment(result.channel_id, 10)
        payment = json.loads(payment_json)

        assert payment["channel_id"] == result.channel_id, "Payment channel_id mismatch"
        assert payment["balance"] == 10, "Payment balance mismatch"
        assert "signature" in payment, "Payment missing signature"
        print("create_payment returned valid JSON")

        # ================================================================
        # Step 4: Build payment headers
        # ================================================================

        # Header WITH funding (first request to server)
        header_with_funding = client_bridge.build_payment_header(result.channel_id, 10, True)
        decoded = base64.b64decode(header_with_funding)
        header_json = json.loads(decoded)

        assert header_json["channel_id"] == result.channel_id, "Header channel_id mismatch"
        assert header_json["balance"] == 10, "Header balance mismatch"
        assert "signature" in header_json, "Header missing signature"
        assert "params" in header_json, "Header with funding should include params"
        assert "funding_proofs" in header_json, "Header with funding should include funding_proofs"
        print("Payment header (with funding) is valid")

        # Header WITHOUT funding (subsequent requests)
        header_no_funding = client_bridge.build_payment_header(result.channel_id, 20, False)
        decoded2 = base64.b64decode(header_no_funding)
        header_json2 = json.loads(decoded2)

        assert header_json2["balance"] == 20, "Header balance mismatch"
        assert "params" not in header_json2, "Header without funding should NOT include params"
        assert "funding_proofs" not in header_json2, "Header without funding should NOT include funding_proofs"
        print("Payment header (without funding) omits params/proofs")

        # ================================================================
        # Step 5: Server-side validation (end-to-end!)
        # ================================================================

        server_host = MockServerHost(keyset_id, keyset_json, charlie_secret)
        server_bridge = cdk_spilman.SpilmanBridge(server_host)

        # First payment: header with funding (server learns about channel)
        payment_result = server_bridge.process_payment(decoded.decode(), '{"type":"test"}')

        assert payment_result.channel_id == result.channel_id, "Server channel_id mismatch"
        assert payment_result.balance == 10, f"Server balance mismatch: expected 10, got {payment_result.balance}"
        assert payment_result.capacity == result.capacity, (
            f"Server capacity mismatch: expected {result.capacity}, got {payment_result.capacity}"
        )
        print(
            f"Server accepted first payment (balance={payment_result.balance}, "
            f"capacity={payment_result.capacity})"
        )

        # Second payment: header without funding (server already knows channel)
        payment_result2 = server_bridge.process_payment(decoded2.decode(), '{"type":"test"}')

        assert payment_result2.balance == 20, f"Server balance mismatch: expected 20, got {payment_result2.balance}"
        print(f"Server accepted second payment (balance={payment_result2.balance})")

        # ================================================================
        # Step 6: Delete channel
        # ================================================================

        client_bridge.delete_channel(result.channel_id)

        assert client_bridge.get_channel_info(result.channel_id) is None, "Channel should be deleted"
        assert len(client_bridge.list_channels()) == 0, "Channel list should be empty"
        print("Channel deleted from storage")

    def test_open_channel_preserves_structured_mint_error(self):
        mint_url = get_mint_url()

        keyset_info = fetch_active_keyset(mint_url, "sat")
        assert keyset_info is not None, "Failed to fetch keyset from mint"
        keyset_json = json.dumps(keyset_info)

        charlie_secret, receiver_pubkey = cdk_spilman.generate_keypair()
        alice_secret, sender_pubkey = cdk_spilman.generate_keypair()

        def http_call(method, url, body):
            if method == "GET":
                r = requests.get(url)
            else:
                r = requests.post(url, data=body, headers={"Content-Type": "application/json"})
            return r.text

        proofs_json = cdk_spilman.mint_proofs_from_mint(mint_url, 100, keyset_json, http_call)
        token = cdk_spilman.build_cashu_a_token(mint_url, proofs_json)

        class FailingClientHost(MockClientHost):
            def call_mint_swap(self, mint_url: str, swap_request_json: str) -> str:
                raise RuntimeError(json.dumps({"code": 12001, "detail": "Unknown Keyset"}, indent=2))

        client_host = FailingClientHost(mint_url)
        client_host.register_key(alice_secret, sender_pubkey)
        client_bridge = cdk_spilman.ClientBridge(client_host)

        with pytest.raises(RuntimeError) as excinfo:
            client_bridge.open_channel_from_token(
                token,
                receiver_pubkey,
                sender_pubkey,
                int(time.time()) + 7200,
                keyset_json,
                64,
            )

        err_json = json.loads(str(excinfo.value))
        assert err_json["code"] == 12001
        assert err_json["detail"] == "Unknown Keyset"

        print("All client bridge tests passed!")
