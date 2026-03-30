import json
import base64
import time
import requests
from typing import Optional, List, Dict, Any
from cdk_spilman import ClientBridge as FfiClientBridge

class BaseSpilmanClientHost:
    """Basic implementation of client host callbacks."""
    def __init__(self, alice_secret: str):
        self.alice_secret = alice_secret
        self.opening: Dict[str, str] = {}  # channel_id -> opening_json
        self.funding: Dict[str, str] = {}  # channel_id -> funding_json
        self.payment_state: Dict[str, str] = {}  # channel_id -> payment_state_json
        self.channel_state: Dict[str, str] = {}  # channel_id -> "open" or "closed"

    # ========================================================================
    # Networking
    # ========================================================================

    def call_mint_swap(self, mint_url: str, swap_request_json: str) -> str:
        resp = requests.post(f"{mint_url}/v1/swap", json=json.loads(swap_request_json))
        if resp.status_code != 200:
            raise RuntimeError(resp.text or f"Mint rejected swap with status {resp.status_code}")
        return resp.text

    def call_mint_restore(self, mint_url: str, restore_request_json: str) -> str:
        resp = requests.post(f"{mint_url}/v1/restore", json=json.loads(restore_request_json))
        if resp.status_code != 200:
            raise RuntimeError(resp.text or f"Mint rejected restore with status {resp.status_code}")
        return resp.text

    # ========================================================================
    # Channel Opening (two-phase)
    # ========================================================================

    def save_opening_from_swap_channel(self, channel_id: str, opening_json: str):
        self.opening[channel_id] = opening_json
        self.channel_state[channel_id] = "opening_from_swap"

    def mark_channel_open(self, channel_id: str, funding_proofs_json: str):
        if channel_id in self.opening:
            try:
                opening = json.loads(self.opening[channel_id])
                funding = {
                    "params_json": opening.get("params_json"),
                    "funding_proofs_json": funding_proofs_json,
                    "channel_secret_hex": opening.get("channel_secret_hex"),
                    "keyset_info_json": opening.get("keyset_info_json"),
                    "sender_pubkey_hex": opening.get("sender_pubkey_hex"),
                    "capacity": opening.get("capacity"),
                    "funding_token_amount": opening.get("funding_token_amount"),
                    "mint_url": opening.get("mint_url"),
                    "created_at": opening.get("created_at"),
                }
                self.funding[channel_id] = json.dumps(funding)
            except (json.JSONDecodeError, TypeError):
                pass
            del self.opening[channel_id]
        self.channel_state[channel_id] = "open"

    def get_channel_funding(self, channel_id: str) -> Optional[str]:
        return self.funding.get(channel_id)

    def get_channel_opening_from_swap(self, channel_id: str) -> Optional[str]:
        return self.opening.get(channel_id)

    # ========================================================================
    # Payment State (mutable)
    # ========================================================================

    def get_payment_state(self, channel_id: str) -> Optional[str]:
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

    def list_channel_ids(self) -> List[str]:
        return list(self.funding.keys() | self.opening.keys())

    def delete_channel(self, channel_id: str):
        self.opening.pop(channel_id, None)
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
        from cdk_spilman import sign_with_tweaked_key_util
        return sign_with_tweaked_key_util(self.alice_secret, message_hex, tweak_scalar_hex)

    def compute_channel_secret(self, sender_pubkey_hex: str, receiver_pubkey_hex: str) -> str:
        from cdk_spilman import compute_channel_secret
        return compute_channel_secret(self.alice_secret, receiver_pubkey_hex)

class SpilmanClient:
    """High-level wrapper for the Spilman client bridge."""
    def __init__(self, host: BaseSpilmanClientHost):
        self.host = host
        self.bridge = FfiClientBridge(host)

    def open_channel_from_token(
        self,
        token: str,
        receiver_pubkey_hex: str,
        sender_pubkey_hex: str,
        expiry_timestamp: int,
        keyset_info_json: str,
        max_amount: int,
    ):
        """Opens a new channel from a Cashu token.
        
        This is the recommended way to fund a channel. It handles:
        1. Computing the channel secret via ECDH
        2. Parsing the token and computing channel parameters
        3. Creating and submitting the funding swap
        4. Saving the channel to storage
        
        Returns:
            OpenChannelResult with channel_id, capacity, etc.
        """
        return self.bridge.open_channel_from_token(
            token,
            receiver_pubkey_hex,
            sender_pubkey_hex,
            expiry_timestamp,
            keyset_info_json,
            max_amount,
        )

    def build_payment_header(self, channel_id: str, balance: int, include_funding: bool = False) -> str:
        """Builds the base64-encoded payment header."""
        return self.bridge.build_payment_header(channel_id, balance, include_funding)

    def create_cooperative_close_request(self, channel_id: str, final_balance: int) -> str:
        """Creates a signed close request for the server."""
        return self.bridge.create_cooperative_close_request(channel_id, final_balance)

    def process_cooperative_close_response(self, response_json: str):
        """Finalizes the channel closure locally."""
        return self.bridge.process_cooperative_close_response(response_json)
