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

    # ========================================================================
    # Funding Data (immutable after creation)
    # ========================================================================

    def save_channel_funding(self, channel_id: str, funding_json: str):
        self.funding[channel_id] = funding_json
        self.channel_state[channel_id] = "open"

    def get_channel_funding(self, channel_id: str) -> Optional[str]:
        return self.funding.get(channel_id)

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

    def build_payment_header(self, channel_id: str, balance: int, include_funding: bool = False) -> str:
        """Builds the base64-encoded payment header."""
        return self.bridge.build_payment_header(channel_id, balance, include_funding)

    def create_cooperative_close_request(self, channel_id: str, final_balance: int) -> str:
        """Creates a signed close request for the server."""
        return self.bridge.create_cooperative_close_request(channel_id, final_balance)

    def process_cooperative_close_response(self, response_json: str):
        """Finalizes the channel closure locally."""
        return self.bridge.process_cooperative_close_response(response_json)
