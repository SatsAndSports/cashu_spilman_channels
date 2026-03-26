import json
import base64
import requests
from typing import Optional, List, Dict, Any, Tuple
from cdk_spilman import ClientBridge as FfiClientBridge

class BaseSpilmanClientHost:
    """Basic implementation of client host callbacks."""
    def __init__(self, alice_secret: str):
        self.alice_secret = alice_secret
        self.channels = {} # channel_id -> {"json": str, "secret": str}

    def call_mint_swap(self, mint_url: str, swap_request_json: str) -> str:
        resp = requests.post(f"{mint_url}/v1/swap", json=json.loads(swap_request_json))
        if resp.status_code != 200:
            raise RuntimeError(resp.text or f"Mint rejected swap with status {resp.status_code}")
        return resp.text

    def save_channel(self, channel_id: str, channel_json: str, channel_secret_hex: str):
        self.channels[channel_id] = {"json": channel_json, "secret": channel_secret_hex}

    def get_channel(self, channel_id: str) -> Optional[Tuple[str, str]]:
        data = self.channels.get(channel_id)
        if not data: return None
        return (data["json"], data["secret"])

    def list_channel_ids(self) -> List[str]:
        return list(self.channels.keys())

    def delete_channel(self, channel_id: str):
        if channel_id in self.channels:
            del self.channels[channel_id]

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
