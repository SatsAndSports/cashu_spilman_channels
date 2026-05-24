import json
from typing import Optional, List, Dict, Any
from cdk_spilman import ClientBridge as FfiClientBridge
from .interfaces import SpilmanClientHost

class SpilmanClient:
    """High-level wrapper for the Spilman client bridge."""
    def __init__(self, host: SpilmanClientHost):
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

    def restore_funding_proofs(self, channel_id: str) -> str:
        """Restores funding proofs for a channel using NUT-09.
        
        This can be used to recover from a failed open_channel_from_token
        where the swap succeeded on the mint's side but the client lost
        the response.
        """
        return self.bridge.restore_funding_proofs(channel_id)

    def build_payment_header(self, channel_id: str, balance: int, include_funding: bool = False) -> str:
        """Builds the base64-encoded payment header."""
        return self.bridge.build_payment_header(channel_id, balance, include_funding)

    def create_cooperative_close_request(self, channel_id: str, final_balance: int) -> str:
        """Creates a signed close request for the server."""
        return self.bridge.create_cooperative_close_request(channel_id, final_balance)

    def process_cooperative_close_response(self, response_json: str):
        """Finalizes the channel closure locally."""
        return self.bridge.process_cooperative_close_response(response_json)

    def get_channel_info(self, channel_id: str) -> Optional[Any]:
        """Returns information about a stored channel."""
        return self.bridge.get_channel_info(channel_id)

    def list_channels(self) -> List[str]:
        """Returns all stored channel IDs."""
        return self.bridge.list_channels()

    def close_channel(self, channel_id: str):
        """Marks a channel as closed locally."""
        return self.bridge.close_channel(channel_id)

    def delete_channel(self, channel_id: str):
        """Removes a channel from storage."""
        return self.bridge.delete_channel(channel_id)
