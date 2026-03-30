"""In-memory implementation of SpilmanClientHost for prototyping and demos.

This provides a ready-to-use client host that stores data in memory.
For production, you would implement a custom host with persistent storage.
"""

import json
import time
import requests
from typing import Optional, List, Dict


class InMemoryClientHost:
    """In-memory implementation of SpilmanClientHost.

    Stores channel data in memory (lost on restart).
    Uses requests for networking and the cdk_spilman crypto functions.

    Args:
        secret_key_hex: The sender's secret key in hex format (64 chars)
    """

    def __init__(self, secret_key_hex: str):
        self.secret_key_hex = secret_key_hex
        self._opening: Dict[str, str] = {}  # channel_id -> opening_json
        self._funding: Dict[str, str] = {}  # channel_id -> funding_json
        self._payment_state: Dict[str, str] = {}  # channel_id -> payment_state_json
        self._channel_state: Dict[str, str] = {}  # channel_id -> "open" or "closed"

    # ========================================================================
    # Networking
    # ========================================================================

    def call_mint_swap(self, mint_url: str, swap_request_json: str) -> str:
        """Call the mint's swap endpoint."""
        resp = requests.post(
            f"{mint_url}/v1/swap",
            json=json.loads(swap_request_json),
            timeout=30,
        )
        if resp.status_code != 200:
            raise RuntimeError(
                resp.text or f"Mint rejected swap with status {resp.status_code}"
            )
        return resp.text

    def call_mint_restore(self, mint_url: str, restore_request_json: str) -> str:
        """Call the mint's restore endpoint."""
        resp = requests.post(
            f"{mint_url}/v1/restore",
            json=json.loads(restore_request_json),
            timeout=30,
        )
        if resp.status_code != 200:
            raise RuntimeError(
                resp.text or f"Mint rejected restore with status {resp.status_code}"
            )
        return resp.text

    # ========================================================================
    # Channel Opening (two-phase)
    # ========================================================================

    def save_opening_from_swap_channel(self, channel_id: str, opening_json: str) -> None:
        """Save channel metadata before the funding swap.

        The channel enters 'opening_from_swap' state.
        """
        self._opening[channel_id] = opening_json
        self._channel_state[channel_id] = "opening_from_swap"

    def mark_channel_open(self, channel_id: str, funding_proofs_json: str) -> None:
        """Transition channel from opening_from_swap to open with funding proofs."""
        if channel_id in self._opening:
            try:
                opening = json.loads(self._opening[channel_id])
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
                self._funding[channel_id] = json.dumps(funding)
            except (json.JSONDecodeError, TypeError):
                pass
            del self._opening[channel_id]
        self._channel_state[channel_id] = "open"

    def get_channel_funding(self, channel_id: str) -> Optional[str]:
        """Get channel funding data, or None if not found."""
        return self._funding.get(channel_id)

    def get_channel_opening_from_swap(self, channel_id: str) -> Optional[str]:
        """Get channel opening data, or None if not in opening_from_swap state."""
        return self._opening.get(channel_id)

    # ========================================================================
    # Payment State (mutable)
    # ========================================================================

    def get_payment_state(self, channel_id: str) -> Optional[str]:
        """Get current payment state for a channel, or None if not found."""
        return self._payment_state.get(channel_id)

    def record_payment(self, channel_id: str, state_json: str) -> None:
        """Record a new payment state for a channel."""
        self._payment_state[channel_id] = state_json

    # ========================================================================
    # Channel Lifecycle
    # ========================================================================

    def get_channel_state(self, channel_id: str) -> str:
        """Get the channel state ('open' or 'closed'). Returns 'open' if unknown."""
        return self._channel_state.get(channel_id, "open")

    def mark_channel_closed(self, channel_id: str) -> None:
        """Mark a channel as closed."""
        self._channel_state[channel_id] = "closed"

    def list_channel_ids(self) -> List[str]:
        """List all channel IDs."""
        return list(self._funding.keys() | self._opening.keys())

    def delete_channel(self, channel_id: str) -> None:
        """Delete all data for a channel."""
        self._opening.pop(channel_id, None)
        self._funding.pop(channel_id, None)
        self._payment_state.pop(channel_id, None)
        self._channel_state.pop(channel_id, None)

    # ========================================================================
    # Time
    # ========================================================================

    def now_seconds(self) -> int:
        """Return current time as Unix timestamp in seconds."""
        return int(time.time())

    # ========================================================================
    # Crypto (delegated to cdk_spilman)
    # ========================================================================

    def sign_with_tweaked_key(
        self, signer_pubkey_hex: str, message_hex: str, tweak_scalar_hex: str
    ) -> str:
        """Sign a message with a tweaked key."""
        from cdk_spilman import sign_with_tweaked_key_util

        return sign_with_tweaked_key_util(
            self.secret_key_hex, message_hex, tweak_scalar_hex
        )

    def compute_channel_secret(
        self, sender_pubkey_hex: str, receiver_pubkey_hex: str
    ) -> str:
        """Compute the channel secret via ECDH."""
        from cdk_spilman import compute_channel_secret

        return compute_channel_secret(self.secret_key_hex, receiver_pubkey_hex)
