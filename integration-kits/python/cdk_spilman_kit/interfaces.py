from typing import Optional, List, Protocol, runtime_checkable

@runtime_checkable
class SpilmanClientHost(Protocol):
    """
    Protocol that client applications must implement to provide storage,
    time, crypto, and networking for the Spilman client bridge.
    """

    # ========================================================================
    # Channel Opening (two-phase)
    # ========================================================================

    def save_opening_from_swap_channel(self, channel_id: str, opening_json: str) -> None:
        """Persists channel metadata before the funding swap."""
        ...

    def mark_channel_open(self, channel_id: str, funding_proofs_json: str) -> None:
        """Transitions a channel from OpeningFromSwap to Open."""
        ...

    def get_channel_funding(self, channel_id: str) -> Optional[str]:
        """Retrieves channel funding data as a JSON string."""
        ...

    def get_channel_opening_from_swap(self, channel_id: str) -> Optional[str]:
        """Retrieves channel opening data as a JSON string."""
        ...

    # ========================================================================
    # Payment State (mutable)
    # ========================================================================

    def get_payment_state(self, channel_id: str) -> Optional[str]:
        """Retrieves the current payment state as a JSON string."""
        ...

    def record_payment(self, channel_id: str, state_json: str) -> None:
        """Stores a new payment state (JSON string)."""
        ...

    # ========================================================================
    # Channel Lifecycle
    # ========================================================================

    def get_channel_state(self, channel_id: str) -> str:
        """Returns the lifecycle state: 'opening_from_swap', 'open', or 'closed'."""
        ...

    def mark_channel_closed(self, channel_id: str) -> None:
        """Marks a channel as closed locally."""
        ...

    def list_channel_ids(self) -> List[str]:
        """Returns all stored channel IDs."""
        ...

    def delete_channel(self, channel_id: str) -> None:
        """Removes a channel and all its data."""
        ...

    # ========================================================================
    # Time
    # ========================================================================

    def now_seconds(self) -> int:
        """Returns the current Unix timestamp in seconds."""
        ...

    # ========================================================================
    # Crypto (delegated to host)
    # ========================================================================

    def sign_with_tweaked_key(
        self, signer_pubkey_hex: str, message_hex: str, tweak_scalar_hex: str
    ) -> str:
        """Signs a message with a tweaked key (BIP-340 Schnorr)."""
        ...

    def compute_channel_secret(
        self, sender_pubkey_hex: str, receiver_pubkey_hex: str
    ) -> str:
        """Computes the hashed ECDH channel secret."""
        ...

    # ========================================================================
    # Networking
    # ========================================================================

    def call_mint_swap(self, mint_url: str, swap_request_json: str) -> str:
        """Executes a swap with the mint. Returns response JSON string."""
        ...

    def call_mint_restore(self, mint_url: str, restore_request_json: str) -> str:
        """Executes a NUT-09 restore with the mint. Returns response JSON string."""
        ...
