import json
import time
import requests
from typing import Optional, Tuple, List, Dict, Any
from .stores import SpilmanStores, ChannelClosedData, UsageMap
from .keysets import refresh_keyset_cache

DEFAULT_TIMEOUT = 10

# We import these from cdk_spilman which should be installed
try:
    from cdk_spilman import secret_key_to_pubkey, compute_channel_secret, sign_with_tweaked_key_util
except ImportError:
    # Fallback for development/testing if not installed in environment
    secret_key_to_pubkey = None
    compute_channel_secret = None
    sign_with_tweaked_key_util = None

class BaseSpilmanHost:
    def __init__(
        self, 
        secret_key: str, 
        mints: Dict[str, List[str]], 
        pricing: Dict[str, Any], 
        stores: SpilmanStores,
        min_expiry_seconds: int = 3600,
        pricing_scale: int = 1,
    ):
        if secret_key_to_pubkey is None:
            raise RuntimeError("cdk_spilman is required to use cdk_spilman_kit")
        self.secret_key = secret_key
        # Normalize mint URLs
        self.mints = {url.rstrip("/"): units for url, units in mints.items()}
        self.pricing = pricing
        self.stores = stores
        self.pubkey = secret_key_to_pubkey(secret_key)
        self.min_expiry_seconds = min_expiry_seconds
        self.pricing_scale = pricing_scale if pricing_scale and pricing_scale > 0 else 1

    def receiver_key_is_acceptable(self, pubkey_hex: str) -> bool:
        return pubkey_hex.lower() == self.pubkey.lower()

    def mint_and_keyset_is_acceptable(self, mint: str, keyset_id: str) -> bool:
        norm_mint = mint.rstrip("/")
        trusted_units = self.mints.get(norm_mint)
        if not trusted_units:
            return False
        
        entry = self.stores.keyset_cache.get((mint, keyset_id))
        return entry is not None and entry.active and entry.unit in trusted_units

    def get_funding_and_params(self, channel_id: str) -> Optional[Tuple[str, str, str, str]]:
        data = self.stores.channel_funding.get(channel_id)
        if not data:
            return None
        return (
            data["params"],
            data["proofs"],
            data["channel_secret"],
            data["keyset_info"]
        )

    def save_funding(self, channel_id, params, proofs, secret, keyset, initial_balance, initial_signature):
        self.stores.channel_funding[channel_id] = {
            "params": params,
            "proofs": proofs,
            "channel_secret": secret,
            "keyset_info": keyset
        }
        # Also update balance store
        self.stores.channel_largest_payment[channel_id] = {
            "balance": initial_balance,
            "signature": initial_signature
        }

    def get_amount_due(self, channel_id: str, context_json: Optional[str]) -> int:
        accumulated = self.stores.get_usage(channel_id)
        pending: UsageMap = json.loads(context_json) if context_json else {}

        funding = self.stores.channel_funding.get(channel_id)
        if not funding:
            return 0
        
        params = json.loads(funding["params"])
        unit = params.get("unit")
        unit_pricing = self.pricing.get(unit)
        if not unit_pricing:
            return 0
        
        total = 0
        variables = unit_pricing.get("variables", {})
        for var_name, price in variables.items():
            acc = accumulated.get(var_name, 0)
            pend = pending.get(var_name, 0)
            total += (acc + pend) * price

        if total == 0:
            return 0

        scale = self.pricing_scale if self.pricing_scale > 0 else 1
        return (total + scale - 1) // scale

    def record_payment(self, channel_id: str, balance: int, signature: str, context_json: str):
        increments: UsageMap = json.loads(context_json) if context_json else {}
        self.stores.increment_usage(channel_id, increments)
        
        current = self.stores.channel_largest_payment.get(channel_id, {})
        if balance > current.get("balance", 0):
            self.stores.channel_largest_payment[channel_id] = {
                "balance": balance,
                "signature": signature
            }

    def get_channel_state(self, channel_id: str) -> str:
        if channel_id in self.stores.channel_closed:
            return "closed"
        if channel_id in self.stores.channel_closing:
            return "closing"
        return "open"

    def mark_channel_closing(self, channel_id, expiry_timestamp, balance, signature):
        if channel_id in self.stores.channel_closed:
            raise ValueError("channel already closed")
        
        # Mirror TS fix: Update balance store during closing
        self.stores.channel_largest_payment[channel_id] = {
            "balance": balance,
            "signature": signature
        }
        
        self.stores.channel_closing[channel_id] = {
            "expiry_timestamp": expiry_timestamp,
            "balance": balance,
            "signature": signature
        }

    def get_closing_data(self, channel_id: str) -> Optional[Dict[str, Any]]:
        return self.stores.channel_closing.get(channel_id)

    def get_channel_policy(self, unit: str) -> Optional[Tuple[int, int, Optional[int]]]:
        p = self.pricing.get(unit)
        if not p:
            return None
        min_cap = p.get("min_capacity", 10)
        max_output = p.get("max_amount_per_output")
        return (self.min_expiry_seconds, min_cap, max_output)

    def now_seconds(self) -> int:
        return int(time.time())

    def get_balance_and_signature_for_unilateral_exit(self, channel_id: str) -> Optional[Tuple[int, str]]:
        payment = self.stores.channel_largest_payment.get(channel_id)
        if not payment:
            return None
        return (payment["balance"], payment["signature"])

    def get_active_keyset_ids(self, mint: str, unit: str) -> List[str]:
        return [kid for (m, kid), entry in self.stores.keyset_cache.items() 
                if m == mint and entry.unit == unit and entry.active]

    def get_keyset_info(self, mint: str, keyset_id: str) -> Optional[str]:
        entry = self.stores.keyset_cache.get((mint, keyset_id))
        return entry.info_json if entry else None

    def call_mint_swap(self, mint_url: str, swap_request_json: str) -> str:
        resp = requests.post(
            f"{mint_url}/v1/swap",
            json=json.loads(swap_request_json),
            timeout=DEFAULT_TIMEOUT,
        )
        if resp.status_code != 200:
            raise RuntimeError(resp.text or f"Mint rejected swap with status {resp.status_code}")
        return resp.text

    def refresh_all_keysets(self, mint: str):
        refresh_keyset_cache(self.stores, mint, list(self.pricing.keys()))

    def mark_channel_closed(self, channel_id, expiry_timestamp, balance, receiver_proofs_json, sender_proofs_json, receiver_sum, sender_sum):
        if channel_id in self.stores.channel_closed:
            raise ValueError("channel already closed")
        self.stores.channel_closed[channel_id] = ChannelClosedData(
            expiry_timestamp=expiry_timestamp,
            balance=balance,
            receiver_proofs=json.loads(receiver_proofs_json),
            sender_proofs=json.loads(sender_proofs_json),
            receiver_sum=receiver_sum,
            sender_sum=sender_sum
        )

    def compute_channel_secret(self, receiver_pubkey_hex: str, sender_pubkey_hex: str) -> str:
        if compute_channel_secret is None:
             raise RuntimeError("cdk_spilman.compute_channel_secret is not available")
        return compute_channel_secret(self.secret_key, sender_pubkey_hex)

    def sign_with_tweaked_key(self, signer_pubkey_hex: str, message_hex: str, tweak_scalar_hex: str) -> str:
        if sign_with_tweaked_key_util is None:
            raise RuntimeError("cdk_spilman.sign_with_tweaked_key_util is not available")
        return sign_with_tweaked_key_util(self.secret_key, message_hex, tweak_scalar_hex)
