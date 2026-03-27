import json
import time
import requests
from typing import List, Dict, Any, Optional

try:
    import qrcode
except ImportError:
    qrcode = None


def _http_callback(method: str, url: str, body: str) -> str:
    """HTTP callback for mint_proofs_from_mint."""
    if method == "GET":
        resp = requests.get(url)
    else:
        resp = requests.post(url, data=body, headers={"Content-Type": "application/json"})
    resp.raise_for_status()
    return resp.text


def mint_plain_proofs(mint_url: str, amount: int, keyset_info_json: str, unit: str = "sat") -> str:
    """Mint plain proofs (not channel-locked) from a mint.
    
    This handles the full flow: create blinded messages, get quote,
    wait for payment, mint, and construct proofs.
    
    Args:
        mint_url: The mint URL
        amount: Amount to mint in the given unit
        keyset_info_json: JSON string of keyset info
        unit: Currency unit (default "sat")
    
    Returns:
        JSON array of proofs ready for use in a token
    """
    from cdk_spilman import mint_proofs_from_mint
    return mint_proofs_from_mint(mint_url, amount, keyset_info_json, _http_callback)


def fetch_active_keyset_info(mint_url: str, unit: str = "sat") -> Dict[str, Any]:
    """Fetch active keyset info from mint for a given unit."""
    # Get keysets
    keysets_resp = requests.get(f"{mint_url}/v1/keysets")
    keysets_resp.raise_for_status()
    keysets = keysets_resp.json()["keysets"]
    
    # Find active keyset for unit
    active = None
    for k in keysets:
        if k["unit"] == unit and k["active"]:
            active = k
            break
    
    if not active:
        raise Exception(f"No active {unit} keyset found at {mint_url}")
    
    keyset_id = active["id"]
    
    # Get keys for this keyset
    keys_resp = requests.get(f"{mint_url}/v1/keys/{keyset_id}")
    keys_resp.raise_for_status()
    keys_data = keys_resp.json()["keysets"][0]
    
    return {
        "keysetId": keyset_id,
        "unit": unit,
        "inputFeePpk": active.get("input_fee_ppk", 0),
        "keys": keys_data["keys"]
    }

def mint_funding_token(mint_url: str, amount: int, blinded_messages: List[Dict[str, Any]], unit: str = "sat") -> List[Dict[str, Any]]:
    """Mint tokens for funding a channel. Handles bolt11 quote and wait."""
    # 1. Request quote
    quote_resp = requests.post(
        f"{mint_url}/v1/mint/quote/bolt11",
        json={"amount": amount, "unit": unit}
    )
    quote_resp.raise_for_status()
    quote = quote_resp.json()
    quote_id = quote["quote"]
    invoice = quote.get("request", "").strip()
    
    # 2. Display invoice and QR code
    if invoice:
        print("\n  " + "=" * 56)
        print("  PAY THIS INVOICE TO FUND THE CHANNEL")
        print("  " + "=" * 56 + "\n")
        print(f"  {invoice}\n")
        
        if qrcode:
            qr = qrcode.QRCode(box_size=1, border=4)
            qr.add_data(invoice.upper())
            qr.make(fit=True)
            qr.print_ascii(invert=True)
            print()
        
        print("  " + "=" * 56 + "\n")
    
    # 3. Wait for quote to be paid
    print("  Waiting for payment...")
    for _ in range(120):  # 60 seconds
        check_resp = requests.get(f"{mint_url}/v1/mint/quote/bolt11/{quote_id}")
        check_resp.raise_for_status()
        status = check_resp.json()
        
        state = status.get("state", status.get("paid"))
        if state == "PAID" or state is True:
            print("  Payment received!")
            break
        time.sleep(0.5)
    else:
        raise Exception("Quote was not paid in time (60s timeout)")
    
    # 4. Mint tokens
    print("  Minting tokens...")
    mint_resp = requests.post(
        f"{mint_url}/v1/mint/bolt11",
        json={"quote": quote_id, "outputs": blinded_messages}
    )
    mint_resp.raise_for_status()
    return mint_resp.json()["signatures"]
