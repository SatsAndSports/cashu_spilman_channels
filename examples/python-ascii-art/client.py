"""
ASCII Art Client - High-level Spilman client using the Integration Kit.

This demonstrates the simplified channel opening flow using open_channel_from_token.
"""

import sys
import json
import time
import requests
import os
from cdk_spilman import generate_keypair, build_cashu_b_token
from cdk_spilman_kit import SpilmanClient, BaseSpilmanClientHost
from cdk_spilman_kit.demo import fetch_active_keyset_info, mint_plain_proofs

MINT_URL = os.environ.get("MINT_URL", "http://localhost:3338")
SERVER_URL = os.environ.get("SERVER_URL", "http://localhost:5000")


def main():
    # 1. Parse arguments
    args = sys.argv[1:]
    should_close = "--close" in args
    messages = [a for a in args if a != "--close"]
    if not messages:
        messages = ["Hello", "Cashu", "World"]

    # 2. Setup Client
    alice_secret, sender_pubkey = generate_keypair()
    host = BaseSpilmanClientHost(alice_secret)
    client = SpilmanClient(host)

    # 3. Get Server Params & Keyset
    print(f"Connecting to {SERVER_URL}...")
    server_params = requests.get(f"{SERVER_URL}/channel/params").json()
    receiver_pubkey = server_params["receiver_pubkey"]
    mint_url = next(iter(server_params["mints_units_keysets"]))
    keyset_info = fetch_active_keyset_info(mint_url)
    keyset_info_json = json.dumps(keyset_info)

    # 4. Mint proofs and build token
    capacity = max(sum(len(m) for m in messages) + 20, 50)
    # Mint slightly more than capacity to cover potential fees
    mint_amount = capacity + 10

    # Use mint_plain_proofs to get proofs (handles quote/pay/mint flow)
    proofs_json = mint_plain_proofs(mint_url, mint_amount, keyset_info_json)

    # Build a cashuB token from the proofs
    token = build_cashu_b_token(mint_url, "sat", proofs_json)

    # 5. Open channel from token (the simplified way!)
    print("Opening channel...")
    expiry = int(time.time()) + 7200  # 2 hours from now
    result = client.open_channel_from_token(
        token,
        receiver_pubkey,
        sender_pubkey,
        expiry,
        keyset_info_json,
        64,  # max_amount per output
    )

    cid = result.channel_id
    print(f"Full channel ID: {cid}")
    print(f"Capacity: {result.capacity} sat")

    # 6. Make Requests
    balance = 0
    print(f"Channel {cid[:8]} ready! Sending requests...")
    for i, msg in enumerate(messages):
        balance += len(msg)
        header = client.build_payment_header(cid, balance, i == 0)

        resp = requests.post(
            f"{SERVER_URL}/ascii",
            json={"message": msg},
            headers={"X-Cashu-Channel": header},
        )
        if resp.ok:
            print(f"\n[{i+1}/{len(messages)}] Accepted:\n{resp.json()['art']}")
        else:
            print(f"Request failed: {resp.status_code} {resp.text}")
            break

    # 7. Optional Close
    if should_close:
        print("\nClosing channel...")
        status = requests.get(f"{SERVER_URL}/channel/{cid}/status").json()
        close_req = client.create_cooperative_close_request(cid, status["amount_due"])

        c_resp = requests.post(
            f"{SERVER_URL}/channel/{cid}/close", json=json.loads(close_req)
        )
        if c_resp.ok:
            client.process_cooperative_close_response(c_resp.text)
            res = c_resp.json()
            print(
                f"Closed! Earned by server: {res['receiver_sum']}, Refunded: {res['sender_sum']}"
            )
        else:
            print(f"Close failed: {c_resp.text}")


if __name__ == "__main__":
    main()
