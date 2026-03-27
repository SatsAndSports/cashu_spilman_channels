"""
ASCII Art Client - High-level Spilman client using the Integration Kit.
"""

import sys
import json
import time
import requests
import os
from cdk_spilman import (
    generate_keypair,
    compute_channel_secret,
    channel_parameters_get_channel_id,
    create_funding_outputs,
    construct_proofs,
    compute_funding_token_amount,
)
from cdk_spilman_kit import SpilmanClient, BaseSpilmanClientHost
from cdk_spilman_kit.demo import fetch_active_keyset_info, mint_funding_token

MINT_URL = os.environ.get("MINT_URL", "http://localhost:3338")
SERVER_URL = os.environ.get("SERVER_URL", "http://localhost:5000")

def main():
    # 1. Parse arguments
    args = sys.argv[1:]
    should_close = "--close" in args
    messages = [a for a in args if a != "--close"]
    if not messages: messages = ["Hello", "Cashu", "World"]

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

    # 4. Fund Channel (Manual for demo, using low-level bridge functions)
    print("Funding channel...")
    capacity = max(sum(len(m) for m in messages) + 20, 50)
    fta = compute_funding_token_amount(capacity, json.dumps(keyset_info), 64)
    ss = compute_channel_secret(alice_secret, receiver_pubkey)
    
    cp = {
        "sender_pubkey": sender_pubkey, "receiver_pubkey": receiver_pubkey,
        "mint": mint_url, "unit": "sat", "capacity": capacity,
        "funding_token_amount": fta, "maximum_amount": 64,
        "expiry_timestamp": int(time.time()) + 7200, "setup_timestamp": int(time.time()),
        "keyset_id": keyset_info["keysetId"], "input_fee_ppk": keyset_info["inputFeePpk"],
    }
    cid = channel_parameters_get_channel_id(json.dumps(cp), ss, json.dumps(keyset_info))
    print(f"Full channel ID: {cid}")
    print(f"Capacity:   {capacity} sat")
    
    funding = json.loads(create_funding_outputs(json.dumps(cp), alice_secret, json.dumps(keyset_info)))
    sigs = mint_funding_token(mint_url, funding["funding_token_nominal"], funding["blinded_messages"])
    proofs = construct_proofs(json.dumps(sigs), json.dumps(funding["secrets_with_blinding"]), json.dumps(keyset_info))
    
    # Save to local host so bridge can see it (new interface)
    # ClientChannelFunding contains all immutable data - field names must match Rust struct
    funding_data = {
        "params_json": json.dumps(cp),
        "funding_proofs_json": proofs,
        "channel_secret_hex": ss,
        "keyset_info_json": json.dumps(keyset_info),
        "sender_pubkey_hex": sender_pubkey,
        "capacity": capacity,
        "funding_token_amount": fta,
        "mint_url": mint_url,
        "created_at": int(time.time()),
    }
    host.save_channel_funding(cid, json.dumps(funding_data))

    # 5. Make Requests
    balance = 0
    print(f"Channel {cid[:8]} ready! Sending requests...")
    for i, msg in enumerate(messages):
        balance += len(msg)
        header = client.build_payment_header(cid, balance, i == 0)
        
        resp = requests.post(f"{SERVER_URL}/ascii", json={"message": msg}, headers={"X-Cashu-Channel": header})
        if resp.ok:
            print(f"\n[{i+1}/{len(messages)}] Accepted:\n{resp.json()['art']}")
        else:
            print(f"Request failed: {resp.status_code} {resp.text}")
            break

    # 6. Optional Close
    if should_close:
        print("\nClosing channel...")
        status = requests.get(f"{SERVER_URL}/channel/{cid}/status").json()
        close_req = client.create_cooperative_close_request(cid, status["amount_due"])
        
        c_resp = requests.post(f"{SERVER_URL}/channel/{cid}/close", json=json.loads(close_req))
        if c_resp.ok:
            client.process_cooperative_close_response(c_resp.text)
            res = c_resp.json()
            print(f"Closed! Earned by server: {res['receiver_sum']}, Refunded: {res['sender_sum']}")
        else:
            print(f"Close failed: {c_resp.text}")

if __name__ == "__main__":
    main()
