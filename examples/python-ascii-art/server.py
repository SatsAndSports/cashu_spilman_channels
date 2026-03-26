import os
import secrets
import json
import pyfiglet
from typing import Optional
from flask import Flask, request, jsonify
from cdk_spilman_kit import ConfigurableSpilman
from cdk_spilman_kit.ext.flask import map_error_status, parse_bridge_error

# Configuration
SECRET_KEY = os.environ.get("SERVER_SECRET_KEY") or secrets.token_hex(32)
CONFIG_PATH = os.environ.get("CONFIG_PATH", "config.yaml")
PORT = int(os.environ.get("PORT", "5000"))

# 1. Bootstrap Spilman components from YAML
spilman_ctx = ConfigurableSpilman.from_yaml(CONFIG_PATH, SECRET_KEY)

app = Flask(__name__)

# 2. Attach management router
spilman = spilman_ctx.init_flask(app)

@app.route("/ascii", methods=["POST"])
def generate_ascii():
    # 1. Validate request body
    data = request.get_json() or {}
    message = data.get("message", "")
    if not message:
        return jsonify({"error": "Missing 'message'"}), 400
    
    print(f"\n[Request] ASCII art for '{message}' ({len(message)} chars)")

    # 2. Process payment using the helper
    try:
        # Pass usage increments in the context
        payment = spilman.process_request_payment({"chars": len(message)})
    except Exception as e:
        msg = str(e)
        status = map_error_status(msg)
        _, reason, _ = parse_bridge_error(msg)
        print(f"  [Payment] REJECTED: {reason or msg}")
        return jsonify({"error": "Payment failed", "reason": reason or msg}), status
    
    print(f"  [Payment] ACCEPTED: balance={payment.balance}/{payment.capacity}")

    # 3. Generate content
    art = pyfiglet.figlet_format(message)
    
    # 4. Return response with confirmation header
    resp = jsonify({
        "art": art,
        "message": message,
        "payment": {
            "channel_id": payment.channel_id,
            "balance": payment.balance,
            "amount_due": payment.amount_due,
            "capacity": payment.capacity,
        }
    })
    return spilman.attach_payment_header(resp, payment)

@app.route("/ascii/preflight", methods=["POST"])
def preflight_ascii():
    data = request.get_json() or {}
    message = data.get("message", "")
    if not message:
        return jsonify({"error": "Missing 'message'"}), 400

    try:
        ok = spilman.payment_covers_amount_due({"chars": len(message)})
        if not ok:
            return jsonify({"ok": False})

        amount_due = spilman.verify_payment_covers_amount_due({"chars": len(message)})
        return jsonify({"ok": True, "amount_due": amount_due})
    except Exception as e:
        msg = str(e)
        status = map_error_status(msg)
        _, reason, _ = parse_bridge_error(msg)
        return jsonify({"error": "Payment preflight failed", "reason": reason or msg}), status

if __name__ == "__main__":
    print(f"Server pubkey: {spilman_ctx.host.pubkey}")
    print(f"Mints:         {', '.join(spilman_ctx.config.get('mints', {}).keys())}")
    
    # Display active pricing
    active_units = spilman_ctx.stores.get_active_units()
    pricing_entries = []
    for unit, p in spilman_ctx.config.get("pricing", {}).items():
        if unit in active_units:
            vars_str = "+".join(f"{price}/{v}" for v, price in p.get("variables", {}).items())
            pricing_entries.append(f"{unit}={vars_str}")
    
    print(f"Pricing:       {', '.join(pricing_entries) or '(no active units)'}")
    app.run(host="0.0.0.0", port=PORT)
