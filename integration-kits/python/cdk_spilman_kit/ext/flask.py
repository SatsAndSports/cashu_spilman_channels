import base64
import json
from functools import wraps
from typing import Optional, Any, Dict, List, Union
from flask import Blueprint, request, jsonify, Flask
from cdk_spilman import SpilmanBridge
from ..host import BaseSpilmanHost
from ..stores import SpilmanStores

def parse_bridge_error(error_msg: str):
    if not error_msg:
        return None, None, None
    try:
        data = json.loads(error_msg)
        if isinstance(data, dict) and "status" in data:
            status = data.get("status")
            reason = data.get("reason") if isinstance(data.get("reason"), str) else None
            code = data.get("code") if isinstance(data.get("code"), str) else None
            return int(status) if status is not None else None, reason, code
    except Exception:
        pass
    return None, None, None

def map_error_status(error_msg: str) -> int:
    status, reason, _ = parse_bridge_error(error_msg)
    if status:
        return status

    msg = reason or error_msg
    if not msg:
        return 500

    lower_msg = msg.lower()
    if "channel closed" in lower_msg: return 410
    if "channel closing" in lower_msg: return 409
    
    # Payment Required (402) cases
    is_payment_required = any(x in lower_msg for x in [
        "missing x-cashu-channel", 
        "invalid signature", 
        "missing header",
        "signature verification failed",
        "channel_id mismatch",
        "insufficient balance",
        "balance exceeds capacity",
        "expiry too soon",
        "mint or keyset not acceptable",
        "max_amount_per_output exceeded"
    ])
    if is_payment_required: return 402

    # Standard 400 Bad Request cases (parsing/malformed request)
    is_bad_request = any(x in lower_msg for x in [
        "invalid base64", 
        "invalid utf8", 
        "invalid json", 
        "missing field", 
        "missing channel_id",
        "missing signature"
    ])
    
    # Bridge often uses "expected ..." for type errors
    if not is_bad_request:
        if "expected" in lower_msg and any(x in lower_msg for x in ["string", "integer", "u64"]):
            is_bad_request = True
            
    if is_bad_request:
        return 400
        
    if "internal" in lower_msg or "misconfigured" in lower_msg:
        return 500
    
    return 402 # Default

def map_error_name(error_msg: str) -> str:
    if map_error_status(error_msg) == 400:
        return "Bad request"
    return "Registration failed"

def normalize_bridge_error(error_msg: str):
    status = map_error_status(error_msg)
    _, reason, _ = parse_bridge_error(error_msg)
    return status, reason or error_msg

class Spilman:
    def __init__(self, app: Optional[Flask] = None, host: Optional[BaseSpilmanHost] = None, bridge: Optional[SpilmanBridge] = None):
        self.host = host
        self.bridge = bridge
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask, host: Optional[BaseSpilmanHost] = None, bridge: Optional[SpilmanBridge] = None):
        if host:
            self.host = host
        if bridge:
            self.bridge = bridge
        
        if not self.host:
            raise RuntimeError("Spilman host must be provided either in constructor or init_app")
        if not self.bridge:
            self.bridge = SpilmanBridge(self.host)
            
        # Register management blueprint
        bp = Blueprint("spilman_management", __name__, url_prefix="/channel")
        
        @bp.route("/params")
        def get_params():
            raw_pricing = self.host.stores.get_active_pricing(self.host.pricing)
            pricing = {}
            for unit, entry in raw_pricing.items():
                min_capacity = entry.get("min_capacity", 0)
                max_output = entry.get("max_amount_per_output")
                data = {
                    "min_capacity": min_capacity,
                    "variables": entry.get("variables", {}),
                }
                if max_output is not None:
                    data["max_amount_per_output"] = max_output
                pricing[unit] = data

            return jsonify({
                "receiver_pubkey": self.host.pubkey,
                "pricing": pricing,
                "mints_units_keysets": self.host.stores.get_mints_units_keysets(),
                "pricing_scale": self.host.pricing_scale,
                "min_expiry_in_seconds": self.host.min_expiry_seconds,
            })

        @bp.route("/register", methods=["POST"])
        def register_channel():
            data = request.get_json() or {}
            if data.get("balance") != 0:
                return jsonify({
                    "error": "Bad request",
                    "reason": f"funding requires balance=0, got {data.get('balance')}"
                }), 400
            
            try:
                result = self.bridge.fund_channel(json.dumps(data))
                return jsonify({
                    "success": True,
                    "channel_id": result.channel_id,
                    "capacity": result.capacity,
                    "already_known": result.already_known,
                })
            except Exception as e:
                msg = str(e)
                status, reason = normalize_bridge_error(msg)
                return jsonify({
                    "success": False,
                    "error": map_error_name(msg),
                    "reason": reason,
                    "status": status,
                }), status

        @bp.route("/<channel_id>/status")
        def channel_status(channel_id):
            funding = self.host.stores.channel_funding.get(channel_id)
            if not funding:
                return jsonify({"error": "unknown channel"}), 404
            
            params = json.loads(funding["params"])
            payment = self.host.stores.channel_largest_payment.get(channel_id, {})
            closed_info = self.host.stores.channel_closed.get(channel_id)
            usage = self.host.stores.get_usage(channel_id)
            
            return jsonify({
                "channel_id": channel_id,
                "capacity": params.get("capacity", 0),
                "balance": payment.get("balance", 0),
                "usage": usage,
                "amount_due": self.host.get_amount_due(channel_id, None),
                "closed": closed_info is not None,
                "closed_amount": closed_info.balance if closed_info else None,
            })

        @bp.route("/<channel_id>/close", methods=["POST"])
        def cooperative_close(channel_id):
            data = request.get_json() or {}
            balance = data.get("balance")
            if balance is None:
                return jsonify({"error": "missing balance"}), 400
            
            # Check if already closed - return idempotent response
            if channel_id in self.host.stores.channel_closed:
                closed_info = self.host.stores.channel_closed[channel_id]
                if closed_info.balance == balance:
                    return jsonify({
                        "success": True,
                        "channel_id": channel_id,
                        "already_closed": True,
                        "total_value": closed_info.receiver_sum + closed_info.sender_sum,
                        "receiver_sum": closed_info.receiver_sum,
                        "sender_sum": closed_info.sender_sum,
                        "sender_proofs": closed_info.sender_proofs,
                    })
                else:
                    return jsonify({
                        "error": "channel already closed at different balance",
                        "closed_amount": closed_info.balance,
                        "requested_amount": balance,
                    }), 400

            data["channel_id"] = channel_id
            try:
                result = self.bridge.execute_cooperative_close(json.dumps(data))
                return jsonify({
                    "success": True,
                    "channel_id": result.channel_id,
                    "total_value": result.total_value,
                    "receiver_sum": result.receiver_sum,
                    "sender_sum": result.sender_sum,
                    "sender_proofs": json.loads(result.sender_proofs),
                    "already_closed": result.already_closed,
                })
            except Exception as e:
                msg = str(e)
                try:
                    err_data = json.loads(msg)
                    return jsonify(err_data), err_data.get("status", 500)
                except:
                    return jsonify({"error": msg}), 500

        @bp.route("/<channel_id>/unilateral-close", methods=["POST"])
        def unilateral_close(channel_id):
            # Check if already closed - return idempotent response
            if channel_id in self.host.stores.channel_closed:
                closed_info = self.host.stores.channel_closed[channel_id]
                return jsonify({
                    "success": True,
                    "channel_id": channel_id,
                    "already_closed": True,
                    "earnedBeforeStage2Fees": closed_info.receiver_sum,
                })

            try:
                result = self.bridge.execute_unilateral_close(channel_id)
                return jsonify({
                    "success": True,
                    "channel_id": channel_id,
                    "earnedBeforeStage2Fees": result.receiver_sum,
                    "already_closed": False,
                })
            except Exception as e:
                msg = str(e)
                try:
                    err_data = json.loads(msg)
                    return jsonify(err_data), err_data.get("status", 500)
                except:
                    return jsonify({"error": msg}), 500

        app.register_blueprint(bp)
        app.extensions["spilman"] = self

    def _decode_payment_header(self) -> str:
        """Decode the X-Cashu-Channel header from the current Flask request."""
        header_b64 = request.headers.get("X-Cashu-Channel")
        if not header_b64:
            raise ValueError("Missing X-Cashu-Channel header")
        try:
            return base64.b64decode(header_b64).decode()
        except Exception:
            raise ValueError("invalid base64")

    def process_request_payment(self, context: Union[str, Dict[str, Any]] = "{}"):
        """Extracts and processes payment from the current Flask request.
        
        Returns:
            PaymentSuccess object.
            
        Raises:
            Exception that should be handled by the caller or caught by Flask.
            Specifically, it might raise errors that map to 400 or 402.
        """
        payment_json = self._decode_payment_header()
        context_json = context if isinstance(context, str) else json.dumps(context)
        return self.bridge.process_payment(payment_json, context_json)

    def process_request_payment_no_usage(self):
        """Process payment with zero usage context.

        Validates that the payment covers prior accumulated usage (raises on
        402 if insufficient), tracks the balance and signature, but does NOT
        increment any usage counters.  Call ``record_usage`` after the work
        is done to apply the actual usage.

        Returns:
            PaymentSuccess object.
        """
        return self.process_request_payment("{}")

    def record_usage(self, increments: Dict[str, Any]):
        """Record usage for the channel in the current request.

        Auto-reads the X-Cashu-Channel header to extract channel_id,
        balance, and signature, then calls ``host.record_payment`` with
        the given usage increments.  Does NOT re-validate the payment.

        This is the companion to ``process_request_payment_no_usage``.
        """
        payment_json = self._decode_payment_header()
        data = json.loads(payment_json)
        channel_id = data.get("channel_id", "")
        balance = data.get("balance", 0)
        signature = data.get("signature", "")
        self.host.record_payment(channel_id, balance, signature, json.dumps(increments))

    def payment_covers_amount_due(self, context: Union[str, Dict[str, Any]] = "{}") -> bool:
        header_b64 = request.headers.get("X-Cashu-Channel")
        if not header_b64:
            raise ValueError("Missing X-Cashu-Channel header")

        try:
            payment_json = base64.b64decode(header_b64).decode()
        except Exception:
            raise ValueError("invalid base64")

        context_json = context if isinstance(context, str) else json.dumps(context)
        return self.bridge.payment_covers_amount_due(payment_json, context_json)

    def verify_payment_covers_amount_due(self, context: Union[str, Dict[str, Any]] = "{}") -> int:
        header_b64 = request.headers.get("X-Cashu-Channel")
        if not header_b64:
            raise ValueError("Missing X-Cashu-Channel header")

        try:
            payment_json = base64.b64decode(header_b64).decode()
        except Exception:
            raise ValueError("invalid base64")

        context_json = context if isinstance(context, str) else json.dumps(context)
        return self.bridge.verify_payment_covers_amount_due(payment_json, context_json)

    def attach_payment_header(self, response, payment_result):
        """Attaches the confirmation header to a Flask response."""
        payment_info = {
            "channel_id": payment_result.channel_id,
            "balance": payment_result.balance,
            "amount_due": payment_result.amount_due,
            "capacity": payment_result.capacity,
        }
        response.headers["X-Cashu-Channel"] = json.dumps(payment_info)
        return response

    def payment_required(self, f=None, context_provider=None, precheck=None):
        if f is None:
            return lambda func: self.payment_required(func, context_provider, precheck)

        @wraps(f)
        def decorated(*args, **kwargs):
            if precheck:
                precheck_result = precheck()
                if precheck_result is not None:
                    return precheck_result

            context = "{}"
            if context_provider:
                try:
                    context = context_provider()
                except Exception as e:
                    print(f"  [Spilman] Context provider failed: {e}")
            
            try:
                result = self.process_request_payment(context)
                request.spilman_payment = result
                
                resp = f(*args, **kwargs)
                
                # Handle different return types (flask common patterns)
                if isinstance(resp, tuple):
                    r_obj, status = resp
                else:
                    r_obj, status = resp, 200
                
                if status == 200 and hasattr(r_obj, "headers"):
                    self.attach_payment_header(r_obj, result)
                
                return resp
            except Exception as e:
                msg = str(e)
                status_code, reason = normalize_bridge_error(msg)
                response = jsonify({
                    "success": False,
                    "error": "Payment failed",
                    "reason": reason,
                })
                response.headers["X-Cashu-Channel"] = json.dumps({"error": reason})
                return response, status_code
        
        return decorated
