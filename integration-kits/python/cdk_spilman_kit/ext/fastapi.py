import base64
import json
from typing import Optional, Any, Callable
from fastapi import APIRouter, Request, HTTPException, Depends, Header, Response
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
    if "channel closed" in lower_msg:
        return 410
    if "channel closing" in lower_msg:
        return 409

    is_bad_request = any(
        x in lower_msg
        for x in [
            "invalid base64",
            "invalid utf8",
            "invalid json",
            "missing field",
            "missing signature",
            "missing channel_id",
        ]
    )

    if not is_bad_request:
        if "expected" in lower_msg and any(x in lower_msg for x in ["string", "integer", "u64"]):
            is_bad_request = True

    if is_bad_request:
        return 400

    if "internal" in lower_msg or "misconfigured" in lower_msg:
        return 500
    return 402


def map_error_name(error_msg: str) -> str:
    if map_error_status(error_msg) == 400:
        return "Bad request"
    return "Registration failed"

def normalize_bridge_error(error_msg: str):
    status = map_error_status(error_msg)
    _, reason, _ = parse_bridge_error(error_msg)
    return status, reason or error_msg

class Spilman:
    def __init__(self, host: BaseSpilmanHost):
        self.host = host
        self.bridge = SpilmanBridge(self.host)
        self.router = self._create_router()

    def _create_router(self) -> APIRouter:
        router = APIRouter(prefix="/channel")

        @router.get("/params")
        async def get_params():
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
            return {
                "receiver_pubkey": self.host.pubkey,
                "pricing": pricing,
                "mints_units_keysets": self.host.stores.get_mints_units_keysets(),
                "pricing_scale": self.host.pricing_scale,
                "min_expiry_in_seconds": self.host.min_expiry_seconds,
            }

        @router.post("/register")
        async def register_channel(data: dict):
            if data.get("balance") != 0:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "Bad request",
                        "reason": f"funding requires balance=0, got {data.get('balance')}",
                    },
                )
            
            try:
                result = self.bridge.fund_channel(json.dumps(data))
                return {
                    "success": True,
                    "channel_id": result.channel_id,
                    "capacity": result.capacity,
                    "already_known": result.already_known,
                }
            except Exception as e:
                msg = str(e)
                status, reason = normalize_bridge_error(msg)
                raise HTTPException(
                    status_code=status,
                    detail={
                        "success": False,
                        "error": map_error_name(msg),
                        "reason": reason,
                        "status": status,
                    },
                )

        @router.get("/{channel_id}/status")
        async def channel_status(channel_id: str):
            funding = self.host.stores.channel_funding.get(channel_id)
            if not funding:
                raise HTTPException(status_code=404, detail="unknown channel")
            
            params = json.loads(funding["params"])
            payment = self.host.stores.channel_largest_payment.get(channel_id, {})
            closed_info = self.host.stores.channel_closed.get(channel_id)
            
            return {
                "channel_id": channel_id,
                "capacity": params.get("capacity", 0),
                "balance": payment.get("balance", 0),
                "amount_due": self.host.get_amount_due(channel_id, None),
                "closed": closed_info is not None,
                "closed_amount": closed_info.balance if closed_info else None,
            }

        @router.post("/{channel_id}/close")
        async def cooperative_close(channel_id: str, data: dict):
            balance = data.get("balance")
            if balance is None:
                raise HTTPException(status_code=400, detail={"error": "missing balance"})

            closed_info = self.host.stores.channel_closed.get(channel_id)
            if closed_info:
                if closed_info.balance == balance:
                    return {
                        "success": True,
                        "channel_id": channel_id,
                        "already_closed": True,
                        "total_value": closed_info.receiver_sum + closed_info.sender_sum,
                        "receiver_sum": closed_info.receiver_sum,
                        "sender_sum": closed_info.sender_sum,
                        "sender_proofs": closed_info.sender_proofs,
                    }
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "channel already closed at different balance",
                        "closed_amount": closed_info.balance,
                        "requested_amount": balance,
                    },
                )

            data["channel_id"] = channel_id
            try:
                result = self.bridge.execute_cooperative_close(json.dumps(data))
                return {
                    "success": True,
                    "channel_id": result.channel_id,
                    "total_value": result.total_value,
                    "receiver_sum": result.receiver_sum,
                    "sender_sum": result.sender_sum,
                    "sender_proofs": json.loads(result.sender_proofs),
                    "already_closed": result.already_closed,
                }
            except Exception as e:
                msg = str(e)
                try:
                    err_data = json.loads(msg)
                    raise HTTPException(status_code=err_data.get("status", 500), detail=err_data)
                except:
                    raise HTTPException(status_code=500, detail=msg)

        @router.post("/{channel_id}/unilateral-close")
        async def unilateral_close(channel_id: str):
            closed_info = self.host.stores.channel_closed.get(channel_id)
            if closed_info:
                return {
                    "success": True,
                    "channel_id": channel_id,
                    "already_closed": True,
                    "earnedBeforeStage2Fees": closed_info.receiver_sum,
                }

            try:
                result = self.bridge.execute_unilateral_close(channel_id)
                return {
                    "success": True,
                    "channel_id": channel_id,
                    "earnedBeforeStage2Fees": result.receiver_sum,
                    "already_closed": False,
                }
            except Exception as e:
                msg = str(e)
                try:
                    err_data = json.loads(msg)
                    raise HTTPException(status_code=err_data.get("status", 500), detail=err_data)
                except:
                    raise HTTPException(status_code=500, detail=msg)

        return router

    def _decode_payment_header(self, x_cashu_channel: Optional[str]) -> str:
        """Decode the X-Cashu-Channel header value."""
        if not x_cashu_channel:
            raise HTTPException(status_code=402, detail={
                "error": "Payment required",
                "reason": "Missing X-Cashu-Channel header",
            })
        try:
            return base64.b64decode(x_cashu_channel).decode()
        except:
            raise HTTPException(status_code=400, detail={
                "error": "Invalid payment header",
                "reason": "invalid base64",
            })

    async def process_request_payment(self, request: Request, x_cashu_channel: Optional[str] = Header(None), context_json: str = "{}"):
        """Extracts and processes payment from the current FastAPI request.
        
        Returns:
            PaymentSuccess object.
            
        Raises:
            HTTPException with 400 or 402 status.
        """
        payment_json = self._decode_payment_header(x_cashu_channel)
        try:
            return self.bridge.process_payment(payment_json, context_json)
        except Exception as e:
            msg = str(e)
            status, reason = normalize_bridge_error(msg)
            raise HTTPException(
                status_code=status,
                detail={
                    "success": False,
                    "error": "Payment failed",
                    "reason": reason,
                },
                headers={"X-Cashu-Channel": json.dumps({"error": reason})},
            )

    async def process_request_payment_no_usage(self, request: Request, x_cashu_channel: Optional[str] = Header(None)):
        """Process payment with zero usage context.

        Validates that the payment covers prior accumulated usage (raises
        HTTPException 402 if insufficient), tracks balance and signature,
        but does NOT increment any usage counters.  Call ``record_usage``
        after the work is done to apply actual usage.

        Returns:
            PaymentSuccess object.
        """
        return await self.process_request_payment(request, x_cashu_channel, "{}")

    async def record_usage(self, request: Request, increments: dict):
        """Record usage for the channel in the current request.

        Auto-reads the X-Cashu-Channel header to extract channel_id,
        balance, and signature, then calls ``host.record_payment`` with
        the given usage increments.  Does NOT re-validate the payment.

        This is the companion to ``process_request_payment_no_usage``.
        """
        x_cashu_channel = request.headers.get("x-cashu-channel")
        payment_json = self._decode_payment_header(x_cashu_channel)
        data = json.loads(payment_json)
        channel_id = data.get("channel_id", "")
        balance = data.get("balance", 0)
        signature = data.get("signature", "")
        self.host.record_payment(channel_id, balance, signature, json.dumps(increments))

    async def payment_covers_amount_due(self, x_cashu_channel: Optional[str] = Header(None), context_json: str = "{}"):
        if not x_cashu_channel:
            raise HTTPException(status_code=402, detail={
                "error": "Payment required",
                "reason": "Missing X-Cashu-Channel header",
            })

        try:
            payment_json = base64.b64decode(x_cashu_channel).decode()
        except:
            raise HTTPException(status_code=400, detail={
                "error": "Invalid payment header",
                "reason": "invalid base64",
            })

        try:
            return self.bridge.payment_covers_amount_due(payment_json, context_json)
        except Exception as e:
            msg = str(e)
            status, reason = normalize_bridge_error(msg)
            raise HTTPException(
                status_code=status,
                detail={
                    "success": False,
                    "error": "Payment preflight failed",
                    "reason": reason,
                },
                headers={"X-Cashu-Channel": json.dumps({"error": reason})},
            )

    async def verify_payment_covers_amount_due(self, x_cashu_channel: Optional[str] = Header(None), context_json: str = "{}"):
        if not x_cashu_channel:
            raise HTTPException(status_code=402, detail={
                "error": "Payment required",
                "reason": "Missing X-Cashu-Channel header",
            })

        try:
            payment_json = base64.b64decode(x_cashu_channel).decode()
        except:
            raise HTTPException(status_code=400, detail={
                "error": "Invalid payment header",
                "reason": "invalid base64",
            })

        try:
            return self.bridge.verify_payment_covers_amount_due(payment_json, context_json)
        except Exception as e:
            msg = str(e)
            status, reason = normalize_bridge_error(msg)
            raise HTTPException(
                status_code=status,
                detail={
                    "success": False,
                    "error": "Payment preflight failed",
                    "reason": reason,
                },
                headers={"X-Cashu-Channel": json.dumps({"error": reason})},
            )

    def add_payment_confirmation_header(self, response: Response, payment_result: Any):
        """Attaches the confirmation header to a FastAPI response."""
        if payment_result:
            payment_info = {
                "channel_id": payment_result.channel_id,
                "balance": payment_result.balance,
                "amount_due": payment_result.amount_due,
                "capacity": payment_result.capacity,
            }
            response.headers["X-Cashu-Channel"] = json.dumps(payment_info)
        return response

    def payment_dependency(self, context_provider: Optional[Callable[[Request], str]] = None, precheck: Optional[Callable[[Request], Any]] = None):
        async def dependency(request: Request, x_cashu_channel: Optional[str] = Header(None)):
            if precheck:
                precheck_result = precheck(request)
                if precheck_result is not None:
                    if isinstance(precheck_result, HTTPException):
                        raise precheck_result
                    if isinstance(precheck_result, tuple) and len(precheck_result) == 2:
                        status_code, detail = precheck_result
                    else:
                        status_code, detail = 400, precheck_result
                    raise HTTPException(status_code=status_code, detail=detail)

            context = "{}"
            if context_provider:
                try:
                    context = context_provider(request)
                except Exception as e:
                    print(f"  [Spilman] Context provider failed: {e}")
            else:
                context = getattr(request.state, "spilman_context", "{}")

            result = await self.process_request_payment(request, x_cashu_channel, context)
            request.state.spilman_payment = result
            return result

        return dependency

    async def payment_required(self, request: Request, x_cashu_channel: Optional[str] = Header(None)):
        result = await self.process_request_payment(request, x_cashu_channel)
        request.state.spilman_payment = result
        return result
