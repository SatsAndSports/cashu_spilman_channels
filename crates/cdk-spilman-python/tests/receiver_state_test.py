import json

import cdk_spilman
import pytest


class StateHost:
    def __init__(self, state):
        self.state = state

    def get_channel_state(self, channel_id):
        if isinstance(self.state, Exception):
            raise self.state
        return self.state


@pytest.mark.parametrize("state,code", [
    (None, "unknown_channel"),
    ("closing", "channel_closing"),
    ("closed", "channel_closed"),
    ("sender_refunded_after_expiry", "channel_closed"),
    ("garbage", "internal"),
    ("", "internal"),
    (42, "internal"),
    (RuntimeError("storage unavailable"), "internal"),
])
def test_receiver_state_callback_is_explicit_and_fallible(state, code):
    bridge = cdk_spilman.SpilmanBridge(StateHost(state))
    payment = json.dumps({"channel_id": "missing", "balance": 0, "signature": "sig"})
    with pytest.raises(RuntimeError) as error:
        bridge.validate_payment(payment, "{}")
    assert json.loads(str(error.value))["code"] == code
