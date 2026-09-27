import { beforeAll, expect, it } from "vitest";
import { init } from "./index.js";
import { WasmSpilmanBridge } from "../wasm/cdk_wasm.js";

beforeAll(async () => { await init(); });

it.each([
  [null, "unknown_channel"],
  ["closing", "channel_closing"],
  ["closed", "channel_closed"],
  ["sender_refunded_after_expiry", "channel_closed"],
  ["invalid", "internal"],
  ["", "internal"],
  [undefined, "internal"],
  [42, "internal"],
  [new Error("lookup failed"), "internal"],
])("receiver state %s is explicit and fallible", (state, code) => {
  const bridge = new WasmSpilmanBridge({
    getChannelState() {
      if (state instanceof Error) throw state;
      return state;
    },
  });
  try {
    const payment = JSON.stringify({ channel_id: "missing", balance: 0, signature: "sig" });
    let failure: unknown;
    try {
      bridge.validatePayment(payment, "{}");
    } catch (error) {
      failure = error;
    }
    expect(failure).toMatchObject({ code });
  } finally {
    bridge.free();
  }
});
