# Spilman TypeScript Integration Kit

Drop-in management router and helpers for Express servers, plus a lightweight
client bridge wrapper for Node.js.

## Quick start

For a runnable demo, use the reference server/client:

```bash
cd examples/ts-ascii-art
npm install
npm run server
```

## Server usage (Express)

```ts
import express from "express";
import { ConfigurableSpilman, init, mapErrorStatus, getBridgeErrorReason } from "cdk-spilman-kit";

await init();
const ctx = await ConfigurableSpilman.fromYaml("config.yaml", secretKeyHex);

const app = express();
app.use(express.json());
const spilman = ctx.initExpress(app);

app.post("/ascii", (req, res) => {
  const { message } = req.body;
  try {
    const payment = spilman.processRequestPayment(req, { chars: message.length });
    spilman.attachPaymentHeader(res, payment);
    res.json({ art: message, payment });
  } catch (e: any) {
    const reason = getBridgeErrorReason(e);
    res.status(mapErrorStatus(e)).json({ error: "Payment failed", reason });
  }
});
```

## Client usage (Node.js)

```ts
import { SpilmanClientBridge, init } from "cdk-spilman-kit";

await init();
const bridge = new SpilmanClientBridge(host);

const header = bridge.buildPaymentHeader(channelId, BigInt(balance), true);
const closeReq = bridge.createCooperativeCloseRequest(channelId, BigInt(finalBalance));
bridge.processCooperativeCloseResponse(closeResponseJson);
```

Note: `openChannelFromToken` is not exposed in the JS wrapper yet because the
WASM client host does not support async mint swaps.

## WASM artifacts

This kit expects the Node.js WASM artifacts under `wasm/`. In the monorepo they
are automatically synchronized from `web/wasm-nodejs` when running `make build-wasm`.

When splitting into a standalone repo, keep `cdk_wasm.js` and `cdk_wasm_bg.wasm`
together in that directory.
