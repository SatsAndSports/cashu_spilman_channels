import express from "express";
import { ConfigurableSpilman, init, mapErrorStatus, getBridgeErrorReason } from "cdk-spilman-kit";
import figlet from "figlet";

const CONFIG_PATH = process.env.CONFIG_PATH || "config.yaml";
const SECRET_KEY = process.env.SERVER_SECRET_KEY || "0000000000000000000000000000000000000000000000000000000000000001";
const PORT = process.env.PORT || 5001;

export async function runServer() {
  await init();
  const ctx = await ConfigurableSpilman.fromYaml(CONFIG_PATH, SECRET_KEY);
  const app = express();
  app.use(express.json());

  const spilman = ctx.initExpress(app);

  app.post("/ascii", (req, res) => {
    const { message } = req.body;
    console.log(`\n[Request] ASCII art for '${message}'`);

    try {
      const payment = spilman.processRequestPayment(req, { chars: message.length });
      console.log(`  [Payment] ACCEPTED: balance=${payment.balance}/${payment.capacity}`);

      const art = figlet.textSync(message);
      spilman.attachPaymentHeader(res, payment);
      res.json({ art, message, payment });
    } catch (e: any) {
      const reason = getBridgeErrorReason(e);
      console.log(`  [Payment] REJECTED: ${reason}`);
      const status = mapErrorStatus(e);
      res.status(status).json({ error: "Payment failed", reason, status });
    }
  });

  app.post("/ascii/preflight", (req, res) => {
    const { message } = req.body || {};
    if (!message || typeof message !== "string") {
      res.status(400).json({ error: "Missing 'message'" });
      return;
    }

    try {
      const ok = spilman.paymentCoversAmountDue(req, { chars: message.length });
      if (!ok) {
        res.json({ ok: false });
        return;
      }

      const amountDue = spilman.verifyPaymentCoversAmountDue(req, { chars: message.length });
      res.json({ ok: true, amount_due: amountDue });
    } catch (e: any) {
      const reason = getBridgeErrorReason(e);
      const status = mapErrorStatus(e);
      res.status(status).json({ error: "Payment preflight failed", reason, status });
    }
  });

  app.listen(PORT, () => {
    console.log(`TS Server listening on :${PORT} (Pubkey: ${ctx.host.pubkey})`);
    console.log("Server is ready.");
  });
}
