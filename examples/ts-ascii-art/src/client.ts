/**
 * ASCII Art Client - High-level Spilman client using the Integration Kit.
 *
 * This demonstrates the simplified channel opening flow using openChannelFromToken.
 */

import {
  init,
  demoFetchActiveKeysetInfo,
  demoMintPlainProofs,
  build_cashu_b_token,
  SpilmanClientBridge,
  InMemorySpilmanClientHost,
} from "cdk-spilman-kit";
import * as secp from "@noble/secp256k1";

const SERVER_URL = process.env.SERVER_URL || "http://localhost:5001";

export async function runClient(args: string[]) {
  await init();
  const shouldClose = args.includes("--close");
  const messages = args.filter(a => a !== "--close");
  if (messages.length === 0) messages.push("Hello", "Cashu", "World");

  // 1. Setup Client
  const aliceSecret = Buffer.from(secp.utils.randomPrivateKey()).toString("hex");
  const senderPubkey = Buffer.from(secp.getPublicKey(aliceSecret, true)).toString("hex");
  const host = new InMemorySpilmanClientHost(aliceSecret);
  const bridge = new SpilmanClientBridge(host);

  // 2. Get Server Params & Keyset
  console.log(`Connecting to ${SERVER_URL}...`);
  const sp = await (await fetch(`${SERVER_URL}/channel/params`)).json() as any;
  const receiverPubkey = sp.receiver_pubkey;
  const mintUrl = Object.keys(sp.mints_units_keysets)[0];
  const ki = await demoFetchActiveKeysetInfo(mintUrl);
  const keysetInfoJson = JSON.stringify(ki);

  // 3. Mint proofs and build token
  const capacity = Math.max(messages.reduce((a, b) => a + b.length, 0) + 20, 50);
  // Mint slightly more than capacity to cover potential fees
  const mintAmount = capacity + 10;

  console.log("Minting tokens...");
  const proofsJson = await demoMintPlainProofs(mintUrl, mintAmount, keysetInfoJson);

  // Build a cashuB token from the proofs
  const token = build_cashu_b_token(mintUrl, "sat", proofsJson);

  // 4. Open channel from token (the simplified way!)
  console.log("Opening channel...");
  const expiry = Math.floor(Date.now() / 1000) + 7200; // 2 hours from now
  const result = await bridge.openChannelFromToken(
    token,
    receiverPubkey,
    senderPubkey,
    BigInt(expiry),
    keysetInfoJson,
    BigInt(64), // max_amount per output
  );

  const cid = result.channel_id;
  console.log(`Full channel ID: ${cid}`);
  console.log(`Capacity: ${result.capacity} sat`);

  // 5. Make Requests
  let balance = 0;
  console.log(`Channel ${cid.slice(0, 8)} ready! Sending requests...`);
  for (let i = 0; i < messages.length; i++) {
    balance += messages[i].length;
    const header = bridge.buildPaymentHeader(cid, BigInt(balance), i === 0);
    const r = await fetch(`${SERVER_URL}/ascii`, {
      method: "POST", body: JSON.stringify({ message: messages[i] }),
      headers: { "Content-Type": "application/json", "X-Cashu-Channel": header }
    });
    if (r.ok) {
      const res = await r.json() as any;
      console.log(`\n[${i + 1}/${messages.length}] Accepted:\n${res.art}`);
    } else {
      console.log(`Request failed: ${r.status} ${await r.text()}`);
      break;
    }
  }

  // 6. Optional Close
  if (shouldClose) {
    console.log("\nClosing channel...");
    const status = await (await fetch(`${SERVER_URL}/channel/${cid}/status`)).json() as any;
    const closeReq = bridge.createCooperativeCloseRequest(cid, BigInt(status.amount_due));
    const cResp = await fetch(`${SERVER_URL}/channel/${cid}/close`, {
      method: "POST", body: JSON.stringify(closeReq), headers: { "Content-Type": "application/json" }
    });
    if (cResp.ok) {
      const body = await cResp.text();
      bridge.processCooperativeCloseResponse(body);
      const cr = JSON.parse(body);
      console.log(`Closed! Earned: ${cr.receiver_sum}, Refunded: ${cr.sender_sum}`);
    } else {
      console.log(`Close failed: ${await cResp.text()}`);
    }
  }
}
