import {
  init,
  demoFetchActiveKeysetInfo,
  demoMintFundingToken,
  compute_channel_secret,
  compute_funding_token_amount,
  channel_parameters_get_channel_id,
  create_funding_outputs,
  construct_proofs,
  sign_with_tweaked_key,
  SpilmanClientBridge,
} from "cdk-spilman-kit";
import * as secp from "@noble/secp256k1";

const SERVER_URL = process.env.SERVER_URL || "http://localhost:5001";

class DemoClientHost {
  funding: Record<string, string> = {};
  paymentState: Record<string, string> = {};
  channelState: Record<string, string> = {};
  constructor(private aliceSecret: string) {}

  // Networking
  async callMintSwap(url: string, req: string) {
    const r = await fetch(`${url}/v1/swap`, { method: "POST", body: req, headers: { "Content-Type": "application/json" } });
    const text = await r.text();
    if (!r.ok) {
      throw (text || `Mint rejected swap with status ${r.status}`);
    }
    return text;
  }

  // Funding Data
  saveChannelFunding(id: string, fundingJson: string) {
    this.funding[id] = fundingJson;
    this.channelState[id] = "open";
  }
  getChannelFunding(id: string): string | null { return this.funding[id] || null; }

  // Payment State
  getPaymentState(id: string): string | null { return this.paymentState[id] || null; }
  recordPayment(id: string, stateJson: string) { this.paymentState[id] = stateJson; }

  // Lifecycle
  getChannelState(id: string) { return this.channelState[id] || "open"; }
  markChannelClosed(id: string) { this.channelState[id] = "closed"; }
  listChannelIds() { return Object.keys(this.funding); }
  deleteChannel(id: string) {
    delete this.funding[id];
    delete this.paymentState[id];
    delete this.channelState[id];
  }

  // Time
  nowSeconds() { return BigInt(Math.floor(Date.now() / 1000)); }

  // Crypto
  signWithTweakedKey(pk: string, msg: string, tw: string) {
    return sign_with_tweaked_key(this.aliceSecret, msg, tw);
  }
  computeChannelSecret(apk: string, cpk: string) { return compute_channel_secret(this.aliceSecret, cpk); }
}

export async function runClient(args: string[]) {
  await init();
  const shouldClose = args.includes("--close");
  const messages = args.filter(a => a !== "--close");
  if (messages.length === 0) messages.push("Hello", "Cashu", "World");

  console.log(`Connecting to ${SERVER_URL}...`);
  const sp = await (await fetch(`${SERVER_URL}/channel/params`)).json() as any;
  const mintUrl = Object.keys(sp.mints_units_keysets)[0];
  const ki = await demoFetchActiveKeysetInfo(mintUrl);

  const aliceSecret = Buffer.from(secp.utils.randomPrivateKey()).toString("hex");
  const alicePub = Buffer.from(secp.getPublicKey(aliceSecret, true)).toString("hex");
  const host = new DemoClientHost(aliceSecret);
  const bridge = new SpilmanClientBridge(host);

  console.log("Funding channel...");
  const cap = Math.max(messages.reduce((a, b) => a + b.length, 0) + 20, 50);
  const fta = compute_funding_token_amount(BigInt(cap), JSON.stringify(ki), BigInt(64));
  const ss = compute_channel_secret(aliceSecret, sp.receiver_pubkey);
  const cp = {
    sender_pubkey: alicePub, receiver_pubkey: sp.receiver_pubkey, mint: mintUrl, unit: "sat", capacity: cap,
    funding_token_amount: Number(fta), maximum_amount: 64, expiry_timestamp: Math.floor(Date.now() / 1000) + 7200,
    setup_timestamp: Math.floor(Date.now() / 1000),
    keyset_id: ki.keysetId, input_fee_ppk: ki.inputFeePpk,
  };
  const cid = channel_parameters_get_channel_id(JSON.stringify(cp), ss, JSON.stringify(ki));
  const funding = JSON.parse(create_funding_outputs(JSON.stringify(cp), aliceSecret, JSON.stringify(ki)));
  const sigs = await demoMintFundingToken(mintUrl, funding.funding_token_nominal, funding.blinded_messages);
  const proofs = construct_proofs(JSON.stringify(sigs), JSON.stringify(funding.secrets_with_blinding), JSON.stringify(ki));

  // ClientChannelFunding structure - field names must match Rust struct
  host.saveChannelFunding(cid, JSON.stringify({
    params_json: JSON.stringify(cp),
    funding_proofs_json: proofs,
    channel_secret_hex: ss,
    keyset_info_json: JSON.stringify(ki),
    sender_pubkey_hex: alicePub,
    capacity: cap,
    funding_token_amount: Number(fta),
    mint_url: mintUrl,
    created_at: Math.floor(Date.now() / 1000),
  }));

  console.log(`Full channel ID: ${cid}\nChannel ready! Sending requests...`);
  let balance = 0;
  for (let i = 0; i < messages.length; i++) {
    balance += messages[i].length;
    const header = bridge.buildPaymentHeader(cid, BigInt(balance), i === 0);
    const r = await fetch(`${SERVER_URL}/ascii`, {
      method: "POST", body: JSON.stringify({ message: messages[i] }),
      headers: { "Content-Type": "application/json", "X-Cashu-Channel": header }
    });
    const res = await r.json() as any;
    console.log(`\n[${i + 1}/${messages.length}] Accepted:\n${res.art}`);
  }

  if (shouldClose) {
    console.log("\nClosing channel...");
    const status = await (await fetch(`${SERVER_URL}/channel/${cid}/status`)).json() as any;
    const closeReq = bridge.createCooperativeCloseRequest(cid, BigInt(status.amount_due));
    const cResp = await fetch(`${SERVER_URL}/channel/${cid}/close`, {
      method: "POST", body: closeReq, headers: { "Content-Type": "application/json" }
    });
    const body = await cResp.text();
    bridge.processCooperativeCloseResponse(body);
    const cr = JSON.parse(body);

    console.log(`Closed! Earned: ${cr.receiver_sum}, Refunded: ${cr.sender_sum}`);
  }
}
