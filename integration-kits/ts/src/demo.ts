import { readFileSync } from "fs";

/**
 * Fetches active keyset info from a mint.
 */
export async function demoFetchActiveKeysetInfo(mintUrl: string, unit: string = "sat"): Promise<any> {
  const resp = await fetch(`${mintUrl}/v1/keysets`);
  const { keysets } = await resp.json() as any;
  const active = keysets.find((k: any) => k.unit === unit && k.active);
  if (!active) throw new Error(`No active ${unit} keyset found`);

  const keysResp = await fetch(`${mintUrl}/v1/keys/${active.id}`);
  const { keysets: keysData } = await keysResp.json() as any;
  return {
    keysetId: active.id,
    unit,
    inputFeePpk: active.input_fee_ppk || 0,
    keys: keysData[0].keys,
  };
}

/**
 * Handles the quote and wait process for funding a channel.
 */
export async function demoMintFundingToken(mintUrl: string, amount: number, blindedMessages: any[], unit: string = "sat"): Promise<any[]> {
  const quoteResp = await fetch(`${mintUrl}/v1/mint/quote/bolt11`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ amount, unit }),
  });
  const quote = await quoteResp.json() as any;

  if (quote.request) {
    console.log("\n  " + "=".repeat(56));
    console.log("  PAY THIS INVOICE TO FUND THE CHANNEL");
    console.log("  " + "=".repeat(56) + "\n");
    console.log(`  ${quote.request}\n`);
    // Note: No QR code library in TS kit by default to keep it small
    console.log("  " + "=".repeat(56) + "\n");
  }

  console.log("  Waiting for payment...");
  for (let i = 0; i < 120; i++) {
    const checkResp = await fetch(`${mintUrl}/v1/mint/quote/bolt11/${quote.quote}`);
    const status = await checkResp.json() as any;
    if (status.state === "PAID" || status.paid) {
      console.log("  Payment received!");
      break;
    }
    await new Promise(r => setTimeout(r, 500));
    if (i === 119) throw new Error("Quote not paid in time");
  }

  const mintResp = await fetch(`${mintUrl}/v1/mint/bolt11`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ quote: quote.quote, outputs: blindedMessages }),
  });
  const { signatures } = await mintResp.json() as any;
  return signatures;
}
