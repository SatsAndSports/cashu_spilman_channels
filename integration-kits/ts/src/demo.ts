import { readFileSync } from "fs";
import { create_plain_blinded_messages, construct_proofs, discover_keysets_json, select_active_keyset_json, build_keyset_info_from_responses } from "../wasm/cdk_wasm.js";

export const KEYSET_VERSIONS_V1 = Object.freeze(["v1"] as const);
export const KEYSET_VERSIONS_V2 = Object.freeze(["v2"] as const);
export const KEYSET_VERSIONS_V1_AND_V2 = Object.freeze(["v1", "v2"] as const);
export type KeysetVersion = "v1" | "v2";

/**
 * Mints plain proofs (not channel-locked) from a mint.
 *
 * This handles the full flow: create blinded messages, get quote,
 * wait for payment, mint, and construct proofs.
 *
 * @param mintUrl - The mint URL
 * @param amount - Amount to mint in the given unit
 * @param keysetInfoJson - JSON string of keyset info
 * @param unit - Currency unit (default "sat")
 * @returns JSON array of proofs ready for use in a token
 */
export async function demoMintPlainProofs(
  mintUrl: string,
  amount: number,
  keysetInfoJson: string,
  unit: string = "sat"
): Promise<string> {
  // 1. Create plain blinded messages
  const resultJson = create_plain_blinded_messages(BigInt(amount), keysetInfoJson);
  const result = JSON.parse(resultJson);
  const blindedMessages = result.blinded_messages;
  const secretsWithBlinding = JSON.stringify(result.secrets_with_blinding);

  // 2. Request a mint quote
  const quoteResp = await fetch(`${mintUrl}/v1/mint/quote/bolt11`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ amount, unit }),
  });
  const quote = await quoteResp.json() as any;

  if (quote.request) {
    console.log("\n  " + "=".repeat(56));
    console.log("  PAY THIS INVOICE TO MINT TOKENS");
    console.log("  " + "=".repeat(56) + "\n");
    console.log(`  ${quote.request}\n`);
    console.log("  " + "=".repeat(56) + "\n");
  }

  // 3. Wait for payment
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

  // 4. Mint tokens
  const mintResp = await fetch(`${mintUrl}/v1/mint/bolt11`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ quote: quote.quote, outputs: blindedMessages }),
  });
  const { signatures } = await mintResp.json() as any;
  const signaturesJson = JSON.stringify(signatures);

  // 5. Construct proofs
  return construct_proofs(signaturesJson, secretsWithBlinding, keysetInfoJson);
}

/**
 * Fetches active keyset info from a mint.
 */
export async function demoFetchActiveKeysetInfo(mintUrl: string, unit: string = "sat", allowedVersions: readonly KeysetVersion[] = KEYSET_VERSIONS_V1_AND_V2): Promise<any> {
  const resp = await fetch(`${mintUrl}/v1/keysets`);
  if (!resp.ok) throw new Error(`Keyset metadata HTTP failure: ${resp.status}`);
  const listing = await resp.text();
  const report = JSON.parse(discover_keysets_json(listing));
  for (const unsupportedUnit of report.unsupported_active_units) {
    console.warn(`Mint ${mintUrl} has only unsupported active keysets for unit ${unsupportedUnit}; supported: V1 (00), V2 (01)`);
  }
  const id = select_active_keyset_json(listing, unit, JSON.stringify({ allowed_versions: allowedVersions }));
  const keysResp = await fetch(`${mintUrl}/v1/keys/${id}`);
  if (!keysResp.ok) throw new Error(`Keyset keys HTTP failure: ${keysResp.status}`);
  return JSON.parse(build_keyset_info_from_responses(listing, await keysResp.text(), id));
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
