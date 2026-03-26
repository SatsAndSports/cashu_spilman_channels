import { KeysetCache, PricingTable } from "./stores.js";

export interface FetchedKeysetEntry {
  id: string;
  infoJson: string;
  active: boolean;
  unit: string;
}

export async function fetchAllKeysetsFromMint(
  mintUrl: string,
  pricing: PricingTable
): Promise<FetchedKeysetEntry[]> {
  const keysetsResp = await fetch(`${mintUrl}/v1/keysets`);
  if (!keysetsResp.ok) throw new Error(`Failed to fetch keysets: ${keysetsResp.status}`);
  const keysetsData = await keysetsResp.json();

  const results: FetchedKeysetEntry[] = [];

  for (const ks of keysetsData.keysets || []) {
    if (!(ks.unit in pricing)) continue;

    const keysResp = await fetch(`${mintUrl}/v1/keys/${ks.id}`);
    if (!keysResp.ok) continue;
    const keysData = await keysResp.json();
    const keys = keysData.keysets[0].keys;

    const keysetInfo = {
      keysetId: ks.id,
      unit: ks.unit,
      keys,
      inputFeePpk: ks.input_fee_ppk || 0,
      amounts: Object.keys(keys).map(Number).sort((a: number, b: number) => b - a),
    };

    results.push({
      id: ks.id,
      infoJson: JSON.stringify(keysetInfo),
      active: ks.active,
      unit: ks.unit,
    });
  }

  return results;
}

export async function fetchAndCacheKeysetsForMint(
  mintUrl: string,
  pricing: PricingTable,
  keysetCache: KeysetCache
): Promise<void> {
  const keysets = await fetchAllKeysetsFromMint(mintUrl, pricing);
  for (const entry of keysets) {
    keysetCache.set(mintUrl, entry.id, {
      infoJson: entry.infoJson,
      active: entry.active,
      unit: entry.unit,
    });
  }
}
