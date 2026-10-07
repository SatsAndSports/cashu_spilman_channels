import { KeysetCache, PricingTable } from "./stores.js";
import { discover_keysets_json, build_keyset_info_from_responses } from "../wasm/cdk_wasm.js";

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
  const listing = await keysetsResp.text();
  const keysetsData = JSON.parse(discover_keysets_json(listing));
  for (const unit of keysetsData.unsupported_active_units) {
    console.warn(`Mint ${mintUrl} has only unsupported active keysets for unit ${unit}; supported: V1 (00), V2 (01)`);
  }

  const results: FetchedKeysetEntry[] = [];

  for (const ks of keysetsData.keysets || []) {
    if (!(ks.unit in pricing)) continue;

    const keysResp = await fetch(`${mintUrl}/v1/keys/${ks.id}`);
    if (!keysResp.ok) throw new Error(`Failed to fetch supported keyset keys: ${keysResp.status}`);
    const infoJson = build_keyset_info_from_responses(listing, await keysResp.text(), ks.id);

    results.push({
      id: ks.id,
      infoJson,
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
