import * as secp from "@noble/secp256k1";
import { compute_channel_secret, sign_with_tweaked_key } from "../wasm/cdk_wasm.js";
import { PricingTable, SpilmanStores } from "./stores.js";

export interface SpilmanHostOptions {
  secretKeyHex: string;
  mints: Record<string, string[]>;
  pricing: PricingTable;
  stores: SpilmanStores;
  pricingScale?: number;
  refreshKeysets?: (mint: string) => Promise<void>;
  minExpirySeconds?: number;
}

export function getServerPubkey(secretKeyHex: string): string {
  const secretBytes = Buffer.from(secretKeyHex, "hex");
  const pubkeyBytes = secp.getPublicKey(secretBytes, true);
  return Buffer.from(pubkeyBytes).toString("hex");
}

export function createSpilmanHost(options: SpilmanHostOptions) {
  const { secretKeyHex, pricing, stores, refreshKeysets } = options;
  const receiverPubkey = getServerPubkey(secretKeyHex);
  const minExpirySeconds = options.minExpirySeconds ?? 3600;
  const pricingScale = options.pricingScale && options.pricingScale > 0 ? options.pricingScale : 1;

  // Pre-normalize mint URLs in the trusted map
  const trustedMints: Record<string, string[]> = {};
  for (const [url, units] of Object.entries(options.mints)) {
    trustedMints[url.replace(/\/$/, "")] = units;
  }

  return {
    serverPubkey: receiverPubkey,

    receiverKeyIsAcceptable: (pubkeyHex: string): boolean => {
      return pubkeyHex.toLowerCase() === receiverPubkey.toLowerCase();
    },

    mintAndKeysetIsAcceptable: (mint: string, keysetId: string): boolean => {
      const normMint = mint.replace(/\/$/, "");
      const trustedUnits = trustedMints[normMint];
      if (!trustedUnits) return false;
      
      const entry = stores.keysetCache.get(mint, keysetId);
      return entry !== null && entry.active && trustedUnits.includes(entry.unit);
    },

    getFundingAndParams: (channelId: string): [string, string, string, string] | null => {
      const funding = stores.channelFunding.get(channelId);
      if (!funding) return null;
      return [
        funding.paramsJson,
        funding.fundingProofsJson,
        funding.channelSecret,
        funding.keysetInfoJson,
      ];
    },

    saveFunding: (
      channelId: string,
      paramsJson: string,
      fundingProofsJson: string,
      channelSecret: string,
      keysetInfoJson: string,
      initialBalance: number,
      initialSignature: string
    ): void => {
      stores.channelFunding.insert(channelId, {
        paramsJson,
        fundingProofsJson,
        channelSecret,
        keysetInfoJson,
        secretKey: secretKeyHex,
      });
      stores.channelBalance.update(channelId, Number(initialBalance), initialSignature);
    },

    getAmountDue: (channelId: string, contextJson: string | null): bigint => {
      const accumulated = stores.channelUsage.getUsage(channelId) ?? {};
      const pending: Record<string, number> = contextJson ? JSON.parse(contextJson) : {};

      const funding = stores.channelFunding.get(channelId);
      if (!funding) return BigInt(0);

      const params = JSON.parse(funding.paramsJson);
      const unitPricing = pricing[params.unit];
      if (!unitPricing) return BigInt(0);

      let total = 0;
      for (const [varName, price] of Object.entries(unitPricing.variables)) {
        const acc = accumulated[varName] ?? 0;
        const pend = pending[varName] ?? 0;
        total += (acc + pend) * price;
      }

      return BigInt(Math.ceil(total / pricingScale));
    },

    recordPayment: (channelId: string, balance: number, signature: string, contextJson: string): void => {
      const increments: Record<string, number> = JSON.parse(contextJson);
      stores.channelUsage.incrementUsage(channelId, increments);
      stores.channelBalance.update(channelId, Number(balance), signature);
    },

    getChannelState: (channelId: string): string => {
      if (stores.channelClosed.isClosed(channelId)) return "closed";
      if (stores.channelClosing.isClosing(channelId)) return "closing";
      return "open";
    },

    markChannelClosing: (
      channel_id: string,
      expiry_timestamp: number,
      balance: number,
      signature: string
    ): void => {
      if (stores.channelClosed.isClosed(channel_id)) {
        throw new Error("channel already closed");
      }
      // Also update balance store so it's available for unilateral exit logic during retry
      stores.channelBalance.update(channel_id, Number(balance), signature);
      stores.channelClosing.markClosing(channel_id, Number(expiry_timestamp), Number(balance), signature);
    },

    getClosingData: (channelId: string): { expiry_timestamp: number; balance: number; signature: string } | null => {
      return stores.channelClosing.get(channelId);
    },

    getChannelPolicy: (unit: string): { min_expiry_in_seconds: number; min_capacity: number; max_amount_per_output?: number } | null => {
      const unitPricing = pricing[unit];
      if (!unitPricing) return null;
      return {
        min_expiry_in_seconds: minExpirySeconds,
        min_capacity: unitPricing.min_capacity ?? 0,
        max_amount_per_output: unitPricing.max_amount_per_output,
      };
    },

    nowSeconds: (): bigint => {
      return BigInt(Math.floor(Date.now() / 1000));
    },

    getBalanceAndSignatureForUnilateralExit: (channelId: string): [number, string] | null => {
      const balanceData = stores.channelBalance.get(channelId);
      if (!balanceData) return null;
      return [balanceData.balance, balanceData.signature];
    },

    getActiveKeysetIds: (mint: string, unit: string): string[] => {
      return stores.keysetCache.getActiveIds(mint, unit);
    },

    getKeysetInfo: (mint: string, keysetId: string): string | null => {
      const entry = stores.keysetCache.get(mint, keysetId);
      return entry?.infoJson ?? null;
    },

    callMintSwap: async (mintUrlArg: string, swapRequestJson: string): Promise<string> => {
      const response = await fetch(`${mintUrlArg}/v1/swap`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: swapRequestJson,
      });
      const text = await response.text();
      if (!response.ok) {
        throw (text || `Mint rejected swap with status ${response.status}`);
      }
      return text;
    },

    markChannelClosed: (
      channelId: string,
      expiry_timestamp: number,
      balance: number,
      receiverProofsJson: string,
      senderProofsJson: string,
      receiverSum: number,
      senderSum: number
    ): void => {
      if (stores.channelClosed.isClosed(channelId)) {
        throw new Error("channel already closed");
      }
      stores.channelClosed.markClosed(
        channelId,
        Number(expiry_timestamp),
        Number(balance),
        Number(receiverSum) + Number(senderSum),
        Number(receiverSum),
        Number(senderSum),
        receiverProofsJson,
        senderProofsJson
      );
    },

    refreshAllKeysets: async (mint: string): Promise<void> => {
      if (!refreshKeysets) return;
      await refreshKeysets(mint);
    },

    computeChannelSecret: (_receiverPubkeyHex: string, senderPubkeyHex: string): string => {
      return compute_channel_secret(secretKeyHex, senderPubkeyHex);
    },

    signWithTweakedKey: (_signerPubkeyHex: string, messageHex: string, tweakScalarHex: string): string => {
      return sign_with_tweaked_key(secretKeyHex, messageHex, tweakScalarHex);
    },
  };
}
