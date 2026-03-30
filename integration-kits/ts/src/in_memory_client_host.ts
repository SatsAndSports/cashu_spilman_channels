/**
 * In-memory implementation of SpilmanClientHost for prototyping and demos.
 *
 * This provides a ready-to-use client host that stores data in memory.
 * For production, you would implement SpilmanClientHost with persistent storage.
 */

import { sign_with_tweaked_key, compute_channel_secret } from "../wasm/cdk_wasm.js";
import type { SpilmanClientHost } from "./client_bridge.js";

/**
 * In-memory implementation of SpilmanClientHost.
 *
 * Stores channel data in memory (lost on restart).
 * Uses fetch for networking and the WASM crypto functions.
 */
export class InMemorySpilmanClientHost implements SpilmanClientHost {
  private opening: Map<string, string> = new Map();
  private funding: Map<string, string> = new Map();
  private paymentState: Map<string, string> = new Map();
  private channelState: Map<string, string> = new Map();

  /**
   * Create a new in-memory client host.
   *
   * @param secretKeyHex - The sender's secret key in hex format (64 chars)
   */
  constructor(private secretKeyHex: string) {}

  // ========================================================================
  // Channel Opening (two-phase)
  // ========================================================================

  saveOpeningFromSwapChannel(channelId: string, openingJson: string): void {
    this.opening.set(channelId, openingJson);
    this.channelState.set(channelId, "opening_from_swap");
  }

  markChannelOpen(channelId: string, fundingProofsJson: string): void {
    // Read opening data, construct funding, store in funding map, remove from opening map
    const openingJson = this.opening.get(channelId);
    if (openingJson) {
      try {
        const opening = JSON.parse(openingJson);
        const funding = {
          params_json: opening.params_json,
          funding_proofs_json: fundingProofsJson,
          channel_secret_hex: opening.channel_secret_hex,
          keyset_info_json: opening.keyset_info_json,
          sender_pubkey_hex: opening.sender_pubkey_hex,
          capacity: opening.capacity,
          funding_token_amount: opening.funding_token_amount,
          mint_url: opening.mint_url,
          created_at: opening.created_at,
        };
        this.funding.set(channelId, JSON.stringify(funding));
      } catch {
        // If parse fails, just update state
      }
      this.opening.delete(channelId);
    }
    this.channelState.set(channelId, "open");
  }

  getChannelFunding(channelId: string): string | null {
    return this.funding.get(channelId) ?? null;
  }

  getChannelOpeningFromSwap(channelId: string): string | null {
    return this.opening.get(channelId) ?? null;
  }

  // ========================================================================
  // Payment State (mutable)
  // ========================================================================

  getPaymentState(channelId: string): string | null {
    return this.paymentState.get(channelId) ?? null;
  }

  recordPayment(channelId: string, stateJson: string): void {
    this.paymentState.set(channelId, stateJson);
  }

  // ========================================================================
  // Channel Lifecycle
  // ========================================================================

  getChannelState(channelId: string): string {
    return this.channelState.get(channelId) ?? "open";
  }

  markChannelClosed(channelId: string): void {
    this.channelState.set(channelId, "closed");
  }

  listChannelIds(): string[] {
    const ids = new Set<string>();
    for (const id of this.funding.keys()) ids.add(id);
    for (const id of this.opening.keys()) ids.add(id);
    return Array.from(ids);
  }

  deleteChannel(channelId: string): void {
    this.opening.delete(channelId);
    this.funding.delete(channelId);
    this.paymentState.delete(channelId);
    this.channelState.delete(channelId);
  }

  // ========================================================================
  // Time
  // ========================================================================

  nowSeconds(): bigint {
    return BigInt(Math.floor(Date.now() / 1000));
  }

  // ========================================================================
  // Crypto (delegated to WASM)
  // ========================================================================

  signWithTweakedKey(
    _signerPubkeyHex: string,
    messageHex: string,
    tweakScalarHex: string
  ): string {
    return sign_with_tweaked_key(this.secretKeyHex, messageHex, tweakScalarHex);
  }

  computeChannelSecret(
    _senderPubkeyHex: string,
    receiverPubkeyHex: string
  ): string {
    return compute_channel_secret(this.secretKeyHex, receiverPubkeyHex);
  }

  // ========================================================================
  // Networking (uses fetch)
  // ========================================================================

  async callMintSwap(mintUrl: string, swapRequestJson: string): Promise<string> {
    const response = await fetch(`${mintUrl}/v1/swap`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: swapRequestJson,
    });

    const text = await response.text();
    if (!response.ok) {
      throw new Error(text || `Mint rejected swap with status ${response.status}`);
    }
    return text;
  }

  async callMintRestore(mintUrl: string, restoreRequestJson: string): Promise<string> {
    const response = await fetch(`${mintUrl}/v1/restore`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: restoreRequestJson,
    });

    const text = await response.text();
    if (!response.ok) {
      throw new Error(text || `Mint rejected restore with status ${response.status}`);
    }
    return text;
  }
}
