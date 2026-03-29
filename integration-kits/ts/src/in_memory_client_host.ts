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

  saveOpeningChannel(channelId: string, fundingJson: string): void {
    this.funding.set(channelId, fundingJson);
    this.channelState.set(channelId, "opening");
  }

  markChannelOpen(channelId: string, fundingProofsJson: string): void {
    // Update the funding JSON with the proofs
    const existingJson = this.funding.get(channelId);
    if (existingJson) {
      try {
        const funding = JSON.parse(existingJson);
        funding.funding_proofs_json = fundingProofsJson;
        this.funding.set(channelId, JSON.stringify(funding));
      } catch {
        // If parse fails, just update state
      }
    }
    this.channelState.set(channelId, "open");
  }

  getChannelFunding(channelId: string): string | null {
    return this.funding.get(channelId) ?? null;
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
    return Array.from(this.funding.keys());
  }

  deleteChannel(channelId: string): void {
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
