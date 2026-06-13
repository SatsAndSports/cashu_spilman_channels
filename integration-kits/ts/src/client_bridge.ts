import { WasmSpilmanClientBridge } from "../wasm/cdk_wasm.js";

/**
 * Interface that client applications must implement to provide storage,
 * time, crypto, and networking for the client bridge.
 */
export interface SpilmanClientHost {
  // ========================================================================
  // Channel Opening (two-phase)
  // ========================================================================

  /** Save channel metadata before the funding swap. Channel enters OpeningFromSwap state. */
  saveOpeningFromSwapChannel(channelId: string, openingJson: string): void;

  /** Transition channel from OpeningFromSwap to Open with the funding proofs. */
  markChannelOpen(channelId: string, fundingProofsJson: string): void;

  /** Retrieves channel funding data. Returns null if the channel doesn't exist. */
  getChannelFunding(channelId: string): string | null;

  /** Retrieves channel opening data. Returns null if not in opening_from_swap state. */
  getChannelOpeningFromSwap(channelId: string): string | null;

  // ========================================================================
  // Payment State (mutable)
  // ========================================================================

  /** Retrieves the current payment state. Returns null if no payments have been made. */
  getPaymentState(channelId: string): string | null;

  /** Stores a new payment state. stateJson is a JSON-serialized ClientPaymentState. */
  recordPayment(channelId: string, stateJson: string): void;

  // ========================================================================
  // Channel Lifecycle
  // ========================================================================

  /** Returns the lifecycle state of a channel. Returns "opening_from_swap", "open", or "closed". */
  getChannelState(channelId: string): string;

  /** Marks a channel as closed. */
  markChannelClosed(channelId: string): void;

  /** Returns all stored channel IDs. */
  listChannelIds(): string[];

  /** Removes a channel and all its data. */
  deleteChannel(channelId: string): void;

  // ========================================================================
  // Time
  // ========================================================================

  /** Returns the current Unix timestamp in seconds. */
  nowSeconds(): bigint;

  // ========================================================================
  // Crypto (delegated to host)
  // ========================================================================

  /**
   * Signs a message with a tweaked key (BIP-340 Schnorr).
   * The bridge computes the tweak and message hash, then asks the host to produce a signature.
   */
  signWithTweakedKey(
    signerPubkeyHex: string,
    messageHex: string,
    tweakScalarHex: string
  ): string;

  /** Computes the hashed ECDH channel secret. */
  computeChannelSecret(senderPubkeyHex: string, receiverPubkeyHex: string): string;

  // ========================================================================
  // Networking
  // ========================================================================

  /**
   * Executes a swap with the mint (async for JS).
   * Posts swapRequestJson to {mintUrl}/v1/swap and returns the response body.
   */
  callMintSwap(mintUrl: string, swapRequestJson: string): Promise<string>;

  /**
   * Executes a NUT-09 restore with the mint (async for JS).
   * Posts restoreRequestJson to {mintUrl}/v1/restore and returns the response body.
   */
  callMintRestore(mintUrl: string, restoreRequestJson: string): Promise<string>;
}

/**
 * Client bridge wrapper for WASM.
 */
export class SpilmanClientBridge {
  private inner: WasmSpilmanClientBridge;

  constructor(host: SpilmanClientHost) {
    this.inner = new WasmSpilmanClientBridge(host as any);
  }

  /**
   * Opens a new channel from a Cashu token (async flow for JS).
   */
  async openChannelFromToken(
    token: string,
    receiverPubkeyHex: string,
    senderPubkeyHex: string,
    expiryTimestamp: bigint,
    keysetInfoJson: string,
    maxAmount: bigint
  ): Promise<any> {
    return await this.inner.openChannelFromTokenAsync(
      token,
      receiverPubkeyHex,
      senderPubkeyHex,
      expiryTimestamp,
      keysetInfoJson,
      maxAmount
    );
  }

  /**
   * Creates a payment for a channel (without funding data).
   */
  createPayment(channelId: string, balance: bigint): string {
    return this.inner.createPayment(channelId, balance);
  }

  /**
   * Creates a payment with funding data (for first payment).
   */
  createPaymentWithFunding(channelId: string, balance: bigint): string {
    return this.inner.createPaymentWithFunding(channelId, balance);
  }

  /**
   * Builds a complete X-Cashu-Channel payment header value.
   */
  buildPaymentHeader(channelId: string, balance: bigint, includeFunding: boolean): string {
    return this.inner.buildPaymentHeader(channelId, balance, includeFunding);
  }

  /**
   * Creates a JSON request for cooperative closing.
   */
  createCooperativeCloseRequest(channelId: string, finalBalance: bigint): string {
    return this.inner.createCooperativeCloseRequest(channelId, finalBalance);
  }

  /**
   * Finalizes the channel closure based on server response.
   */
  processCooperativeCloseResponse(responseJson: string): void {
    this.inner.processCooperativeCloseResponse(responseJson);
  }

  /**
   * Returns information about a stored channel.
   */
  getChannelInfo(channelId: string): any {
    return this.inner.getChannelInfo(channelId);
  }

  /**
   * Returns all stored channel IDs.
   */
  listChannels(): string[] {
    return this.inner.listChannels() as any;
  }

  /**
   * Marks a channel as closed locally.
   */
  closeChannel(channelId: string): void {
    this.inner.closeChannel(channelId);
  }

  /**
   * Removes a channel from storage.
   */
  deleteChannel(channelId: string): void {
    this.inner.deleteChannel(channelId);
  }
}
