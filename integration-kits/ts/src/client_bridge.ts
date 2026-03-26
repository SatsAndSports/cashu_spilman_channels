import { WasmSpilmanClientBridge } from "../wasm/cdk_wasm.js";

export interface SpilmanClientHost {
  saveChannel(channelId: string, channelJson: string, channelSecretHex: string): void;
  getChannel(channelId: string): [string, string] | null;
  listChannelIds(): string[];
  deleteChannel(channelId: string): void;
  signWithTweakedKey(
    signerPubkeyHex: string,
    messageHex: string,
    tweakScalarHex: string
  ): string;
  computeChannelSecret(senderPubkeyHex: string, receiverPubkeyHex: string): string;
}

/**
 * Client bridge wrapper for WASM.
 *
 * Note: openChannelFromToken is intentionally not exposed here because the
 * WASM client host doesn't yet support async mint swap calls.
 */
export class SpilmanClientBridge {
  private inner: WasmSpilmanClientBridge;

  constructor(host: SpilmanClientHost) {
    this.inner = new WasmSpilmanClientBridge(host as any);
  }

  buildPaymentHeader(channelId: string, balance: bigint, includeFunding: boolean): string {
    return this.inner.buildPaymentHeader(channelId, balance, includeFunding);
  }

  createCooperativeCloseRequest(channelId: string, finalBalance: bigint): string {
    return this.inner.createCooperativeCloseRequest(channelId, finalBalance);
  }

  processCooperativeCloseResponse(responseJson: string): void {
    this.inner.processCooperativeCloseResponse(responseJson);
  }

  getChannelInfo(channelId: string): any {
    return this.inner.getChannelInfo(channelId);
  }

  listChannels(): string[] {
    return this.inner.listChannels() as any;
  }

  removeChannel(channelId: string): void {
    this.inner.removeChannel(channelId);
  }
}
