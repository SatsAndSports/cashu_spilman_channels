export {
  WasmSpilmanBridge,
  compute_channel_secret,
  compute_funding_token_amount,
  channel_parameters_get_channel_id,
  create_funding_outputs,
  construct_proofs,
  spilman_channel_sender_create_signed_balance_update,
  sign_with_tweaked_key,
  get_sender_blinded_secret_key_for_stage2_output,
  get_receiver_blinded_secret_key_for_stage2_output,
  compute_funding_token_nominal,
  verify_proof_dleq,
  verify_channel,
  build_cashu_b_token,
  create_plain_blinded_messages,
} from "../wasm/cdk_wasm.js";

export { createSpilmanManagementRouter } from "./router.js";
export { createSpilmanHost, getServerPubkey } from "./host.js";
export { createInMemoryStores } from "./stores.js";
export { createSqliteStores } from "./sqlite_stores.js";
export {
  getActivePricing,
  getChannelStatus,
  type PricingTable,
  type PricingEntry,
  type SpilmanStores,
  type UsageMap,
  type ChannelFundingData,
  type ChannelBalance,
  type ClosingChannelData,
  type ClosedChannelData,
  type ChannelStatus,
} from "./stores.js";
export { fetchAllKeysetsFromMint, fetchAndCacheKeysetsForMint } from "./keysets.js";
export {
  Spilman,
  mapErrorStatus,
  decodePaymentHeader,
  parseBridgeError,
  getBridgeErrorReason,
} from "./express.js";
export { ConfigurableSpilman, type SpilmanConfig } from "./config.js";
export { demoFetchActiveKeysetInfo, demoMintFundingToken, demoMintPlainProofs } from "./demo.js";
export { SpilmanClientBridge, type SpilmanClientHost } from "./client_bridge.js";
export { InMemorySpilmanClientHost } from "./in_memory_client_host.js";

let _initialized = false;

/**
 * Initializes the WASM module.
 *
 * Must be called before using any WASM functions (crypto, bridge, etc.).
 * Safe to call multiple times - subsequent calls are no-ops.
 *
 * Works with both `--target nodejs` (auto-init on import) and
 * `--target web` (requires explicit init with wasm file).
 */
export async function init() {
  if (_initialized) return;

  // Dynamic import to check which WASM target we have.
  // The type of `initSync` varies between --target web and --target nodejs,
  // so we use `any` to handle both cases at runtime.
  const wasm: any = await import("../wasm/cdk_wasm.js");

  if (typeof wasm.initSync === "function") {
    // --target web: must load the wasm file and call initSync
    const { readFileSync } = await import("node:fs");
    const { fileURLToPath } = await import("node:url");
    const { dirname, join } = await import("node:path");

    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);
    const wasmPath = join(__dirname, "..", "wasm", "cdk_wasm_bg.wasm");
    const wasmBuffer = readFileSync(wasmPath);

    wasm.initSync({ module: wasmBuffer });
  }
  // --target nodejs: WASM is already initialized on import; nothing to do.

  _initialized = true;
}
