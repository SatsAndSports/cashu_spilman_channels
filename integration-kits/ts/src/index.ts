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
export { demoFetchActiveKeysetInfo, demoMintFundingToken } from "./demo.js";
export { SpilmanClientBridge, type SpilmanClientHost } from "./client_bridge.js";

/**
 * Initializes the WASM module for Node.js environment.
 *
 * With `wasm-pack --target nodejs`, the WASM binary is loaded synchronously
 * when the module is first imported, so this function is a no-op.  It is
 * retained for backward compatibility with callers that `await init()`.
 */
export async function init() {
  // WASM is loaded synchronously on import by the nodejs target; nothing to do.
}
