//! WASM bindings for Cashu payment channels

use async_trait::async_trait;
use std::str::FromStr;
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;

use cashu::nuts::{CurrencyUnit, Id, Proof, PublicKey, SecretKey};
use cashu::util::hex;
use cdk_spilman::{
    compute_funding_token_amount as rust_compute_funding_token_amount, BalanceUpdateMessage,
    BridgeError, BridgeErrorResponse, ChannelFunding, ChannelParameters, ChannelPolicy,
    ChannelState, ClientChannelFunding, ClientChannelState, ClientPaymentState, ClosingData,
    EstablishedChannel, PaymentProof, SpilmanAsyncNetworking, SpilmanBridge,
    SpilmanClientAsyncNetworking, SpilmanClientBridge as RustSpilmanClientBridge,
    SpilmanClientHost as RustSpilmanClientHost, SpilmanClientNetworking, SpilmanHost,
};

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

/// Extract error string from JsValue, falling back to debug format.
/// This ensures JS error strings are passed through cleanly instead of
/// being wrapped as `JsValue("...")`.
fn js_error_to_string(e: JsValue) -> String {
    e.as_string().unwrap_or_else(|| format!("{:?}", e))
}

#[wasm_bindgen]
extern "C" {
    pub type JsSpilmanHost;
    #[wasm_bindgen(method, js_name = getFundingAndParams)]
    fn get_funding_and_params(this: &JsSpilmanHost, channel_id: &str) -> JsValue;
    #[wasm_bindgen(method, js_name = receiverKeyIsAcceptable)]
    fn receiver_key_is_acceptable(this: &JsSpilmanHost, receiver_pubkey_hex: &str) -> bool;
    #[wasm_bindgen(method, js_name = mintAndKeysetIsAcceptable)]
    fn mint_and_keyset_is_acceptable(this: &JsSpilmanHost, mint: &str, keyset_id: &str) -> bool;
    #[wasm_bindgen(method, js_name = saveFunding)]
    fn save_funding(
        this: &JsSpilmanHost,
        channel_id: &str,
        params_json: &str,
        funding_proofs_json: &str,
        channel_secret_hex: &str,
        keyset_info_json: &str,
        initial_balance: u64,
        initial_signature: &str,
    );
    #[wasm_bindgen(method, js_name = getAmountDue)]
    fn get_amount_due(this: &JsSpilmanHost, channel_id: &str, context_json: JsValue) -> u64;
    #[wasm_bindgen(method, js_name = recordPayment)]
    fn record_payment(
        this: &JsSpilmanHost,
        channel_id: &str,
        balance: u64,
        signature: &str,
        context_json: &str,
    );
    #[wasm_bindgen(method, js_name = getChannelState)]
    fn get_channel_state(this: &JsSpilmanHost, channel_id: &str) -> String;
    #[wasm_bindgen(method, catch, js_name = markChannelClosing)]
    fn mark_channel_closing(
        this: &JsSpilmanHost,
        channel_id: &str,
        expiry_timestamp: u64,
        balance: u64,
        signature: &str,
    ) -> Result<(), JsValue>;
    #[wasm_bindgen(method, js_name = getClosingData)]
    fn get_closing_data(this: &JsSpilmanHost, channel_id: &str) -> JsValue;
    #[wasm_bindgen(method, js_name = getChannelPolicy)]
    fn get_channel_policy(this: &JsSpilmanHost, unit: &str) -> JsValue;
    #[wasm_bindgen(method, js_name = nowSeconds)]
    fn now_seconds(this: &JsSpilmanHost) -> u64;
    #[wasm_bindgen(method, js_name = getBalanceAndSignatureForUnilateralExit)]
    fn get_balance_and_signature_for_unilateral_exit(
        this: &JsSpilmanHost,
        channel_id: &str,
    ) -> JsValue;
    #[wasm_bindgen(method, js_name = getActiveKeysetIds)]
    fn get_active_keyset_ids(this: &JsSpilmanHost, mint: &str, unit: &str) -> JsValue;
    #[wasm_bindgen(method, js_name = getKeysetInfo)]
    fn get_keyset_info(this: &JsSpilmanHost, mint: &str, keyset_id: &str) -> JsValue;
    #[wasm_bindgen(method, js_name = callMintSwap)]
    fn call_mint_swap(
        this: &JsSpilmanHost,
        mint_url: &str,
        swap_request_json: &str,
    ) -> js_sys::Promise;
    #[wasm_bindgen(method, catch, js_name = markChannelClosed)]
    fn mark_channel_closed(
        this: &JsSpilmanHost,
        channel_id: &str,
        expiry_timestamp: u64,
        balance: u64,
        receiver_proofs_json: &str,
        sender_proofs_json: &str,
        receiver_sum: u64,
        sender_sum: u64,
    ) -> Result<(), JsValue>;
    #[wasm_bindgen(method, js_name = refreshAllKeysets)]
    fn refresh_all_keysets(this: &JsSpilmanHost, mint: &str) -> js_sys::Promise;
    #[wasm_bindgen(method, catch, js_name = computeChannelSecret)]
    fn compute_channel_secret_host(
        this: &JsSpilmanHost,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
    ) -> Result<String, JsValue>;
    #[wasm_bindgen(method, catch, js_name = signWithTweakedKey)]
    fn sign_with_tweaked_key_host(
        this: &JsSpilmanHost,
        signer_pubkey_hex: &str,
        message_hex: &str,
        tweak_scalar_hex: &str,
    ) -> Result<String, JsValue>;

    pub type JsSpilmanClientHost;
    // Channel opening (two-phase)
    #[wasm_bindgen(method, js_name = saveOpeningChannel)]
    fn save_opening_channel(
        this: &JsSpilmanClientHost,
        channel_id: &str,
        funding_json: &str,
    );
    #[wasm_bindgen(method, js_name = markChannelOpen)]
    fn mark_channel_open(
        this: &JsSpilmanClientHost,
        channel_id: &str,
        funding_proofs_json: &str,
    );
    #[wasm_bindgen(method, js_name = getChannelFunding)]
    fn get_channel_funding(this: &JsSpilmanClientHost, channel_id: &str) -> JsValue;
    // Payment state (mutable)
    #[wasm_bindgen(method, js_name = getPaymentState)]
    fn get_payment_state(this: &JsSpilmanClientHost, channel_id: &str) -> JsValue;
    #[wasm_bindgen(method, js_name = recordPayment)]
    fn client_record_payment(
        this: &JsSpilmanClientHost,
        channel_id: &str,
        state_json: &str,
    );
    // Lifecycle
    #[wasm_bindgen(method, js_name = getChannelState)]
    fn client_get_channel_state(this: &JsSpilmanClientHost, channel_id: &str) -> String;
    #[wasm_bindgen(method, js_name = markChannelClosed)]
    fn client_mark_channel_closed(this: &JsSpilmanClientHost, channel_id: &str);
    #[wasm_bindgen(method, js_name = listChannelIds)]
    fn list_channel_ids(this: &JsSpilmanClientHost) -> JsValue;
    #[wasm_bindgen(method, js_name = deleteChannel)]
    fn delete_channel(this: &JsSpilmanClientHost, channel_id: &str);
    // Time
    #[wasm_bindgen(method, js_name = nowSeconds)]
    fn client_now_seconds(this: &JsSpilmanClientHost) -> u64;
    // Crypto
    #[wasm_bindgen(method, catch, js_name = signWithTweakedKey)]
    fn client_sign_with_tweaked_key(
        this: &JsSpilmanClientHost,
        signer_pubkey_hex: &str,
        message_hex: &str,
        tweak_scalar_hex: &str,
    ) -> Result<String, JsValue>;
    #[wasm_bindgen(method, catch, js_name = computeChannelSecret)]
    fn client_compute_channel_secret(
        this: &JsSpilmanClientHost,
        sender_pubkey_hex: &str,
        receiver_pubkey_hex: &str,
    ) -> Result<String, JsValue>;
    // Networking (for async operations)
    #[wasm_bindgen(method, js_name = callMintSwap)]
    fn client_call_mint_swap(
        this: &JsSpilmanClientHost,
        mint_url: &str,
        swap_request_json: &str,
    ) -> js_sys::Promise;
}

struct WasmSpilmanHostProxy {
    js_host: JsSpilmanHost,
}
unsafe impl Send for WasmSpilmanHostProxy {}
unsafe impl Sync for WasmSpilmanHostProxy {}

impl SpilmanHost<String> for WasmSpilmanHostProxy {
    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
        let val = self.js_host.get_funding_and_params(channel_id);
        if val.is_null() || val.is_undefined() {
            return None;
        }
        let arr = js_sys::Array::from(&val);
        if arr.length() != 4 {
            return None;
        }
        Some(ChannelFunding {
            params_json: arr.get(0).as_string()?,
            funding_proofs_json: arr.get(1).as_string()?,
            channel_secret_hex: arr.get(2).as_string()?,
            keyset_info_json: arr.get(3).as_string()?,
        })
    }
    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool {
        self.js_host
            .receiver_key_is_acceptable(&receiver_pubkey.to_hex())
    }
    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &Id) -> bool {
        self.js_host
            .mint_and_keyset_is_acceptable(mint, &keyset_id.to_string())
    }
    fn save_funding(
        &self,
        channel_id: &str,
        funding: ChannelFunding,
        initial_payment: PaymentProof,
    ) {
        self.js_host.save_funding(
            channel_id,
            &funding.params_json,
            &funding.funding_proofs_json,
            &funding.channel_secret_hex,
            &funding.keyset_info_json,
            initial_payment.balance,
            &initial_payment.signature,
        );
    }
    fn get_amount_due(&self, channel_id: &str, context_json: Option<&String>) -> u64 {
        let ctx_val = match context_json {
            Some(s) => JsValue::from_str(s),
            None => JsValue::NULL,
        };
        self.js_host.get_amount_due(channel_id, ctx_val)
    }
    fn record_payment(&self, channel_id: &str, payment: PaymentProof, context_json: &String) {
        self.js_host.record_payment(
            channel_id,
            payment.balance,
            &payment.signature,
            context_json,
        );
    }
    fn get_channel_state(&self, channel_id: &str) -> ChannelState {
        match self.js_host.get_channel_state(channel_id).as_str() {
            "closed" => ChannelState::Closed,
            "closing" => ChannelState::Closing,
            _ => ChannelState::Open,
        }
    }
    fn mark_channel_closing(
        &self,
        channel_id: &str,
        expiry_timestamp: u64,
        payment: PaymentProof,
    ) -> Result<(), String> {
        self.js_host
            .mark_channel_closing(
                channel_id,
                expiry_timestamp,
                payment.balance,
                &payment.signature,
            )
            .map_err(js_error_to_string)
    }
    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData> {
        let val = self.js_host.get_closing_data(channel_id);
        if val.is_null() || val.is_undefined() {
            return None;
        }
        let obj = js_sys::Object::try_from(&val)?;
        let expiry_timestamp = js_sys::Reflect::get(obj, &JsValue::from_str("expiry_timestamp"))
            .ok()?
            .as_f64()? as u64;
        let balance = js_sys::Reflect::get(obj, &JsValue::from_str("balance"))
            .ok()?
            .as_f64()? as u64;
        let signature = js_sys::Reflect::get(obj, &JsValue::from_str("signature"))
            .ok()?
            .as_string()?;
        Some(ClosingData {
            expiry_timestamp,
            balance,
            signature,
        })
    }
    fn get_channel_policy(&self, unit: &str) -> Option<ChannelPolicy> {
        let val = self.js_host.get_channel_policy(unit);
        if val.is_null() || val.is_undefined() {
            return None;
        }
        let obj = js_sys::Object::try_from(&val)?;
        let min_expiry_in_seconds =
            js_sys::Reflect::get(obj, &JsValue::from_str("min_expiry_in_seconds"))
                .ok()?
                .as_f64()? as u64;
        let min_capacity = js_sys::Reflect::get(obj, &JsValue::from_str("min_capacity"))
            .ok()?
            .as_f64()? as u64;
        let max_amount_per_output =
            js_sys::Reflect::get(obj, &JsValue::from_str("max_amount_per_output"))
                .ok()
                .and_then(|v| v.as_f64())
                .map(|v| v as u64);
        Some(ChannelPolicy {
            min_expiry_in_seconds,
            min_capacity,
            max_amount_per_output,
        })
    }
    fn now_seconds(&self) -> u64 {
        self.js_host.now_seconds()
    }
    fn get_balance_and_signature_for_unilateral_exit(
        &self,
        channel_id: &str,
    ) -> Option<PaymentProof> {
        let val = self
            .js_host
            .get_balance_and_signature_for_unilateral_exit(channel_id);
        if val.is_null() || val.is_undefined() {
            return None;
        }
        let arr = js_sys::Array::from(&val);
        if arr.length() != 2 {
            return None;
        }
        Some(PaymentProof {
            balance: arr.get(0).as_f64()? as u64,
            signature: arr.get(1).as_string()?,
        })
    }
    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id> {
        let val = self.js_host.get_active_keyset_ids(mint, &unit.to_string());
        js_sys::Array::from(&val)
            .iter()
            .filter_map(|v| v.as_string().and_then(|s| Id::from_str(&s).ok()))
            .collect()
    }
    fn get_keyset_info(&self, mint: &str, keyset_id: &Id) -> Option<String> {
        self.js_host
            .get_keyset_info(mint, &keyset_id.to_string())
            .as_string()
    }
    fn mark_channel_closed(
        &self,
        channel_id: &str,
        expiry_timestamp: u64,
        balance: u64,
        receiver_proofs_json: &str,
        sender_proofs_json: &str,
        receiver_sum: u64,
        sender_sum: u64,
    ) -> Result<(), String> {
        self.js_host
            .mark_channel_closed(
                channel_id,
                expiry_timestamp,
                balance,
                receiver_proofs_json,
                sender_proofs_json,
                receiver_sum,
                sender_sum,
            )
            .map_err(js_error_to_string)
    }
    fn compute_channel_secret(
        &self,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
    ) -> Result<String, String> {
        self.js_host
            .compute_channel_secret_host(receiver_pubkey_hex, sender_pubkey_hex)
            .map_err(js_error_to_string)
    }
    fn sign_with_tweaked_key(
        &self,
        signer_pubkey_hex: &str,
        message_hex: &str,
        tweak_scalar_hex: &str,
    ) -> Result<String, String> {
        self.js_host
            .sign_with_tweaked_key_host(signer_pubkey_hex, message_hex, tweak_scalar_hex)
            .map_err(js_error_to_string)
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
impl SpilmanAsyncNetworking for WasmSpilmanHostProxy {
    async fn call_mint_swap(
        &self,
        mint_url: &str,
        swap_request_json: &str,
    ) -> Result<String, String> {
        JsFuture::from(self.js_host.call_mint_swap(mint_url, swap_request_json))
            .await
            .map_err(js_error_to_string)?
            .as_string()
            .ok_or_else(|| "Result not a string".to_string())
    }
    async fn refresh_all_keysets(&self, mint: &str) -> Result<(), String> {
        let _ = JsFuture::from(self.js_host.refresh_all_keysets(mint))
            .await
            .map_err(js_error_to_string)?;
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl SpilmanAsyncNetworking for WasmSpilmanHostProxy {
    async fn call_mint_swap(
        &self,
        _mint_url: &str,
        _swap_request_json: &str,
    ) -> Result<String, String> {
        Err("WASM proxy only works on wasm32".to_string())
    }
    async fn refresh_all_keysets(&self, _mint: &str) -> Result<(), String> {
        Err("WASM proxy only works on wasm32".to_string())
    }
}

struct WasmSpilmanClientHostProxy {
    js_host: JsSpilmanClientHost,
}
unsafe impl Send for WasmSpilmanClientHostProxy {}
unsafe impl Sync for WasmSpilmanClientHostProxy {}

impl RustSpilmanClientHost for WasmSpilmanClientHostProxy {
    // ========================================================================
    // Channel Opening (two-phase)
    // ========================================================================

    fn save_opening_channel(&self, channel_id: &str, funding: ClientChannelFunding) {
        let funding_json =
            serde_json::to_string(&funding).expect("ClientChannelFunding serialization failed");
        self.js_host
            .save_opening_channel(channel_id, &funding_json);
    }

    fn mark_channel_open(&self, channel_id: &str, funding_proofs_json: &str) {
        self.js_host
            .mark_channel_open(channel_id, funding_proofs_json);
    }

    fn get_channel_funding(&self, channel_id: &str) -> Option<ClientChannelFunding> {
        let val = self.js_host.get_channel_funding(channel_id);
        if val.is_null() || val.is_undefined() {
            return None;
        }
        let json_str = val.as_string()?;
        serde_json::from_str(&json_str).ok()
    }

    // ========================================================================
    // Payment State (mutable)
    // ========================================================================

    fn get_payment_state(&self, channel_id: &str) -> Option<ClientPaymentState> {
        let val = self.js_host.get_payment_state(channel_id);
        if val.is_null() || val.is_undefined() {
            return None;
        }
        let json_str = val.as_string()?;
        serde_json::from_str(&json_str).ok()
    }

    fn record_payment(&self, channel_id: &str, state: ClientPaymentState) {
        let state_json =
            serde_json::to_string(&state).expect("ClientPaymentState serialization failed");
        self.js_host.client_record_payment(channel_id, &state_json);
    }

    // ========================================================================
    // Channel Lifecycle
    // ========================================================================

    fn get_channel_state(&self, channel_id: &str) -> ClientChannelState {
        match self.js_host.client_get_channel_state(channel_id).as_str() {
            "closed" | "Closed" => ClientChannelState::Closed,
            _ => ClientChannelState::Open,
        }
    }

    fn mark_channel_closed(&self, channel_id: &str) {
        self.js_host.client_mark_channel_closed(channel_id);
    }

    fn list_channel_ids(&self) -> Vec<String> {
        js_sys::Array::from(&self.js_host.list_channel_ids())
            .iter()
            .filter_map(|v| v.as_string())
            .collect()
    }

    fn delete_channel(&self, channel_id: &str) {
        self.js_host.delete_channel(channel_id);
    }

    // ========================================================================
    // Time
    // ========================================================================

    fn now_seconds(&self) -> u64 {
        self.js_host.client_now_seconds()
    }

    // ========================================================================
    // Crypto (delegated to host)
    // ========================================================================

    fn sign_with_tweaked_key(
        &self,
        signer_pubkey_hex: &str,
        message_hex: &str,
        tweak_scalar_hex: &str,
    ) -> Result<String, String> {
        self.js_host
            .client_sign_with_tweaked_key(signer_pubkey_hex, message_hex, tweak_scalar_hex)
            .map_err(js_error_to_string)
    }

    fn compute_channel_secret(
        &self,
        sender_pubkey_hex: &str,
        receiver_pubkey_hex: &str,
    ) -> Result<String, String> {
        self.js_host
            .client_compute_channel_secret(sender_pubkey_hex, receiver_pubkey_hex)
            .map_err(js_error_to_string)
    }
}

// ============================================================================
// Dummy sync networking (not used in WASM async flow)
// ============================================================================

struct WasmDummyNetworking;

impl SpilmanClientNetworking for WasmDummyNetworking {
    fn call_mint_swap(&self, _mint_url: &str, _swap_request_json: &str) -> Result<String, String> {
        Err("Sync networking not supported in WASM; use openChannelFromTokenAsync".to_string())
    }
}

// ============================================================================
// Async networking proxy for WASM
// ============================================================================

struct WasmSpilmanClientAsyncNetworkingProxy {
    #[allow(dead_code)] // Used only on wasm32 target
    js_host: JsSpilmanClientHost,
}
unsafe impl Send for WasmSpilmanClientAsyncNetworkingProxy {}
unsafe impl Sync for WasmSpilmanClientAsyncNetworkingProxy {}

#[cfg(target_arch = "wasm32")]
#[async_trait::async_trait(?Send)]
impl SpilmanClientAsyncNetworking for WasmSpilmanClientAsyncNetworkingProxy {
    async fn call_mint_swap(
        &self,
        mint_url: &str,
        swap_request_json: &str,
    ) -> Result<String, String> {
        JsFuture::from(self.js_host.client_call_mint_swap(mint_url, swap_request_json))
            .await
            .map_err(js_error_to_string)?
            .as_string()
            .ok_or_else(|| "Result not a string".to_string())
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl SpilmanClientAsyncNetworking for WasmSpilmanClientAsyncNetworkingProxy {
    async fn call_mint_swap(
        &self,
        _mint_url: &str,
        _swap_request_json: &str,
    ) -> Result<String, String> {
        Err("WASM proxy only works on wasm32".to_string())
    }
}

fn bridge_error_to_js_value(err: BridgeError) -> JsValue {
    serde_wasm_bindgen::to_value(&BridgeErrorResponse::from_bridge_error(&err))
        .unwrap_or_else(|_| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub struct WasmSpilmanBridge {
    bridge: SpilmanBridge<WasmSpilmanHostProxy, String>,
}

#[wasm_bindgen]
impl WasmSpilmanBridge {
    #[wasm_bindgen(constructor)]
    pub fn new(js_host: JsSpilmanHost) -> WasmSpilmanBridge {
        WasmSpilmanBridge {
            bridge: SpilmanBridge::new(WasmSpilmanHostProxy { js_host }),
        }
    }

    #[wasm_bindgen(js_name = processPayment)]
    pub fn process_payment(
        &self,
        payment_json: &str,
        context_json: &str,
    ) -> Result<JsValue, JsValue> {
        self.bridge
            .process_payment_via_json(payment_json, &context_json.to_string())
            .map(|r| serde_wasm_bindgen::to_value(&r).unwrap())
            .map_err(bridge_error_to_js_value)
    }

    #[wasm_bindgen(js_name = validatePayment)]
    pub fn validate_payment(
        &self,
        payment_json: &str,
        context_json: &str,
    ) -> Result<JsValue, JsValue> {
        self.bridge
            .validate_payment_via_json(payment_json, &context_json.to_string())
            .map(|r| serde_wasm_bindgen::to_value(&r).unwrap())
            .map_err(bridge_error_to_js_value)
    }

    #[wasm_bindgen(js_name = paymentCoversAmountDue)]
    pub fn payment_covers_amount_due(
        &self,
        payment_json: &str,
        context_json: &str,
    ) -> Result<bool, JsValue> {
        self.bridge
            .payment_covers_amount_due_via_json(payment_json, &context_json.to_string())
            .map_err(bridge_error_to_js_value)
    }

    #[wasm_bindgen(js_name = verifyPaymentCoversAmountDue)]
    pub fn verify_payment_covers_amount_due(
        &self,
        payment_json: &str,
        context_json: &str,
    ) -> Result<u64, JsValue> {
        self.bridge
            .verify_payment_covers_amount_due_via_json(payment_json, &context_json.to_string())
            .map_err(bridge_error_to_js_value)
    }

    #[wasm_bindgen(js_name = fundChannel)]
    pub fn fund_channel(&self, payment_json: &str) -> Result<JsValue, JsValue> {
        self.bridge
            .fund_channel_via_json(payment_json)
            .map(|r| serde_wasm_bindgen::to_value(&r).unwrap())
            .map_err(bridge_error_to_js_value)
    }

    #[wasm_bindgen(js_name = executeCooperativeClose)]
    pub async fn execute_cooperative_close(&self, payment_json: &str) -> Result<JsValue, JsValue> {
        self.bridge
            .execute_cooperative_close_async(payment_json, self.bridge.host())
            .await
            .map(|r| serde_wasm_bindgen::to_value(&r).unwrap())
            .map_err(|e| {
                serde_wasm_bindgen::to_value(&e)
                    .unwrap_or_else(|_| JsValue::from_str(&e.to_string()))
            })
    }

    #[wasm_bindgen(js_name = executeUnilateralClose)]
    pub async fn execute_unilateral_close(&self, channel_id: &str) -> Result<JsValue, JsValue> {
        self.bridge
            .execute_unilateral_close_async(channel_id, self.bridge.host())
            .await
            .map(|r| serde_wasm_bindgen::to_value(&r).unwrap())
            .map_err(|e| {
                serde_wasm_bindgen::to_value(&e)
                    .unwrap_or_else(|_| JsValue::from_str(&e.to_string()))
            })
    }
}

#[wasm_bindgen]
pub struct WasmSpilmanClientBridge {
    bridge: RustSpilmanClientBridge<WasmSpilmanClientHostProxy, WasmDummyNetworking>,
    // Keep a reference to the JS host for async networking
    js_host: JsSpilmanClientHost,
}

#[wasm_bindgen]
impl WasmSpilmanClientBridge {
    #[wasm_bindgen(constructor)]
    pub fn new(js_host: JsSpilmanClientHost) -> WasmSpilmanClientBridge {
        // Clone the JsValue for use in the proxy
        let js_host_for_bridge: JsSpilmanClientHost = js_host.clone().unchecked_into();
        WasmSpilmanClientBridge {
            bridge: RustSpilmanClientBridge::new(
                WasmSpilmanClientHostProxy {
                    js_host: js_host_for_bridge,
                },
                WasmDummyNetworking,
            ),
            js_host,
        }
    }

    /// Open a channel from a Cashu token (async version for WASM).
    ///
    /// This uses async networking which is required in the browser environment.
    #[wasm_bindgen(js_name = openChannelFromTokenAsync)]
    pub async fn open_channel_from_token_async(
        &self,
        token_string: &str,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
        expiry_timestamp: u64,
        keyset_info_json: &str,
        max_amount: u64,
    ) -> Result<JsValue, JsValue> {
        // Create an async networking proxy using the stored JS host
        let async_networking = WasmSpilmanClientAsyncNetworkingProxy {
            js_host: self.js_host.clone().unchecked_into(),
        };

        self.bridge
            .open_channel_from_token_async(
                token_string,
                receiver_pubkey_hex,
                sender_pubkey_hex,
                expiry_timestamp,
                keyset_info_json,
                max_amount,
                &async_networking,
            )
            .await
            .map(|r| serde_wasm_bindgen::to_value(&r).unwrap())
            .map_err(|e| JsValue::from_str(&e))
    }

    /// Create a payment for a channel (without funding data).
    /// Returns the Payment struct as a JSON string.
    #[wasm_bindgen(js_name = createPayment)]
    pub fn create_payment(&self, channel_id: &str, balance: u64) -> Result<String, JsValue> {
        self.bridge
            .create_payment(channel_id, balance)
            .and_then(|p| serde_json::to_string(&p).map_err(|e| e.to_string()))
            .map_err(|e| JsValue::from_str(&e))
    }

    /// Create a payment with funding data (for first payment).
    /// Returns the Payment struct as a JSON string.
    #[wasm_bindgen(js_name = createPaymentWithFunding)]
    pub fn create_payment_with_funding(
        &self,
        channel_id: &str,
        balance: u64,
    ) -> Result<String, JsValue> {
        self.bridge
            .create_payment_with_funding(channel_id, balance)
            .and_then(|p| serde_json::to_string(&p).map_err(|e| e.to_string()))
            .map_err(|e| JsValue::from_str(&e))
    }

    #[wasm_bindgen(js_name = buildPaymentHeader)]
    pub fn build_payment_header(
        &self,
        channel_id: &str,
        balance: u64,
        include_funding: bool,
    ) -> Result<String, JsValue> {
        self.bridge
            .build_payment_header(channel_id, balance, include_funding)
            .map_err(|e| JsValue::from_str(&e))
    }

    #[wasm_bindgen(js_name = createCooperativeCloseRequest)]
    pub fn create_cooperative_close_request(
        &self,
        channel_id: &str,
        final_balance: u64,
    ) -> Result<JsValue, JsValue> {
        self.bridge
            .create_cooperative_close_request(channel_id, final_balance)
            .map(|r| serde_wasm_bindgen::to_value(&r).unwrap())
            .map_err(|e| JsValue::from_str(&e))
    }

    #[wasm_bindgen(js_name = processCooperativeCloseResponse)]
    pub fn process_cooperative_close_response(&self, response_json: &str) -> Result<(), JsValue> {
        self.bridge
            .process_cooperative_close_response(response_json)
            .map_err(|e| JsValue::from_str(&e))
    }

    #[wasm_bindgen(js_name = getChannelInfo)]
    pub fn get_channel_info(&self, channel_id: &str) -> JsValue {
        self.bridge
            .get_channel_info(channel_id)
            .map(|info| serde_wasm_bindgen::to_value(&info).unwrap())
            .unwrap_or(JsValue::NULL)
    }

    #[wasm_bindgen(js_name = listChannels)]
    pub fn list_channels(&self) -> JsValue {
        let channels = self.bridge.list_channels();
        serde_wasm_bindgen::to_value(&channels).unwrap()
    }

    /// Mark a channel as closed locally.
    #[wasm_bindgen(js_name = closeChannel)]
    pub fn close_channel(&self, channel_id: &str) {
        self.bridge.close_channel(channel_id);
    }

    #[wasm_bindgen(js_name = deleteChannel)]
    pub fn delete_channel(&self, channel_id: &str) {
        self.bridge.delete_channel(channel_id);
    }
}

#[wasm_bindgen]
pub fn compute_channel_secret(
    my_secret_hex: &str,
    their_pubkey_hex: &str,
) -> Result<String, JsValue> {
    cdk_spilman::compute_channel_secret_from_hex(my_secret_hex, their_pubkey_hex)
        .map_err(|e| JsValue::from_str(&e))
}
#[wasm_bindgen]
pub fn sign_with_tweaked_key(
    secret_key_hex: &str,
    message_hex: &str,
    tweak_scalar_hex: &str,
) -> Result<String, JsValue> {
    cdk_spilman::sign_with_tweaked_key_util(secret_key_hex, message_hex, tweak_scalar_hex)
        .map_err(|e| JsValue::from_str(&e))
}
#[wasm_bindgen]
pub fn channel_parameters_get_channel_id(
    params_json: &str,
    channel_secret_hex: &str,
    keyset_info_json: &str,
) -> Result<String, JsValue> {
    cdk_spilman::channel_parameters_get_channel_id(
        params_json,
        channel_secret_hex,
        keyset_info_json,
    )
    .map_err(|e| JsValue::from_str(&e))
}
#[wasm_bindgen]
pub fn compute_funding_token_amount(
    capacity: u64,
    keyset_info_json: &str,
    maximum_amount: u64,
) -> Result<u64, JsValue> {
    rust_compute_funding_token_amount(capacity, keyset_info_json, maximum_amount)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn compute_funding_token_nominal(
    capacity: u64,
    keyset_info_json: &str,
    maximum_amount: u64,
) -> Result<u64, JsValue> {
    rust_compute_funding_token_amount(capacity, keyset_info_json, maximum_amount)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}
#[wasm_bindgen]
pub fn create_funding_outputs(
    params_json: &str,
    my_secret_hex: &str,
    keyset_info_json: &str,
) -> Result<String, JsValue> {
    cdk_spilman::create_funding_outputs(params_json, my_secret_hex, keyset_info_json)
        .map_err(|e| JsValue::from_str(&e))
}
#[wasm_bindgen]
pub fn construct_proofs(
    sigs_json: &str,
    swb_json: &str,
    keyset_json: &str,
) -> Result<String, JsValue> {
    cdk_spilman::construct_proofs(sigs_json, swb_json, keyset_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}
#[wasm_bindgen]
pub fn get_sender_blinded_secret_key_for_stage2_output(
    params_json: &str,
    keyset_json: &str,
    secret_hex: &str,
    amount: u64,
    index: u32,
) -> Result<String, JsValue> {
    let s = SecretKey::from_hex(secret_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let p = ChannelParameters::from_json_with_secret_key(
        params_json,
        cdk_spilman::parse_keyset_info_from_json(keyset_json)
            .map_err(|e| JsValue::from_str(&e.to_string()))?,
        &s,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;
    p.get_sender_blinded_secret_key_for_stage2_output(&s, amount, index as usize)
        .map(|k| k.to_secret_hex())
        .map_err(|e| JsValue::from_str(&e.to_string()))
}
#[wasm_bindgen]
pub fn get_receiver_blinded_secret_key_for_stage2_output(
    params_json: &str,
    keyset_json: &str,
    secret_hex: &str,
    channel_secret_hex: &str,
    amount: u64,
    index: u32,
) -> Result<String, JsValue> {
    let s = SecretKey::from_hex(secret_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let cs: [u8; 32] = hex::decode(channel_secret_hex)
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid secret"))?;
    let p = ChannelParameters::from_json_with_channel_secret(
        params_json,
        cdk_spilman::parse_keyset_info_from_json(keyset_json)
            .map_err(|e| JsValue::from_str(&e.to_string()))?,
        cs,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;
    p.get_receiver_blinded_secret_key_for_stage2_output(&s, amount, index as usize)
        .map(|k| k.to_secret_hex())
        .map_err(|e| JsValue::from_str(&e.to_string()))
}
#[wasm_bindgen]
pub fn spilman_channel_sender_create_signed_balance_update(
    params_json: &str,
    keyset_info_json: &str,
    alice_secret_hex: &str,
    funding_proofs_json: &str,
    charlie_balance: u64,
) -> Result<String, JsValue> {
    cdk_spilman::create_signed_balance_update(
        params_json,
        keyset_info_json,
        alice_secret_hex,
        funding_proofs_json,
        charlie_balance,
    )
    .map_err(|e| JsValue::from_str(&e))
}
#[wasm_bindgen]
pub fn verify_balance_update_signature(
    params_json: &str,
    channel_secret_hex: &str,
    funding_proofs_json: &str,
    keyset_info_json: &str,
    channel_id: &str,
    balance: u64,
    signature: &str,
) -> Result<bool, JsValue> {
    let secret: [u8; 32] = hex::decode(channel_secret_hex)
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid secret"))?;
    let params = cdk_spilman::ChannelParameters::from_json_with_channel_secret(
        params_json,
        cdk_spilman::parse_keyset_info_from_json(keyset_info_json)
            .map_err(|e| JsValue::from_str(&e.to_string()))?,
        secret,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let channel = EstablishedChannel::new(
        params,
        serde_json::from_str::<Vec<Proof>>(funding_proofs_json)
            .map_err(|e| JsValue::from_str(&e.to_string()))?,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;
    BalanceUpdateMessage {
        channel_id: channel_id.to_string(),
        amount: balance,
        signature: signature.parse().map_err(
            |e: <bitcoin::secp256k1::schnorr::Signature as FromStr>::Err| {
                JsValue::from_str(&e.to_string())
            },
        )?,
    }
    .verify_sender_signature(&channel)
    .map(|_| true)
    .map_err(|e| JsValue::from_str(&e.to_string()))
}
#[wasm_bindgen]
pub fn verify_proof_dleq(proof_json: &str, mint_pubkey_hex: &str) -> Result<bool, JsValue> {
    let proof: Proof =
        serde_json::from_str(proof_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    proof
        .verify_dleq(
            PublicKey::from_str(mint_pubkey_hex).map_err(|e| JsValue::from_str(&e.to_string()))?,
        )
        .map(|_| true)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}
#[wasm_bindgen]
pub fn verify_channel(
    params_json: &str,
    channel_secret_hex: &str,
    funding_proofs_json: &str,
    keyset_info_json: &str,
) -> Result<String, JsValue> {
    let secret: [u8; 32] = hex::decode(channel_secret_hex)
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid secret"))?;
    let params = ChannelParameters::from_json_with_channel_secret(
        params_json,
        cdk_spilman::parse_keyset_info_from_json(keyset_info_json)
            .map_err(|e| JsValue::from_str(&e.to_string()))?,
        secret,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let result = cdk_spilman::verify_valid_channel(
        &serde_json::from_str::<Vec<Proof>>(funding_proofs_json)
            .map_err(|e| JsValue::from_str(&e.to_string()))?,
        &params,
    );
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}
#[wasm_bindgen]
pub fn build_cashu_b_token(
    mint_url: &str,
    unit: &str,
    proofs_json: &str,
) -> Result<String, JsValue> {
    cdk_spilman::build_cashu_b_token(mint_url, unit, proofs_json).map_err(|e| JsValue::from_str(&e))
}

/// Creates plain blinded messages for minting tokens (not channel-locked).
///
/// Returns JSON with:
/// - `blinded_messages`: Array of blinded messages (ready for mint request)
/// - `secrets_with_blinding`: Array of {secret, blinding_factor, amount} for unblinding later
#[wasm_bindgen]
pub fn create_plain_blinded_messages(
    amount_sat: u64,
    keyset_info_json: &str,
) -> Result<String, JsValue> {
    cdk_spilman::create_plain_blinded_messages(amount_sat, keyset_info_json)
        .map_err(|e| JsValue::from_str(&e))
}
