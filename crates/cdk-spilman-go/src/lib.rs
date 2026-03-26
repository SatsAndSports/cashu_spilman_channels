//! FFI bindings for CDK Spilman payment channels (for Go integration)
//!
//! This module provides C-compatible FFI functions for use with cgo.
//! All `unsafe extern "C"` functions require valid pointers as documented.

// FFI functions have uniform safety requirements: callers must pass valid pointers
#![allow(clippy::missing_safety_doc)]

use cashu::nuts::SecretKey;
use cdk_spilman::{
    self, BridgeError, BridgeErrorResponse, ChannelFunding, ChannelPolicy, ChannelState,
    ClosingData, PaymentProof, SpilmanBridge, SpilmanClientBridge, SpilmanClientHost, SpilmanHost,
    SpilmanNetworking,
};
pub use libc::{c_char, c_int};
use std::ffi::{CStr, CString};
use std::ptr;

// ============================================================================
// C-Compatible Types
// ============================================================================

#[repr(C)]
pub struct CResult {
    pub data: *mut c_char,
    pub error: *mut c_char,
}

impl CResult {
    fn success(data: String) -> Self {
        CResult {
            data: CString::new(data).unwrap().into_raw(),
            error: ptr::null_mut(),
        }
    }

    fn error(err: String) -> Self {
        CResult {
            data: ptr::null_mut(),
            error: CString::new(err).unwrap().into_raw(),
        }
    }
}

fn bridge_error_response_json(err: &BridgeError) -> String {
    serde_json::to_string(&BridgeErrorResponse::from_bridge_error(err))
        .unwrap_or_else(|_| err.to_string())
}

#[repr(C)]
pub struct SpilmanHostCallbacks {
    pub user_data: *mut libc::c_void,
    pub receiver_key_is_acceptable:
        extern "C" fn(user_data: *mut libc::c_void, pubkey_hex: *const c_char) -> c_int,
    pub mint_and_keyset_is_acceptable: extern "C" fn(
        user_data: *mut libc::c_void,
        mint: *const c_char,
        keyset_id: *const c_char,
    ) -> c_int,
    pub get_funding_and_params: extern "C" fn(
        user_data: *mut libc::c_void,
        channel_id: *const c_char,
        params_out: *mut *mut c_char,
        proofs_out: *mut *mut c_char,
        secret_out: *mut *mut c_char,
        keyset_out: *mut *mut c_char,
    ) -> c_int,
    pub save_funding: extern "C" fn(
        user_data: *mut libc::c_void,
        channel_id: *const c_char,
        params_json: *const c_char,
        funding_proofs_json: *const c_char,
        channel_secret_hex: *const c_char,
        keyset_info_json: *const c_char,
        initial_balance: u64,
        initial_signature: *const c_char,
    ),
    pub get_amount_due: extern "C" fn(
        user_data: *mut libc::c_void,
        channel_id: *const c_char,
        context_json: *const c_char,
    ) -> u64,
    pub record_payment: extern "C" fn(
        user_data: *mut libc::c_void,
        channel_id: *const c_char,
        balance: u64,
        signature: *const c_char,
        context_json: *const c_char,
    ),
    /// Get channel state: returns "open", "closing", or "closed"
    pub get_channel_state:
        extern "C" fn(user_data: *mut libc::c_void, channel_id: *const c_char) -> *mut c_char,
    /// Mark channel as closing: returns 1=success, 0=error
    pub mark_channel_closing: extern "C" fn(
        user_data: *mut libc::c_void,
        channel_id: *const c_char,
        expiry_timestamp: u64,
        balance: u64,
        signature: *const c_char,
    ) -> c_int,
    /// Get closing data: returns 1 and fills outputs if channel is closing, 0 otherwise
    pub get_closing_data: extern "C" fn(
        user_data: *mut libc::c_void,
        channel_id: *const c_char,
        expiry_timestamp_out: *mut u64,
        balance_out: *mut u64,
        signature_out: *mut *mut c_char,
    ) -> c_int,
    pub get_channel_policy: extern "C" fn(
        user_data: *mut libc::c_void,
        unit: *const c_char,
        min_expiry_out: *mut u64,
        min_capacity_out: *mut u64,
        max_amount_per_output_out: *mut i64,
    ) -> c_int,
    pub now_seconds: extern "C" fn(user_data: *mut libc::c_void) -> u64,
    pub get_balance_and_signature_for_unilateral_exit: extern "C" fn(
        user_data: *mut libc::c_void,
        channel_id: *const c_char,
        balance_out: *mut u64,
        signature_out: *mut *mut c_char,
    ) -> c_int,
    pub get_active_keyset_ids: extern "C" fn(
        user_data: *mut libc::c_void,
        mint: *const c_char,
        unit: *const c_char,
    ) -> *mut c_char, // Returns JSON array string
    pub get_keyset_info: extern "C" fn(
        user_data: *mut libc::c_void,
        mint: *const c_char,
        keyset_id: *const c_char,
    ) -> *mut c_char, // Returns KeysetInfo JSON
    pub call_mint_swap: extern "C" fn(
        user_data: *mut libc::c_void,
        mint_url: *const c_char,
        swap_request_json: *const c_char,
        response_out: *mut *mut c_char,
    ) -> c_int, // 1 = success, 0 = error (response_out contains error message)
    pub refresh_all_keysets:
        extern "C" fn(user_data: *mut libc::c_void, mint_url: *const c_char) -> c_int, // 1 = success, 0 = error (optional - can be no-op returning 1)
    /// Compute channel secret: performs ECDH and returns hex. Returns 1=success, 0=error.
    pub compute_channel_secret: extern "C" fn(
        user_data: *mut libc::c_void,
        receiver_pubkey_hex: *const c_char,
        sender_pubkey_hex: *const c_char,
        result_out: *mut *mut c_char,
    ) -> c_int,
    /// Sign with tweaked key: returns 1=success, 0=error. result_out gets signature hex.
    pub sign_with_tweaked_key: extern "C" fn(
        user_data: *mut libc::c_void,
        signer_pubkey_hex: *const c_char,
        message_hex: *const c_char,
        tweak_scalar_hex: *const c_char,
        result_out: *mut *mut c_char,
    ) -> c_int,
    pub mark_channel_closed: extern "C" fn(
        user_data: *mut libc::c_void,
        channel_id: *const c_char,
        expiry_timestamp: u64,
        balance: u64,
        receiver_proofs_json: *const c_char,
        sender_proofs_json: *const c_char,
        receiver_sum: u64,
        sender_sum: u64,
    ) -> c_int, // 1 = success, 0 = error
}

struct CGoSpilmanHost {
    callbacks: SpilmanHostCallbacks,
}

// Safety: We assume the Go side handles thread safety if it provides a shared user_data
unsafe impl Send for CGoSpilmanHost {}
unsafe impl Sync for CGoSpilmanHost {}

impl SpilmanHost<String> for CGoSpilmanHost {
    fn receiver_key_is_acceptable(&self, receiver_pubkey: &cashu::nuts::PublicKey) -> bool {
        let hex = CString::new(receiver_pubkey.to_hex()).unwrap();
        (self.callbacks.receiver_key_is_acceptable)(self.callbacks.user_data, hex.as_ptr()) != 0
    }

    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &cashu::nuts::Id) -> bool {
        let mint_c = CString::new(mint).unwrap();
        let kid_c = CString::new(keyset_id.to_string()).unwrap();
        (self.callbacks.mint_and_keyset_is_acceptable)(
            self.callbacks.user_data,
            mint_c.as_ptr(),
            kid_c.as_ptr(),
        ) != 0
    }

    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
        let id_c = CString::new(channel_id).unwrap();
        let mut p_ptr: *mut c_char = ptr::null_mut();
        let mut pr_ptr: *mut c_char = ptr::null_mut();
        let mut s_ptr: *mut c_char = ptr::null_mut();
        let mut k_ptr: *mut c_char = ptr::null_mut();

        let ok = (self.callbacks.get_funding_and_params)(
            self.callbacks.user_data,
            id_c.as_ptr(),
            &mut p_ptr,
            &mut pr_ptr,
            &mut s_ptr,
            &mut k_ptr,
        );

        if ok == 0 {
            return None;
        }

        unsafe {
            let params_json = CString::from_raw(p_ptr).into_string().unwrap();
            let funding_proofs_json = CString::from_raw(pr_ptr).into_string().unwrap();
            let channel_secret_hex = CString::from_raw(s_ptr).into_string().unwrap();
            let keyset_info_json = CString::from_raw(k_ptr).into_string().unwrap();
            Some(ChannelFunding {
                params_json,
                funding_proofs_json,
                channel_secret_hex,
                keyset_info_json,
            })
        }
    }

    fn save_funding(
        &self,
        channel_id: &str,
        funding: ChannelFunding,
        initial_payment: PaymentProof,
    ) {
        let id_c = CString::new(channel_id).unwrap();
        let p_c = CString::new(funding.params_json).unwrap();
        let pr_c = CString::new(funding.funding_proofs_json).unwrap();
        let s_c = CString::new(funding.channel_secret_hex).unwrap();
        let k_c = CString::new(funding.keyset_info_json).unwrap();
        let sig_c = CString::new(initial_payment.signature).unwrap();

        (self.callbacks.save_funding)(
            self.callbacks.user_data,
            id_c.as_ptr(),
            p_c.as_ptr(),
            pr_c.as_ptr(),
            s_c.as_ptr(),
            k_c.as_ptr(),
            initial_payment.balance,
            sig_c.as_ptr(),
        );
    }

    fn get_amount_due(&self, channel_id: &str, context_json: Option<&String>) -> u64 {
        let id_c = CString::new(channel_id).unwrap();
        let ctx_c = context_json.map(|s| CString::new(s.as_str()).unwrap());
        let ctx_ptr = ctx_c.as_ref().map(|c| c.as_ptr()).unwrap_or(ptr::null());
        (self.callbacks.get_amount_due)(self.callbacks.user_data, id_c.as_ptr(), ctx_ptr)
    }

    fn record_payment(&self, channel_id: &str, payment: PaymentProof, context_json: &String) {
        let id_c = CString::new(channel_id).unwrap();
        let sig_c = CString::new(payment.signature).unwrap();
        let ctx_c = CString::new(context_json.as_str()).unwrap();
        (self.callbacks.record_payment)(
            self.callbacks.user_data,
            id_c.as_ptr(),
            payment.balance,
            sig_c.as_ptr(),
            ctx_c.as_ptr(),
        );
    }

    fn get_channel_state(&self, channel_id: &str) -> ChannelState {
        let id_c = CString::new(channel_id).unwrap();
        let ptr = (self.callbacks.get_channel_state)(self.callbacks.user_data, id_c.as_ptr());
        if ptr.is_null() {
            return ChannelState::Open;
        }
        let state_str = unsafe { CString::from_raw(ptr).into_string().unwrap_or_default() };
        match state_str.as_str() {
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
        let id_c = CString::new(channel_id).unwrap();
        let sig_c = CString::new(payment.signature).unwrap();
        let ok = (self.callbacks.mark_channel_closing)(
            self.callbacks.user_data,
            id_c.as_ptr(),
            expiry_timestamp,
            payment.balance,
            sig_c.as_ptr(),
        );
        if ok != 0 {
            Ok(())
        } else {
            Err("mark_channel_closing failed".to_string())
        }
    }

    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData> {
        let id_c = CString::new(channel_id).unwrap();
        let mut expiry_timestamp: u64 = 0;
        let mut balance: u64 = 0;
        let mut sig_ptr: *mut c_char = ptr::null_mut();

        let ok = (self.callbacks.get_closing_data)(
            self.callbacks.user_data,
            id_c.as_ptr(),
            &mut expiry_timestamp,
            &mut balance,
            &mut sig_ptr,
        );

        if ok != 0 {
            unsafe {
                let signature = CString::from_raw(sig_ptr).into_string().unwrap();
                Some(ClosingData {
                    expiry_timestamp,
                    balance,
                    signature,
                })
            }
        } else {
            None
        }
    }

    fn get_channel_policy(&self, unit: &str) -> Option<ChannelPolicy> {
        let c_unit = CString::new(unit).ok()?;
        let mut min_expiry: u64 = 0;
        let mut min_capacity: u64 = 0;
        let mut max_amount: i64 = -1; // -1 = None
        let found = (self.callbacks.get_channel_policy)(
            self.callbacks.user_data,
            c_unit.as_ptr(),
            &mut min_expiry,
            &mut min_capacity,
            &mut max_amount,
        );
        if found == 0 {
            return None;
        }
        Some(ChannelPolicy {
            min_expiry_in_seconds: min_expiry,
            min_capacity,
            max_amount_per_output: if max_amount >= 0 {
                Some(max_amount as u64)
            } else {
                None
            },
        })
    }

    fn now_seconds(&self) -> u64 {
        (self.callbacks.now_seconds)(self.callbacks.user_data)
    }

    fn get_balance_and_signature_for_unilateral_exit(
        &self,
        channel_id: &str,
    ) -> Option<PaymentProof> {
        let id_c = CString::new(channel_id).unwrap();
        let mut balance: u64 = 0;
        let mut sig_ptr: *mut c_char = ptr::null_mut();

        let ok = (self.callbacks.get_balance_and_signature_for_unilateral_exit)(
            self.callbacks.user_data,
            id_c.as_ptr(),
            &mut balance,
            &mut sig_ptr,
        );

        if ok == 0 {
            return None;
        }

        unsafe {
            let signature = CString::from_raw(sig_ptr).into_string().unwrap();
            Some(PaymentProof { balance, signature })
        }
    }

    fn get_active_keyset_ids(
        &self,
        mint: &str,
        unit: &cashu::nuts::CurrencyUnit,
    ) -> Vec<cashu::nuts::Id> {
        let mint_c = CString::new(mint).unwrap();
        let unit_str = unit.to_string();
        let unit_c = CString::new(unit_str).unwrap();

        let json_ptr = (self.callbacks.get_active_keyset_ids)(
            self.callbacks.user_data,
            mint_c.as_ptr(),
            unit_c.as_ptr(),
        );
        if json_ptr.is_null() {
            return Vec::new();
        }

        unsafe {
            let json = CString::from_raw(json_ptr).into_string().unwrap();
            serde_json::from_str(&json).unwrap_or_default()
        }
    }

    fn get_keyset_info(&self, mint: &str, keyset_id: &cashu::nuts::Id) -> Option<String> {
        let mint_c = CString::new(mint).unwrap();
        let kid_c = CString::new(keyset_id.to_string()).unwrap();

        let json_ptr = (self.callbacks.get_keyset_info)(
            self.callbacks.user_data,
            mint_c.as_ptr(),
            kid_c.as_ptr(),
        );
        if json_ptr.is_null() {
            return None;
        }

        unsafe { Some(CString::from_raw(json_ptr).into_string().unwrap()) }
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
        let id_c = CString::new(channel_id).unwrap();
        let rp_c = CString::new(receiver_proofs_json).unwrap();
        let sp_c = CString::new(sender_proofs_json).unwrap();

        let ok = (self.callbacks.mark_channel_closed)(
            self.callbacks.user_data,
            id_c.as_ptr(),
            expiry_timestamp,
            balance,
            rp_c.as_ptr(),
            sp_c.as_ptr(),
            receiver_sum,
            sender_sum,
        );

        if ok != 0 {
            Ok(())
        } else {
            Err("mark_channel_closed failed".to_string())
        }
    }

    fn compute_channel_secret(
        &self,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
    ) -> Result<String, String> {
        let cp_c = CString::new(receiver_pubkey_hex).unwrap();
        let ap_c = CString::new(sender_pubkey_hex).unwrap();
        let mut result_ptr: *mut c_char = ptr::null_mut();

        let ok = (self.callbacks.compute_channel_secret)(
            self.callbacks.user_data,
            cp_c.as_ptr(),
            ap_c.as_ptr(),
            &mut result_ptr,
        );

        unsafe {
            let result = CString::from_raw(result_ptr).into_string().unwrap();
            if ok != 0 {
                Ok(result)
            } else {
                Err(result)
            }
        }
    }

    fn sign_with_tweaked_key(
        &self,
        signer_pubkey_hex: &str,
        message_hex: &str,
        tweak_scalar_hex: &str,
    ) -> Result<String, String> {
        let sp_c = CString::new(signer_pubkey_hex).unwrap();
        let msg_c = CString::new(message_hex).unwrap();
        let tw_c = CString::new(tweak_scalar_hex).unwrap();
        let mut result_ptr: *mut c_char = ptr::null_mut();

        let ok = (self.callbacks.sign_with_tweaked_key)(
            self.callbacks.user_data,
            sp_c.as_ptr(),
            msg_c.as_ptr(),
            tw_c.as_ptr(),
            &mut result_ptr,
        );

        unsafe {
            let result = CString::from_raw(result_ptr).into_string().unwrap();
            if ok != 0 {
                Ok(result)
            } else {
                Err(result)
            }
        }
    }
}

impl SpilmanNetworking for CGoSpilmanHost {
    fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String> {
        let mint_c = CString::new(mint_url).unwrap();
        let req_c = CString::new(swap_request_json).unwrap();
        let mut response_ptr: *mut c_char = ptr::null_mut();

        let ok = (self.callbacks.call_mint_swap)(
            self.callbacks.user_data,
            mint_c.as_ptr(),
            req_c.as_ptr(),
            &mut response_ptr,
        );

        unsafe {
            let response = CString::from_raw(response_ptr).into_string().unwrap();
            if ok != 0 {
                Ok(response)
            } else {
                Err(response)
            }
        }
    }

    fn refresh_all_keysets(&self, mint: &str) -> Result<(), String> {
        let mint_c = CString::new(mint).unwrap();
        let ok = (self.callbacks.refresh_all_keysets)(self.callbacks.user_data, mint_c.as_ptr());
        if ok != 0 {
            Ok(())
        } else {
            Err("refresh_all_keysets failed".to_string())
        }
    }
}

// ============================================================================
// Bridge Instance
// ============================================================================

pub struct BridgeInstance {
    bridge: SpilmanBridge<CGoSpilmanHost>,
}

#[no_mangle]
pub unsafe extern "C" fn spilman_bridge_new(
    callbacks: SpilmanHostCallbacks,
) -> *mut BridgeInstance {
    let host = CGoSpilmanHost { callbacks };
    let bridge = SpilmanBridge::new(host);

    Box::into_raw(Box::new(BridgeInstance { bridge }))
}

#[no_mangle]
pub unsafe extern "C" fn spilman_bridge_free(ptr: *mut BridgeInstance) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}

/// Process a payment and record usage.
///
/// Returns JSON-serialized PaymentSuccess on success, or error string on failure.
#[no_mangle]
pub unsafe extern "C" fn spilman_bridge_process_payment(
    ptr: *mut BridgeInstance,
    payment_json: *const c_char,
    context_json: *const c_char,
) -> CResult {
    let instance = &*ptr;
    let payment = CStr::from_ptr(payment_json).to_str().unwrap();
    let context = CStr::from_ptr(context_json).to_str().unwrap().to_string();

    match instance.bridge.process_payment_via_json(payment, &context) {
        Ok(result) => {
            let json = serde_json::to_string(&result).unwrap();
            CResult::success(json)
        }
        Err(e) => CResult::error(bridge_error_response_json(&e)),
    }
}

/// Validate a payment without recording it.
///
/// Performs all validation (parsing, channel verification, balance checks,
/// signature verification) but does NOT call record_payment.
///
/// For new channels, funding data IS saved (idempotent).
///
/// Returns JSON-serialized PaymentValidationResult on success, or error string on failure.
#[no_mangle]
pub unsafe extern "C" fn spilman_bridge_validate_payment(
    ptr: *mut BridgeInstance,
    payment_json: *const c_char,
    context_json: *const c_char,
) -> CResult {
    let instance = &*ptr;
    let payment = CStr::from_ptr(payment_json).to_str().unwrap();
    let context = CStr::from_ptr(context_json).to_str().unwrap().to_string();

    match instance.bridge.validate_payment_via_json(payment, &context) {
        Ok(result) => {
            let json = serde_json::to_string(&result).unwrap();
            CResult::success(json)
        }
        Err(e) => CResult::error(bridge_error_response_json(&e)),
    }
}

/// Register/fund a channel without recording any usage.
///
/// Validates the channel (params, funding proofs, signature for balance=0)
/// and saves it to the funding store, but does NOT record any payment/usage.
///
/// Returns JSON-serialized FundChannelResult on success, or error string on failure.
#[no_mangle]
pub unsafe extern "C" fn spilman_bridge_fund_channel(
    ptr: *mut BridgeInstance,
    payment_json: *const c_char,
) -> CResult {
    let instance = &*ptr;
    let payment = CStr::from_ptr(payment_json).to_str().unwrap();

    match instance.bridge.fund_channel_via_json(payment) {
        Ok(result) => {
            let json = serde_json::to_string(&result).unwrap();
            CResult::success(json)
        }
        Err(e) => CResult::error(bridge_error_response_json(&e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_bridge_validate_and_prepare_cooperative_close(
    ptr: *mut BridgeInstance,
    payment_json: *const c_char,
) -> CResult {
    let instance = &*ptr;
    let payment = CStr::from_ptr(payment_json).to_str().unwrap();

    match instance
        .bridge
        .validate_and_prepare_cooperative_close(payment)
    {
        Ok(close_data) => CResult::success(close_data.to_json_value().to_string()),
        Err(e) => CResult::error(bridge_error_response_json(&e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_bridge_create_unilateral_close_data(
    ptr: *mut BridgeInstance,
    channel_id: *const c_char,
) -> CResult {
    let instance = &*ptr;
    let id = CStr::from_ptr(channel_id).to_str().unwrap();

    match instance.bridge.create_unilateral_close_data(id) {
        Ok(close_data) => CResult::success(close_data.to_json_value().to_string()),
        Err(e) => CResult::error(bridge_error_response_json(&e)),
    }
}

/// Execute a cooperative close: validate, submit swap, unblind, and mark closed.
///
/// Returns CloseSuccess JSON on success (in data), or CloseError JSON on failure (in error).
#[no_mangle]
pub unsafe extern "C" fn spilman_bridge_execute_cooperative_close(
    ptr: *mut BridgeInstance,
    payment_json: *const c_char,
) -> CResult {
    let instance = &*ptr;
    let payment_str = CStr::from_ptr(payment_json).to_str().unwrap();

    match instance
        .bridge
        .execute_cooperative_close(payment_str, instance.bridge.host())
    {
        Ok(result) => {
            let json = serde_json::to_string(&result).unwrap();
            CResult::success(json)
        }
        Err(e) => {
            let error_json = serde_json::to_string(&e).unwrap_or_else(|_| e.to_string());
            CResult::error(error_json)
        }
    }
}

/// Execute a unilateral close: retrieve stored payment, submit swap, unblind, and mark closed.
///
/// Returns CloseSuccess JSON on success (in data), or CloseError JSON on failure (in error).
#[no_mangle]
pub unsafe extern "C" fn spilman_bridge_execute_unilateral_close(
    ptr: *mut BridgeInstance,
    channel_id: *const c_char,
) -> CResult {
    let instance = &*ptr;
    let channel_id_str = CStr::from_ptr(channel_id).to_str().unwrap();

    match instance
        .bridge
        .execute_unilateral_close(channel_id_str, instance.bridge.host())
    {
        Ok(result) => {
            let json = serde_json::to_string(&result).unwrap();
            CResult::success(json)
        }
        Err(e) => {
            let error_json = serde_json::to_string(&e).unwrap_or_else(|_| e.to_string());
            CResult::error(error_json)
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_create_signed_balance_update(
    params_json: *const c_char,
    keyset_json: *const c_char,
    secret_hex: *const c_char,
    proofs_json: *const c_char,
    balance: u64,
) -> CResult {
    let p = CStr::from_ptr(params_json).to_str().unwrap();
    let k = CStr::from_ptr(keyset_json).to_str().unwrap();
    let s = CStr::from_ptr(secret_hex).to_str().unwrap();
    let pr = CStr::from_ptr(proofs_json).to_str().unwrap();

    match cdk_spilman::create_signed_balance_update(p, k, s, pr, balance) {
        Ok(res) => CResult::success(res),
        Err(e) => CResult::error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_generate_keypair() -> CResult {
    let secret = SecretKey::generate();
    let pubkey = secret.public_key();
    let json = serde_json::json!({
        "secret": secret.to_secret_hex(),
        "pubkey": pubkey.to_hex()
    })
    .to_string();
    CResult::success(json)
}

#[no_mangle]
pub unsafe extern "C" fn spilman_secret_key_to_pubkey(secret_hex: *const c_char) -> CResult {
    let hex = CStr::from_ptr(secret_hex).to_str().unwrap();
    match SecretKey::from_hex(hex) {
        Ok(sk) => CResult::success(sk.public_key().to_hex()),
        Err(e) => CResult::error(e.to_string()),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_free_cresult(res: CResult) {
    spilman_free_string(res.data);
    spilman_free_string(res.error);
}

#[no_mangle]
pub unsafe extern "C" fn spilman_compute_channel_secret(
    my_secret_hex: *const c_char,
    their_pubkey_hex: *const c_char,
) -> CResult {
    let my_sk = CStr::from_ptr(my_secret_hex).to_str().unwrap();
    let their_pk = CStr::from_ptr(their_pubkey_hex).to_str().unwrap();

    match cdk_spilman::compute_channel_secret_from_hex(my_sk, their_pk) {
        Ok(s) => CResult::success(s),
        Err(e) => CResult::error(e.to_string()),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_compute_funding_token_amount(
    capacity: u64,
    keyset_info_json: *const c_char,
    maximum_amount: u64,
) -> CResult {
    let k = CStr::from_ptr(keyset_info_json).to_str().unwrap();

    match cdk_spilman::compute_funding_token_amount(capacity, k, maximum_amount) {
        Ok(amount) => CResult::success(amount.to_string()),
        Err(e) => CResult::error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_channel_parameters_get_channel_id(
    params_json: *const c_char,
    channel_secret_hex: *const c_char,
    keyset_info_json: *const c_char,
) -> CResult {
    let p = CStr::from_ptr(params_json).to_str().unwrap();
    let s = CStr::from_ptr(channel_secret_hex).to_str().unwrap();
    let k = CStr::from_ptr(keyset_info_json).to_str().unwrap();

    match cdk_spilman::channel_parameters_get_channel_id(p, s, k) {
        Ok(id) => CResult::success(id),
        Err(e) => CResult::error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_create_plain_blinded_messages(
    amount_sat: u64,
    keyset_info_json: *const c_char,
) -> CResult {
    let k = CStr::from_ptr(keyset_info_json).to_str().unwrap();

    match cdk_spilman::create_plain_blinded_messages(amount_sat, k) {
        Ok(json) => CResult::success(json),
        Err(e) => CResult::error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_create_funding_outputs(
    params_json: *const c_char,
    alice_secret_hex: *const c_char,
    keyset_info_json: *const c_char,
) -> CResult {
    let p = CStr::from_ptr(params_json).to_str().unwrap();
    let s = CStr::from_ptr(alice_secret_hex).to_str().unwrap();
    let k = CStr::from_ptr(keyset_info_json).to_str().unwrap();

    match cdk_spilman::create_funding_outputs(p, s, k) {
        Ok(json) => CResult::success(json),
        Err(e) => CResult::error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_construct_proofs(
    blind_signatures_json: *const c_char,
    secrets_with_blinding_json: *const c_char,
    keyset_info_json: *const c_char,
) -> CResult {
    let sigs = CStr::from_ptr(blind_signatures_json).to_str().unwrap();
    let secrets = CStr::from_ptr(secrets_with_blinding_json).to_str().unwrap();
    let k = CStr::from_ptr(keyset_info_json).to_str().unwrap();

    match cdk_spilman::construct_proofs(sigs, secrets, k) {
        Ok(json) => CResult::success(json),
        Err(e) => CResult::error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_build_cashu_a_token(
    mint_url: *const c_char,
    proofs_json: *const c_char,
) -> CResult {
    let m = CStr::from_ptr(mint_url).to_str().unwrap();
    let p = CStr::from_ptr(proofs_json).to_str().unwrap();

    match cdk_spilman::build_cashu_a_token(m, p) {
        Ok(token) => CResult::success(token),
        Err(e) => CResult::error(e),
    }
}

/// C callback type for HTTP requests: (user_data, method, url, body, response_out) -> error_out
/// Returns null on success (response written to response_out), or error string on failure.
type HttpCallbackFn = extern "C" fn(
    user_data: *mut libc::c_void,
    method: *const c_char,
    url: *const c_char,
    body: *const c_char,
    response_out: *mut *mut c_char,
) -> *mut c_char;

#[no_mangle]
pub unsafe extern "C" fn spilman_mint_proofs_from_mint(
    mint_url: *const c_char,
    amount_sat: u64,
    keyset_info_json: *const c_char,
    call_http: HttpCallbackFn,
    user_data: *mut libc::c_void,
) -> CResult {
    let m = CStr::from_ptr(mint_url).to_str().unwrap();
    let k = CStr::from_ptr(keyset_info_json).to_str().unwrap();

    let http_fn = |method: &str, url: &str, body: &str| -> Result<String, String> {
        let c_method = CString::new(method).unwrap();
        let c_url = CString::new(url).unwrap();
        let c_body = CString::new(body).unwrap();
        let mut response_ptr: *mut c_char = std::ptr::null_mut();

        let err_ptr = call_http(
            user_data,
            c_method.as_ptr(),
            c_url.as_ptr(),
            c_body.as_ptr(),
            &mut response_ptr,
        );

        if !err_ptr.is_null() {
            let err = CStr::from_ptr(err_ptr).to_str().unwrap().to_string();
            libc::free(err_ptr as *mut libc::c_void);
            return Err(err);
        }

        if response_ptr.is_null() {
            return Err("HTTP callback returned null response".to_string());
        }

        let response = CStr::from_ptr(response_ptr).to_str().unwrap().to_string();
        libc::free(response_ptr as *mut libc::c_void);
        Ok(response)
    };

    match cdk_spilman::mint_proofs_from_mint(m, amount_sat, k, &http_fn) {
        Ok(json) => CResult::success(json),
        Err(e) => CResult::error(e),
    }
}

// ============================================================================
// Client Bridge: SpilmanClientBridge via C callbacks
// ============================================================================

#[repr(C)]
pub struct SpilmanClientHostCallbacks {
    pub user_data: *mut libc::c_void,
    pub call_mint_swap: extern "C" fn(
        user_data: *mut libc::c_void,
        mint_url: *const c_char,
        swap_request_json: *const c_char,
        response_out: *mut *mut c_char,
    ) -> c_int, // 1 = success, 0 = error (response_out contains error message)
    pub save_channel: extern "C" fn(
        user_data: *mut libc::c_void,
        channel_id: *const c_char,
        channel_json: *const c_char,
        channel_secret_hex: *const c_char,
    ),
    pub get_channel:
        extern "C" fn(user_data: *mut libc::c_void, channel_id: *const c_char) -> *mut c_char, // NULL = not found, otherwise JSON: {"channel_json":"...","channel_secret_hex":"..."}
    pub list_channel_ids: extern "C" fn(user_data: *mut libc::c_void) -> *mut c_char, // JSON array string
    pub delete_channel: extern "C" fn(user_data: *mut libc::c_void, channel_id: *const c_char),
    pub sign_with_tweaked_key: extern "C" fn(
        user_data: *mut libc::c_void,
        signer_pubkey_hex: *const c_char,
        message_hex: *const c_char,
        tweak_scalar_hex: *const c_char,
        response_out: *mut *mut c_char,
    ) -> c_int, // 1 = success, 0 = error (response_out contains error message)
    pub compute_channel_secret: extern "C" fn(
        user_data: *mut libc::c_void,
        sender_pubkey_hex: *const c_char,
        receiver_pubkey_hex: *const c_char,
        response_out: *mut *mut c_char,
    ) -> c_int, // 1 = success, 0 = error (response_out contains error message)
}

struct CGoSpilmanClientHost {
    callbacks: SpilmanClientHostCallbacks,
}

// Safety: We assume the Go side handles thread safety if it provides a shared user_data
unsafe impl Send for CGoSpilmanClientHost {}
unsafe impl Sync for CGoSpilmanClientHost {}

impl SpilmanClientHost for CGoSpilmanClientHost {
    fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String> {
        let mint_c = CString::new(mint_url).unwrap();
        let req_c = CString::new(swap_request_json).unwrap();
        let mut response_ptr: *mut c_char = ptr::null_mut();

        let ok = (self.callbacks.call_mint_swap)(
            self.callbacks.user_data,
            mint_c.as_ptr(),
            req_c.as_ptr(),
            &mut response_ptr,
        );

        unsafe {
            let response = CString::from_raw(response_ptr).into_string().unwrap();
            if ok != 0 {
                Ok(response)
            } else {
                Err(response)
            }
        }
    }

    fn save_channel(&self, channel_id: &str, channel_json: &str, channel_secret_hex: &str) {
        let id_c = CString::new(channel_id).unwrap();
        let json_c = CString::new(channel_json).unwrap();
        let secret_c = CString::new(channel_secret_hex).unwrap();
        (self.callbacks.save_channel)(
            self.callbacks.user_data,
            id_c.as_ptr(),
            json_c.as_ptr(),
            secret_c.as_ptr(),
        );
    }

    fn get_channel(&self, channel_id: &str) -> Option<cdk_spilman::ChannelData> {
        let id_c = CString::new(channel_id).unwrap();
        let ptr = (self.callbacks.get_channel)(self.callbacks.user_data, id_c.as_ptr());
        if ptr.is_null() {
            return None;
        }
        unsafe {
            let json_str = CString::from_raw(ptr).into_string().unwrap();
            let v: serde_json::Value = serde_json::from_str(&json_str).ok()?;
            Some(cdk_spilman::ChannelData {
                channel_json: v["channel_json"].as_str()?.to_string(),
                channel_secret_hex: v["channel_secret_hex"].as_str()?.to_string(),
            })
        }
    }

    fn list_channel_ids(&self) -> Vec<String> {
        let ptr = (self.callbacks.list_channel_ids)(self.callbacks.user_data);
        if ptr.is_null() {
            return Vec::new();
        }
        unsafe {
            let json = CString::from_raw(ptr).into_string().unwrap();
            serde_json::from_str(&json).unwrap_or_default()
        }
    }

    fn delete_channel(&self, channel_id: &str) {
        let id_c = CString::new(channel_id).unwrap();
        (self.callbacks.delete_channel)(self.callbacks.user_data, id_c.as_ptr());
    }

    fn sign_with_tweaked_key(
        &self,
        signer_pubkey_hex: &str,
        message_hex: &str,
        tweak_scalar_hex: &str,
    ) -> Result<String, String> {
        let pubkey_c = CString::new(signer_pubkey_hex).unwrap();
        let msg_c = CString::new(message_hex).unwrap();
        let tweak_c = CString::new(tweak_scalar_hex).unwrap();
        let mut response_ptr: *mut c_char = ptr::null_mut();

        let ok = (self.callbacks.sign_with_tweaked_key)(
            self.callbacks.user_data,
            pubkey_c.as_ptr(),
            msg_c.as_ptr(),
            tweak_c.as_ptr(),
            &mut response_ptr,
        );

        unsafe {
            let response = CString::from_raw(response_ptr).into_string().unwrap();
            if ok != 0 {
                Ok(response)
            } else {
                Err(response)
            }
        }
    }

    fn compute_channel_secret(
        &self,
        sender_pubkey_hex: &str,
        receiver_pubkey_hex: &str,
    ) -> Result<String, String> {
        let alice_c = CString::new(sender_pubkey_hex).unwrap();
        let charlie_c = CString::new(receiver_pubkey_hex).unwrap();
        let mut response_ptr: *mut c_char = ptr::null_mut();

        let ok = (self.callbacks.compute_channel_secret)(
            self.callbacks.user_data,
            alice_c.as_ptr(),
            charlie_c.as_ptr(),
            &mut response_ptr,
        );

        unsafe {
            let response = CString::from_raw(response_ptr).into_string().unwrap();
            if ok != 0 {
                Ok(response)
            } else {
                Err(response)
            }
        }
    }
}

pub struct ClientBridgeInstance {
    bridge: SpilmanClientBridge<CGoSpilmanClientHost>,
}

#[no_mangle]
pub unsafe extern "C" fn spilman_client_bridge_new(
    callbacks: SpilmanClientHostCallbacks,
) -> *mut ClientBridgeInstance {
    let host = CGoSpilmanClientHost { callbacks };
    let bridge = SpilmanClientBridge::new(host);
    Box::into_raw(Box::new(ClientBridgeInstance { bridge }))
}

#[no_mangle]
pub unsafe extern "C" fn spilman_client_bridge_free(ptr: *mut ClientBridgeInstance) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_client_bridge_open_channel_from_token(
    ptr: *mut ClientBridgeInstance,
    token_string: *const c_char,
    receiver_pubkey_hex: *const c_char,
    sender_pubkey_hex: *const c_char,
    expiry_timestamp: u64,
    keyset_info_json: *const c_char,
    max_amount: u64,
) -> CResult {
    let instance = &*ptr;
    let token = CStr::from_ptr(token_string).to_str().unwrap();
    let charlie = CStr::from_ptr(receiver_pubkey_hex).to_str().unwrap();
    let alice = CStr::from_ptr(sender_pubkey_hex).to_str().unwrap();
    let keyset = CStr::from_ptr(keyset_info_json).to_str().unwrap();

    match instance.bridge.open_channel_from_token(
        token,
        charlie,
        alice,
        expiry_timestamp,
        keyset,
        max_amount,
    ) {
        Ok(result) => {
            let json = serde_json::to_string(&result).unwrap();
            CResult::success(json)
        }
        Err(e) => CResult::error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_client_bridge_sign_balance_update(
    ptr: *mut ClientBridgeInstance,
    channel_id: *const c_char,
    balance: u64,
) -> CResult {
    let instance = &*ptr;
    let id = CStr::from_ptr(channel_id).to_str().unwrap();

    match instance.bridge.sign_balance_update(id, balance) {
        Ok(json) => CResult::success(json),
        Err(e) => CResult::error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_client_bridge_build_payment_header(
    ptr: *mut ClientBridgeInstance,
    channel_id: *const c_char,
    balance: u64,
    include_funding: c_int,
) -> CResult {
    let instance = &*ptr;
    let id = CStr::from_ptr(channel_id).to_str().unwrap();

    match instance
        .bridge
        .build_payment_header(id, balance, include_funding != 0)
    {
        Ok(header) => CResult::success(header),
        Err(e) => CResult::error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_client_bridge_get_channel_info(
    ptr: *mut ClientBridgeInstance,
    channel_id: *const c_char,
) -> CResult {
    let instance = &*ptr;
    let id = CStr::from_ptr(channel_id).to_str().unwrap();

    match instance.bridge.get_channel_info(id) {
        Some(info) => {
            let json = serde_json::to_string(&info).unwrap();
            CResult::success(json)
        }
        None => CResult::error("Channel not found".to_string()),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_client_bridge_list_channels(
    ptr: *mut ClientBridgeInstance,
) -> CResult {
    let instance = &*ptr;
    let channels = instance.bridge.list_channels();
    let json = serde_json::to_string(&channels).unwrap();
    CResult::success(json)
}

#[no_mangle]
pub unsafe extern "C" fn spilman_client_bridge_create_cooperative_close_request(
    ptr: *mut ClientBridgeInstance,
    channel_id: *const c_char,
    final_balance: u64,
) -> CResult {
    let instance = &*ptr;
    let id = CStr::from_ptr(channel_id).to_str().unwrap();

    match instance
        .bridge
        .create_cooperative_close_request(id, final_balance)
    {
        Ok(json) => CResult::success(json),
        Err(e) => CResult::error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_client_bridge_process_cooperative_close_response(
    ptr: *mut ClientBridgeInstance,
    response_json: *const c_char,
) -> CResult {
    let instance = &*ptr;
    let json = CStr::from_ptr(response_json).to_str().unwrap();

    match instance.bridge.process_cooperative_close_response(json) {
        Ok(_) => CResult::success("ok".to_string()),
        Err(e) => CResult::error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_client_bridge_remove_channel(
    ptr: *mut ClientBridgeInstance,
    channel_id: *const c_char,
) {
    let instance = &*ptr;
    let id = CStr::from_ptr(channel_id).to_str().unwrap();
    instance.bridge.remove_channel(id);
}

/// Utility function for signing with a tweaked key.
///
/// Hosts can use this to implement `sign_with_tweaked_key` when they hold raw secret keys.
/// Handles BIP-340 parity, adds tweak to secret, produces BIP-340 Schnorr signature.
#[no_mangle]
pub unsafe extern "C" fn spilman_sign_with_tweaked_key_util(
    secret_key_hex: *const c_char,
    message_hex: *const c_char,
    tweak_scalar_hex: *const c_char,
) -> CResult {
    let secret = CStr::from_ptr(secret_key_hex).to_str().unwrap();
    let msg = CStr::from_ptr(message_hex).to_str().unwrap();
    let tweak = CStr::from_ptr(tweak_scalar_hex).to_str().unwrap();

    match cdk_spilman::sign_with_tweaked_key_util(secret, msg, tweak) {
        Ok(sig) => CResult::success(sig),
        Err(e) => CResult::error(e),
    }
}
