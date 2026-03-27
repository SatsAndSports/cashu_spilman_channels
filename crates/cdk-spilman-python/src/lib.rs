//! Python bindings for CDK Spilman payment channels
//!
//! This module provides PyO3 bindings for both server-side (SpilmanBridge)
//! and client-side (standalone functions) Spilman channel operations.

// Clippy false positive: it flags PyResult<String> type annotations as "useless conversion"
// when PyResult is used in function return types. This is a known issue with PyO3.
#![allow(clippy::useless_conversion)]

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyTuple;
use std::str::FromStr;

use cashu::nuts::{Id, PublicKey, SecretKey};
use spilman_core::{
    self, BridgeError, BridgeErrorResponse, ChannelPolicy, ChannelState, ClientChannelFunding,
    ClientChannelState, ClientPaymentState, ClosingData, SpilmanBridge as RustSpilmanBridge,
    SpilmanClientBridge as RustSpilmanClientBridge, SpilmanClientHost, SpilmanClientNetworking,
    SpilmanHost,
};

// ============================================================================
// Result types for Python
// ============================================================================

fn bridge_error_response_json(err: &BridgeError) -> String {
    serde_json::to_string(&BridgeErrorResponse::from_bridge_error(err))
        .unwrap_or_else(|_| err.to_string())
}

/// Result of a successful payment
#[pyclass(get_all)]
#[derive(Clone)]
pub struct PaymentSuccess {
    pub channel_id: String,
    pub balance: u64,
    pub amount_due: u64,
    pub capacity: u64,
}

impl From<spilman_core::PaymentSuccess> for PaymentSuccess {
    fn from(r: spilman_core::PaymentSuccess) -> Self {
        Self {
            channel_id: r.channel_id,
            balance: r.balance,
            amount_due: r.amount_due,
            capacity: r.capacity,
        }
    }
}

/// Result of validating a payment without recording it
#[pyclass(get_all)]
#[derive(Clone)]
pub struct PaymentValidationResult {
    pub channel_id: String,
    pub balance: u64,
    pub amount_due: u64,
    pub capacity: u64,
    pub sender_signature: String,
}

impl From<spilman_core::PaymentValidationResult> for PaymentValidationResult {
    fn from(r: spilman_core::PaymentValidationResult) -> Self {
        Self {
            channel_id: r.channel_id,
            balance: r.balance,
            amount_due: r.amount_due,
            capacity: r.capacity,
            sender_signature: r.sender_signature,
        }
    }
}

/// Result of registering/funding a channel
#[pyclass(get_all)]
#[derive(Clone)]
pub struct FundChannelResult {
    pub channel_id: String,
    pub capacity: u64,
    pub already_known: bool,
}

impl From<spilman_core::FundChannelResult> for FundChannelResult {
    fn from(r: spilman_core::FundChannelResult) -> Self {
        Self {
            channel_id: r.channel_id,
            capacity: r.capacity,
            already_known: r.already_known,
        }
    }
}

/// Result of successfully closing a channel
#[pyclass(get_all)]
#[derive(Clone)]
pub struct CloseSuccess {
    pub channel_id: String,
    pub total_value: u64,
    pub receiver_sum: u64,
    pub sender_sum: u64,
    pub sender_proofs: String,
    pub already_closed: bool,
}

impl From<spilman_core::CloseSuccess> for CloseSuccess {
    fn from(r: spilman_core::CloseSuccess) -> Self {
        Self {
            channel_id: r.channel_id,
            total_value: r.total_value,
            receiver_sum: r.receiver_sum,
            sender_sum: r.sender_sum,
            sender_proofs: r.sender_proofs,
            already_closed: r.already_closed,
        }
    }
}

// ============================================================================
// Server-side: SpilmanBridge with Python host callbacks
// ============================================================================

/// Wrapper that delegates SpilmanHost trait calls to a Python object.
///
/// The Python object must implement these methods:
/// - receiver_key_is_acceptable(pubkey_hex: str) -> bool
/// - mint_and_keyset_is_acceptable(mint: str, keyset_id: str) -> bool
/// - get_funding_and_params(channel_id: str) -> Optional[Tuple[str, str, str, str]]
/// - save_funding(channel_id: str, params: str, proofs: str, secret: str, keyset: str, initial_balance: int, initial_signature: str)
/// - get_amount_due(channel_id: str, context_json: str) -> int
/// - record_payment(channel_id: str, balance: int, signature: str, context_json: str)
/// - get_channel_state(channel_id: str) -> str  # Returns "open", "closing", or "closed"
/// - mark_channel_closing(channel_id: str, expiry_timestamp: int, balance: int, signature: str) -> None  # Raises on error
/// - get_closing_data(channel_id: str) -> Optional[dict]  # Returns {expiry_timestamp, balance, signature} or None
/// - get_channel_policy(unit: str) -> Optional[Tuple[int, int, Optional[int]]]  # (min_expiry_in_seconds, min_capacity, max_amount_per_output) or None
/// - now_seconds() -> int
/// - get_balance_and_signature_for_unilateral_exit(channel_id: str) -> Optional[Tuple[int, str]]
/// - get_active_keyset_ids(mint: str, unit: str) -> List[str]
/// - get_keyset_info(mint: str, keyset_id: str) -> Optional[str]
/// - call_mint_swap(mint_url: str, swap_request_json: str) -> str  # Returns response JSON or raises
/// - mark_channel_closed(channel_id: str, ...) -> None  # Raises on error
///
/// Optional methods (default implementations exist):
/// - refresh_all_keysets(mint: str) -> None  # Re-fetch keysets from mint (for retry logic)
struct PySpilmanHost {
    py_host: PyObject,
}

impl SpilmanHost for PySpilmanHost {
    fn get_active_keyset_ids(&self, mint: &str, unit: &cashu::nuts::CurrencyUnit) -> Vec<Id> {
        let unit_str = unit.to_string();

        Python::with_gil(|py| {
            match self
                .py_host
                .call_method1(py, "get_active_keyset_ids", (mint, unit_str))
            {
                Ok(result) => {
                    if let Ok(list) = result.extract::<Vec<String>>(py) {
                        list.into_iter()
                            .filter_map(|s| Id::from_str(&s).ok())
                            .collect()
                    } else {
                        Vec::new()
                    }
                }
                Err(e) => {
                    eprintln!("[PySpilmanHost] get_active_keyset_ids call error: {}", e);
                    Vec::new()
                }
            }
        })
    }

    fn get_keyset_info(&self, mint: &str, keyset_id: &Id) -> Option<String> {
        Python::with_gil(|py| {
            match self
                .py_host
                .call_method1(py, "get_keyset_info", (mint, keyset_id.to_string()))
            {
                Ok(result) => {
                    if result.is_none(py) {
                        None
                    } else {
                        result.extract::<String>(py).ok()
                    }
                }
                Err(e) => {
                    eprintln!("[PySpilmanHost] get_keyset_info call error: {}", e);
                    None
                }
            }
        })
    }

    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool {
        Python::with_gil(|py| {
            match self.py_host.call_method1(
                py,
                "receiver_key_is_acceptable",
                (receiver_pubkey.to_hex(),),
            ) {
                Ok(result) => match result.extract::<bool>(py) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!(
                            "[PySpilmanHost] receiver_key_is_acceptable extract error: {}",
                            e
                        );
                        false
                    }
                },
                Err(e) => {
                    eprintln!(
                        "[PySpilmanHost] receiver_key_is_acceptable call error: {}",
                        e
                    );
                    false
                }
            }
        })
    }

    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &Id) -> bool {
        Python::with_gil(|py| {
            match self.py_host.call_method1(
                py,
                "mint_and_keyset_is_acceptable",
                (mint, keyset_id.to_string()),
            ) {
                Ok(result) => match result.extract::<bool>(py) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!(
                            "[PySpilmanHost] mint_and_keyset_is_acceptable extract error: {}",
                            e
                        );
                        false
                    }
                },
                Err(e) => {
                    eprintln!(
                        "[PySpilmanHost] mint_and_keyset_is_acceptable call error: {}",
                        e
                    );
                    false
                }
            }
        })
    }

    fn get_funding(&self, channel_id: &str) -> Option<spilman_core::ChannelFunding> {
        Python::with_gil(|py| {
            let result = self
                .py_host
                .call_method1(py, "get_funding_and_params", (channel_id,))
                .ok()?;

            if result.is_none(py) {
                return None;
            }

            let tuple = result.downcast_bound::<PyTuple>(py).ok()?;
            if tuple.len() != 4 {
                return None;
            }

            Some(spilman_core::ChannelFunding {
                params_json: tuple.get_item(0).ok()?.extract::<String>().ok()?,
                funding_proofs_json: tuple.get_item(1).ok()?.extract::<String>().ok()?,
                channel_secret_hex: tuple.get_item(2).ok()?.extract::<String>().ok()?,
                keyset_info_json: tuple.get_item(3).ok()?.extract::<String>().ok()?,
            })
        })
    }

    fn save_funding(
        &self,
        channel_id: &str,
        funding: spilman_core::ChannelFunding,
        initial_payment: spilman_core::PaymentProof,
    ) {
        Python::with_gil(|py| {
            let _ = self.py_host.call_method1(
                py,
                "save_funding",
                (
                    channel_id,
                    funding.params_json,
                    funding.funding_proofs_json,
                    funding.channel_secret_hex,
                    funding.keyset_info_json,
                    initial_payment.balance,
                    initial_payment.signature,
                ),
            );
        });
    }

    fn get_amount_due(&self, channel_id: &str, context_json: Option<&String>) -> u64 {
        Python::with_gil(|py| {
            let ctx = match context_json {
                Some(s) => s.as_str().into_py(py),
                None => py.None(),
            };
            self.py_host
                .call_method1(py, "get_amount_due", (channel_id, ctx))
                .and_then(|r| r.extract::<u64>(py))
                .unwrap_or(0)
        })
    }

    fn record_payment(
        &self,
        channel_id: &str,
        payment: spilman_core::PaymentProof,
        context_json: &String,
    ) {
        Python::with_gil(|py| {
            let _ = self.py_host.call_method1(
                py,
                "record_payment",
                (
                    channel_id,
                    payment.balance,
                    payment.signature,
                    context_json.as_str(),
                ),
            );
        });
    }

    fn get_channel_state(&self, channel_id: &str) -> ChannelState {
        Python::with_gil(|py| {
            match self
                .py_host
                .call_method1(py, "get_channel_state", (channel_id,))
            {
                Ok(result) => match result.extract::<String>(py) {
                    Ok(state_str) => match state_str.as_str() {
                        "closed" => ChannelState::Closed,
                        "closing" => ChannelState::Closing,
                        _ => ChannelState::Open,
                    },
                    Err(_) => ChannelState::Open,
                },
                Err(_) => ChannelState::Open,
            }
        })
    }

    fn mark_channel_closing(
        &self,
        channel_id: &str,
        expiry_timestamp: u64,
        payment: spilman_core::PaymentProof,
    ) -> Result<(), String> {
        Python::with_gil(|py| {
            match self.py_host.call_method1(
                py,
                "mark_channel_closing",
                (
                    channel_id,
                    expiry_timestamp,
                    payment.balance,
                    payment.signature,
                ),
            ) {
                Ok(_) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        })
    }

    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData> {
        Python::with_gil(|py| {
            let result = self
                .py_host
                .call_method1(py, "get_closing_data", (channel_id,))
                .ok()?;

            if result.is_none(py) {
                return None;
            }

            // Expecting a dict with expiry_timestamp, balance, signature
            let expiry_timestamp = result
                .getattr(py, "expiry_timestamp")
                .or_else(|_| result.call_method1(py, "__getitem__", ("expiry_timestamp",)))
                .ok()?
                .extract::<u64>(py)
                .ok()?;

            let balance = result
                .getattr(py, "balance")
                .or_else(|_| result.call_method1(py, "__getitem__", ("balance",)))
                .ok()?
                .extract::<u64>(py)
                .ok()?;

            let signature = result
                .getattr(py, "signature")
                .or_else(|_| result.call_method1(py, "__getitem__", ("signature",)))
                .ok()?
                .extract::<String>(py)
                .ok()?;

            Some(ClosingData {
                expiry_timestamp,
                balance,
                signature,
            })
        })
    }

    fn get_channel_policy(&self, unit: &str) -> Option<ChannelPolicy> {
        Python::with_gil(|py| {
            let result = self
                .py_host
                .call_method1(py, "get_channel_policy", (unit,))
                .ok()?;
            if result.is_none(py) {
                return None;
            }
            let tuple = result.extract::<(u64, u64, Option<u64>)>(py).ok()?;
            Some(ChannelPolicy {
                min_expiry_in_seconds: tuple.0,
                min_capacity: tuple.1,
                max_amount_per_output: tuple.2,
            })
        })
    }

    fn now_seconds(&self) -> u64 {
        Python::with_gil(|py| {
            self.py_host
                .call_method0(py, "now_seconds")
                .and_then(|r| r.extract::<u64>(py))
                .unwrap_or(0)
        })
    }

    fn get_balance_and_signature_for_unilateral_exit(
        &self,
        channel_id: &str,
    ) -> Option<spilman_core::PaymentProof> {
        Python::with_gil(|py| {
            let result = self
                .py_host
                .call_method1(
                    py,
                    "get_balance_and_signature_for_unilateral_exit",
                    (channel_id,),
                )
                .ok()?;

            if result.is_none(py) {
                return None;
            }

            let tuple = result.downcast_bound::<PyTuple>(py).ok()?;
            if tuple.len() != 2 {
                return None;
            }

            Some(spilman_core::PaymentProof {
                balance: tuple.get_item(0).ok()?.extract::<u64>().ok()?,
                signature: tuple.get_item(1).ok()?.extract::<String>().ok()?,
            })
        })
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
        Python::with_gil(|py| {
            match self.py_host.call_method1(
                py,
                "mark_channel_closed",
                (
                    channel_id,
                    expiry_timestamp,
                    balance,
                    receiver_proofs_json,
                    sender_proofs_json,
                    receiver_sum,
                    sender_sum,
                ),
            ) {
                Ok(_) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        })
    }

    fn compute_channel_secret(
        &self,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
    ) -> Result<String, String> {
        Python::with_gil(|py| {
            match self.py_host.call_method1(
                py,
                "compute_channel_secret",
                (receiver_pubkey_hex, sender_pubkey_hex),
            ) {
                Ok(result) => result.extract::<String>(py).map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            }
        })
    }

    fn sign_with_tweaked_key(
        &self,
        signer_pubkey_hex: &str,
        message_hex: &str,
        tweak_scalar_hex: &str,
    ) -> Result<String, String> {
        Python::with_gil(|py| {
            match self.py_host.call_method1(
                py,
                "sign_with_tweaked_key",
                (signer_pubkey_hex, message_hex, tweak_scalar_hex),
            ) {
                Ok(result) => result.extract::<String>(py).map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            }
        })
    }
}

impl spilman_core::SpilmanNetworking for PySpilmanHost {
    fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String> {
        Python::with_gil(|py| {
            match self
                .py_host
                .call_method1(py, "call_mint_swap", (mint_url, swap_request_json))
            {
                Ok(result) => result.extract::<String>(py).map_err(|e| e.to_string()),
                Err(e) => Err(python_error_message(py, e)),
            }
        })
    }

    fn refresh_all_keysets(&self, mint: &str) -> Result<(), String> {
        Python::with_gil(|py| {
            // Check if the method exists on the Python host
            if self.py_host.getattr(py, "refresh_all_keysets").is_err() {
                // Method not implemented, use default behavior
                return Err("refresh_all_keysets not implemented".to_string());
            }

            match self
                .py_host
                .call_method1(py, "refresh_all_keysets", (mint,))
            {
                Ok(_) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        })
    }
}

/// Spilman payment channel bridge for servers (receivers).
///
/// This validates incoming payments and manages channel state through
/// the provided host object which implements storage and pricing logic.
#[pyclass]
struct SpilmanBridge {
    inner: RustSpilmanBridge<PySpilmanHost>,
}

#[pymethods]
impl SpilmanBridge {
    /// Create a new SpilmanBridge.
    ///
    /// The bridge itself is keyless — all secret key operations are delegated
    /// to the host via `compute_channel_secret()` and `sign_with_tweaked_key()`.
    ///
    /// Args:
    ///     host: Python object implementing SpilmanHost methods
    #[new]
    fn new(host: PyObject) -> Self {
        let py_host = PySpilmanHost { py_host: host };
        let inner = RustSpilmanBridge::new(py_host);

        SpilmanBridge { inner }
    }

    /// Process an incoming payment request.
    ///
    /// Validates the payment and records usage if valid.
    ///
    /// Args:
    ///     payment_json: JSON string with channel_id, balance, signature, and optionally params/funding_proofs
    ///     context_json: JSON string with request context (for pricing)
    ///
    /// Returns:
    ///     PaymentSuccess object with channel_id, balance, amount_due, capacity
    ///
    /// Raises:
    ///     RuntimeError: If validation fails
    #[pyo3(signature = (payment_json, context_json))]
    fn process_payment(&self, payment_json: &str, context_json: &str) -> PyResult<PaymentSuccess> {
        let context_json = context_json.to_string();
        self.inner
            .process_payment_via_json(payment_json, &context_json)
            .map(PaymentSuccess::from)
            .map_err(|e| PyRuntimeError::new_err(bridge_error_response_json(&e)))
    }

    /// Validate a payment without recording it.
    ///
    /// Performs all validation (parsing, channel verification, balance checks,
    /// signature verification) but does NOT call record_payment.
    ///
    /// For new channels, funding data IS saved (idempotent).
    ///
    /// Args:
    ///     payment_json: Payment request JSON with channel_id, balance, signature,
    ///                   and optionally params + funding_proofs for unknown channels
    ///     context_json: Context JSON describing the request (e.g., {"type": "ascii", "chars": 5})
    ///
    /// Returns:
    ///     PaymentValidationResult object
    ///
    /// Raises:
    ///     RuntimeError: If validation fails
    #[pyo3(signature = (payment_json, context_json))]
    fn validate_payment(
        &self,
        payment_json: &str,
        context_json: &str,
    ) -> PyResult<PaymentValidationResult> {
        let context_json = context_json.to_string();
        self.inner
            .validate_payment_via_json(payment_json, &context_json)
            .map(PaymentValidationResult::from)
            .map_err(|e| PyRuntimeError::new_err(bridge_error_response_json(&e)))
    }

    /// Verify that a payment covers the current amount due.
    ///
    /// Performs full validation (including signature checks) but does NOT record usage.
    /// Returns the computed amount_due on success.
    ///
    /// Raises:
    ///     RuntimeError: If validation fails or balance is insufficient
    #[pyo3(signature = (payment_json, context_json))]
    fn verify_payment_covers_amount_due(
        &self,
        payment_json: &str,
        context_json: &str,
    ) -> PyResult<u64> {
        let context_json = context_json.to_string();
        self.inner
            .verify_payment_covers_amount_due_via_json(payment_json, &context_json)
            .map_err(|e| PyRuntimeError::new_err(bridge_error_response_json(&e)))
    }

    /// Return true if the payment covers the amount due.
    ///
    /// Returns false only for insufficient balance. Other validation errors are raised.
    #[pyo3(signature = (payment_json, context_json))]
    fn payment_covers_amount_due(&self, payment_json: &str, context_json: &str) -> PyResult<bool> {
        let context_json = context_json.to_string();
        self.inner
            .payment_covers_amount_due_via_json(payment_json, &context_json)
            .map_err(|e| PyRuntimeError::new_err(bridge_error_response_json(&e)))
    }

    /// Register/fund a channel without recording any usage.
    ///
    /// Validates the channel (params, funding proofs, signature for balance=0)
    /// and saves it to the funding store, but does NOT record any payment/usage.
    ///
    /// Args:
    ///     payment_json: Payment request JSON with channel_id, balance=0, signature,
    ///                   params, and funding_proofs
    ///
    /// Returns:
    ///     FundChannelResult object with channel_id, capacity, already_known
    ///
    /// Raises:
    ///     RuntimeError: If validation fails
    #[pyo3(signature = (payment_json))]
    fn fund_channel(&self, payment_json: &str) -> PyResult<FundChannelResult> {
        self.inner
            .fund_channel_via_json(payment_json)
            .map(FundChannelResult::from)
            .map_err(|e| PyRuntimeError::new_err(bridge_error_response_json(&e)))
    }

    #[pyo3(signature = (payment_json))]
    fn validate_and_prepare_cooperative_close(&self, payment_json: &str) -> PyResult<String> {
        match self
            .inner
            .validate_and_prepare_cooperative_close(payment_json)
        {
            Ok(close_data) => Ok(close_data.to_json_value().to_string()),
            Err(e) => {
                let result = serde_json::json!({
                    "success": false,
                    "error": e.to_string()
                });
                Ok(result.to_string())
            }
        }
    }

    /// Create data for a unilateral (server-initiated) channel close.
    ///
    /// This retrieves the largest balance and signature from the host
    /// and constructs a fully-signed swap request ready for the mint.
    ///
    /// Args:
    ///     channel_id: The channel ID to close
    ///
    /// Returns:
    ///     JSON string with swap_request, expected_total, and secrets_with_blinding
    fn create_unilateral_close_data(&self, channel_id: &str) -> PyResult<String> {
        match self.inner.create_unilateral_close_data(channel_id) {
            Ok(close_data) => Ok(close_data.to_json_value().to_string()),
            Err(e) => {
                let result = serde_json::json!({
                    "success": false,
                    "error": e.to_string()
                });
                Ok(result.to_string())
            }
        }
    }

    /// Execute a cooperative close: validate, submit swap, unblind, and mark closed.
    ///
    /// This method orchestrates the full cooperative close flow:
    /// 1. Validates the payment signature and checks balance == amount_due
    /// 2. Creates the fully-signed swap request
    /// 3. Submits the swap to the mint via host.call_mint_swap()
    /// 4. If swap fails, calls host.refresh_all_keysets() and retries once
    /// 5. Unblinds signatures and verifies DLEQ proofs
    /// 6. Marks the channel as closed via host.mark_channel_closed()
    ///
    /// Args:
    ///     payment_json: Payment request JSON with channel_id, balance, signature,
    ///                   and optionally params + funding_proofs for unknown channels
    ///
    /// Returns:
    ///     CloseSuccess object on success
    ///
    /// Raises:
    ///     RuntimeError: With JSON-encoded CloseError on failure
    fn execute_cooperative_close(&self, payment_json: &str) -> PyResult<CloseSuccess> {
        self.inner
            .execute_cooperative_close(payment_json, self.inner.host())
            .map(CloseSuccess::from)
            .map_err(|e| {
                let error_json = serde_json::to_string(&e).unwrap_or_else(|_| e.to_string());
                PyRuntimeError::new_err(error_json)
            })
    }

    /// Execute a unilateral close: retrieve stored payment, submit swap, unblind, and mark closed.
    ///
    /// This method orchestrates the full unilateral (server-initiated) close flow:
    /// 1. Retrieves the stored balance and signature from the host
    /// 2. Creates the fully-signed swap request
    /// 3. Submits the swap to the mint via host.call_mint_swap()
    /// 4. If swap fails, calls host.refresh_all_keysets() and retries once
    /// 5. Unblinds signatures and verifies DLEQ proofs
    /// 6. Marks the channel as closed via host.mark_channel_closed()
    ///
    /// Args:
    ///     channel_id: The channel ID to close
    ///
    /// Returns:
    ///     CloseSuccess object on success
    ///
    /// Raises:
    ///     RuntimeError: With JSON-encoded CloseError on failure
    fn execute_unilateral_close(&self, channel_id: &str) -> PyResult<CloseSuccess> {
        self.inner
            .execute_unilateral_close(channel_id, self.inner.host())
            .map(CloseSuccess::from)
            .map_err(|e| {
                let error_json = serde_json::to_string(&e).unwrap_or_else(|_| e.to_string());
                PyRuntimeError::new_err(error_json)
            })
    }
}

// ============================================================================
// Client-side: Standalone functions for Alice (sender)
// ============================================================================

/// Generate a new keypair for use as Alice (sender).
///
/// Returns:
///     Tuple of (secret_key_hex, pubkey_hex)
#[pyfunction]
fn generate_keypair() -> PyResult<(String, String)> {
    let secret = SecretKey::generate();
    let pubkey = secret.public_key();
    Ok((secret.to_secret_hex(), pubkey.to_hex()))
}

/// Derive public key from a secret key.
///
/// Args:
///     secret_hex: Secret key as hex string (64 chars)
///
/// Returns:
///     Public key as hex string (66 chars, compressed)
#[pyfunction]
fn secret_key_to_pubkey(secret_hex: &str) -> PyResult<String> {
    let secret =
        SecretKey::from_hex(secret_hex).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(secret.public_key().to_hex())
}

/// Compute ECDH shared secret between two parties.
///
/// Args:
///     my_secret_hex: Your secret key (hex)
///     their_pubkey_hex: Counterparty's public key (hex)
///
/// Returns:
///     Shared secret as hex string (64 chars)
#[pyfunction]
fn compute_channel_secret(my_secret_hex: &str, their_pubkey_hex: &str) -> PyResult<String> {
    spilman_core::compute_channel_secret_from_hex(my_secret_hex, their_pubkey_hex)
        .map_err(PyValueError::new_err)
}

/// Compute the minimum funding_token_amount needed for a given capacity.
///
/// Uses the double-inverse computation to determine the minimum funding token
/// nominal value that will yield at least `capacity` after both fee stages.
///
/// Args:
///     capacity: Desired channel capacity
///     keyset_info_json: Keyset info JSON
///     maximum_amount: Maximum amount per output (0 = no limit)
///
/// Returns:
///     The minimum funding_token_amount as an integer
#[pyfunction]
fn compute_funding_token_amount(
    capacity: u64,
    keyset_info_json: &str,
    maximum_amount: u64,
) -> PyResult<u64> {
    spilman_core::compute_funding_token_amount(capacity, keyset_info_json, maximum_amount)
        .map_err(PyValueError::new_err)
}

/// Get channel ID from parameters.
///
/// Args:
///     params_json: Channel parameters JSON
///     channel_secret_hex: Pre-computed shared secret (hex)
///     keyset_info_json: Keyset info JSON
///
/// Returns:
///     Channel ID as hex string
#[pyfunction]
fn channel_parameters_get_channel_id(
    params_json: &str,
    channel_secret_hex: &str,
    keyset_info_json: &str,
) -> PyResult<String> {
    spilman_core::channel_parameters_get_channel_id(
        params_json,
        channel_secret_hex,
        keyset_info_json,
    )
    .map_err(PyValueError::new_err)
}

/// Create funding outputs (blinded messages) for minting.
///
/// Args:
///     params_json: Channel parameters JSON
///     my_secret_hex: Alice's secret key (hex)
///     keyset_info_json: Keyset info JSON
///
/// Returns:
///     JSON with funding_token_nominal, blinded_messages, and secrets_with_blinding
#[pyfunction]
fn create_funding_outputs(
    params_json: &str,
    my_secret_hex: &str,
    keyset_info_json: &str,
) -> PyResult<String> {
    spilman_core::create_funding_outputs(params_json, my_secret_hex, keyset_info_json)
        .map_err(PyValueError::new_err)
}

/// Construct proofs from blind signatures.
///
/// Args:
///     signatures_json: JSON array of blind signatures from mint
///     secrets_with_blinding_json: JSON array from create_funding_outputs
///     keyset_info_json: Keyset info JSON
///
/// Returns:
///     JSON array of proofs
#[pyfunction]
fn construct_proofs(
    signatures_json: &str,
    secrets_with_blinding_json: &str,
    keyset_info_json: &str,
) -> PyResult<String> {
    spilman_core::construct_proofs(
        signatures_json,
        secrets_with_blinding_json,
        keyset_info_json,
    )
    .map_err(PyValueError::new_err)
}

/// Create a signed balance update for a payment.
///
/// Args:
///     params_json: Channel parameters JSON
///     keyset_info_json: Keyset info JSON
///     secret_hex: Alice's secret key (hex)
///     proofs_json: Funding proofs JSON array
///     balance: New balance (Charlie's amount)
///
/// Returns:
///     JSON with channel_id, amount, and signature
#[pyfunction]
fn create_signed_balance_update(
    params_json: &str,
    keyset_info_json: &str,
    secret_hex: &str,
    proofs_json: &str,
    balance: u64,
) -> PyResult<String> {
    spilman_core::create_signed_balance_update(
        params_json,
        keyset_info_json,
        secret_hex,
        proofs_json,
        balance,
    )
    .map_err(PyValueError::new_err)
}

/// Create plain (non-P2PK) blinded messages for minting.
///
/// This creates blinded messages suitable for the mint's /v1/mint/bolt11 endpoint.
/// The resulting proofs can be wrapped in a cashuA token and passed to
/// ClientBridge.open_channel_from_token() for channel funding.
///
/// Args:
///     amount_sat: Amount in satoshis to create blinded messages for
///     keyset_info_json: Keyset info JSON (from mint's /v1/keys/{id})
///
/// Returns:
///     JSON with blinded_messages and secrets_with_blinding arrays
#[pyfunction]
fn create_plain_blinded_messages(amount_sat: u64, keyset_info_json: &str) -> PyResult<String> {
    spilman_core::create_plain_blinded_messages(amount_sat, keyset_info_json)
        .map_err(PyValueError::new_err)
}

/// Build a cashuA token string from proofs JSON and a mint URL.
///
/// Args:
///     mint_url: The mint URL to embed in the token
///     proofs_json: JSON array of proofs (from construct_proofs or mint response)
///
/// Returns:
///     A cashuA token string (e.g. "cashuAeyJ0b2...")
#[pyfunction]
fn build_cashu_a_token(mint_url: &str, proofs_json: &str) -> PyResult<String> {
    spilman_core::build_cashu_a_token(mint_url, proofs_json).map_err(PyValueError::new_err)
}

/// Build a cashuB format token from proofs.
///
/// Args:
///     mint_url: The mint URL to embed in the token
///     unit: The currency unit (e.g. "sat")
///     proofs_json: JSON array of proofs (from construct_proofs or mint response)
///
/// Returns:
///     A cashuB token string (e.g. "cashuBeyJ0b2...")
#[pyfunction]
fn build_cashu_b_token(mint_url: &str, unit: &str, proofs_json: &str) -> PyResult<String> {
    spilman_core::build_cashu_b_token(mint_url, unit, proofs_json).map_err(PyValueError::new_err)
}

/// Mint plain proofs from a Cashu mint via HTTP.
///
/// Performs the full minting flow: create blinded messages, request a mint
/// quote, poll until paid, mint tokens, and construct proofs.
///
/// Args:
///     mint_url: The mint URL (e.g. "http://localhost:3338")
///     amount_sat: Amount to mint in satoshis
///     keyset_info_json: Keyset info JSON (from fetch_active_keyset)
///     call_http: Python callable (method: str, url: str, body: str) -> str
///
/// Returns:
///     JSON array of proofs ready for use
#[pyfunction]
fn mint_proofs_from_mint(
    py: Python<'_>,
    mint_url: &str,
    amount_sat: u64,
    keyset_info_json: &str,
    call_http: PyObject,
) -> PyResult<String> {
    let http_fn = |method: &str, url: &str, body: &str| -> Result<String, String> {
        Python::with_gil(|py| {
            let result = call_http
                .call1(py, (method, url, body))
                .map_err(|e| format!("HTTP callback failed: {}", e))?;
            result
                .extract::<String>(py)
                .map_err(|e| format!("HTTP callback returned non-string: {}", e))
        })
    };

    // Release the GIL during the Rust execution (which includes sleeping for poll)
    py.allow_threads(|| {
        spilman_core::mint_proofs_from_mint(mint_url, amount_sat, keyset_info_json, &http_fn)
            .map_err(PyValueError::new_err)
    })
}

/// Utility function for signing with a tweaked key (BIP-340 Schnorr).
///
/// Handles BIP-340 parity: if the public key has odd Y, negates the secret
/// before adding the tweak. Then produces a BIP-340 Schnorr signature.
///
/// This is a convenience function for SpilmanClientHost implementations
/// that hold raw secret keys.
///
/// Args:
///     secret_key_hex: The signer's secret key (32 bytes, hex)
///     message_hex: SHA-256 hash of the message (32 bytes, hex)
///     tweak_scalar_hex: P2BK blinding scalar to add (32 bytes, hex)
///
/// Returns:
///     BIP-340 Schnorr signature (64 bytes, hex)
#[pyfunction]
fn sign_with_tweaked_key_util(
    secret_key_hex: &str,
    message_hex: &str,
    tweak_scalar_hex: &str,
) -> PyResult<String> {
    spilman_core::sign_with_tweaked_key_util(secret_key_hex, message_hex, tweak_scalar_hex)
        .map_err(PyValueError::new_err)
}

// ============================================================================
// Client-side: SpilmanClientBridge with Python host callbacks
// ============================================================================

/// Result of opening a new channel via ClientBridge.
#[pyclass(get_all)]
#[derive(Clone)]
pub struct ClientOpenChannelResult {
    pub channel_id: String,
    pub capacity: u64,
    pub funding_token_amount: u64,
    pub mint_url: String,
    pub sender_pubkey_hex: String,
}

/// Information about a stored channel.
#[pyclass(get_all)]
#[derive(Clone)]
pub struct ClientChannelInfo {
    pub channel_id: String,
    pub capacity: u64,
    pub funding_token_amount: u64,
    pub mint_url: String,
    pub current_balance: u64,
    pub payment_count: u64,
    pub state: String,
}

/// Wrapper that delegates SpilmanClientHost trait calls to a Python object.
///
/// The Python object must implement these methods:
///
/// Storage (immutable funding data):
/// - save_channel_funding(channel_id: str, funding_json: str)
/// - get_channel_funding(channel_id: str) -> Optional[str]  # Returns funding JSON or None
///
/// Storage (mutable payment state):
/// - get_payment_state(channel_id: str) -> Optional[str]  # Returns payment state JSON or None
/// - record_payment(channel_id: str, state_json: str)
///
/// Lifecycle:
/// - get_channel_state(channel_id: str) -> str  # Returns "open" or "closed"
/// - mark_channel_closed(channel_id: str)
/// - list_channel_ids() -> List[str]
/// - delete_channel(channel_id: str)
///
/// Time:
/// - now_seconds() -> int
///
/// Crypto:
/// - sign_with_tweaked_key(signer_pubkey_hex: str, message_hex: str, tweak_scalar_hex: str) -> str
/// - compute_channel_secret(sender_pubkey_hex: str, receiver_pubkey_hex: str) -> str
struct PySpilmanClientHost {
    py_host: PyObject,
}

/// Wrapper that delegates SpilmanClientNetworking trait calls to a Python object.
///
/// The Python object must implement:
/// - call_mint_swap(mint_url: str, swap_request_json: str) -> str  # Raises on error
struct PySpilmanClientNetworking {
    py_host: PyObject,
}

fn python_error_message(py: Python<'_>, err: PyErr) -> String {
    err.value_bound(py)
        .str()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|_| err.to_string())
}

impl SpilmanClientHost for PySpilmanClientHost {
    // ========================================================================
    // Funding Data (immutable after creation)
    // ========================================================================

    fn save_channel_funding(&self, channel_id: &str, funding: ClientChannelFunding) {
        Python::with_gil(|py| {
            let funding_json =
                serde_json::to_string(&funding).expect("ClientChannelFunding serialization failed");
            let _ =
                self.py_host
                    .call_method1(py, "save_channel_funding", (channel_id, funding_json));
        });
    }

    fn get_channel_funding(&self, channel_id: &str) -> Option<ClientChannelFunding> {
        Python::with_gil(|py| {
            let result = self
                .py_host
                .call_method1(py, "get_channel_funding", (channel_id,))
                .ok()?;

            if result.is_none(py) {
                return None;
            }

            let json_str = result.extract::<String>(py).ok()?;
            serde_json::from_str(&json_str).ok()
        })
    }

    // ========================================================================
    // Payment State (mutable)
    // ========================================================================

    fn get_payment_state(&self, channel_id: &str) -> Option<ClientPaymentState> {
        Python::with_gil(|py| {
            let result = self
                .py_host
                .call_method1(py, "get_payment_state", (channel_id,))
                .ok()?;

            if result.is_none(py) {
                return None;
            }

            let json_str = result.extract::<String>(py).ok()?;
            serde_json::from_str(&json_str).ok()
        })
    }

    fn record_payment(&self, channel_id: &str, state: ClientPaymentState) {
        Python::with_gil(|py| {
            let state_json =
                serde_json::to_string(&state).expect("ClientPaymentState serialization failed");
            let _ = self
                .py_host
                .call_method1(py, "record_payment", (channel_id, state_json));
        });
    }

    // ========================================================================
    // Channel Lifecycle
    // ========================================================================

    fn get_channel_state(&self, channel_id: &str) -> ClientChannelState {
        Python::with_gil(|py| {
            match self
                .py_host
                .call_method1(py, "get_channel_state", (channel_id,))
            {
                Ok(result) => match result.extract::<String>(py) {
                    Ok(state_str) => match state_str.as_str() {
                        "closed" | "Closed" => ClientChannelState::Closed,
                        _ => ClientChannelState::Open,
                    },
                    Err(_) => ClientChannelState::Open,
                },
                Err(_) => ClientChannelState::Open,
            }
        })
    }

    fn mark_channel_closed(&self, channel_id: &str) {
        Python::with_gil(|py| {
            let _ = self
                .py_host
                .call_method1(py, "mark_channel_closed", (channel_id,));
        });
    }

    fn list_channel_ids(&self) -> Vec<String> {
        Python::with_gil(|py| {
            self.py_host
                .call_method0(py, "list_channel_ids")
                .and_then(|r| r.extract::<Vec<String>>(py))
                .unwrap_or_default()
        })
    }

    fn delete_channel(&self, channel_id: &str) {
        Python::with_gil(|py| {
            let _ = self
                .py_host
                .call_method1(py, "delete_channel", (channel_id,));
        });
    }

    // ========================================================================
    // Time
    // ========================================================================

    fn now_seconds(&self) -> u64 {
        Python::with_gil(|py| {
            self.py_host
                .call_method0(py, "now_seconds")
                .and_then(|r| r.extract::<u64>(py))
                .unwrap_or(0)
        })
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
        Python::with_gil(|py| {
            match self.py_host.call_method1(
                py,
                "sign_with_tweaked_key",
                (signer_pubkey_hex, message_hex, tweak_scalar_hex),
            ) {
                Ok(result) => result.extract::<String>(py).map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            }
        })
    }

    fn compute_channel_secret(
        &self,
        sender_pubkey_hex: &str,
        receiver_pubkey_hex: &str,
    ) -> Result<String, String> {
        Python::with_gil(|py| {
            match self.py_host.call_method1(
                py,
                "compute_channel_secret",
                (sender_pubkey_hex, receiver_pubkey_hex),
            ) {
                Ok(result) => result.extract::<String>(py).map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            }
        })
    }
}

impl SpilmanClientNetworking for PySpilmanClientNetworking {
    fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String> {
        Python::with_gil(|py| {
            match self
                .py_host
                .call_method1(py, "call_mint_swap", (mint_url, swap_request_json))
            {
                Ok(result) => result.extract::<String>(py).map_err(|e| e.to_string()),
                Err(e) => Err(python_error_message(py, e)),
            }
        })
    }
}

/// Client-side Spilman channel bridge.
///
/// This is the client-side counterpart of SpilmanBridge. It orchestrates
/// channel creation from tokens, payment signing, and HTTP header construction.
///
/// The bridge is stateless and keyless — all channel state is stored via the
/// host callbacks. The bridge never holds or sees Alice's secret key; all
/// operations requiring the key are delegated to the host.
#[pyclass]
struct ClientBridge {
    inner: RustSpilmanClientBridge<PySpilmanClientHost, PySpilmanClientNetworking>,
}

#[pymethods]
impl ClientBridge {
    /// Create a new ClientBridge.
    ///
    /// The bridge is stateless and keyless — it delegates all key operations
    /// to the host. The caller passes sender_pubkey_hex per channel when
    /// opening channels.
    ///
    /// Args:
    ///     host: Python object implementing SpilmanClientHost methods
    ///           (also must implement call_mint_swap for networking)
    #[new]
    #[pyo3(signature = (host))]
    fn new(host: PyObject) -> Self {
        Python::with_gil(|py| {
            let py_host = PySpilmanClientHost {
                py_host: host.clone_ref(py),
            };
            let py_networking = PySpilmanClientNetworking { py_host: host };
            let inner = RustSpilmanClientBridge::new(py_host, py_networking);

            ClientBridge { inner }
        })
    }

    /// Open a new channel from a Cashu token.
    ///
    /// Performs the full funding flow:
    /// 1. Compute ECDH channel secret via host.compute_channel_secret()
    /// 2. Parse the token and compute channel parameters
    /// 3. Create a funding swap request (deterministic 2-of-2 locked outputs)
    /// 4. Submit the swap to the mint via host.call_mint_swap()
    /// 5. Unblind signatures and verify DLEQ proofs
    /// 6. Save the channel via host.save_channel_funding()
    ///
    /// Args:
    ///     token_string: Cashu token (cashuA... or cashuB...)
    ///     receiver_pubkey_hex: Receiver's public key (from server's /channel/params)
    ///     sender_pubkey_hex: Sender's public key (caller chooses which key for this channel)
    ///     expiry_timestamp: Unix timestamp for channel expiry
    ///     keyset_info_json: Keyset info JSON (from mint's /v1/keys/{id})
    ///     max_amount: Maximum amount per output (from server policy, 0 = no limit)
    ///
    /// Returns:
    ///     ClientOpenChannelResult with channel_id, capacity, funding_token_amount, mint_url, sender_pubkey_hex
    #[pyo3(signature = (token_string, receiver_pubkey_hex, sender_pubkey_hex, expiry_timestamp, keyset_info_json, max_amount))]
    fn open_channel_from_token(
        &self,
        token_string: &str,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
        expiry_timestamp: u64,
        keyset_info_json: &str,
        max_amount: u64,
    ) -> PyResult<ClientOpenChannelResult> {
        let result = self
            .inner
            .open_channel_from_token(
                token_string,
                receiver_pubkey_hex,
                sender_pubkey_hex,
                expiry_timestamp,
                keyset_info_json,
                max_amount,
            )
            .map_err(PyRuntimeError::new_err)?;

        Ok(ClientOpenChannelResult {
            channel_id: result.channel_id,
            capacity: result.capacity,
            funding_token_amount: result.funding_token_amount,
            mint_url: result.mint_url,
            sender_pubkey_hex: result.sender_pubkey_hex,
        })
    }

    /// Create a payment for a channel (without funding data).
    ///
    /// Returns a JSON string with channel_id, balance, signature.
    /// Use this for subsequent payments after the channel is registered.
    ///
    /// Args:
    ///     channel_id: The channel ID
    ///     balance: New cumulative balance (must increase monotonically)
    ///
    /// Returns:
    ///     JSON string with the Payment struct
    #[pyo3(signature = (channel_id, balance))]
    fn create_payment(&self, channel_id: &str, balance: u64) -> PyResult<String> {
        self.inner
            .create_payment(channel_id, balance)
            .map(|p| serde_json::to_string(&p).expect("Payment serialization failed"))
            .map_err(PyRuntimeError::new_err)
    }

    /// Create a payment with funding data (for first payment).
    ///
    /// Returns a JSON string with channel_id, balance, signature, params, and funding_proofs.
    /// Use this for the first payment when registering a channel with the server.
    ///
    /// Args:
    ///     channel_id: The channel ID
    ///     balance: New cumulative balance
    ///
    /// Returns:
    ///     JSON string with the Payment struct including funding data
    #[pyo3(signature = (channel_id, balance))]
    fn create_payment_with_funding(&self, channel_id: &str, balance: u64) -> PyResult<String> {
        self.inner
            .create_payment_with_funding(channel_id, balance)
            .map(|p| serde_json::to_string(&p).expect("Payment serialization failed"))
            .map_err(PyRuntimeError::new_err)
    }

    /// Build a complete X-Cashu-Channel payment header value.
    ///
    /// Returns a base64-encoded JSON string ready to use as the header value.
    ///
    /// Args:
    ///     channel_id: The channel ID
    ///     balance: New cumulative balance
    ///     include_funding: If True, include params and funding_proofs (first request)
    ///
    /// Returns:
    ///     Base64-encoded payment header string
    #[pyo3(signature = (channel_id, balance, include_funding))]
    fn build_payment_header(
        &self,
        channel_id: &str,
        balance: u64,
        include_funding: bool,
    ) -> PyResult<String> {
        self.inner
            .build_payment_header(channel_id, balance, include_funding)
            .map_err(PyRuntimeError::new_err)
    }

    /// Create a cooperative close request for a channel.
    ///
    /// Args:
    ///     channel_id: The channel ID
    ///     final_balance: Final cumulative balance
    ///
    /// Returns:
    ///     JSON string with balance and signature (Payment struct)
    #[pyo3(signature = (channel_id, final_balance))]
    fn create_cooperative_close_request(
        &self,
        channel_id: &str,
        final_balance: u64,
    ) -> PyResult<String> {
        self.inner
            .create_cooperative_close_request(channel_id, final_balance)
            .map(|p| serde_json::to_string(&p).expect("Payment serialization failed"))
            .map_err(PyRuntimeError::new_err)
    }

    /// Process a cooperative close response from the server.
    ///
    /// Args:
    ///     response_json: The server's close response JSON
    #[pyo3(signature = (response_json))]
    fn process_cooperative_close_response(&self, response_json: &str) -> PyResult<()> {
        self.inner
            .process_cooperative_close_response(response_json)
            .map_err(PyRuntimeError::new_err)
    }

    /// Close a channel locally.
    ///
    /// Marks the channel as closed so no more payments can be made.
    /// Does not communicate with the server.
    ///
    /// Args:
    ///     channel_id: The channel ID
    #[pyo3(signature = (channel_id))]
    fn close_channel(&self, channel_id: &str) {
        self.inner.close_channel(channel_id);
    }

    /// Get information about a stored channel.
    ///
    /// Args:
    ///     channel_id: The channel ID
    ///
    /// Returns:
    ///     ClientChannelInfo or None if not found
    #[pyo3(signature = (channel_id))]
    fn get_channel_info(&self, channel_id: &str) -> Option<ClientChannelInfo> {
        self.inner.get_channel_info(channel_id).map(|info| {
            let state_str = match info.state {
                ClientChannelState::Open => "open",
                ClientChannelState::Closed => "closed",
            };
            ClientChannelInfo {
                channel_id: info.channel_id,
                capacity: info.capacity,
                funding_token_amount: info.funding_token_amount,
                mint_url: info.mint_url,
                current_balance: info.current_balance,
                payment_count: info.payment_count,
                state: state_str.to_string(),
            }
        })
    }

    /// List all stored channel IDs.
    fn list_channels(&self) -> Vec<String> {
        self.inner.list_channels()
    }

    /// Delete a channel from storage.
    ///
    /// Removes all data associated with the channel.
    #[pyo3(signature = (channel_id))]
    fn delete_channel(&self, channel_id: &str) {
        self.inner.delete_channel(channel_id);
    }
}

// ============================================================================
// Module registration
// ============================================================================

/// Python module for CDK Spilman payment channels.
#[pymodule]
fn cdk_spilman(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Server-side
    m.add_class::<SpilmanBridge>()?;

    // Result types
    m.add_class::<PaymentSuccess>()?;
    m.add_class::<PaymentValidationResult>()?;
    m.add_class::<FundChannelResult>()?;

    // Client-side: ClientBridge
    m.add_class::<ClientBridge>()?;
    m.add_class::<ClientOpenChannelResult>()?;
    m.add_class::<ClientChannelInfo>()?;

    // Client-side functions
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(secret_key_to_pubkey, m)?)?;
    m.add_function(wrap_pyfunction!(compute_channel_secret, m)?)?;
    m.add_function(wrap_pyfunction!(compute_funding_token_amount, m)?)?;
    m.add_function(wrap_pyfunction!(channel_parameters_get_channel_id, m)?)?;
    m.add_function(wrap_pyfunction!(create_funding_outputs, m)?)?;
    m.add_function(wrap_pyfunction!(construct_proofs, m)?)?;
    m.add_function(wrap_pyfunction!(create_signed_balance_update, m)?)?;
    m.add_function(wrap_pyfunction!(create_plain_blinded_messages, m)?)?;
    m.add_function(wrap_pyfunction!(build_cashu_a_token, m)?)?;
    m.add_function(wrap_pyfunction!(build_cashu_b_token, m)?)?;
    m.add_function(wrap_pyfunction!(mint_proofs_from_mint, m)?)?;
    m.add_function(wrap_pyfunction!(sign_with_tweaked_key_util, m)?)?;

    Ok(())
}
