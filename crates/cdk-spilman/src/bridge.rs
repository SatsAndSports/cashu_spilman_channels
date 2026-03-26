#![allow(missing_docs)]
//! Spilman Protocol Bridge
//!
//! This module provides a high-level bridge for implementing Spilman payment channels
//! in any service provider. It handles the core protocol logic, validation, and
//! signature verification, while delegating storage and pricing to a host hook.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};

use super::params::Stage2Role;
use super::{
    verify_valid_channel, BalanceUpdateMessage, ChannelParameters, CommitmentOutputs,
    DeterministicSecretWithBlinding, EstablishedChannel, KeysetInfo,
};
use async_trait::async_trait;
use cashu::nuts::{BlindSignature, CurrencyUnit, Id, Proof, PublicKey, SwapRequest};
use cashu::util::hex;
use std::str::FromStr;

/// Funding data for a channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelFunding {
    /// Serialized channel parameters
    pub params_json: String,
    /// Serialized funding proofs
    pub funding_proofs_json: String,
    /// Hex-encoded channel secret
    pub channel_secret_hex: String,
    /// Serialized keyset info
    pub keyset_info_json: String,
}

/// Payment proof for a channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentProof {
    /// Current balance
    pub balance: u64,
    /// Alice's signature over the balance
    pub signature: String,
}

/// Channel lifecycle states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelState {
    /// Channel is open and accepting payments
    Open,
    /// Channel is closing (swap pending, no more payments accepted)
    Closing,
    /// Channel is closed (swap completed, proofs stored)
    Closed,
}

/// Data stored when a channel enters CLOSING state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosingData {
    /// The channel's expiry timestamp
    pub expiry_timestamp: u64,
    /// The balance at close
    pub balance: u64,
    /// The client's Schnorr signature authorizing this balance
    pub signature: String,
}

/// Host hooks for the Spilman bridge
///
/// Implement this trait to provide storage and pricing logic for your service.
/// The generic type `C` allows for a custom request context used in pricing.
pub trait SpilmanHost<C = String> {
    /// Check if the receiver pubkey in the channel params is acceptable
    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool;

    /// Check if the mint and keyset are acceptable
    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &cashu::nuts::Id) -> bool;

    /// Get cached funding data for a channel
    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding>;

    /// Save funding data for a channel, including the initial payment proof
    fn save_funding(
        &self,
        channel_id: &str,
        funding: ChannelFunding,
        initial_payment: PaymentProof,
    );

    /// Get the current amount due for a channel
    fn get_amount_due(&self, channel_id: &str, context: Option<&C>) -> u64;

    /// Record a successful payment and update usage
    fn record_payment(&self, channel_id: &str, payment: PaymentProof, context: &C);

    /// Get the current state of a channel.
    fn get_channel_state(&self, channel_id: &str) -> ChannelState;

    /// Mark a channel as closing (pre-swap state).
    fn mark_channel_closing(
        &self,
        channel_id: &str,
        expiry_timestamp: u64,
        payment: PaymentProof,
    ) -> Result<(), String>;

    /// Get the stored closing data for a channel in CLOSING state.
    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData>;

    /// Get channel policy for a given unit: funding-time validation thresholds.
    /// Returns `None` if the unit is not supported.
    fn get_channel_policy(&self, unit: &str) -> Option<ChannelPolicy>;

    /// Get the current time in seconds
    fn now_seconds(&self) -> u64;

    /// Get the balance and signature for a unilateral exit
    fn get_balance_and_signature_for_unilateral_exit(
        &self,
        channel_id: &str,
    ) -> Option<PaymentProof>;

    /// Get active keyset IDs for a mint and unit
    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id>;

    /// Get full KeysetInfo JSON for a specific keyset
    fn get_keyset_info(&self, mint: &str, keyset_id: &Id) -> Option<String>;

    /// Mark a channel as closed and persist the final state
    #[allow(clippy::too_many_arguments)]
    fn mark_channel_closed(
        &self,
        channel_id: &str,
        expiry_timestamp: u64,
        balance: u64,
        receiver_proofs_json: &str,
        sender_proofs_json: &str,
        receiver_sum: u64,
        sender_sum: u64,
    ) -> Result<(), String>;

    /// Compute the ECDH-derived channel secret.
    fn compute_channel_secret(
        &self,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
    ) -> Result<String, String>;

    /// Sign a message with the tweaked (P2BK-blinded) server key.
    fn sign_with_tweaked_key(
        &self,
        signer_pubkey_hex: &str,
        message_hex: &str,
        tweak_scalar_hex: &str,
    ) -> Result<String, String>;
}

/// Sync networking hooks for the Spilman bridge
pub trait SpilmanNetworking {
    /// Call the mint's /v1/swap endpoint
    fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String>;

    /// Refresh the keyset cache for a mint
    fn refresh_all_keysets(&self, mint: &str) -> Result<(), String>;
}

/// Async networking hooks for the Spilman bridge
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait SpilmanAsyncNetworking {
    /// Call the mint's /v1/swap endpoint
    async fn call_mint_swap(
        &self,
        mint_url: &str,
        swap_request_json: &str,
    ) -> Result<String, String>;

    /// Refresh the keyset cache for a mint
    async fn refresh_all_keysets(&self, mint: &str) -> Result<(), String>;
}

/// Bridge for processing Spilman payments
#[derive(Debug)]
pub struct SpilmanBridge<H: SpilmanHost<C>, C = String> {
    host: H,
    _phantom: std::marker::PhantomData<C>,
}

#[derive(Debug, Deserialize)]
pub struct PaymentRequest {
    pub channel_id: String,
    pub balance: u64,
    pub signature: String,
    pub params: Option<serde_json::Value>,
    pub funding_proofs: Option<Vec<Proof>>,
}

/// Result of a successful payment
#[derive(Debug, Clone, Serialize)]
pub struct PaymentSuccess {
    pub channel_id: String,
    pub balance: u64,
    pub amount_due: u64,
    pub capacity: u64,
}

/// Data needed to close a channel
#[derive(Debug)]
pub struct CloseData {
    pub swap_request: SwapRequest,
    pub expected_total: u64,
    pub secrets_with_blinding: Vec<(DeterministicSecretWithBlinding, bool)>,
    pub output_keyset_info: KeysetInfo,
}

impl CloseData {
    pub fn to_json_value(self) -> serde_json::Value {
        let swap_request_json =
            serde_json::to_value(&self.swap_request).unwrap_or(serde_json::Value::Null);

        let secrets_with_blinding: Vec<serde_json::Value> = self
            .secrets_with_blinding
            .into_iter()
            .map(|(s, is_receiver)| {
                serde_json::json!({
                    "secret": s.secret.to_string(),
                    "blinding_factor": hex::encode(s.blinding_factor.secret_bytes()),
                    "amount": s.amount,
                    "index": s.index,
                    "is_receiver": is_receiver
                })
            })
            .collect();

        serde_json::json!({
            "success": true,
            "swap_request": swap_request_json,
            "expected_total": self.expected_total,
            "secrets_with_blinding": secrets_with_blinding,
            "output_keyset_info": serde_json::to_value(&self.output_keyset_info).unwrap_or(serde_json::Value::Null)
        })
    }
}

/// A proof with its (amount, index) metadata from the commitment outputs
#[derive(Debug)]
pub struct ProofWithMeta {
    pub proof: Proof,
    pub amount: u64,
    pub index: usize,
    pub is_receiver: bool,
}

/// Result of unblinding and verifying stage 1 swap response
#[derive(Debug)]
pub struct UnblindResult {
    pub receiver_proofs: Vec<ProofWithMeta>,
    pub sender_proofs: Vec<ProofWithMeta>,
    pub receiver_sum: u64,
    pub sender_sum: u64,
}

/// Everything needed to execute a close operation after sync validation.
#[derive(Debug)]
pub struct PreparedClose {
    pub channel_id: String,
    pub balance: u64,
    pub mint_url: String,
    pub swap_request: serde_json::Value,
    pub secrets_with_blinding: serde_json::Value,
    pub output_keyset_info: serde_json::Value,
    pub params_json: String,
    pub keyset_info_json: String,
    pub channel_secret: String,
}

/// HTTP-friendly error for close preparation.
#[derive(Debug, Clone, Serialize)]
pub struct ClosePreparationError {
    pub error: String,
    pub reason: String,
    pub status: u16,
    #[serde(flatten)]
    pub extra: Option<serde_json::Map<String, serde_json::Value>>,
}

impl ClosePreparationError {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn bad_request(reason: impl Into<String>) -> Self {
        Self {
            error: "Bad request".into(),
            reason: reason.into(),
            status: 400,
            extra: None,
        }
    }

    pub fn payment_required(reason: impl Into<String>) -> Self {
        Self {
            error: "Payment required".into(),
            reason: reason.into(),
            status: 402,
            extra: None,
        }
    }

    pub fn not_found(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            error: reason.clone(),
            reason,
            status: 404,
            extra: None,
        }
    }

    pub fn internal(reason: impl Into<String>) -> Self {
        Self {
            error: "Internal error".into(),
            reason: reason.into(),
            status: 500,
            extra: None,
        }
    }

    pub fn conflict(reason: impl Into<String>) -> Self {
        Self {
            error: "Channel closing".into(),
            reason: reason.into(),
            status: 409,
            extra: None,
        }
    }

    pub fn gone(reason: impl Into<String>) -> Self {
        Self {
            error: "Channel closed".into(),
            reason: reason.into(),
            status: 410,
            extra: None,
        }
    }

    pub fn with_extra(mut self, extra: serde_json::Map<String, serde_json::Value>) -> Self {
        self.extra = Some(extra);
        self
    }

    pub fn from_bridge_error(err: BridgeError) -> Self {
        let reason = err.to_string();
        match &err {
            BridgeError::ChannelClosed => Self::gone(reason),
            BridgeError::ChannelClosing => Self::conflict(reason),
            BridgeError::UnknownChannel => Self::not_found(reason),
            BridgeError::InvalidRequest(msg) if msg.contains("no payment proof") => {
                Self::bad_request(reason)
            }
            BridgeError::Internal(_) | BridgeError::ServerMisconfigured(_) => {
                Self::internal(reason)
            }
            BridgeError::BalanceMismatch { expected, actual } => {
                let mut extra = serde_json::Map::new();
                extra.insert("expected".into(), serde_json::json!(expected));
                extra.insert("actual".into(), serde_json::json!(actual));
                Self::payment_required(reason).with_extra(extra)
            }
            _ => Self::payment_required(reason),
        }
    }
}

/// HTTP-friendly error for payment/validation failures.
#[derive(Debug, Clone, Serialize)]
pub struct BridgeErrorResponse {
    pub error: String,
    pub reason: String,
    pub status: u16,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Map<String, serde_json::Value>>,
}

impl BridgeErrorResponse {
    pub fn from_bridge_error(err: &BridgeError) -> Self {
        let reason = err.to_string();
        let mut extra: Option<serde_json::Map<String, serde_json::Value>> = None;

        let (status, error, code) = match err {
            BridgeError::InvalidRequest(_) => (400, "Bad request", "invalid_request"),
            BridgeError::UnknownChannel => (404, "Not found", "unknown_channel"),
            BridgeError::ChannelClosing => (409, "Channel closing", "channel_closing"),
            BridgeError::ChannelClosed => (410, "Channel closed", "channel_closed"),
            BridgeError::ServerMisconfigured(_) => (500, "Internal error", "server_misconfigured"),
            BridgeError::Internal(_) => (500, "Internal error", "internal"),
            BridgeError::BalanceMismatch { expected, actual } => {
                let mut map = serde_json::Map::new();
                map.insert("expected".into(), serde_json::json!(expected));
                map.insert("actual".into(), serde_json::json!(actual));
                extra = Some(map);
                (402, "Payment required", "balance_mismatch")
            }
            BridgeError::BalanceExceedsCapacity { balance, capacity } => {
                let mut map = serde_json::Map::new();
                map.insert("balance".into(), serde_json::json!(balance));
                map.insert("capacity".into(), serde_json::json!(capacity));
                extra = Some(map);
                (402, "Payment required", "balance_exceeds_capacity")
            }
            BridgeError::InsufficientBalance {
                balance,
                amount_due,
            } => {
                let mut map = serde_json::Map::new();
                map.insert("balance".into(), serde_json::json!(balance));
                map.insert("amount_due".into(), serde_json::json!(amount_due));
                extra = Some(map);
                (402, "Payment required", "insufficient_balance")
            }
            BridgeError::CapacityTooSmall {
                capacity,
                min_capacity,
            } => {
                let mut map = serde_json::Map::new();
                map.insert("capacity".into(), serde_json::json!(capacity));
                map.insert("min_capacity".into(), serde_json::json!(min_capacity));
                extra = Some(map);
                (402, "Payment required", "capacity_too_small")
            }
            BridgeError::ExpiryTooSoon {
                expiry_timestamp,
                min_expiry,
                now,
            } => {
                let mut map = serde_json::Map::new();
                map.insert(
                    "expiry_timestamp".into(),
                    serde_json::json!(expiry_timestamp),
                );
                map.insert("min_expiry".into(), serde_json::json!(min_expiry));
                map.insert("now".into(), serde_json::json!(now));
                extra = Some(map);
                (402, "Payment required", "expiry_too_soon")
            }
            BridgeError::MaxAmountExceeded {
                amount,
                max_allowed,
            } => {
                let mut map = serde_json::Map::new();
                map.insert("amount".into(), serde_json::json!(amount));
                map.insert("max_allowed".into(), serde_json::json!(max_allowed));
                extra = Some(map);
                (402, "Payment required", "max_amount_exceeded")
            }
            BridgeError::UnsupportedUnit(_) => (402, "Payment required", "unsupported_unit"),
            BridgeError::ChannelIdMismatch => (402, "Payment required", "channel_id_mismatch"),
            BridgeError::ValidationFailed(_) => (402, "Payment required", "validation_failed"),
            BridgeError::InvalidSignature(_) => (402, "Payment required", "invalid_signature"),
            BridgeError::ReceiverKeyNotAcceptable => {
                (402, "Payment required", "receiver_key_not_acceptable")
            }
            BridgeError::MintOrKeysetNotAcceptable => {
                (402, "Payment required", "mint_or_keyset_not_acceptable")
            }
        };

        Self {
            error: error.to_string(),
            reason,
            status,
            code: code.to_string(),
            extra,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            "{\"error\":\"Internal error\",\"reason\":\"failed to serialize bridge error\",\"status\":500,\"code\":\"internal\"}"
                .to_string()
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PaymentValidationResult {
    pub channel_id: String,
    pub balance: u64,
    pub amount_due: u64,
    pub capacity: u64,
    pub sender_signature: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FundChannelResult {
    pub channel_id: String,
    pub capacity: u64,
    pub already_known: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CloseSuccess {
    pub channel_id: String,
    pub total_value: u64,
    pub receiver_sum: u64,
    pub sender_sum: u64,
    pub sender_proofs: String,
    pub already_closed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum CloseError {
    #[serde(rename = "validation_failed")]
    ValidationFailed {
        reason: String,
        status: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        expected_balance: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        actual_balance: Option<u64>,
    },
    #[serde(rename = "unknown_channel")]
    UnknownChannel { status: u16 },
    #[serde(rename = "already_closed")]
    AlreadyClosed {
        closed_balance: u64,
        requested_balance: u64,
        status: u16,
    },
    #[serde(rename = "mint_rejected")]
    MintRejected {
        mint_error: serde_json::Value,
        status: u16,
    },
    #[serde(rename = "mint_rejected_after_retry")]
    MintRejectedAfterRetry {
        original_error: serde_json::Value,
        retry_error: serde_json::Value,
        status: u16,
    },
    #[serde(rename = "unblind_failed")]
    UnblindFailed { reason: String, status: u16 },
    #[serde(rename = "storage_failed")]
    StorageFailed { reason: String, status: u16 },
}

impl CloseError {
    pub fn status_code(&self) -> u16 {
        match self {
            Self::ValidationFailed { status, .. }
            | Self::UnknownChannel { status }
            | Self::AlreadyClosed { status, .. }
            | Self::MintRejected { status, .. }
            | Self::MintRejectedAfterRetry { status, .. }
            | Self::UnblindFailed { status, .. }
            | Self::StorageFailed { status, .. } => *status,
        }
    }

    pub fn from_preparation_error(err: ClosePreparationError) -> Self {
        let (expected_balance, actual_balance) = if let Some(extra) = &err.extra {
            (
                extra.get("expected").and_then(|v| v.as_u64()),
                extra.get("actual").and_then(|v| v.as_u64()),
            )
        } else {
            (None, None)
        };
        Self::ValidationFailed {
            reason: err.reason,
            status: err.status,
            expected_balance,
            actual_balance,
        }
    }

    pub fn unknown_channel() -> Self {
        Self::UnknownChannel { status: 404 }
    }
    pub fn mint_rejected(mint_error: serde_json::Value) -> Self {
        Self::MintRejected {
            mint_error,
            status: 502,
        }
    }
    pub fn mint_rejected_after_retry(
        original_error: serde_json::Value,
        retry_error: serde_json::Value,
    ) -> Self {
        Self::MintRejectedAfterRetry {
            original_error,
            retry_error,
            status: 502,
        }
    }
    pub fn unblind_failed(reason: impl Into<String>) -> Self {
        Self::UnblindFailed {
            reason: reason.into(),
            status: 500,
        }
    }
    pub fn storage_failed(reason: impl Into<String>) -> Self {
        Self::StorageFailed {
            reason: reason.into(),
            status: 500,
        }
    }
}

fn parse_mint_error_value(raw: &str) -> serde_json::Value {
    serde_json::from_str(raw).unwrap_or_else(|_| serde_json::Value::String(raw.to_string()))
}

/// Extract the NUT-00 error code from a raw error string.
/// Returns None if the string is not valid JSON or lacks a "code" field.
fn extract_nut00_error_code(raw: &str) -> Option<u16> {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| v.get("code")?.as_u64())
        .map(|c| c as u16)
}

/// Returns true if the error code is in the keyset error range (12xxx).
/// These errors may be recoverable by refreshing keysets and retrying.
fn is_keyset_error_code(code: u16) -> bool {
    (12000..13000).contains(&code)
}

/// Determine if a swap error should trigger a retry (refresh keysets + re-attempt).
/// Only keyset errors (12xxx) are retryable. All other errors fail immediately.
/// If the error can't be parsed, fail immediately (strict mode).
fn should_retry_swap_error(raw: &str) -> bool {
    match extract_nut00_error_code(raw) {
        Some(code) => {
            let retryable = is_keyset_error_code(code);
            if retryable {
                tracing::debug!(code, "Keyset error detected, will retry after refreshing keysets");
            } else {
                tracing::debug!(code, "Non-retryable NUT-00 error code, failing immediately");
            }
            retryable
        }
        None => {
            tracing::debug!(error = %raw, "Could not parse NUT-00 error code, failing immediately");
            false
        }
    }
}

impl std::fmt::Display for CloseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ValidationFailed { reason, .. } => write!(f, "validation failed: {}", reason),
            Self::UnknownChannel { .. } => write!(f, "unknown channel"),
            Self::AlreadyClosed {
                closed_balance,
                requested_balance,
                ..
            } => write!(
                f,
                "channel already closed with balance {} (requested {})",
                closed_balance, requested_balance
            ),
            Self::MintRejected { mint_error, .. } => {
                write!(f, "mint rejected swap: {}", mint_error)
            }
            Self::MintRejectedAfterRetry {
                original_error,
                retry_error,
                ..
            } => write!(
                f,
                "mint rejected swap after retry: original={}, retry={}",
                original_error, retry_error
            ),
            Self::UnblindFailed { reason, .. } => write!(f, "unblind failed: {}", reason),
            Self::StorageFailed { reason, .. } => write!(f, "storage failed: {}", reason),
        }
    }
}

impl std::error::Error for CloseError {}

/// Funding-time validation thresholds for a given unit, returned by
/// [`SpilmanHost::get_channel_policy`].
#[derive(Debug, Clone)]
pub struct ChannelPolicy {
    /// Minimum seconds between now and the channel expiry timestamp.
    pub min_expiry_in_seconds: u64,
    /// Minimum channel capacity (in the unit's base denomination).
    pub min_capacity: u64,
    /// Optional cap on the largest single proof denomination.
    pub max_amount_per_output: Option<u64>,
}

#[derive(Debug)]
pub enum BridgeError {
    InvalidRequest(String),
    ChannelClosed,
    ChannelClosing,
    ServerMisconfigured(String),
    CapacityTooSmall {
        capacity: u64,
        min_capacity: u64,
    },
    ExpiryTooSoon {
        expiry_timestamp: u64,
        min_expiry: u64,
        now: u64,
    },
    MaxAmountExceeded {
        amount: u64,
        max_allowed: u64,
    },
    BalanceExceedsCapacity {
        balance: u64,
        capacity: u64,
    },
    UnsupportedUnit(String),
    ChannelIdMismatch,
    ValidationFailed(String),
    UnknownChannel,
    InvalidSignature(String),
    InsufficientBalance {
        balance: u64,
        amount_due: u64,
    },
    BalanceMismatch {
        expected: u64,
        actual: u64,
    },
    Internal(String),
    ReceiverKeyNotAcceptable,
    MintOrKeysetNotAcceptable,
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(s) => write!(f, "{}", s),
            Self::ChannelClosed => write!(f, "channel closed"),
            Self::ChannelClosing => write!(f, "channel closing, swap pending"),
            Self::ServerMisconfigured(s) => write!(f, "server misconfigured: {}", s),
            Self::CapacityTooSmall {
                capacity,
                min_capacity,
            } => write!(f, "capacity too small: {} < {}", capacity, min_capacity),
            Self::ExpiryTooSoon {
                expiry_timestamp,
                min_expiry,
                now,
            } => write!(
                f,
                "expiry too soon: {} < {} ({}s remaining)",
                expiry_timestamp,
                min_expiry,
                expiry_timestamp.saturating_sub(*now)
            ),
            Self::MaxAmountExceeded {
                amount,
                max_allowed,
            } => write!(
                f,
                "max_amount_per_output exceeded: {} > {}",
                amount, max_allowed
            ),
            Self::BalanceExceedsCapacity { balance, capacity } => {
                write!(f, "balance exceeds capacity: {} > {}", balance, capacity)
            }
            Self::UnsupportedUnit(u) => write!(f, "unsupported unit: {}", u),
            Self::ChannelIdMismatch => write!(f, "channel_id mismatch"),
            Self::ValidationFailed(s) => write!(f, "channel validation failed: {}", s),
            Self::UnknownChannel => write!(f, "unknown channel"),
            Self::InvalidSignature(s) => write!(f, "invalid signature: {}", s),
            Self::InsufficientBalance {
                balance,
                amount_due,
            } => write!(f, "insufficient balance: {} < {}", balance, amount_due),
            Self::BalanceMismatch { expected, actual } => {
                write!(f, "balance mismatch: expected {}, got {}", expected, actual)
            }
            Self::Internal(s) => write!(f, "internal error: {}", s),
            Self::ReceiverKeyNotAcceptable => write!(f, "receiver key not acceptable"),
            Self::MintOrKeysetNotAcceptable => write!(f, "mint or keyset not acceptable"),
        }
    }
}

impl BridgeError {
    pub fn to_response(&self) -> BridgeErrorResponse {
        BridgeErrorResponse::from_bridge_error(self)
    }

    pub fn to_response_json(&self) -> String {
        self.to_response().to_json()
    }
}

pub fn unblind_and_verify_stage1_response(
    blind_signatures: Vec<BlindSignature>,
    secrets_with_blinding: Vec<(DeterministicSecretWithBlinding, bool)>,
    params: &ChannelParameters,
    output_keyset_info: &KeysetInfo,
    balance: u64,
) -> Result<UnblindResult, BridgeError> {
    if blind_signatures.len() != secrets_with_blinding.len() {
        return Err(BridgeError::Internal(
            "Length mismatch between signatures and secrets".into(),
        ));
    }
    let mut secrets = Vec::with_capacity(secrets_with_blinding.len());
    let mut blinding_factors = Vec::with_capacity(secrets_with_blinding.len());
    let mut is_receiver_flags = Vec::with_capacity(secrets_with_blinding.len());
    let mut amount_index_pairs = Vec::with_capacity(secrets_with_blinding.len());

    for (swb, is_receiver) in secrets_with_blinding {
        secrets.push(swb.secret);
        blinding_factors.push(swb.blinding_factor);
        is_receiver_flags.push(is_receiver);
        amount_index_pairs.push((swb.amount, swb.index));
    }

    let proofs = cashu::dhke::construct_proofs(
        blind_signatures,
        blinding_factors,
        secrets,
        &output_keyset_info.active_keys,
    )
    .map_err(|e| BridgeError::Internal(format!("Failed to construct proofs: {}", e)))?;

    for (i, proof) in proofs.iter().enumerate() {
        let mint_pubkey = output_keyset_info
            .active_keys
            .amount_key(proof.amount)
            .ok_or_else(|| BridgeError::Internal("Missing mint key".into()))?;
        proof.verify_dleq(mint_pubkey).map_err(|e| {
            BridgeError::ValidationFailed(format!("DLEQ failed for proof {}: {}", i, e))
        })?;
    }

    let mut receiver_proofs = Vec::new();
    let mut sender_proofs = Vec::new();
    let mut receiver_sum = 0;
    let mut sender_sum = 0;

    for ((mut proof, is_receiver), (amount, index)) in proofs
        .into_iter()
        .zip(is_receiver_flags)
        .zip(amount_index_pairs)
    {
        let role = if is_receiver {
            Stage2Role::Receiver
        } else {
            Stage2Role::Sender
        };
        params
            .attach_stage2_p2pk_e(&mut proof, role, amount, index)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        if is_receiver {
            let expected_pubkey = params
                .get_receiver_blinded_pubkey_for_stage2_output(amount, index)
                .map_err(|e| BridgeError::Internal(e.to_string()))?;
            let secret_json: serde_json::Value = serde_json::from_str(&proof.secret.to_string())
                .map_err(|e| BridgeError::Internal(e.to_string()))?;
            if secret_json.get(0).and_then(|v| v.as_str()) != Some("P2PK")
                || secret_json
                    .get(1)
                    .and_then(|v| v.get("data"))
                    .and_then(|v| v.as_str())
                    != Some(&expected_pubkey.to_hex())
            {
                return Err(BridgeError::ValidationFailed(
                    "Receiver proof locked to wrong pubkey".into(),
                ));
            }
            receiver_sum += u64::from(proof.amount);
            receiver_proofs.push(ProofWithMeta {
                proof,
                amount,
                index,
                is_receiver: true,
            });
        } else {
            sender_sum += u64::from(proof.amount);
            sender_proofs.push(ProofWithMeta {
                proof,
                amount,
                index,
                is_receiver: false,
            });
        }
    }

    let expected_nominal = output_keyset_info
        .inverse_deterministic_value_after_fees(balance, params.maximum_amount_for_one_output)
        .map_err(|e| BridgeError::Internal(e.to_string()))?
        .nominal_value;
    if receiver_sum != expected_nominal {
        return Err(BridgeError::ValidationFailed(format!(
            "Receiver nominal mismatch: expected {}, got {}",
            expected_nominal, receiver_sum
        )));
    }

    Ok(UnblindResult {
        receiver_proofs,
        sender_proofs,
        receiver_sum,
        sender_sum,
    })
}

impl<H: SpilmanHost<C>, C> SpilmanBridge<H, C> {
    pub fn new(host: H) -> Self {
        Self {
            host,
            _phantom: std::marker::PhantomData,
        }
    }
    pub fn host(&self) -> &H {
        &self.host
    }

    fn decode_payment_header(base64_header: &str) -> Result<PaymentRequest, BridgeError> {
        let decoded = BASE64
            .decode(base64_header)
            .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        let json =
            String::from_utf8(decoded).map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        serde_json::from_str(&json).map_err(|e| BridgeError::InvalidRequest(e.to_string()))
    }

    pub fn process_payment(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
        params: Option<&serde_json::Value>,
        funding_proofs: Option<&[Proof]>,
        context: &C,
    ) -> Result<PaymentSuccess, BridgeError> {
        let val = self.validate_payment(
            channel_id,
            balance,
            signature,
            params,
            funding_proofs,
            context,
        )?;
        self.host.record_payment(
            &val.channel_id,
            PaymentProof {
                balance: val.balance,
                signature: val.sender_signature.clone(),
            },
            context,
        );
        Ok(PaymentSuccess {
            channel_id: val.channel_id,
            balance: val.balance,
            amount_due: val.amount_due,
            capacity: val.capacity,
        })
    }

    pub fn process_payment_via_json(
        &self,
        payment_json: &str,
        context: &C,
    ) -> Result<PaymentSuccess, BridgeError> {
        let p: PaymentRequest = serde_json::from_str(payment_json)
            .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        self.process_payment(
            &p.channel_id,
            p.balance,
            &p.signature,
            p.params.as_ref(),
            p.funding_proofs.as_deref(),
            context,
        )
    }

    pub fn process_payment_via_base64_header(
        &self,
        base64_header: &str,
        context: &C,
    ) -> Result<PaymentSuccess, BridgeError> {
        let p = Self::decode_payment_header(base64_header)?;
        self.process_payment(
            &p.channel_id,
            p.balance,
            &p.signature,
            p.params.as_ref(),
            p.funding_proofs.as_deref(),
            context,
        )
    }

    pub fn validate_payment(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
        params: Option<&serde_json::Value>,
        funding_proofs: Option<&[Proof]>,
        context: &C,
    ) -> Result<PaymentValidationResult, BridgeError> {
        if channel_id.is_empty() {
            return Err(BridgeError::InvalidRequest("missing channel_id".into()));
        }
        if signature.is_empty() {
            return Err(BridgeError::InvalidRequest("missing signature".into()));
        }
        match self.host.get_channel_state(channel_id) {
            ChannelState::Closed => return Err(BridgeError::ChannelClosed),
            ChannelState::Closing => return Err(BridgeError::ChannelClosing),
            ChannelState::Open => {}
        }
        let (funding, is_new) = match self.host.get_funding(channel_id) {
            Some(f) => (f, false),
            None => (
                self.validate_and_save_new_channel(
                    channel_id,
                    params.ok_or(BridgeError::UnknownChannel)?,
                    funding_proofs.ok_or(BridgeError::UnknownChannel)?,
                    balance,
                    signature,
                )?,
                true,
            ),
        };
        let params_val: serde_json::Value = serde_json::from_str(&funding.params_json)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;
        let capacity = params_val["capacity"].as_u64().unwrap_or(0);
        if !is_new {
            if balance > capacity {
                return Err(BridgeError::BalanceExceedsCapacity { balance, capacity });
            }
            self.verify_signature(
                &funding.params_json,
                &funding.funding_proofs_json,
                &funding.channel_secret_hex,
                &funding.keyset_info_json,
                channel_id,
                balance,
                signature,
            )
            .map_err(BridgeError::InvalidSignature)?;
        }
        let amount_due = self.host.get_amount_due(channel_id, Some(context));
        if balance < amount_due {
            return Err(BridgeError::InsufficientBalance {
                balance,
                amount_due,
            });
        }
        Ok(PaymentValidationResult {
            channel_id: channel_id.to_string(),
            balance,
            amount_due,
            capacity,
            sender_signature: signature.to_string(),
        })
    }

    pub fn validate_payment_via_json(
        &self,
        payment_json: &str,
        context: &C,
    ) -> Result<PaymentValidationResult, BridgeError> {
        let p: PaymentRequest = serde_json::from_str(payment_json)
            .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        self.validate_payment(
            &p.channel_id,
            p.balance,
            &p.signature,
            p.params.as_ref(),
            p.funding_proofs.as_deref(),
            context,
        )
    }

    pub fn validate_payment_via_base64_header(
        &self,
        base64_header: &str,
        context: &C,
    ) -> Result<PaymentValidationResult, BridgeError> {
        let p = Self::decode_payment_header(base64_header)?;
        self.validate_payment(
            &p.channel_id,
            p.balance,
            &p.signature,
            p.params.as_ref(),
            p.funding_proofs.as_deref(),
            context,
        )
    }

    /// Verify that a payment covers the current amount due.
    ///
    /// This performs full validation (including signature checks) and returns the
    /// computed amount_due on success. It does NOT record usage, but may save
    /// funding data for new channels (same behavior as validate_payment).
    pub fn verify_payment_covers_amount_due(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
        params: Option<&serde_json::Value>,
        funding_proofs: Option<&[Proof]>,
        context: &C,
    ) -> Result<u64, BridgeError> {
        let val = self.validate_payment(
            channel_id,
            balance,
            signature,
            params,
            funding_proofs,
            context,
        )?;
        Ok(val.amount_due)
    }

    pub fn verify_payment_covers_amount_due_via_json(
        &self,
        payment_json: &str,
        context: &C,
    ) -> Result<u64, BridgeError> {
        let p: PaymentRequest = serde_json::from_str(payment_json)
            .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        self.verify_payment_covers_amount_due(
            &p.channel_id,
            p.balance,
            &p.signature,
            p.params.as_ref(),
            p.funding_proofs.as_deref(),
            context,
        )
    }

    pub fn verify_payment_covers_amount_due_via_base64_header(
        &self,
        base64_header: &str,
        context: &C,
    ) -> Result<u64, BridgeError> {
        let p = Self::decode_payment_header(base64_header)?;
        self.verify_payment_covers_amount_due(
            &p.channel_id,
            p.balance,
            &p.signature,
            p.params.as_ref(),
            p.funding_proofs.as_deref(),
            context,
        )
    }

    /// Return true if the payment covers the amount due.
    ///
    /// Returns Ok(false) only for insufficient balance. Other validation errors
    /// are returned as Err.
    pub fn payment_covers_amount_due(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
        params: Option<&serde_json::Value>,
        funding_proofs: Option<&[Proof]>,
        context: &C,
    ) -> Result<bool, BridgeError> {
        match self.verify_payment_covers_amount_due(
            channel_id,
            balance,
            signature,
            params,
            funding_proofs,
            context,
        ) {
            Ok(_) => Ok(true),
            Err(BridgeError::InsufficientBalance { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub fn payment_covers_amount_due_via_json(
        &self,
        payment_json: &str,
        context: &C,
    ) -> Result<bool, BridgeError> {
        let p: PaymentRequest = serde_json::from_str(payment_json)
            .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        self.payment_covers_amount_due(
            &p.channel_id,
            p.balance,
            &p.signature,
            p.params.as_ref(),
            p.funding_proofs.as_deref(),
            context,
        )
    }

    pub fn payment_covers_amount_due_via_base64_header(
        &self,
        base64_header: &str,
        context: &C,
    ) -> Result<bool, BridgeError> {
        let p = Self::decode_payment_header(base64_header)?;
        self.payment_covers_amount_due(
            &p.channel_id,
            p.balance,
            &p.signature,
            p.params.as_ref(),
            p.funding_proofs.as_deref(),
            context,
        )
    }

    pub fn fund_channel(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
        params: Option<&serde_json::Value>,
        funding_proofs: Option<&[Proof]>,
    ) -> Result<FundChannelResult, BridgeError> {
        if channel_id.is_empty() {
            return Err(BridgeError::InvalidRequest("missing channel_id".into()));
        }
        if signature.is_empty() {
            return Err(BridgeError::InvalidRequest("missing signature".into()));
        }
        match self.host.get_channel_state(channel_id) {
            ChannelState::Closed => return Err(BridgeError::ChannelClosed),
            ChannelState::Closing => return Err(BridgeError::ChannelClosing),
            ChannelState::Open => {}
        }
        let (funding, already_known) = match self.host.get_funding(channel_id) {
            Some(f) => (f, true),
            None => (
                self.validate_and_save_new_channel(
                    channel_id,
                    params.ok_or(BridgeError::InvalidRequest("Missing params".into()))?,
                    funding_proofs.ok_or(BridgeError::InvalidRequest("Missing proofs".into()))?,
                    balance,
                    signature,
                )?,
                false,
            ),
        };
        let params_val: serde_json::Value = serde_json::from_str(&funding.params_json)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;
        let capacity = params_val["capacity"].as_u64().unwrap_or(0);
        if already_known {
            self.verify_signature(
                &funding.params_json,
                &funding.funding_proofs_json,
                &funding.channel_secret_hex,
                &funding.keyset_info_json,
                channel_id,
                balance,
                signature,
            )
            .map_err(BridgeError::InvalidSignature)?;
        }
        Ok(FundChannelResult {
            channel_id: channel_id.to_string(),
            capacity,
            already_known,
        })
    }

    pub fn fund_channel_via_json(&self, json: &str) -> Result<FundChannelResult, BridgeError> {
        let p: PaymentRequest =
            serde_json::from_str(json).map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        self.fund_channel(
            &p.channel_id,
            p.balance,
            &p.signature,
            p.params.as_ref(),
            p.funding_proofs.as_deref(),
        )
    }

    pub fn fund_channel_via_base64_header(
        &self,
        base64_header: &str,
    ) -> Result<FundChannelResult, BridgeError> {
        let p = Self::decode_payment_header(base64_header)?;
        self.fund_channel(
            &p.channel_id,
            p.balance,
            &p.signature,
            p.params.as_ref(),
            p.funding_proofs.as_deref(),
        )
    }

    fn validate_and_save_new_channel(
        &self,
        channel_id: &str,
        params_val: &serde_json::Value,
        proofs: &[Proof],
        balance: u64,
        signature: &str,
    ) -> Result<ChannelFunding, BridgeError> {
        let unit = params_val["unit"]
            .as_str()
            .ok_or(BridgeError::InvalidRequest("Missing unit".into()))?;
        let capacity = params_val["capacity"]
            .as_u64()
            .ok_or(BridgeError::InvalidRequest("Missing capacity".into()))?;
        let expiry_timestamp =
            params_val["expiry_timestamp"]
                .as_u64()
                .ok_or(BridgeError::InvalidRequest(
                    "Missing expiry_timestamp".into(),
                ))?;
        let maximum_amount = params_val["maximum_amount"]
            .as_u64()
            .ok_or(BridgeError::InvalidRequest("Missing maximum_amount".into()))?;
        let receiver_pubkey_hex =
            params_val["receiver_pubkey"]
                .as_str()
                .ok_or(BridgeError::InvalidRequest(
                    "Missing receiver_pubkey".into(),
                ))?;
        let receiver_pubkey = PublicKey::from_hex(receiver_pubkey_hex)
            .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        if !self.host.receiver_key_is_acceptable(&receiver_pubkey) {
            return Err(BridgeError::ReceiverKeyNotAcceptable);
        }
        let sender_pubkey_hex = params_val["sender_pubkey"]
            .as_str()
            .ok_or(BridgeError::InvalidRequest("Missing sender_pubkey".into()))?;
        let keyset_id = Id::from_str(
            params_val["keyset_id"]
                .as_str()
                .ok_or(BridgeError::InvalidRequest("Missing keyset_id".into()))?,
        )
        .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        let mint = params_val["mint"]
            .as_str()
            .ok_or(BridgeError::InvalidRequest("Missing mint".into()))?;
        if !self.host.mint_and_keyset_is_acceptable(mint, &keyset_id) {
            return Err(BridgeError::MintOrKeysetNotAcceptable);
        }
        let keyset_info_json = self
            .host
            .get_keyset_info(mint, &keyset_id)
            .ok_or(BridgeError::MintOrKeysetNotAcceptable)?;
        let policy = self
            .host
            .get_channel_policy(unit)
            .ok_or(BridgeError::UnsupportedUnit(unit.to_string()))?;
        if capacity < policy.min_capacity {
            return Err(BridgeError::CapacityTooSmall {
                capacity,
                min_capacity: policy.min_capacity,
            });
        }
        if let Some(max) = policy.max_amount_per_output {
            if max > 0 && maximum_amount > max {
                return Err(BridgeError::MaxAmountExceeded {
                    amount: maximum_amount,
                    max_allowed: max,
                });
            }
        }
        let now = self.host.now_seconds();
        if expiry_timestamp < now + policy.min_expiry_in_seconds {
            return Err(BridgeError::ExpiryTooSoon {
                expiry_timestamp,
                min_expiry: now + policy.min_expiry_in_seconds,
                now,
            });
        }
        if balance > capacity {
            return Err(BridgeError::BalanceExceedsCapacity { balance, capacity });
        }
        let channel_secret_hex = self
            .host
            .compute_channel_secret(receiver_pubkey_hex, sender_pubkey_hex)
            .map_err(BridgeError::ServerMisconfigured)?;
        let channel_secret: [u8; 32] = hex::decode(&channel_secret_hex)
            .map_err(|e| BridgeError::Internal(e.to_string()))?
            .try_into()
            .map_err(|_| BridgeError::Internal("Invalid secret length".into()))?;
        let params = ChannelParameters::from_json_with_channel_secret(
            &params_val.to_string(),
            super::parse_keyset_info_from_json(&keyset_info_json)
                .map_err(BridgeError::InvalidRequest)?,
            channel_secret,
        )
        .map_err(|e| BridgeError::Internal(e.to_string()))?;
        if params.get_channel_id() != channel_id {
            return Err(BridgeError::ChannelIdMismatch);
        }
        let verif = verify_valid_channel(proofs, &params);
        if !verif.valid {
            let errors_json =
                serde_json::to_string(&verif.errors).unwrap_or_else(|_| "[]".to_string());
            return Err(BridgeError::ValidationFailed(errors_json));
        }
        let proofs_json =
            serde_json::to_string(proofs).map_err(|e| BridgeError::Internal(e.to_string()))?;
        self.verify_signature(
            &params_val.to_string(),
            &proofs_json,
            &channel_secret_hex,
            &keyset_info_json,
            channel_id,
            balance,
            signature,
        )
        .map_err(BridgeError::InvalidSignature)?;
        let funding = ChannelFunding {
            params_json: params_val.to_string(),
            funding_proofs_json: proofs_json,
            channel_secret_hex,
            keyset_info_json,
        };
        self.host.save_funding(
            channel_id,
            funding.clone(),
            PaymentProof {
                balance,
                signature: signature.to_string(),
            },
        );
        Ok(funding)
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_signature(
        &self,
        params_json: &str,
        proofs_json: &str,
        secret_hex: &str,
        keyset_json: &str,
        channel_id: &str,
        balance: u64,
        signature: &str,
    ) -> Result<(), String> {
        let secret: [u8; 32] = hex::decode(secret_hex)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "Invalid secret length")?;
        let params = ChannelParameters::from_json_with_channel_secret(
            params_json,
            super::parse_keyset_info_from_json(keyset_json).map_err(|e| e.to_string())?,
            secret,
        )
        .map_err(|e| e.to_string())?;
        let channel = EstablishedChannel::new(
            params,
            serde_json::from_str(proofs_json).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let sig: bitcoin::secp256k1::schnorr::Signature = signature
            .parse()
            .map_err(|e: <bitcoin::secp256k1::schnorr::Signature as FromStr>::Err| e.to_string())?;
        BalanceUpdateMessage {
            channel_id: channel_id.to_string(),
            amount: balance,
            signature: sig,
        }
        .verify_sender_signature(&channel)
        .map_err(|e| e.to_string())
    }

    fn prepare_close_data_impl(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
        funding: ChannelFunding,
        validate_due: bool,
    ) -> Result<CloseData, BridgeError> {
        let secret: [u8; 32] = hex::decode(&funding.channel_secret_hex)
            .map_err(|e| BridgeError::Internal(e.to_string()))?
            .try_into()
            .map_err(|_| BridgeError::Internal("Invalid secret length".into()))?;
        let params = ChannelParameters::from_json_with_channel_secret(
            &funding.params_json,
            super::parse_keyset_info_from_json(&funding.keyset_info_json)
                .map_err(|e| BridgeError::Internal(e.to_string()))?,
            secret,
        )
        .map_err(|e| BridgeError::Internal(e.to_string()))?;
        let proofs: Vec<Proof> = serde_json::from_str(&funding.funding_proofs_json)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;
        let active = self.host.get_active_keyset_ids(&params.mint, &params.unit);
        let out_keyset = if active.contains(&params.keyset_info.keyset_id) {
            params.keyset_info.clone()
        } else {
            let nid = active
                .first()
                .ok_or_else(|| BridgeError::Internal("No active keysets".into()))?;
            super::parse_keyset_info_from_json(
                &self
                    .host
                    .get_keyset_info(&params.mint, nid)
                    .ok_or_else(|| BridgeError::Internal("Missing keyset info".into()))?,
            )
            .map_err(|e| BridgeError::Internal(e.to_string()))?
        };
        if balance > params.capacity {
            return Err(BridgeError::BalanceExceedsCapacity {
                balance,
                capacity: params.capacity,
            });
        }
        if validate_due && balance != self.host.get_amount_due(channel_id, None) {
            return Err(BridgeError::BalanceMismatch {
                expected: self.host.get_amount_due(channel_id, None),
                actual: balance,
            });
        }
        let sig: bitcoin::secp256k1::schnorr::Signature = signature.parse().map_err(
            |e: <bitcoin::secp256k1::schnorr::Signature as FromStr>::Err| {
                BridgeError::InvalidSignature(e.to_string())
            },
        )?;
        let commitment = CommitmentOutputs::for_balance(balance, &params)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;
        let mut swap = commitment
            .create_swap_request(proofs.clone(), Some(out_keyset.keyset_id))
            .map_err(|e| BridgeError::Internal(e.to_string()))?;
        super::balance_update::attach_signature_to_first_input(&mut swap, &sig.to_string())
            .map_err(|e| BridgeError::Internal(e.to_string()))?;
        let channel = EstablishedChannel::new(params.clone(), proofs)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;
        BalanceUpdateMessage {
            channel_id: channel_id.to_string(),
            amount: balance,
            signature: sig,
        }
        .verify_sender_signature(&channel)
        .map_err(|e| BridgeError::InvalidSignature(e.to_string()))?;
        let tweak = hex::encode(
            params
                .derive_receiver_blinding_scalar_for_stage1()
                .map_err(|e| BridgeError::Internal(e.to_string()))?
                .to_be_bytes(),
        );
        let server_sig = self
            .host
            .sign_with_tweaked_key(
                &params.receiver_pubkey.to_hex(),
                &super::balance_update::sig_all_message_hash_hex(&swap),
                &tweak,
            )
            .map_err(BridgeError::ServerMisconfigured)?;
        super::balance_update::attach_signature_to_first_input(&mut swap, &server_sig)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;
        let expected_total = params
            .get_value_after_stage1_with_keyset(&out_keyset)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;
        let mut swb: Vec<_> = commitment
            .receiver_outputs
            .get_secrets_with_blinding()
            .map_err(|e| BridgeError::Internal(e.to_string()))?
            .into_iter()
            .map(|s| (s, true))
            .chain(
                commitment
                    .sender_outputs
                    .get_secrets_with_blinding()
                    .map_err(|e| BridgeError::Internal(e.to_string()))?
                    .into_iter()
                    .map(|s| (s, false)),
            )
            .collect();
        swb.sort_by_key(|(s, _)| s.amount);
        Ok(CloseData {
            swap_request: swap,
            expected_total,
            secrets_with_blinding: swb,
            output_keyset_info: out_keyset,
        })
    }

    fn prepare_close_data(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
        params: Option<&serde_json::Value>,
        funding_proofs: Option<&[Proof]>,
        validate_due: bool,
    ) -> Result<CloseData, BridgeError> {
        if self.host.get_channel_state(channel_id) == ChannelState::Closed {
            return Err(BridgeError::ChannelClosed);
        }
        let funding = match self.host.get_funding(channel_id) {
            Some(f) => f,
            None => self.validate_and_save_new_channel(
                channel_id,
                params.ok_or(BridgeError::UnknownChannel)?,
                funding_proofs.ok_or(BridgeError::UnknownChannel)?,
                balance,
                signature,
            )?,
        };
        self.prepare_close_data_impl(channel_id, balance, signature, funding, validate_due)
    }

    pub fn validate_and_prepare_cooperative_close(
        &self,
        json: &str,
    ) -> Result<CloseData, BridgeError> {
        let p: PaymentRequest =
            serde_json::from_str(json).map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        if p.channel_id.is_empty() {
            return Err(BridgeError::InvalidRequest("missing channel_id".into()));
        }
        if p.signature.is_empty() {
            return Err(BridgeError::InvalidRequest("missing signature".into()));
        }
        self.prepare_close_data(
            &p.channel_id,
            p.balance,
            &p.signature,
            p.params.as_ref(),
            p.funding_proofs.as_deref(),
            true,
        )
    }

    pub fn create_unilateral_close_data(&self, channel_id: &str) -> Result<CloseData, BridgeError> {
        if self.host.get_funding(channel_id).is_none() {
            return Err(BridgeError::UnknownChannel);
        }
        let p = self
            .host
            .get_balance_and_signature_for_unilateral_exit(channel_id)
            .ok_or_else(|| BridgeError::InvalidRequest("No payment proof".into()))?;
        self.prepare_close_data(channel_id, p.balance, &p.signature, None, None, false)
    }

    pub fn prepare_cooperative_close_for_execution(
        &self,
        json: &str,
    ) -> Result<PreparedClose, ClosePreparationError> {
        let p: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| ClosePreparationError::bad_request(e.to_string()))?;
        let channel_id = p["channel_id"]
            .as_str()
            .ok_or_else(|| ClosePreparationError::bad_request("Missing ID"))?
            .to_string();
        let close_data = self
            .validate_and_prepare_cooperative_close(json)
            .map_err(ClosePreparationError::from_bridge_error)?;
        let balance = p["balance"].as_u64().unwrap_or(0);
        let funding = self
            .host
            .get_funding(&channel_id)
            .ok_or_else(|| ClosePreparationError::internal("Missing funding"))?;
        Self::wrap_close_data(close_data, &channel_id, balance, funding)
    }

    pub fn prepare_unilateral_close_for_execution(
        &self,
        channel_id: &str,
    ) -> Result<PreparedClose, ClosePreparationError> {
        let close_data = self
            .create_unilateral_close_data(channel_id)
            .map_err(ClosePreparationError::from_bridge_error)?;
        let funding = self
            .host
            .get_funding(channel_id)
            .ok_or_else(|| ClosePreparationError::internal("Missing funding"))?;
        let p = self
            .host
            .get_balance_and_signature_for_unilateral_exit(channel_id)
            .ok_or_else(|| ClosePreparationError::internal("Missing payment"))?;
        Self::wrap_close_data(close_data, channel_id, p.balance, funding)
    }

    /// Prepare a close using explicit balance/signature (used by the unified Closing→Closed path).
    fn prepare_close_for_closing_channel(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
    ) -> Result<PreparedClose, ClosePreparationError> {
        let close_data = self
            .prepare_close_data(channel_id, balance, signature, None, None, false)
            .map_err(ClosePreparationError::from_bridge_error)?;
        let funding = self
            .host
            .get_funding(channel_id)
            .ok_or_else(|| ClosePreparationError::internal("Missing funding"))?;
        Self::wrap_close_data(close_data, channel_id, balance, funding)
    }

    /// Wrap a CloseData + funding into a PreparedClose struct.
    fn wrap_close_data(
        close_data: CloseData,
        channel_id: &str,
        balance: u64,
        funding: ChannelFunding,
    ) -> Result<PreparedClose, ClosePreparationError> {
        let mint_url = serde_json::from_str::<serde_json::Value>(&funding.params_json)
            .map_err(|e| ClosePreparationError::internal(e.to_string()))?["mint"]
            .as_str()
            .ok_or_else(|| ClosePreparationError::internal("Missing mint"))?
            .to_string();
        Ok(PreparedClose { channel_id: channel_id.to_string(), balance, mint_url, swap_request: serde_json::to_value(&close_data.swap_request).unwrap_or(serde_json::Value::Null), secrets_with_blinding: close_data.secrets_with_blinding.iter().map(|(s, is_r)| serde_json::json!({ "secret": s.secret.to_string(), "blinding_factor": hex::encode(s.blinding_factor.secret_bytes()), "amount": s.amount, "index": s.index, "is_receiver": is_r })).collect(), output_keyset_info: serde_json::to_value(&close_data.output_keyset_info).unwrap_or(serde_json::Value::Null), params_json: funding.params_json, keyset_info_json: funding.keyset_info_json, channel_secret: funding.channel_secret_hex })
    }

    fn sign_receiver_close_proof(
        &self,
        params: &ChannelParameters,
        proof_meta: &ProofWithMeta,
    ) -> Result<Proof, CloseError> {
        use bitcoin::hashes::{sha256::Hash as Sha256Hash, Hash};

        let mut proof = proof_meta.proof.clone();
        params
            .attach_stage2_p2pk_e(
                &mut proof,
                Stage2Role::Receiver,
                proof_meta.amount,
                proof_meta.index,
            )
            .map_err(|e| {
                CloseError::unblind_failed(format!("Failed to attach stage2 metadata: {}", e))
            })?;
        let tweak_info = params
            .stage2_tweak_info_for_role(Stage2Role::Receiver, proof_meta.amount, proof_meta.index)
            .map_err(|e| {
                CloseError::unblind_failed(format!("Failed to derive stage2 tweak: {}", e))
            })?;
        let tweak_hex = hex::encode(tweak_info.stage2_tweak_scalar.to_be_bytes());
        let msg_hash = Sha256Hash::hash(&proof.secret.to_bytes());
        let msg_hex = hex::encode(msg_hash.as_byte_array());
        let sig = self
            .host
            .sign_with_tweaked_key(&params.receiver_pubkey.to_hex(), &msg_hex, &tweak_hex)
            .map_err(|e| {
                CloseError::unblind_failed(format!("Failed to sign receiver proof: {}", e))
            })?;
        proof.witness = Some(cashu::nuts::Witness::P2PKWitness(
            cashu::nuts::P2PKWitness {
                signatures: vec![sig],
            },
        ));

        Ok(proof)
    }

    fn finalize_close(
        &self,
        channel_id: &str,
        expiry_timestamp: u64,
        payment: PaymentProof,
        resp_json: &str,
        prep: &PreparedClose,
    ) -> Result<CloseSuccess, CloseError> {
        use super::parse_keyset_info_from_json;
        use cashu::nuts::SecretKey;
        use cashu::secret::Secret;

        let resp: serde_json::Value =
            serde_json::from_str(resp_json).map_err(|e| CloseError::UnblindFailed {
                reason: e.to_string(),
                status: 500,
            })?;
        let sigs_value = resp
            .get("signatures")
            .ok_or_else(|| CloseError::UnblindFailed {
                reason: "Missing signatures".into(),
                status: 500,
            })?;

        // Parse inputs for the internal unblind function
        let keyset_info = parse_keyset_info_from_json(&prep.keyset_info_json)
            .map_err(CloseError::unblind_failed)?;
        let output_keyset_info = parse_keyset_info_from_json(&prep.output_keyset_info.to_string())
            .map_err(CloseError::unblind_failed)?;
        let channel_secret_bytes =
            hex::decode(&prep.channel_secret).map_err(|e| CloseError::UnblindFailed {
                reason: e.to_string(),
                status: 500,
            })?;
        let channel_secret: [u8; 32] =
            channel_secret_bytes
                .try_into()
                .map_err(|_| CloseError::UnblindFailed {
                    reason: "Invalid channel secret length".into(),
                    status: 500,
                })?;
        let params = ChannelParameters::from_json_with_channel_secret(
            &prep.params_json,
            keyset_info,
            channel_secret,
        )
        .map_err(|e| CloseError::UnblindFailed {
            reason: e.to_string(),
            status: 500,
        })?;

        let blind_signatures: Vec<BlindSignature> = serde_json::from_str(&sigs_value.to_string())
            .map_err(|e| CloseError::UnblindFailed {
            reason: e.to_string(),
            status: 500,
        })?;
        let swb_raw: Vec<serde_json::Value> =
            serde_json::from_str(&prep.secrets_with_blinding.to_string()).map_err(|e| {
                CloseError::UnblindFailed {
                    reason: e.to_string(),
                    status: 500,
                }
            })?;

        let mut secrets_with_blinding = Vec::new();
        for swb in swb_raw {
            let secret = Secret::new(
                swb["secret"]
                    .as_str()
                    .ok_or_else(|| CloseError::UnblindFailed {
                        reason: "Missing secret".into(),
                        status: 500,
                    })?
                    .to_string(),
            );
            let blinding_factor = SecretKey::from_slice(
                &hex::decode(swb["blinding_factor"].as_str().ok_or_else(|| {
                    CloseError::UnblindFailed {
                        reason: "Missing blinding".into(),
                        status: 500,
                    }
                })?)
                .map_err(|e| CloseError::UnblindFailed {
                    reason: e.to_string(),
                    status: 500,
                })?,
            )
            .map_err(|e| CloseError::UnblindFailed {
                reason: e.to_string(),
                status: 500,
            })?;
            let amount = swb["amount"]
                .as_u64()
                .ok_or_else(|| CloseError::UnblindFailed {
                    reason: "Missing amount".into(),
                    status: 500,
                })?;
            let index = swb["index"]
                .as_u64()
                .ok_or_else(|| CloseError::UnblindFailed {
                    reason: "Missing index".into(),
                    status: 500,
                })? as usize;
            let is_receiver =
                swb["is_receiver"]
                    .as_bool()
                    .ok_or_else(|| CloseError::UnblindFailed {
                        reason: "Missing is_receiver".into(),
                        status: 500,
                    })?;
            secrets_with_blinding.push((
                DeterministicSecretWithBlinding {
                    secret,
                    blinding_factor,
                    amount,
                    index,
                },
                is_receiver,
            ));
        }

        // Unblind and verify (returns enriched proofs with amount/index metadata)
        let result = unblind_and_verify_stage1_response(
            blind_signatures,
            secrets_with_blinding,
            &params,
            &output_keyset_info,
            payment.balance,
        )
        .map_err(|e| CloseError::UnblindFailed {
            reason: e.to_string(),
            status: 500,
        })?;

        // Sign each receiver proof with P2PK witness using the host's tweaked signing
        let mut signed_receiver_proofs: Vec<Proof> =
            Vec::with_capacity(result.receiver_proofs.len());
        for pm in &result.receiver_proofs {
            signed_receiver_proofs.push(self.sign_receiver_close_proof(&params, pm)?);
        }

        let sender_proofs: Vec<&Proof> = result.sender_proofs.iter().map(|pm| &pm.proof).collect();
        let r_sum = result.receiver_sum;
        let s_sum = result.sender_sum;

        let receiver_proofs_json =
            serde_json::to_string(&signed_receiver_proofs).unwrap_or_default();
        let sender_proofs_json = serde_json::to_string(&sender_proofs).unwrap_or_default();

        self.host
            .mark_channel_closed(
                channel_id,
                expiry_timestamp,
                payment.balance,
                &receiver_proofs_json,
                &sender_proofs_json,
                r_sum,
                s_sum,
            )
            .map_err(CloseError::storage_failed)?;
        Ok(CloseSuccess {
            channel_id: channel_id.to_string(),
            total_value: r_sum + s_sum,
            receiver_sum: r_sum,
            sender_sum: s_sum,
            sender_proofs: sender_proofs_json,
            already_closed: false,
        })
    }

    pub fn execute_close_for_closing_channel<N: SpilmanNetworking>(
        &self,
        channel_id: &str,
        net: &N,
    ) -> Result<CloseSuccess, CloseError> {
        if self.host.get_channel_state(channel_id) != ChannelState::Closing {
            return Err(CloseError::ValidationFailed {
                reason: "Not closing".into(),
                status: 400,
                expected_balance: None,
                actual_balance: None,
            });
        }
        let cd =
            self.host
                .get_closing_data(channel_id)
                .ok_or_else(|| CloseError::ValidationFailed {
                    reason: "Missing closing data".into(),
                    status: 500,
                    expected_balance: None,
                    actual_balance: None,
                })?;
        let prep = self
            .prepare_close_for_closing_channel(channel_id, cd.balance, &cd.signature)
            .map_err(CloseError::from_preparation_error)?;
        let (prep, resp) = match net.call_mint_swap(&prep.mint_url, &prep.swap_request.to_string())
        {
            Ok(r) => (prep, r),
            Err(e) => {
                // Only retry on keyset errors (12xxx); fail immediately otherwise
                if !should_retry_swap_error(&e) {
                    return Err(CloseError::mint_rejected(parse_mint_error_value(&e)));
                }
                let _ = net.refresh_all_keysets(&prep.mint_url);
                let retry = self
                    .prepare_close_for_closing_channel(channel_id, cd.balance, &cd.signature)
                    .map_err(CloseError::from_preparation_error)?;
                let resp = net
                    .call_mint_swap(&retry.mint_url, &retry.swap_request.to_string())
                    .map_err(|re| {
                        CloseError::mint_rejected_after_retry(
                            parse_mint_error_value(&e),
                            parse_mint_error_value(&re),
                        )
                    })?;
                (retry, resp)
            }
        };
        self.finalize_close(
            channel_id,
            cd.expiry_timestamp,
            PaymentProof {
                balance: cd.balance,
                signature: cd.signature,
            },
            &resp,
            &prep,
        )
    }

    pub async fn execute_close_for_closing_channel_async<N: SpilmanAsyncNetworking>(
        &self,
        channel_id: &str,
        net: &N,
    ) -> Result<CloseSuccess, CloseError> {
        if self.host.get_channel_state(channel_id) != ChannelState::Closing {
            return Err(CloseError::ValidationFailed {
                reason: "Not closing".into(),
                status: 400,
                expected_balance: None,
                actual_balance: None,
            });
        }
        let cd =
            self.host
                .get_closing_data(channel_id)
                .ok_or_else(|| CloseError::ValidationFailed {
                    reason: "Missing closing data".into(),
                    status: 500,
                    expected_balance: None,
                    actual_balance: None,
                })?;
        let prep = self
            .prepare_close_for_closing_channel(channel_id, cd.balance, &cd.signature)
            .map_err(CloseError::from_preparation_error)?;
        let (prep, resp) = match net
            .call_mint_swap(&prep.mint_url, &prep.swap_request.to_string())
            .await
        {
            Ok(r) => (prep, r),
            Err(e) => {
                // Only retry on keyset errors (12xxx); fail immediately otherwise
                if !should_retry_swap_error(&e) {
                    return Err(CloseError::mint_rejected(parse_mint_error_value(&e)));
                }
                let _ = net.refresh_all_keysets(&prep.mint_url).await;
                let retry = self
                    .prepare_close_for_closing_channel(channel_id, cd.balance, &cd.signature)
                    .map_err(CloseError::from_preparation_error)?;
                let resp = net
                    .call_mint_swap(&retry.mint_url, &retry.swap_request.to_string())
                    .await
                    .map_err(|re| {
                        CloseError::mint_rejected_after_retry(
                            parse_mint_error_value(&e),
                            parse_mint_error_value(&re),
                        )
                    })?;
                (retry, resp)
            }
        };
        self.finalize_close(
            channel_id,
            cd.expiry_timestamp,
            PaymentProof {
                balance: cd.balance,
                signature: cd.signature,
            },
            &resp,
            &prep,
        )
    }

    pub fn execute_cooperative_close<N: SpilmanNetworking>(
        &self,
        json: &str,
        net: &N,
    ) -> Result<CloseSuccess, CloseError> {
        let prep = self
            .prepare_cooperative_close_for_execution(json)
            .map_err(CloseError::from_preparation_error)?;
        let expiry_timestamp = serde_json::from_str::<serde_json::Value>(&prep.params_json)
            .unwrap_or_default()["expiry_timestamp"]
            .as_u64()
            .unwrap_or(0);
        let sig = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default()["signature"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        self.host
            .mark_channel_closing(
                &prep.channel_id,
                expiry_timestamp,
                PaymentProof {
                    balance: prep.balance,
                    signature: sig,
                },
            )
            .map_err(CloseError::storage_failed)?;
        self.execute_close_for_closing_channel(&prep.channel_id, net)
    }

    pub async fn execute_cooperative_close_async<N: SpilmanAsyncNetworking>(
        &self,
        json: &str,
        net: &N,
    ) -> Result<CloseSuccess, CloseError> {
        let prep = self
            .prepare_cooperative_close_for_execution(json)
            .map_err(CloseError::from_preparation_error)?;
        let expiry_timestamp = serde_json::from_str::<serde_json::Value>(&prep.params_json)
            .unwrap_or_default()["expiry_timestamp"]
            .as_u64()
            .unwrap_or(0);
        let sig = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default()["signature"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        self.host
            .mark_channel_closing(
                &prep.channel_id,
                expiry_timestamp,
                PaymentProof {
                    balance: prep.balance,
                    signature: sig,
                },
            )
            .map_err(CloseError::storage_failed)?;
        self.execute_close_for_closing_channel_async(&prep.channel_id, net)
            .await
    }

    pub fn execute_unilateral_close<N: SpilmanNetworking>(
        &self,
        channel_id: &str,
        net: &N,
    ) -> Result<CloseSuccess, CloseError> {
        let prep = self
            .prepare_unilateral_close_for_execution(channel_id)
            .map_err(CloseError::from_preparation_error)?;
        let expiry_timestamp = serde_json::from_str::<serde_json::Value>(&prep.params_json)
            .unwrap_or_default()["expiry_timestamp"]
            .as_u64()
            .unwrap_or(0);
        let p = self
            .host
            .get_balance_and_signature_for_unilateral_exit(channel_id)
            .ok_or_else(|| CloseError::ValidationFailed {
                reason: "No payment".into(),
                status: 400,
                expected_balance: None,
                actual_balance: None,
            })?;
        self.host
            .mark_channel_closing(channel_id, expiry_timestamp, p)
            .map_err(CloseError::storage_failed)?;
        self.execute_close_for_closing_channel(channel_id, net)
    }

    pub async fn execute_unilateral_close_async<N: SpilmanAsyncNetworking>(
        &self,
        channel_id: &str,
        net: &N,
    ) -> Result<CloseSuccess, CloseError> {
        let prep = self
            .prepare_unilateral_close_for_execution(channel_id)
            .map_err(CloseError::from_preparation_error)?;
        let expiry_timestamp = serde_json::from_str::<serde_json::Value>(&prep.params_json)
            .unwrap_or_default()["expiry_timestamp"]
            .as_u64()
            .unwrap_or(0);
        let p = self
            .host
            .get_balance_and_signature_for_unilateral_exit(channel_id)
            .ok_or_else(|| CloseError::ValidationFailed {
                reason: "No payment".into(),
                status: 400,
                expected_balance: None,
                actual_balance: None,
            })?;
        self.host
            .mark_channel_closing(channel_id, expiry_timestamp, p)
            .map_err(CloseError::storage_failed)?;
        self.execute_close_for_closing_channel_async(channel_id, net)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cashu::nuts::{Id, PublicKey, SecretKey};
    struct MockHost {
        ra: bool,
        ma: bool,
    }
    impl SpilmanHost<String> for MockHost {
        fn receiver_key_is_acceptable(&self, _: &PublicKey) -> bool {
            self.ra
        }
        fn mint_and_keyset_is_acceptable(&self, _: &str, _: &Id) -> bool {
            self.ma
        }
        fn get_funding(&self, _: &str) -> Option<ChannelFunding> {
            None
        }
        fn save_funding(&self, _: &str, _: ChannelFunding, _: PaymentProof) {}
        fn get_amount_due(&self, _: &str, _: Option<&String>) -> u64 {
            0
        }
        fn record_payment(&self, _: &str, _: PaymentProof, _: &String) {}
        fn get_channel_state(&self, _: &str) -> ChannelState {
            ChannelState::Open
        }
        fn mark_channel_closing(&self, _: &str, _: u64, _: PaymentProof) -> Result<(), String> {
            Ok(())
        }
        fn get_closing_data(&self, _: &str) -> Option<ClosingData> {
            None
        }
        fn get_channel_policy(&self, _unit: &str) -> Option<ChannelPolicy> {
            Some(ChannelPolicy {
                min_expiry_in_seconds: 3600,
                min_capacity: 100,
                max_amount_per_output: None,
            })
        }
        fn now_seconds(&self) -> u64 {
            1700000000
        }
        fn get_balance_and_signature_for_unilateral_exit(&self, _: &str) -> Option<PaymentProof> {
            None
        }
        fn get_active_keyset_ids(&self, _: &str, _: &CurrencyUnit) -> Vec<Id> {
            Vec::new()
        }
        fn get_keyset_info(&self, _: &str, _: &Id) -> Option<String> {
            None
        }
        fn mark_channel_closed(
            &self,
            _: &str,
            _: u64,
            _: u64,
            _: &str,
            _: &str,
            _: u64,
            _: u64,
        ) -> Result<(), String> {
            Ok(())
        }
        fn compute_channel_secret(&self, _: &str, _: &str) -> Result<String, String> {
            Err("N/A".into())
        }
        fn sign_with_tweaked_key(&self, _: &str, _: &str, _: &str) -> Result<String, String> {
            Err("N/A".into())
        }
    }
    impl SpilmanNetworking for MockHost {
        fn call_mint_swap(&self, _: &str, _: &str) -> Result<String, String> {
            Err("N/A".into())
        }
        fn refresh_all_keysets(&self, _: &str) -> Result<(), String> {
            Err("N/A".into())
        }
    }
    #[test]
    fn test_bridge_rejects_unacceptable_receiver() {
        let b = SpilmanBridge::new(MockHost {
            ra: false,
            ma: true,
        });
        let p = serde_json::json!({ "sender_pubkey": SecretKey::generate().public_key().to_hex(), "receiver_pubkey": SecretKey::generate().public_key().to_hex(), "mint": "https://m", "unit": "sat", "capacity": 1000, "funding_token_amount": 1000, "maximum_amount": 64, "expiry_timestamp": 1700007200, "setup_timestamp": 1700000000, "keyset_id": "00" });
        let pay = serde_json::json!({ "channel_id": "i", "balance": 100, "signature": "s", "params": p, "funding_proofs": [] });
        assert!(b
            .process_payment_via_json(&pay.to_string(), &"{}".to_string())
            .unwrap_err()
            .to_string()
            .contains("receiver key not acceptable"));
    }
}
