//! Client-side Spilman channel bridge
//!
//! This module provides a high-level client-side API for managing Spilman payment channels,
//! mirroring the server-side `SpilmanBridge` / `SpilmanHost` pattern.
//!
//! The `SpilmanClientHost` trait handles storage and crypto callbacks, while
//! `SpilmanClientNetworking` handles mint communication. The `SpilmanClientBridge`
//! orchestrates channel creation, payment signing, and header construction.
//!
//! # Example (pseudocode)
//! ```ignore
//! let host = MyClientHost::new();
//! let networking = MyNetworking::new();
//! let bridge = SpilmanClientBridge::new(host, networking);
//!
//! // Open a channel from an existing Cashu token
//! let result = bridge.open_channel_from_token(...)?;
//!
//! // Make payments
//! let payment = bridge.create_payment(&result.channel_id, 10)?;
//! let payment_with_funding = bridge.create_payment_with_funding(&result.channel_id, 10)?;
//! ```

use base64::Engine;
use cashu::nuts::{CurrencyUnit, Id, Proof};
use serde::{Deserialize, Serialize};

use super::balance_update::{BalanceUpdateMessage, UnsignedBalanceUpdate};
#[cfg(feature = "wallet")]
use super::bindings::{
    complete_funding_restore, complete_funding_swap_with_plain_change,
    complete_plain_change_restore,
    compute_channel_from_proofs_with_input_keysets_and_funding_amount, compute_channel_from_token,
    compute_channel_from_token_with_input_keysets, create_funding_restore_request,
    create_funding_swap_with_plain_change, create_plain_change_restore_request,
    parse_keyset_info_from_json,
};
use super::bridge::Payment;
use super::client_storage::{
    ClientChannelFunding, ClientChannelOpeningFromSwap, ClientChannelState, ClientKeysetCacheEntry,
    ClientOpeningFailure, ClientPaymentState,
};
#[cfg(feature = "wallet")]
use crate::mint_errors::{extract_nut00_error_code, is_retryable_keyset_mint_error};
#[cfg(feature = "wallet")]
use crate::{with_active_keyset_retry, KeysetRetryError, SelectedOutputKeyset};

// ============================================================================
// SpilmanClientHost trait
// ============================================================================

/// Trait for client-side host callbacks.
///
/// Provides storage and crypto operations. This is the client-side
/// counterpart of the server-side `SpilmanHost` trait.
///
/// The trait separates immutable funding data from mutable payment state,
/// mirroring the server-side pattern. Networking is handled by a separate
/// `SpilmanClientNetworking` trait.
pub trait SpilmanClientHost {
    // ========================================================================
    // Channel Opening (two-phase)
    // ========================================================================

    /// Save channel metadata before the funding swap.
    ///
    /// Called before submitting the funding swap to the mint. The channel
    /// enters `OpeningFromSwap` state. The opening data includes the original
    /// input token for recovery if the swap fails.
    ///
    /// If the swap fails or the client crashes, the channel remains in
    /// `OpeningFromSwap` state with enough data to attempt NUT-09 restore
    /// or reclaim the input token.
    fn save_opening_from_swap_channel(
        &self,
        channel_id: &str,
        opening: ClientChannelOpeningFromSwap,
    ) -> Result<(), String>;

    /// Transition a channel from OpeningFromSwap to Open.
    ///
    /// Called after the funding swap succeeds and proofs are unblinded.
    /// The host reads the opening data, constructs funding data with
    /// the proofs, stores it, and removes the opening record.
    fn mark_channel_open(&self, channel_id: &str, funding_proofs_json: &str) -> Result<(), String>;

    /// Get opening data for a channel in OpeningFromSwap state.
    ///
    /// Returns `None` if the channel is not in OpeningFromSwap state.
    fn get_channel_opening_from_swap(
        &self,
        channel_id: &str,
    ) -> Option<ClientChannelOpeningFromSwap>;

    /// Mark a channel opening attempt as explicitly failed.
    fn mark_channel_opening_failed(
        &self,
        channel_id: &str,
        failure: ClientOpeningFailure,
    ) -> Result<(), String>;

    /// Get funding data for an open channel.
    ///
    /// Returns `None` if the channel is not in Open (or Closed) state.
    fn get_channel_funding(&self, channel_id: &str) -> Option<ClientChannelFunding>;

    // ========================================================================
    // Payment State (mutable)
    // ========================================================================

    /// Get the current payment state for a channel.
    ///
    /// Returns `None` if no payments have been made yet.
    fn get_payment_state(&self, channel_id: &str) -> Option<ClientPaymentState>;

    /// Record a new payment state.
    ///
    /// Called after each successful payment signing. Updates the stored
    /// balance, signature, payment count, and timestamp.
    fn record_payment(&self, channel_id: &str, state: ClientPaymentState) -> Result<(), String>;

    // ========================================================================
    // Channel Lifecycle
    // ========================================================================

    /// Get the lifecycle state of a channel.
    ///
    /// Returns `None` if the channel is not present in storage.
    fn get_channel_state(&self, channel_id: &str) -> Option<ClientChannelState>;

    /// Mark a channel as closed.
    ///
    /// After this, the channel cannot accept new payments.
    fn mark_channel_closed(&self, channel_id: &str) -> Result<(), String>;

    /// Mark a channel as closing / unusable.
    ///
    /// After this, the channel remains in storage but must not be used for new
    /// payments.
    fn mark_channel_closing(&self, channel_id: &str) -> Result<(), String>;

    /// List all stored channel IDs.
    fn list_channel_ids(&self) -> Vec<String>;

    /// Delete a channel and all its data.
    fn delete_channel(&self, channel_id: &str) -> Result<(), String>;

    // ========================================================================
    // Keyset Cache
    // ========================================================================

    /// Get cached keyset metadata.
    fn get_keyset(&self, _mint: &str, _keyset_id: &Id) -> Option<ClientKeysetCacheEntry> {
        None
    }

    /// Insert or update cached keyset metadata.
    fn set_keyset(
        &self,
        _mint: &str,
        _keyset_id: Id,
        _entry: ClientKeysetCacheEntry,
    ) -> Result<(), String> {
        Err("client host does not support keyset caching".to_string())
    }

    /// Get cached active keyset IDs for a mint and unit.
    fn get_active_keyset_ids(&self, _mint: &str, _unit: &CurrencyUnit) -> Vec<Id> {
        Vec::new()
    }

    /// List cached keyset metadata for a mint and unit, including inactive keysets.
    fn list_keysets_for_unit(
        &self,
        _mint: &str,
        _unit: &CurrencyUnit,
    ) -> Vec<(Id, ClientKeysetCacheEntry)> {
        Vec::new()
    }

    // ========================================================================
    // Time
    // ========================================================================

    /// Get the current time in seconds since Unix epoch.
    fn now_seconds(&self) -> u64;

    // ========================================================================
    // Crypto (delegated to host)
    // ========================================================================

    /// Compute the hashed ECDH channel secret for a channel.
    ///
    /// The host performs ECDH between the sender's secret key (identified by
    /// `sender_pubkey_hex`) and the receiver's public key, then hashes the result
    /// with a domain separator:
    ///   SHA256("Cashu_Spilman_channel_secret_v1" || ECDH(sender_secret, receiver_pubkey))
    ///
    /// For hosts that hold raw secret keys, the convenience function
    /// `crate::bindings::compute_channel_secret_from_hex()` provides
    /// a standard implementation.
    ///
    /// # Arguments
    /// * `sender_pubkey_hex` - Sender's public key (identifies which secret key to use)
    /// * `receiver_pubkey_hex` - Receiver's public key
    ///
    /// # Returns
    /// The hashed channel secret as a 64-char hex string (32 bytes).
    fn compute_channel_secret(
        &self,
        sender_pubkey_hex: &str,
        receiver_pubkey_hex: &str,
    ) -> Result<String, String>;

    /// Sign a message with a tweaked key (BIP-340 Schnorr).
    ///
    /// The bridge computes the tweak (P2BK blinding scalar) and message hash,
    /// then asks the host to produce a BIP-340 Schnorr signature using
    /// the key `(secret + tweak)` where `secret` is the key corresponding
    /// to `signer_pubkey_hex`.
    ///
    /// The host must handle BIP-340 parity: if the public key has odd Y,
    /// negate the secret key before adding the tweak.
    ///
    /// For hosts that hold raw secret keys, the convenience function
    /// `crate::bindings::sign_with_tweaked_key_util()` provides
    /// a standard implementation.
    ///
    /// # Arguments
    /// * `signer_pubkey_hex` - Identifies which key to use (Alice's pubkey for this channel)
    /// * `message_hex` - SHA-256 hash of the SIG_ALL message (32 bytes, hex-encoded)
    /// * `tweak_scalar_hex` - The P2BK blinding scalar to add to the secret key (32 bytes, hex)
    ///
    /// # Returns
    /// The BIP-340 Schnorr signature as a 64-byte hex string.
    fn sign_with_tweaked_key(
        &self,
        signer_pubkey_hex: &str,
        message_hex: &str,
        tweak_scalar_hex: &str,
    ) -> Result<String, String>;
}

// ============================================================================
// SpilmanClientNetworking trait
// ============================================================================

/// Networking trait for client-side mint communication.
///
/// Separated from `SpilmanClientHost` to allow different networking
/// implementations (sync, async, mock for testing).
pub trait SpilmanClientNetworking {
    /// Execute a swap with the mint.
    ///
    /// Posts `swap_request_json` to `{mint_url}/v1/swap` and returns the
    /// response body as a JSON string.
    fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String>;

    /// Execute a NUT-09 restore with the mint.
    ///
    /// Posts `restore_request_json` to `{mint_url}/v1/restore` and returns the
    /// response body as a JSON string.
    fn call_mint_restore(
        &self,
        mint_url: &str,
        restore_request_json: &str,
    ) -> Result<String, String>;

    /// Fetch the list of keysets from a mint.
    ///
    /// Calls `GET {mint_url}/v1/keysets` and returns the response body as a
    /// JSON string.
    fn call_mint_keysets(&self, mint_url: &str) -> Result<String, String>;

    /// Fetch the keys for a specific keyset from a mint.
    ///
    /// Calls `GET {mint_url}/v1/keys/{keyset_id}` and returns the response
    /// body as a JSON string.
    fn call_mint_keys(&self, mint_url: &str, keyset_id: &str) -> Result<String, String>;
}

// ============================================================================
// SpilmanClientAsyncNetworking trait (for WASM)
// ============================================================================

/// Async networking trait for client-side mint communication.
///
/// This is the async counterpart of `SpilmanClientNetworking`, designed for
/// environments like WASM where networking must be asynchronous.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait SpilmanClientAsyncNetworking {
    /// Execute a swap with the mint (async version).
    ///
    /// Posts `swap_request_json` to `{mint_url}/v1/swap` and returns the
    /// response body as a JSON string.
    async fn call_mint_swap(
        &self,
        mint_url: &str,
        swap_request_json: &str,
    ) -> Result<String, String>;

    /// Execute a NUT-09 restore with the mint (async version).
    ///
    /// Posts `restore_request_json` to `{mint_url}/v1/restore` and returns the
    /// response body as a JSON string.
    async fn call_mint_restore(
        &self,
        mint_url: &str,
        restore_request_json: &str,
    ) -> Result<String, String>;

    /// Fetch the list of keysets from a mint (async version).
    ///
    /// Calls `GET {mint_url}/v1/keysets` and returns the response body as a
    /// JSON string.
    async fn call_mint_keysets(&self, mint_url: &str) -> Result<String, String>;

    /// Fetch the keys for a specific keyset from a mint (async version).
    ///
    /// Calls `GET {mint_url}/v1/keys/{keyset_id}` and returns the response
    /// body as a JSON string.
    async fn call_mint_keys(&self, mint_url: &str, keyset_id: &str) -> Result<String, String>;
}

// ============================================================================
// Result/info types
// ============================================================================

/// Result of opening a new channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenChannelResult {
    /// Stable identifier for the newly opened channel.
    pub channel_id: String,
    /// Maximum final value the receiver can claim from the channel.
    pub capacity: u64,
    /// Nominal funding token amount required to support `capacity`.
    pub funding_token_amount: u64,
    /// Mint URL associated with the channel's funding proofs.
    pub mint_url: String,
    /// Unit of the channel (e.g. "sat").
    pub unit: String,
    /// Keyset ID used for the channel's funding outputs.
    pub keyset_id: String,
    /// Sender public key used for this channel.
    pub sender_pubkey_hex: String,
    /// Receiver public key used for this channel.
    pub receiver_pubkey_hex: String,
    /// Plain loose change proofs returned by the funding swap.
    #[serde(default)]
    pub change_proofs_json: String,
}

#[cfg(feature = "wallet")]
struct TokenAutoAttempt {
    output_keyset: SelectedOutputKeyset,
    input_keysets: String,
}

/// Stage where channel opening failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpenChannelFailureStage {
    /// Failure happened before any opening record was persisted.
    BeforeOpeningSaved,
    /// Mint explicitly rejected the funding swap.
    MintRejected,
    /// Swap may have been submitted to the mint.
    SwapSubmitted,
    /// Funding proofs were received/unblinded, but later verification failed.
    FundingProofsReceived,
    /// Restore verification failed after swap submission.
    RestoreVerification,
    /// Funding proofs could not be persisted as an open channel.
    MarkOpen,
}

impl OpenChannelFailureStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::BeforeOpeningSaved => "before_opening_saved",
            Self::MintRejected => "mint_rejected",
            Self::SwapSubmitted => "swap_submitted",
            Self::FundingProofsReceived => "funding_proofs_received",
            Self::RestoreVerification => "restore_verification",
            Self::MarkOpen => "mark_open",
        }
    }
}

/// Structured channel-open error for safe input proof reservation handling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenChannelError {
    /// Stage where the failure occurred.
    pub stage: OpenChannelFailureStage,
    /// Channel ID when one had already been computed.
    pub channel_id: Option<String>,
    /// Whether the input proofs may already have been consumed by the mint.
    pub input_may_be_spent: bool,
    /// Human-readable failure details.
    pub message: String,
}

#[cfg(feature = "wallet")]
impl OpenChannelError {
    fn new(
        stage: OpenChannelFailureStage,
        channel_id: Option<String>,
        message: impl Into<String>,
    ) -> Self {
        let input_may_be_spent = matches!(
            stage,
            OpenChannelFailureStage::SwapSubmitted
                | OpenChannelFailureStage::FundingProofsReceived
                | OpenChannelFailureStage::RestoreVerification
                | OpenChannelFailureStage::MarkOpen
        );
        Self {
            stage,
            channel_id,
            input_may_be_spent,
            message: message.into(),
        }
    }
}

#[cfg(feature = "wallet")]
impl OpenChannelError {
    /// Returns true when the mint explicitly rejected the opening due to stale
    /// or unknown keyset state and the input proofs are known not to be spent.
    pub fn is_retryable_keyset_rejection(&self) -> bool {
        self.stage == OpenChannelFailureStage::MintRejected
            && is_keyset_mint_rejection(&self.message)
    }
}

impl std::fmt::Display for OpenChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "channel open failed at {}: {}",
            self.stage.as_str(),
            self.message
        )
    }
}

impl std::error::Error for OpenChannelError {}

#[cfg(feature = "wallet")]
fn token_unit(token_string: &str) -> Result<CurrencyUnit, OpenChannelError> {
    let token: cashu::nuts::Token = token_string.parse().map_err(|e| {
        OpenChannelError::new(
            OpenChannelFailureStage::BeforeOpeningSaved,
            None,
            format!("Failed to parse token: {e}"),
        )
    })?;
    Ok(token.unit().unwrap_or(cashu::nuts::CurrencyUnit::Sat))
}

#[cfg(feature = "wallet")]
fn unwrap_open_channel_retry_result<A>(
    result: Result<
        crate::KeysetRetrySuccess<A, OpenChannelResult>,
        KeysetRetryError<A, OpenChannelError, OpenChannelError>,
    >,
) -> Result<OpenChannelResult, OpenChannelError> {
    match result {
        Ok(success) => Ok(success.value),
        Err(KeysetRetryError::Select { error, .. })
        | Err(KeysetRetryError::Prepare { error, .. })
        | Err(KeysetRetryError::Refresh { error })
        | Err(KeysetRetryError::Cleanup { error })
        | Err(KeysetRetryError::Submit { error, .. })
        | Err(KeysetRetryError::RetryKeysetUnchanged { error, .. }) => Err(error),
    }
}

/// Information about a stored channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientChannelInfo {
    /// Stable identifier for the stored channel.
    pub channel_id: String,
    /// Maximum final value the receiver can claim from the channel.
    pub capacity: u64,
    /// Nominal funding token amount backing the channel.
    pub funding_token_amount: u64,
    /// Mint URL associated with the channel.
    pub mint_url: String,
    /// Current balance (last signed amount).
    pub current_balance: u64,
    /// Number of payments made through this channel.
    pub payment_count: u64,
    /// Channel state (Open/Closed).
    pub state: ClientChannelState,
}

// ============================================================================
// SpilmanClientBridge
// ============================================================================

/// Client-side bridge for managing Spilman payment channels.
///
/// This is the client-side counterpart of `SpilmanBridge`. It orchestrates
/// channel creation from tokens, payment signing, and HTTP header construction.
///
/// The bridge itself is stateless — all channel state is stored via the host.
/// The bridge never holds or sees Alice's secret key; all operations requiring
/// the key are delegated to the host via callbacks.
#[derive(Debug)]
pub struct SpilmanClientBridge<H: SpilmanClientHost, N: SpilmanClientNetworking> {
    host: H,
    #[allow(dead_code)] // Used only with "wallet" feature for open_channel_from_token
    networking: N,
}

#[cfg(feature = "wallet")]
fn normalize_mint_error_string(raw: String) -> String {
    serde_json::from_str::<serde_json::Value>(&raw)
        .map(|value| value.to_string())
        .unwrap_or(raw)
}

#[cfg(feature = "wallet")]
fn is_explicit_mint_rejection(raw: &str) -> bool {
    extract_nut00_error_code(raw).is_some()
}

#[cfg(feature = "wallet")]
fn is_keyset_mint_rejection(raw: &str) -> bool {
    is_retryable_keyset_mint_error(raw)
}

/// Build keyset info JSON from the responses of `/v1/keysets` and `/v1/keys/{id}`.
///
/// Extracts the matching keyset metadata (unit, input_fee_ppk) from the keysets
/// response and the public keys from the keys response, then assembles them into
/// the format expected by [`parse_keyset_info_from_json`](crate::parse_keyset_info_from_json).
fn build_keyset_info_from_responses(
    keysets_json: &str,
    keys_json: &str,
    keyset_id: &str,
) -> Result<String, String> {
    let keysets_resp: serde_json::Value = serde_json::from_str(keysets_json)
        .map_err(|e| format!("Failed to parse /v1/keysets response: {}", e))?;
    let keys_resp: serde_json::Value = serde_json::from_str(keys_json)
        .map_err(|e| format!("Failed to parse /v1/keys response: {}", e))?;

    // Find the matching keyset in /v1/keysets response
    let keysets = keysets_resp
        .get("keysets")
        .and_then(|k| k.as_array())
        .ok_or("Invalid /v1/keysets response: missing 'keysets' array")?;

    let keyset_entry = keysets
        .iter()
        .find(|k| k.get("id").and_then(|v| v.as_str()) == Some(keyset_id))
        .ok_or_else(|| format!("Keyset '{}' not found in /v1/keysets response", keyset_id))?;

    let unit = keyset_entry
        .get("unit")
        .and_then(|v| v.as_str())
        .ok_or("Missing 'unit' in keyset entry")?;

    let input_fee_ppk = keyset_entry
        .get("input_fee_ppk")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let final_expiry = keyset_entry.get("final_expiry").cloned();

    // Extract the keys from /v1/keys/{id} response
    let keys = keys_resp
        .get("keysets")
        .and_then(|k| k.as_array())
        .and_then(|arr| arr.first())
        .and_then(|k| k.get("keys"))
        .cloned()
        .ok_or("Invalid /v1/keys response: missing keys")?;

    let mut value = serde_json::json!({
        "keysetId": keyset_id,
        "unit": unit,
        "keys": keys,
        "inputFeePpk": input_fee_ppk,
    });
    if let Some(final_expiry) = final_expiry {
        value["finalExpiry"] = final_expiry;
    }
    let json_string = value.to_string();

    // Verify the keyset ID is consistent with the keys and metadata.
    // This prevents a malicious mint (or MITM) from serving keys that don't
    // match the claimed keyset ID.
    let keyset_info = crate::parse_keyset_info_from_json(&json_string)?;
    let computed_id = match keyset_info.keyset_id.get_version() {
        cashu::nuts::nut02::KeySetVersion::Version00 => {
            cashu::nuts::nut02::Id::v1_from_keys(&keyset_info.active_keys)
        }
        cashu::nuts::nut02::KeySetVersion::Version01 => cashu::nuts::nut02::Id::v2_from_data(
            &keyset_info.active_keys,
            &keyset_info.unit,
            keyset_info.input_fee_ppk,
            keyset_info.final_expiry,
        ),
    };
    if keyset_info.keyset_id != computed_id {
        return Err(format!(
            "Keyset ID mismatch: claimed {} but keys derive {}",
            keyset_info.keyset_id, computed_id
        ));
    }

    Ok(json_string)
}

#[cfg(feature = "wallet")]
fn token_input_keysets_from_response(keysets_json: &str, unit: &str) -> Result<String, String> {
    let keysets_resp: serde_json::Value = serde_json::from_str(keysets_json)
        .map_err(|e| format!("Failed to parse /v1/keysets response: {e}"))?;
    let keysets = keysets_resp
        .get("keysets")
        .and_then(|k| k.as_array())
        .ok_or("Invalid /v1/keysets response: missing 'keysets' array")?;

    let mut out = Vec::new();
    for keyset in keysets {
        if keyset.get("unit").and_then(|v| v.as_str()) != Some(unit) {
            continue;
        }
        let id = keyset
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("Missing 'id' in keyset entry")?;
        let active = keyset
            .get("active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let input_fee_ppk = keyset
            .get("input_fee_ppk")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let mut value = serde_json::json!({
            "id": id,
            "unit": unit,
            "active": active,
            "input_fee_ppk": input_fee_ppk,
        });
        if let Some(final_expiry) = keyset.get("final_expiry") {
            value["final_expiry"] = final_expiry.clone();
        }
        out.push(value);
    }

    if out.is_empty() {
        return Err(format!("no keysets found for unit '{unit}'"));
    }
    serde_json::to_string(&out).map_err(|e| format!("Failed to serialize input keysets: {e}"))
}

#[cfg(feature = "wallet")]
fn keyset_summary_from_cache_entry(
    keyset_id: Id,
    entry: &ClientKeysetCacheEntry,
    expected_unit: &CurrencyUnit,
) -> Result<serde_json::Value, String> {
    if &entry.unit != expected_unit {
        return Err(format!(
            "cached keyset {keyset_id} unit mismatch: expected {expected_unit}, got {}",
            entry.unit
        ));
    }
    let info = parse_keyset_info_from_json(&entry.info_json)?;
    if info.keyset_id != keyset_id {
        return Err(format!(
            "cached keyset id mismatch: requested {keyset_id}, cache entry has {}",
            info.keyset_id
        ));
    }
    if &info.unit != expected_unit {
        return Err(format!(
            "cached keyset {keyset_id} info unit mismatch: expected {expected_unit}, got {}",
            info.unit
        ));
    }
    let mut value = serde_json::json!({
        "id": keyset_id.to_string(),
        "unit": expected_unit.to_string(),
        "active": entry.active,
        "input_fee_ppk": info.input_fee_ppk,
    });
    if let Some(final_expiry) = info.final_expiry {
        value["final_expiry"] = serde_json::json!(final_expiry);
    }
    Ok(value)
}

#[cfg(feature = "wallet")]
fn input_keysets_from_cache_entries(
    entries: Vec<(Id, ClientKeysetCacheEntry)>,
    unit: &CurrencyUnit,
) -> Result<String, String> {
    let summaries = entries
        .iter()
        .map(|(keyset_id, entry)| keyset_summary_from_cache_entry(*keyset_id, entry, unit))
        .collect::<Result<Vec<_>, _>>()?;
    serde_json::to_string(&summaries)
        .map_err(|e| format!("Failed to serialize cached input keysets: {e}"))
}

#[cfg(feature = "wallet")]
fn proof_keyset_ids(input_proofs_json: &str) -> Result<Vec<Id>, String> {
    let proofs: Vec<Proof> = serde_json::from_str(input_proofs_json)
        .map_err(|e| format!("Failed to parse input proofs: {e}"))?;
    let mut ids = Vec::new();
    for proof in proofs {
        if !ids.contains(&proof.keyset_id) {
            ids.push(proof.keyset_id);
        }
    }
    if ids.is_empty() {
        return Err("input proofs are empty".to_string());
    }
    Ok(ids)
}

#[cfg(feature = "wallet")]
fn first_active_keyset_id_from_response(
    keysets_json: &str,
    unit: &CurrencyUnit,
) -> Result<Id, String> {
    let keysets_resp: serde_json::Value = serde_json::from_str(keysets_json)
        .map_err(|e| format!("Failed to parse /v1/keysets response: {e}"))?;
    let keysets = keysets_resp
        .get("keysets")
        .and_then(|k| k.as_array())
        .ok_or("Invalid /v1/keysets response: missing 'keysets' array")?;

    keysets
        .iter()
        .find(|keyset| {
            keyset.get("unit").and_then(|v| v.as_str()) == Some(&unit.to_string())
                && keyset
                    .get("active")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
        })
        .and_then(|keyset| keyset.get("id").and_then(|v| v.as_str()))
        .ok_or_else(|| format!("no active keyset found for unit '{unit}'"))?
        .parse::<Id>()
        .map_err(|e| format!("Invalid active keyset id: {e}"))
}

impl<H: SpilmanClientHost, N: SpilmanClientNetworking> SpilmanClientBridge<H, N> {
    /// Create a new client bridge.
    ///
    /// The bridge is stateless and keyless — it delegates all key operations
    /// to the host. The caller passes `sender_pubkey_hex` per channel when
    /// opening channels.
    pub fn new(host: H, networking: N) -> Self {
        Self { host, networking }
    }

    /// Fetch keyset info from a mint for a specific keyset.
    ///
    /// Calls `GET /v1/keysets` and `GET /v1/keys/{keyset_id}` via the
    /// networking layer, then assembles the result into the keyset info JSON
    /// format expected by [`open_channel_from_token`](Self::open_channel_from_token).
    pub fn fetch_keyset_info(&self, mint_url: &str, keyset_id: &str) -> Result<String, String> {
        let keysets_json = self.networking.call_mint_keysets(mint_url)?;
        let keys_json = self.networking.call_mint_keys(mint_url, keyset_id)?;
        build_keyset_info_from_responses(&keysets_json, &keys_json, keyset_id)
    }

    /// Refresh and persist all keysets for a mint in the client host cache.
    #[cfg(feature = "wallet")]
    pub fn refresh_keysets(&self, mint_url: &str) -> Result<(), OpenChannelError> {
        self.refresh_keysets_inner(mint_url).map(|_| ())
    }

    /// Refresh and persist all keysets for a mint, returning the raw
    /// `/v1/keysets` response used for the refresh.
    #[cfg(feature = "wallet")]
    pub fn refresh_keysets_response(&self, mint_url: &str) -> Result<String, OpenChannelError> {
        self.refresh_keysets_inner(mint_url)
    }

    /// Return cached full keyset info JSON for a mint keyset.
    #[cfg(feature = "wallet")]
    pub fn cached_keyset_info(&self, mint_url: &str, keyset_id: &Id) -> Option<String> {
        self.host
            .get_keyset(mint_url, keyset_id)
            .map(|entry| entry.info_json)
    }

    /// Return cached active keyset IDs for a mint and unit.
    #[cfg(feature = "wallet")]
    pub fn cached_active_keyset_ids(&self, mint_url: &str, unit: &CurrencyUnit) -> Vec<Id> {
        self.host.get_active_keyset_ids(mint_url, unit)
    }

    /// Return cached keyset metadata for a mint and unit, including inactive keysets.
    #[cfg(feature = "wallet")]
    pub fn cached_keysets_for_unit(
        &self,
        mint_url: &str,
        unit: &CurrencyUnit,
    ) -> Vec<(Id, ClientKeysetCacheEntry)> {
        self.host.list_keysets_for_unit(mint_url, unit)
    }

    #[cfg(feature = "wallet")]
    fn refresh_keysets_inner(&self, mint_url: &str) -> Result<String, OpenChannelError> {
        let keysets_json = self.networking.call_mint_keysets(mint_url).map_err(|e| {
            OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e)
        })?;
        let keysets_resp: serde_json::Value = serde_json::from_str(&keysets_json).map_err(|e| {
            OpenChannelError::new(
                OpenChannelFailureStage::BeforeOpeningSaved,
                None,
                format!("Failed to parse /v1/keysets response: {e}"),
            )
        })?;
        let keysets = keysets_resp
            .get("keysets")
            .and_then(|k| k.as_array())
            .ok_or_else(|| {
                OpenChannelError::new(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    None,
                    "Invalid /v1/keysets response: missing 'keysets' array",
                )
            })?;

        for keyset in keysets {
            let id_str = keyset.get("id").and_then(|v| v.as_str()).ok_or_else(|| {
                OpenChannelError::new(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    None,
                    "Missing 'id' in keyset entry",
                )
            })?;
            let id = id_str.parse::<Id>().map_err(|e| {
                OpenChannelError::new(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    None,
                    format!("Invalid keyset id: {e}"),
                )
            })?;
            let unit = keyset
                .get("unit")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    OpenChannelError::new(
                        OpenChannelFailureStage::BeforeOpeningSaved,
                        None,
                        "Missing 'unit' in keyset entry",
                    )
                })?
                .parse::<CurrencyUnit>()
                .map_err(|e| {
                    OpenChannelError::new(
                        OpenChannelFailureStage::BeforeOpeningSaved,
                        None,
                        format!("Invalid keyset unit: {e}"),
                    )
                })?;
            let active = keyset
                .get("active")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let keys_json = self
                .networking
                .call_mint_keys(mint_url, id_str)
                .map_err(|e| {
                    OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e)
                })?;
            let info_json = build_keyset_info_from_responses(&keysets_json, &keys_json, id_str)
                .map_err(|e| {
                    OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e)
                })?;
            self.host
                .set_keyset(
                    mint_url,
                    id,
                    ClientKeysetCacheEntry {
                        info_json,
                        active,
                        unit,
                    },
                )
                .map_err(|e| {
                    OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e)
                })?;
        }

        Ok(keysets_json)
    }

    /// Fetch full keyset info for the first active keyset the mint reports for a unit.
    #[cfg(feature = "wallet")]
    pub fn fetch_active_keyset_info(
        &self,
        mint_url: &str,
        unit: &CurrencyUnit,
    ) -> Result<String, OpenChannelError> {
        self.fetch_active_output_keyset(mint_url, unit)
            .map(|keyset| keyset.info_json)
    }

    #[cfg(feature = "wallet")]
    fn fetch_active_output_keyset(
        &self,
        mint_url: &str,
        unit: &CurrencyUnit,
    ) -> Result<SelectedOutputKeyset, OpenChannelError> {
        let keysets_json = self.refresh_keysets_inner(mint_url)?;
        let keyset_id = first_active_keyset_id_from_response(&keysets_json, unit).map_err(|e| {
            OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e)
        })?;
        self.cached_active_output_keyset(mint_url, unit, &keyset_id)
    }

    #[cfg(feature = "wallet")]
    fn ensure_keysets_cached_for_unit(
        &self,
        mint_url: &str,
        unit: &CurrencyUnit,
    ) -> Result<(), OpenChannelError> {
        if self.host.list_keysets_for_unit(mint_url, unit).is_empty() {
            self.refresh_keysets(mint_url)?;
        }
        Ok(())
    }

    #[cfg(feature = "wallet")]
    fn cached_active_output_keyset(
        &self,
        mint_url: &str,
        unit: &CurrencyUnit,
        preferred_keyset_id: &Id,
    ) -> Result<SelectedOutputKeyset, OpenChannelError> {
        let keyset_id = self
            .host
            .get_active_keyset_ids(mint_url, unit)
            .into_iter()
            .find(|id| id == preferred_keyset_id)
            .or_else(|| {
                self.host
                    .get_active_keyset_ids(mint_url, unit)
                    .into_iter()
                    .next()
            })
            .ok_or_else(|| {
                OpenChannelError::new(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    None,
                    format!("mint {mint_url} has no cached active keyset for unit {unit}"),
                )
            })?;
        self.host
            .get_keyset(mint_url, &keyset_id)
            .map(|entry| SelectedOutputKeyset {
                id: keyset_id.to_string(),
                info_json: entry.info_json,
            })
            .ok_or_else(|| {
                OpenChannelError::new(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    None,
                    format!("active keyset {keyset_id} was not cached"),
                )
            })
    }

    #[cfg(feature = "wallet")]
    fn first_cached_active_output_keyset(
        &self,
        mint_url: &str,
        unit: &CurrencyUnit,
    ) -> Result<SelectedOutputKeyset, OpenChannelError> {
        let keyset_id = self
            .host
            .get_active_keyset_ids(mint_url, unit)
            .into_iter()
            .next()
            .ok_or_else(|| {
                OpenChannelError::new(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    None,
                    format!("mint {mint_url} has no cached active keyset for unit {unit}"),
                )
            })?;
        self.host
            .get_keyset(mint_url, &keyset_id)
            .map(|entry| SelectedOutputKeyset {
                id: keyset_id.to_string(),
                info_json: entry.info_json,
            })
            .ok_or_else(|| {
                OpenChannelError::new(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    None,
                    format!("active keyset {keyset_id} was not cached"),
                )
            })
    }

    #[cfg(feature = "wallet")]
    fn fetch_token_input_keysets(&self, mint_url: &str, unit: &str) -> Result<String, String> {
        let unit = unit
            .parse::<CurrencyUnit>()
            .map_err(|e| format!("Invalid token unit: {e}"))?;
        let cached = self.host.list_keysets_for_unit(mint_url, &unit);
        if !cached.is_empty() {
            return input_keysets_from_cache_entries(cached, &unit);
        }

        let keysets_json = self.networking.call_mint_keysets(mint_url)?;
        token_input_keysets_from_response(&keysets_json, &unit.to_string())
    }

    #[cfg(feature = "wallet")]
    fn fetch_proof_input_keysets(
        &self,
        mint_url: &str,
        unit: &str,
        input_proofs_json: &str,
    ) -> Result<String, String> {
        let expected_unit = unit
            .parse::<CurrencyUnit>()
            .map_err(|e| format!("Invalid input proof unit: {e}"))?;
        let proof_keyset_ids = proof_keyset_ids(input_proofs_json)?;

        let mut summaries = Vec::new();
        let mut missing = Vec::new();
        for keyset_id in &proof_keyset_ids {
            match self.host.get_keyset(mint_url, keyset_id) {
                Some(entry) => summaries.push(keyset_summary_from_cache_entry(
                    *keyset_id,
                    &entry,
                    &expected_unit,
                )?),
                None => missing.push(*keyset_id),
            }
        }

        if missing.is_empty() {
            return serde_json::to_string(&summaries)
                .map_err(|e| format!("Failed to serialize cached input keysets: {e}"));
        }

        let keysets_json = self.networking.call_mint_keysets(mint_url)?;
        let fetched_json = token_input_keysets_from_response(&keysets_json, unit)?;
        let fetched: Vec<cashu::nuts::KeySetInfo> = serde_json::from_str(&fetched_json)
            .map_err(|e| format!("Failed to parse fetched input keysets: {e}"))?;

        for missing_id in missing {
            let keyset = fetched
                .iter()
                .find(|keyset| keyset.id == missing_id)
                .ok_or_else(|| {
                    format!("missing input keyset metadata for proof keyset {missing_id}")
                })?;
            summaries.push(serde_json::json!({
                "id": keyset.id.to_string(),
                "unit": keyset.unit.to_string(),
                "active": keyset.active,
                "input_fee_ppk": keyset.input_fee_ppk,
                "final_expiry": keyset.final_expiry,
            }));
        }

        serde_json::to_string(&summaries)
            .map_err(|e| format!("Failed to serialize input keysets: {e}"))
    }

    /// Open a new channel from a Cashu token using the first active output keyset.
    ///
    /// # Arguments
    /// * `token_string` - Cashu token (cashuA... or cashuB...)
    /// * `receiver_pubkey_hex` - Receiver's public key
    /// * `sender_pubkey_hex` - Sender's public key
    /// * `expiry_timestamp` - Unix timestamp for channel expiry
    /// * `mint_url` - URL of the mint to fetch keyset info from
    /// * `max_amount` - Maximum amount per output (0 = no limit)
    #[cfg(feature = "wallet")]
    #[allow(clippy::too_many_arguments)]
    pub fn open_channel_from_token_auto(
        &self,
        token_string: &str,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
        expiry_timestamp: u64,
        mint_url: &str,
        max_amount: u64,
    ) -> Result<OpenChannelResult, OpenChannelError> {
        let token_unit = token_unit(token_string)?;
        self.ensure_keysets_cached_for_unit(mint_url, &token_unit)?;

        // Opening a channel creates a mint swap whose outputs are locked to a
        // mint keyset.  Mints rotate active keysets, while clients cache keyset
        // metadata locally because swap construction needs the full keyset info
        // JSON, not just the keyset id.  Before entering the retry helper we
        // ensure the cache has at least some data for this mint/unit; inside the
        // helper the selector is cache-only.  If that cached active output
        // keyset is stale, the mint can reject the swap with a keyset error
        // before input proofs are spent.  The helper centralizes the safe
        // pattern: build and submit once, refresh/reselect on retryable keyset
        // rejection, skip the retry if refresh still selects the same keyset id,
        // otherwise rebuild and retry once.
        let result = with_active_keyset_retry(
            // Cache-only selection of the active output keyset info needed to
            // construct the funding swap.
            || self.first_cached_active_output_keyset(mint_url, &token_unit),
            // Preparation is cheap and has no external reservation here: parse
            // the token and fetch/cache metadata for the token's input keysets.
            |output_keyset| self.prepare_token_auto_attempt(mint_url, token_string, output_keyset),
            // Submission constructs the channel opening and calls the mint swap.
            |attempt| {
                self.open_channel_from_token_with_input_keysets(
                    token_string,
                    receiver_pubkey_hex,
                    sender_pubkey_hex,
                    expiry_timestamp,
                    &attempt.output_keyset.info_json,
                    &attempt.input_keysets,
                    max_amount,
                )
            },
            // Only retry explicit, safe keyset rejections.  Ambiguous submit
            // failures may have spent inputs and are never retried here.
            OpenChannelError::is_retryable_keyset_rejection,
            // On retryable keyset rejection, refresh all keysets for this mint
            // before the helper reselects from cache.
            || self.refresh_keysets(mint_url),
            // No cleanup is needed because this auto path does not reserve
            // caller-owned state outside the upstream opening record.
            |_attempt, _error| Ok(()),
        );
        unwrap_open_channel_retry_result(result)
    }

    #[cfg(feature = "wallet")]
    fn prepare_token_auto_attempt(
        &self,
        mint_url: &str,
        token_string: &str,
        output_keyset: SelectedOutputKeyset,
    ) -> Result<TokenAutoAttempt, OpenChannelError> {
        let token: cashu::nuts::Token = token_string.parse().map_err(|e| {
            OpenChannelError::new(
                OpenChannelFailureStage::BeforeOpeningSaved,
                None,
                format!("Failed to parse token: {e}"),
            )
        })?;
        let unit = token.unit().unwrap_or(cashu::nuts::CurrencyUnit::Sat);
        let input_keysets = self
            .fetch_token_input_keysets(mint_url, &unit.to_string())
            .map_err(|e| {
                OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e)
            })?;
        Ok(TokenAutoAttempt {
            output_keyset,
            input_keysets,
        })
    }

    /// Open a new channel from a Cashu token using a specific output keyset id.
    #[cfg(feature = "wallet")]
    #[allow(clippy::too_many_arguments)]
    pub fn open_channel_from_token_with_keyset_id(
        &self,
        token_string: &str,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
        expiry_timestamp: u64,
        mint_url: &str,
        keyset_id: &str,
        max_amount: u64,
    ) -> Result<OpenChannelResult, OpenChannelError> {
        let keyset_info = self.fetch_keyset_info(mint_url, keyset_id).map_err(|e| {
            OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e)
        })?;
        let token: cashu::nuts::Token = token_string.parse().map_err(|e| {
            OpenChannelError::new(
                OpenChannelFailureStage::BeforeOpeningSaved,
                None,
                format!("Failed to parse token: {e}"),
            )
        })?;
        let unit = token.unit().unwrap_or(cashu::nuts::CurrencyUnit::Sat);
        let input_keysets = self
            .fetch_token_input_keysets(mint_url, &unit.to_string())
            .map_err(|e| {
                OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e)
            })?;
        self.open_channel_from_token_with_input_keysets(
            token_string,
            receiver_pubkey_hex,
            sender_pubkey_hex,
            expiry_timestamp,
            &keyset_info,
            &input_keysets,
            max_amount,
        )
    }

    #[cfg(feature = "wallet")]
    #[allow(clippy::too_many_arguments)]
    fn open_channel_from_token_with_input_keysets(
        &self,
        token_string: &str,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
        expiry_timestamp: u64,
        keyset_info_json: &str,
        input_keysets_json: &str,
        max_amount: u64,
    ) -> Result<OpenChannelResult, OpenChannelError> {
        let channel_secret_hex = self
            .host
            .compute_channel_secret(sender_pubkey_hex, receiver_pubkey_hex)
            .map_err(|e| {
                OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e)
            })?;

        let compute_result = compute_channel_from_token_with_input_keysets(
            token_string,
            receiver_pubkey_hex,
            sender_pubkey_hex,
            &channel_secret_hex,
            expiry_timestamp,
            keyset_info_json,
            input_keysets_json,
            max_amount,
            None,
        )
        .map_err(|e| OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e))?;

        self.open_channel_from_compute_result(
            &compute_result,
            &channel_secret_hex,
            keyset_info_json,
            token_string,
            sender_pubkey_hex,
        )
    }

    /// Open a new channel from a Cashu token.
    ///
    /// This performs the full funding flow:
    /// 1. Compute ECDH channel secret via `host.compute_channel_secret()`
    /// 2. Parse the token and compute channel parameters
    /// 3. Create a funding swap request (deterministic 2-of-2 locked outputs)
    /// 4. Save channel in Opening state via `host.save_opening_channel()`
    /// 5. Submit the swap to the mint via `networking.call_mint_swap()`
    /// 6. Unblind signatures and verify DLEQ proofs
    /// 7. Verify restore path via `networking.call_mint_restore()` (temporary)
    /// 8. Transition to Open via `host.mark_channel_open()`
    ///
    /// # Arguments
    /// * `token_string` - Cashu token (cashuA... or cashuB...)
    /// * `receiver_pubkey_hex` - Receiver's public key (from server's `/channel/params`)
    /// * `sender_pubkey_hex` - Sender's public key (caller chooses which key for this channel)
    /// * `expiry_timestamp` - Unix timestamp for channel expiry (refund becomes available)
    /// * `keyset_info_json` - Keyset info JSON (from mint's `/v1/keys/{id}`)
    /// * `max_amount` - Maximum amount per output (from server policy, 0 = no limit)
    #[cfg(feature = "wallet")]
    pub fn open_channel_from_token(
        &self,
        token_string: &str,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
        expiry_timestamp: u64,
        keyset_info_json: &str,
        max_amount: u64,
    ) -> Result<OpenChannelResult, OpenChannelError> {
        // Step 1: Compute channel secret via host (ECDH delegation)
        let channel_secret_hex = self
            .host
            .compute_channel_secret(sender_pubkey_hex, receiver_pubkey_hex)
            .map_err(|e| {
                OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e)
            })?;

        // Step 2: Parse token and compute channel parameters
        let compute_result = compute_channel_from_token(
            token_string,
            receiver_pubkey_hex,
            sender_pubkey_hex,
            &channel_secret_hex,
            expiry_timestamp,
            keyset_info_json,
            max_amount,
            None,
        )
        .map_err(|e| OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e))?;

        self.open_channel_from_compute_result(
            &compute_result,
            &channel_secret_hex,
            keyset_info_json,
            token_string,
            sender_pubkey_hex,
        )
    }

    /// Open a new channel from input proofs using the first active output keyset.
    #[cfg(feature = "wallet")]
    #[allow(clippy::too_many_arguments)]
    pub fn open_channel_from_proofs_auto(
        &self,
        mint_url: &str,
        unit: &str,
        input_proofs_json: &str,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
        expiry_timestamp: u64,
        max_amount: u64,
    ) -> Result<OpenChannelResult, OpenChannelError> {
        let parsed_unit = unit
            .parse::<CurrencyUnit>()
            .unwrap_or(CurrencyUnit::Custom(unit.to_string()));
        self.ensure_keysets_cached_for_unit(mint_url, &parsed_unit)?;

        // Opening from raw proofs has the same stale-output-keyset problem as
        // token opens: output proofs must be created for an active mint keyset,
        // but the locally cached view of active keysets may be old.  We ensure
        // the cache is non-empty for this mint/unit before entering the helper;
        // after that, selection is cache-only until a retryable keyset rejection
        // triggers the helper's refresh callback.  Input proofs may come from
        // inactive/old keysets as long as the mint accepts them; the retry
        // decision is only about the selected output keyset for the new channel
        // funding swap.  Explicit-keyset methods intentionally do not use this
        // helper, because their callers have already chosen the keyset and own
        // any retry/reselection policy.
        let result = with_active_keyset_retry(
            // Cache-only selection of the first active keyset for the requested
            // unit.
            || self.first_cached_active_output_keyset(mint_url, &parsed_unit),
            // The selected output keyset is already the complete attempt input
            // for this auto path.
            Ok,
            // Construct the channel opening from the caller's proofs and submit
            // the mint swap using the selected output keyset info JSON.
            |output_keyset| {
                self.open_channel_from_proofs(
                    mint_url,
                    unit,
                    input_proofs_json,
                    receiver_pubkey_hex,
                    sender_pubkey_hex,
                    expiry_timestamp,
                    &output_keyset.info_json,
                    max_amount,
                    None,
                )
            },
            // Retry only when the mint explicitly rejected the output keyset and
            // the input proofs are known not to have been spent.
            OpenChannelError::is_retryable_keyset_rejection,
            // Refresh this mint before the helper reselects from cache.
            || self.refresh_keysets(mint_url),
            // No external reservation is owned by this upstream auto path.
            |_attempt, _error| Ok(()),
        );
        unwrap_open_channel_retry_result(result)
    }

    /// Open a new channel from input proofs using a specific output keyset id.
    ///
    /// `requested_capacity` is in raw units of the channel. Use `None` to
    /// request the maximum capacity supported by the input proofs.
    #[cfg(feature = "wallet")]
    #[allow(clippy::too_many_arguments)]
    pub fn open_channel_from_proofs_with_keyset_id(
        &self,
        mint_url: &str,
        unit: &str,
        input_proofs_json: &str,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
        expiry_timestamp: u64,
        output_keyset_id: &str,
        max_amount: u64,
        requested_capacity: Option<u64>,
    ) -> Result<OpenChannelResult, OpenChannelError> {
        let keyset_info = self
            .fetch_keyset_info(mint_url, output_keyset_id)
            .map_err(|e| {
                OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e)
            })?;
        self.open_channel_from_proofs(
            mint_url,
            unit,
            input_proofs_json,
            receiver_pubkey_hex,
            sender_pubkey_hex,
            expiry_timestamp,
            &keyset_info,
            max_amount,
            requested_capacity,
        )
    }

    /// Open a new channel from input proofs and provided output keyset info.
    ///
    /// `requested_capacity` is in raw units of the channel. Use `None` to
    /// request the maximum capacity supported by the input proofs.
    #[cfg(feature = "wallet")]
    #[allow(clippy::too_many_arguments)]
    pub fn open_channel_from_proofs(
        &self,
        mint_url: &str,
        unit: &str,
        input_proofs_json: &str,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
        expiry_timestamp: u64,
        output_keyset_info_json: &str,
        max_amount: u64,
        requested_capacity: Option<u64>,
    ) -> Result<OpenChannelResult, OpenChannelError> {
        self.open_channel_from_proofs_with_funding_amount(
            mint_url,
            unit,
            input_proofs_json,
            receiver_pubkey_hex,
            sender_pubkey_hex,
            expiry_timestamp,
            output_keyset_info_json,
            max_amount,
            requested_capacity,
            None,
        )
    }

    /// Open a new channel while optionally allocating only part of the selected
    /// post-swap input value to the channel funding token. Any remainder is
    /// returned as plain change proofs in [`OpenChannelResult::change_proofs_json`].
    #[cfg(feature = "wallet")]
    #[allow(clippy::too_many_arguments)]
    pub fn open_channel_from_proofs_with_funding_amount(
        &self,
        mint_url: &str,
        unit: &str,
        input_proofs_json: &str,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
        expiry_timestamp: u64,
        output_keyset_info_json: &str,
        max_amount: u64,
        requested_capacity: Option<u64>,
        requested_funding_token_amount: Option<u64>,
    ) -> Result<OpenChannelResult, OpenChannelError> {
        let channel_secret_hex = self
            .host
            .compute_channel_secret(sender_pubkey_hex, receiver_pubkey_hex)
            .map_err(|e| {
                OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e)
            })?;
        let input_keysets = self
            .fetch_proof_input_keysets(mint_url, unit, input_proofs_json)
            .map_err(|e| {
                OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e)
            })?;
        let compute_result = compute_channel_from_proofs_with_input_keysets_and_funding_amount(
            mint_url,
            unit,
            input_proofs_json,
            &input_keysets,
            receiver_pubkey_hex,
            sender_pubkey_hex,
            &channel_secret_hex,
            expiry_timestamp,
            output_keyset_info_json,
            max_amount,
            requested_capacity,
            requested_funding_token_amount,
        )
        .map_err(|e| OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e))?;

        self.open_channel_from_compute_result(
            &compute_result,
            &channel_secret_hex,
            output_keyset_info_json,
            input_proofs_json,
            sender_pubkey_hex,
        )
    }

    #[cfg(feature = "wallet")]
    fn open_channel_from_compute_result(
        &self,
        compute_result: &str,
        channel_secret_hex: &str,
        keyset_info_json: &str,
        input_token: &str,
        sender_pubkey_hex: &str,
    ) -> Result<OpenChannelResult, OpenChannelError> {
        let compute_json: serde_json::Value =
            serde_json::from_str(compute_result).map_err(|e| {
                OpenChannelError::new(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    None,
                    format!("Failed to parse compute result: {e}"),
                )
            })?;

        let capacity = compute_json["capacity"].as_u64().ok_or_else(|| {
            OpenChannelError::new(
                OpenChannelFailureStage::BeforeOpeningSaved,
                None,
                "Missing 'capacity' in compute result",
            )
        })?;
        let funding_token_amount =
            compute_json["funding_token_amount"]
                .as_u64()
                .ok_or_else(|| {
                    OpenChannelError::new(
                        OpenChannelFailureStage::BeforeOpeningSaved,
                        None,
                        "Missing 'funding_token_amount' in compute result",
                    )
                })?;
        let mint_url = compute_json["mint_url"]
            .as_str()
            .ok_or_else(|| {
                OpenChannelError::new(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    None,
                    "Missing 'mint_url' in compute result",
                )
            })?
            .to_string();
        let params_json = compute_json["params_json"].as_str().ok_or_else(|| {
            OpenChannelError::new(
                OpenChannelFailureStage::BeforeOpeningSaved,
                None,
                "Missing 'params_json' in compute result",
            )
        })?;
        let proofs_json = compute_json["proofs_json"].as_str().ok_or_else(|| {
            OpenChannelError::new(
                OpenChannelFailureStage::BeforeOpeningSaved,
                None,
                "Missing 'proofs_json' in compute result",
            )
        })?;
        let unit = compute_json["unit"]
            .as_str()
            .ok_or_else(|| {
                OpenChannelError::new(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    None,
                    "Missing 'unit' in compute result",
                )
            })?
            .to_string();
        let output_keyset_id = compute_json["output_keyset_id"]
            .as_str()
            .ok_or_else(|| {
                OpenChannelError::new(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    None,
                    "Missing 'output_keyset_id' in compute result",
                )
            })?
            .to_string();
        let change_amount_raw = compute_json["change_amount_raw"].as_u64().unwrap_or(0);
        let receiver_pubkey_hex = compute_json["receiver_pubkey_hex"]
            .as_str()
            .ok_or_else(|| {
                OpenChannelError::new(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    None,
                    "Missing 'receiver_pubkey_hex' in compute result",
                )
            })?
            .to_string();

        let swap_result = create_funding_swap_with_plain_change(
            params_json,
            channel_secret_hex,
            keyset_info_json,
            proofs_json,
            change_amount_raw,
        )
        .map_err(|e| OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e))?;
        let swap_json: serde_json::Value = serde_json::from_str(&swap_result).map_err(|e| {
            OpenChannelError::new(
                OpenChannelFailureStage::BeforeOpeningSaved,
                None,
                format!("Failed to parse swap result: {e}"),
            )
        })?;
        let swap_request_json = swap_json["swap_request_json"].as_str().ok_or_else(|| {
            OpenChannelError::new(
                OpenChannelFailureStage::BeforeOpeningSaved,
                None,
                "Missing 'swap_request_json' in swap result",
            )
        })?;
        let funding_secrets_json = swap_json["funding_secrets_json"].as_str().ok_or_else(|| {
            OpenChannelError::new(
                OpenChannelFailureStage::BeforeOpeningSaved,
                None,
                "Missing 'funding_secrets_json' in swap result",
            )
        })?;
        let change_secrets_json = swap_json["change_secrets_json"].as_str().ok_or_else(|| {
            OpenChannelError::new(
                OpenChannelFailureStage::BeforeOpeningSaved,
                None,
                "Missing 'change_secrets_json' in swap result",
            )
        })?;

        let channel_id = super::bindings::channel_parameters_get_channel_id(
            params_json,
            channel_secret_hex,
            keyset_info_json,
        )
        .map_err(|e| OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e))?;

        let opening = ClientChannelOpeningFromSwap {
            params_json: params_json.to_string(),
            channel_secret_hex: channel_secret_hex.to_string(),
            keyset_info_json: keyset_info_json.to_string(),
            sender_pubkey_hex: sender_pubkey_hex.to_string(),
            receiver_pubkey_hex: receiver_pubkey_hex.clone(),
            capacity,
            funding_token_amount,
            mint_url: mint_url.clone(),
            unit: unit.clone(),
            input_token: input_token.to_string(),
            change_secrets_json: change_secrets_json.to_string(),
            change_amount_raw,
            created_at: self.host.now_seconds(),
        };

        self.host
            .save_opening_from_swap_channel(&channel_id, opening)
            .map_err(|e| {
                OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e)
            })?;

        let swap_response_json = self
            .networking
            .call_mint_swap(&mint_url, swap_request_json)
            .map_err(|e| {
                let message = normalize_mint_error_string(e);
                if is_explicit_mint_rejection(&message) {
                    let failure = ClientOpeningFailure {
                        stage: OpenChannelFailureStage::MintRejected.as_str().to_string(),
                        message: message.clone(),
                        failed_at: self.host.now_seconds(),
                    };
                    if let Err(mark_err) = self.host.mark_channel_opening_failed(&channel_id, failure) {
                        return OpenChannelError::new(
                            OpenChannelFailureStage::MarkOpen,
                            Some(channel_id.clone()),
                            format!("mint rejected swap, but failed to mark opening failed: {mark_err}; mint error: {message}"),
                        );
                    }
                    OpenChannelError::new(
                        OpenChannelFailureStage::MintRejected,
                        Some(channel_id.clone()),
                        message,
                    )
                } else {
                    OpenChannelError::new(
                        OpenChannelFailureStage::SwapSubmitted,
                        Some(channel_id.clone()),
                        message,
                    )
                }
            })?;

        let complete_result = complete_funding_swap_with_plain_change(
            &swap_response_json,
            funding_secrets_json,
            change_secrets_json,
            keyset_info_json,
        )
        .map_err(|e| {
            OpenChannelError::new(
                OpenChannelFailureStage::SwapSubmitted,
                Some(channel_id.clone()),
                e,
            )
        })?;
        let complete_json: serde_json::Value =
            serde_json::from_str(&complete_result).map_err(|e| {
                OpenChannelError::new(
                    OpenChannelFailureStage::FundingProofsReceived,
                    Some(channel_id.clone()),
                    format!("Failed to parse complete result: {e}"),
                )
            })?;
        let funding_proofs_json =
            complete_json["funding_proofs_json"]
                .as_str()
                .ok_or_else(|| {
                    OpenChannelError::new(
                        OpenChannelFailureStage::FundingProofsReceived,
                        Some(channel_id.clone()),
                        "Missing 'funding_proofs_json' in complete result",
                    )
                })?;
        let change_proofs_json = complete_json["change_proofs_json"].as_str().unwrap_or("[]");

        let restore_request =
            create_funding_restore_request(params_json, channel_secret_hex, keyset_info_json)
                .map_err(|e| {
                    OpenChannelError::new(
                        OpenChannelFailureStage::FundingProofsReceived,
                        Some(channel_id.clone()),
                        e,
                    )
                })?;
        let restore_response = self
            .networking
            .call_mint_restore(&mint_url, &restore_request)
            .map_err(|e| {
                OpenChannelError::new(
                    OpenChannelFailureStage::RestoreVerification,
                    Some(channel_id.clone()),
                    e,
                )
            })?;
        let restore_result = complete_funding_restore(
            &restore_response,
            params_json,
            channel_secret_hex,
            keyset_info_json,
        )
        .map_err(|e| {
            OpenChannelError::new(
                OpenChannelFailureStage::RestoreVerification,
                Some(channel_id.clone()),
                e,
            )
        })?;
        let restore_json: serde_json::Value =
            serde_json::from_str(&restore_result).map_err(|e| {
                OpenChannelError::new(
                    OpenChannelFailureStage::RestoreVerification,
                    Some(channel_id.clone()),
                    format!("Failed to parse restore result: {e}"),
                )
            })?;
        let restored_proofs_json =
            restore_json["funding_proofs_json"]
                .as_str()
                .ok_or_else(|| {
                    OpenChannelError::new(
                        OpenChannelFailureStage::RestoreVerification,
                        Some(channel_id.clone()),
                        "Missing 'funding_proofs_json' in restore result",
                    )
                })?;

        if funding_proofs_json != restored_proofs_json {
            return Err(OpenChannelError::new(
                OpenChannelFailureStage::RestoreVerification,
                Some(channel_id.clone()),
                "Restore verification failed: swap proofs differ from restored proofs",
            ));
        }

        self.host
            .mark_channel_open(&channel_id, funding_proofs_json)
            .map_err(|e| {
                OpenChannelError::new(
                    OpenChannelFailureStage::MarkOpen,
                    Some(channel_id.clone()),
                    e,
                )
            })?;

        Ok(OpenChannelResult {
            channel_id,
            capacity,
            funding_token_amount,
            mint_url,
            unit,
            keyset_id: output_keyset_id,
            sender_pubkey_hex: sender_pubkey_hex.to_string(),
            receiver_pubkey_hex,
            change_proofs_json: change_proofs_json.to_string(),
        })
    }

    /// Open a channel from a Cashu token (async version for WASM).
    ///
    /// This is the async counterpart of `open_channel_from_token`, designed for
    /// environments like WASM where networking must be asynchronous.
    ///
    /// Takes an async networking implementation instead of using the bridge's
    /// sync networking.
    #[cfg(feature = "wallet")]
    #[allow(clippy::too_many_arguments)]
    pub async fn open_channel_from_token_async<AN: SpilmanClientAsyncNetworking>(
        &self,
        token_string: &str,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
        expiry_timestamp: u64,
        keyset_info_json: &str,
        max_amount: u64,
        async_networking: &AN,
    ) -> Result<OpenChannelResult, OpenChannelError> {
        // Step 1: Compute channel secret via host (ECDH delegation)
        let channel_secret_hex = self
            .host
            .compute_channel_secret(sender_pubkey_hex, receiver_pubkey_hex)
            .map_err(|e| {
                OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e)
            })?;

        // Step 2: Parse token and compute channel parameters
        let compute_result = compute_channel_from_token(
            token_string,
            receiver_pubkey_hex,
            sender_pubkey_hex,
            &channel_secret_hex,
            expiry_timestamp,
            keyset_info_json,
            max_amount,
            None,
        )
        .map_err(|e| OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e))?;

        let compute_json: serde_json::Value =
            serde_json::from_str(&compute_result).map_err(|e| {
                OpenChannelError::new(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    None,
                    format!("Failed to parse compute result: {e}"),
                )
            })?;

        let capacity = compute_json["capacity"].as_u64().ok_or_else(|| {
            OpenChannelError::new(
                OpenChannelFailureStage::BeforeOpeningSaved,
                None,
                "Missing 'capacity' in compute result",
            )
        })?;
        let funding_token_amount =
            compute_json["funding_token_amount"]
                .as_u64()
                .ok_or_else(|| {
                    OpenChannelError::new(
                        OpenChannelFailureStage::BeforeOpeningSaved,
                        None,
                        "Missing 'funding_token_amount' in compute result",
                    )
                })?;
        let mint_url = compute_json["mint_url"]
            .as_str()
            .ok_or_else(|| {
                OpenChannelError::new(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    None,
                    "Missing 'mint_url' in compute result",
                )
            })?
            .to_string();
        let params_json = compute_json["params_json"].as_str().ok_or_else(|| {
            OpenChannelError::new(
                OpenChannelFailureStage::BeforeOpeningSaved,
                None,
                "Missing 'params_json' in compute result",
            )
        })?;
        let proofs_json = compute_json["proofs_json"].as_str().ok_or_else(|| {
            OpenChannelError::new(
                OpenChannelFailureStage::BeforeOpeningSaved,
                None,
                "Missing 'proofs_json' in compute result",
            )
        })?;
        let unit = compute_json["unit"]
            .as_str()
            .ok_or_else(|| {
                OpenChannelError::new(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    None,
                    "Missing 'unit' in compute result",
                )
            })?
            .to_string();
        let output_keyset_id = compute_json["output_keyset_id"]
            .as_str()
            .ok_or_else(|| {
                OpenChannelError::new(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    None,
                    "Missing 'output_keyset_id' in compute result",
                )
            })?
            .to_string();
        let change_amount_raw = compute_json["change_amount_raw"].as_u64().unwrap_or(0);
        let receiver_pubkey_hex_from_compute = compute_json["receiver_pubkey_hex"]
            .as_str()
            .ok_or_else(|| {
                OpenChannelError::new(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    None,
                    "Missing 'receiver_pubkey_hex' in compute result",
                )
            })?
            .to_string();

        // Step 3: Create funding swap request
        let swap_result = create_funding_swap_with_plain_change(
            params_json,
            &channel_secret_hex,
            keyset_info_json,
            proofs_json,
            change_amount_raw,
        )
        .map_err(|e| OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e))?;

        let swap_json: serde_json::Value = serde_json::from_str(&swap_result).map_err(|e| {
            OpenChannelError::new(
                OpenChannelFailureStage::BeforeOpeningSaved,
                None,
                format!("Failed to parse swap result: {e}"),
            )
        })?;

        let swap_request_json = swap_json["swap_request_json"].as_str().ok_or_else(|| {
            OpenChannelError::new(
                OpenChannelFailureStage::BeforeOpeningSaved,
                None,
                "Missing 'swap_request_json' in swap result",
            )
        })?;
        let funding_secrets_json = swap_json["funding_secrets_json"].as_str().ok_or_else(|| {
            OpenChannelError::new(
                OpenChannelFailureStage::BeforeOpeningSaved,
                None,
                "Missing 'funding_secrets_json' in swap result",
            )
        })?;
        let change_secrets_json = swap_json["change_secrets_json"].as_str().ok_or_else(|| {
            OpenChannelError::new(
                OpenChannelFailureStage::BeforeOpeningSaved,
                None,
                "Missing 'change_secrets_json' in swap result",
            )
        })?;

        // Compute channel ID
        let channel_id = super::bindings::channel_parameters_get_channel_id(
            params_json,
            &channel_secret_hex,
            keyset_info_json,
        )
        .map_err(|e| OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e))?;

        // Step 4: Save channel in OpeningFromSwap state (before the swap)
        let opening = ClientChannelOpeningFromSwap {
            params_json: params_json.to_string(),
            channel_secret_hex: channel_secret_hex.clone(),
            keyset_info_json: keyset_info_json.to_string(),
            sender_pubkey_hex: sender_pubkey_hex.to_string(),
            receiver_pubkey_hex: receiver_pubkey_hex_from_compute.clone(),
            capacity,
            funding_token_amount,
            mint_url: mint_url.clone(),
            unit: unit.clone(),
            input_token: token_string.to_string(),
            change_secrets_json: change_secrets_json.to_string(),
            change_amount_raw,
            created_at: self.host.now_seconds(),
        };

        self.host
            .save_opening_from_swap_channel(&channel_id, opening)
            .map_err(|e| {
                OpenChannelError::new(OpenChannelFailureStage::BeforeOpeningSaved, None, e)
            })?;

        // Step 5: Submit swap to mint (async)
        let swap_response_json = async_networking
            .call_mint_swap(&mint_url, swap_request_json)
            .await
            .map_err(|e| {
                let message = normalize_mint_error_string(e);
                if is_explicit_mint_rejection(&message) {
                    let failure = ClientOpeningFailure {
                        stage: OpenChannelFailureStage::MintRejected.as_str().to_string(),
                        message: message.clone(),
                        failed_at: self.host.now_seconds(),
                    };
                    if let Err(mark_err) = self.host.mark_channel_opening_failed(&channel_id, failure) {
                        return OpenChannelError::new(
                            OpenChannelFailureStage::MarkOpen,
                            Some(channel_id.clone()),
                            format!("mint rejected swap, but failed to mark opening failed: {mark_err}; mint error: {message}"),
                        );
                    }
                    OpenChannelError::new(
                        OpenChannelFailureStage::MintRejected,
                        Some(channel_id.clone()),
                        message,
                    )
                } else {
                    OpenChannelError::new(
                        OpenChannelFailureStage::SwapSubmitted,
                        Some(channel_id.clone()),
                        message,
                    )
                }
            })?;

        // Step 6: Unblind signatures and verify DLEQ
        let complete_result = complete_funding_swap_with_plain_change(
            &swap_response_json,
            funding_secrets_json,
            change_secrets_json,
            keyset_info_json,
        )
        .map_err(|e| {
            OpenChannelError::new(
                OpenChannelFailureStage::SwapSubmitted,
                Some(channel_id.clone()),
                e,
            )
        })?;

        let complete_json: serde_json::Value =
            serde_json::from_str(&complete_result).map_err(|e| {
                OpenChannelError::new(
                    OpenChannelFailureStage::FundingProofsReceived,
                    Some(channel_id.clone()),
                    format!("Failed to parse complete result: {e}"),
                )
            })?;

        let funding_proofs_json =
            complete_json["funding_proofs_json"]
                .as_str()
                .ok_or_else(|| {
                    OpenChannelError::new(
                        OpenChannelFailureStage::FundingProofsReceived,
                        Some(channel_id.clone()),
                        "Missing 'funding_proofs_json' in complete result",
                    )
                })?;
        let change_proofs_json = complete_json["change_proofs_json"].as_str().unwrap_or("[]");

        // Step 6b: Verify restore path produces identical proofs
        let restore_request =
            create_funding_restore_request(params_json, &channel_secret_hex, keyset_info_json)
                .map_err(|e| {
                    OpenChannelError::new(
                        OpenChannelFailureStage::FundingProofsReceived,
                        Some(channel_id.clone()),
                        e,
                    )
                })?;
        let restore_response = async_networking
            .call_mint_restore(&mint_url, &restore_request)
            .await
            .map_err(|e| {
                OpenChannelError::new(
                    OpenChannelFailureStage::RestoreVerification,
                    Some(channel_id.clone()),
                    e,
                )
            })?;
        let restore_result = complete_funding_restore(
            &restore_response,
            params_json,
            &channel_secret_hex,
            keyset_info_json,
        )
        .map_err(|e| {
            OpenChannelError::new(
                OpenChannelFailureStage::RestoreVerification,
                Some(channel_id.clone()),
                e,
            )
        })?;
        let restore_json: serde_json::Value =
            serde_json::from_str(&restore_result).map_err(|e| {
                OpenChannelError::new(
                    OpenChannelFailureStage::RestoreVerification,
                    Some(channel_id.clone()),
                    format!("Failed to parse restore result: {e}"),
                )
            })?;
        let restored_proofs_json =
            restore_json["funding_proofs_json"]
                .as_str()
                .ok_or_else(|| {
                    OpenChannelError::new(
                        OpenChannelFailureStage::RestoreVerification,
                        Some(channel_id.clone()),
                        "Missing 'funding_proofs_json' in restore result",
                    )
                })?;

        if funding_proofs_json != restored_proofs_json {
            return Err(OpenChannelError::new(
                OpenChannelFailureStage::RestoreVerification,
                Some(channel_id.clone()),
                "Restore verification failed: swap proofs differ from restored proofs",
            ));
        }

        // Step 7: Transition to Open
        self.host
            .mark_channel_open(&channel_id, funding_proofs_json)
            .map_err(|e| {
                OpenChannelError::new(
                    OpenChannelFailureStage::MarkOpen,
                    Some(channel_id.clone()),
                    e,
                )
            })?;

        Ok(OpenChannelResult {
            channel_id,
            capacity,
            funding_token_amount,
            mint_url,
            unit,
            keyset_id: output_keyset_id,
            sender_pubkey_hex: sender_pubkey_hex.to_string(),
            receiver_pubkey_hex: receiver_pubkey_hex_from_compute,
            change_proofs_json: change_proofs_json.to_string(),
        })
    }

    /// Restore funding proofs for a channel using NUT-09.
    ///
    /// Given a channel ID in OpeningFromSwap state, reconstructs the
    /// deterministic blinded messages, calls `/v1/restore`, unblinds the
    /// response, and returns the funding proofs JSON string.
    ///
    /// This can be used to recover from a failed `open_channel_from_token`
    /// where the swap succeeded on the mint's side but the client lost
    /// the response.
    #[cfg(feature = "wallet")]
    pub fn restore_funding_proofs(&self, channel_id: &str) -> Result<String, String> {
        let opening = self
            .host
            .get_channel_opening_from_swap(channel_id)
            .ok_or_else(|| format!("Channel not found in OpeningFromSwap state: {}", channel_id))?;

        let restore_request = create_funding_restore_request(
            &opening.params_json,
            &opening.channel_secret_hex,
            &opening.keyset_info_json,
        )?;

        let restore_response = self
            .networking
            .call_mint_restore(&opening.mint_url, &restore_request)?;

        let result = complete_funding_restore(
            &restore_response,
            &opening.params_json,
            &opening.channel_secret_hex,
            &opening.keyset_info_json,
        )?;

        let result_json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|e| format!("Failed to parse restore result: {}", e))?;

        result_json["funding_proofs_json"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| "Missing 'funding_proofs_json' in restore result".to_string())
    }

    /// Restore plain change proofs for an opening channel using persisted change secrets.
    #[cfg(feature = "wallet")]
    pub fn restore_change_proofs(&self, channel_id: &str) -> Result<String, String> {
        let opening = self
            .host
            .get_channel_opening_from_swap(channel_id)
            .ok_or_else(|| format!("Channel not found in OpeningFromSwap state: {}", channel_id))?;

        if opening.change_amount_raw == 0 {
            return Ok("[]".to_string());
        }

        let restore_request = create_plain_change_restore_request(
            &opening.change_secrets_json,
            &opening.keyset_info_json,
        )?;

        let restore_response = self
            .networking
            .call_mint_restore(&opening.mint_url, &restore_request)?;

        let result = complete_plain_change_restore(
            &restore_response,
            &opening.change_secrets_json,
            &opening.keyset_info_json,
        )?;

        let result_json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|e| format!("Failed to parse change restore result: {}", e))?;

        result_json["change_proofs_json"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| "Missing 'change_proofs_json' in change restore result".to_string())
    }

    /// Recover an `OpeningFromSwap` channel by restoring funding proofs and marking it open.
    #[cfg(feature = "wallet")]
    pub fn recover_open_channel_from_swap(
        &self,
        channel_id: &str,
    ) -> Result<OpenChannelResult, OpenChannelError> {
        let opening = self
            .host
            .get_channel_opening_from_swap(channel_id)
            .ok_or_else(|| {
                OpenChannelError::new(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    Some(channel_id.to_string()),
                    format!("Channel not found in OpeningFromSwap state: {channel_id}"),
                )
            })?;
        let funding_proofs_json = self.restore_funding_proofs(channel_id).map_err(|e| {
            OpenChannelError::new(
                OpenChannelFailureStage::RestoreVerification,
                Some(channel_id.to_string()),
                e,
            )
        })?;
        let change_proofs_json = self.restore_change_proofs(channel_id).map_err(|e| {
            OpenChannelError::new(
                OpenChannelFailureStage::RestoreVerification,
                Some(channel_id.to_string()),
                e,
            )
        })?;
        self.host
            .mark_channel_open(channel_id, &funding_proofs_json)
            .map_err(|e| {
                OpenChannelError::new(
                    OpenChannelFailureStage::MarkOpen,
                    Some(channel_id.to_string()),
                    e,
                )
            })?;
        let keyset_info = parse_keyset_info_from_json(&opening.keyset_info_json).map_err(|e| {
            OpenChannelError::new(
                OpenChannelFailureStage::MarkOpen,
                Some(channel_id.to_string()),
                format!("Failed to parse stored keyset info: {e}"),
            )
        })?;
        Ok(OpenChannelResult {
            channel_id: channel_id.to_string(),
            capacity: opening.capacity,
            funding_token_amount: opening.funding_token_amount,
            mint_url: opening.mint_url,
            unit: opening.unit,
            keyset_id: keyset_info.keyset_id.to_string(),
            sender_pubkey_hex: opening.sender_pubkey_hex,
            receiver_pubkey_hex: opening.receiver_pubkey_hex,
            change_proofs_json,
        })
    }

    /// Restore funding proofs for a channel using NUT-09 (async version).
    #[cfg(feature = "wallet")]
    pub async fn restore_funding_proofs_async<AN: SpilmanClientAsyncNetworking>(
        &self,
        channel_id: &str,
        async_networking: &AN,
    ) -> Result<String, String> {
        let opening = self
            .host
            .get_channel_opening_from_swap(channel_id)
            .ok_or_else(|| format!("Channel not found in OpeningFromSwap state: {}", channel_id))?;

        let restore_request = create_funding_restore_request(
            &opening.params_json,
            &opening.channel_secret_hex,
            &opening.keyset_info_json,
        )?;

        let restore_response = async_networking
            .call_mint_restore(&opening.mint_url, &restore_request)
            .await?;

        let result = complete_funding_restore(
            &restore_response,
            &opening.params_json,
            &opening.channel_secret_hex,
            &opening.keyset_info_json,
        )?;

        let result_json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|e| format!("Failed to parse restore result: {}", e))?;

        result_json["funding_proofs_json"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| "Missing 'funding_proofs_json' in restore result".to_string())
    }

    /// Restore plain change proofs for an opening channel using async networking.
    #[cfg(feature = "wallet")]
    pub async fn restore_change_proofs_async<AN: SpilmanClientAsyncNetworking>(
        &self,
        channel_id: &str,
        async_networking: &AN,
    ) -> Result<String, String> {
        let opening = self
            .host
            .get_channel_opening_from_swap(channel_id)
            .ok_or_else(|| format!("Channel not found in OpeningFromSwap state: {}", channel_id))?;

        if opening.change_amount_raw == 0 {
            return Ok("[]".to_string());
        }

        let restore_request = create_plain_change_restore_request(
            &opening.change_secrets_json,
            &opening.keyset_info_json,
        )?;

        let restore_response = async_networking
            .call_mint_restore(&opening.mint_url, &restore_request)
            .await?;

        let result = complete_plain_change_restore(
            &restore_response,
            &opening.change_secrets_json,
            &opening.keyset_info_json,
        )?;

        let result_json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|e| format!("Failed to parse change restore result: {}", e))?;

        result_json["change_proofs_json"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| "Missing 'change_proofs_json' in change restore result".to_string())
    }

    /// Create a payment for a channel (without funding data).
    ///
    /// Returns a `Payment` struct ready to send to the server.
    /// Use this for subsequent payments after the channel is registered.
    ///
    /// The `balance` is the cumulative amount the receiver can claim.
    ///
    /// # Errors
    /// - Returns an error if the channel doesn't exist or is closed
    /// - Returns an error if `balance` exceeds the channel capacity
    pub fn create_payment(&self, channel_id: &str, balance: u64) -> Result<Payment, String> {
        self.create_payment_internal(channel_id, balance, false)
    }

    /// Create a payment with funding data (for first payment).
    ///
    /// Returns a `Payment` struct with `params` and `funding_proofs` included.
    /// Use this for the first payment when registering a channel with the server.
    ///
    /// The same validation rules apply as `create_payment()`.
    pub fn create_payment_with_funding(
        &self,
        channel_id: &str,
        balance: u64,
    ) -> Result<Payment, String> {
        self.create_payment_internal(channel_id, balance, true)
    }

    /// Internal implementation for creating payments.
    fn create_payment_internal(
        &self,
        channel_id: &str,
        balance: u64,
        include_funding: bool,
    ) -> Result<Payment, String> {
        // Load channel funding data
        let funding = self
            .host
            .get_channel_funding(channel_id)
            .ok_or_else(|| format!("Channel not found: {}", channel_id))?;

        // Check channel state
        let state = self
            .host
            .get_channel_state(channel_id)
            .ok_or_else(|| format!("Channel not found: {}", channel_id))?;
        if !state.is_payable() {
            return Err(format!(
                "Channel is not usable for payments: {} ({:?})",
                channel_id, state
            ));
        }

        // Validate balance doesn't exceed capacity
        if balance > funding.capacity {
            return Err(format!(
                "Balance {} exceeds channel capacity {}",
                balance, funding.capacity
            ));
        }

        // Create unsigned balance update and sign it
        let unsigned = self.create_unsigned_balance_update(channel_id, balance, &funding)?;
        let balance_update = self.sign_balance_update(unsigned, &funding.sender_pubkey_hex)?;

        let signature = balance_update.signature.to_string();

        // Record the payment state
        let payment_state = self.host.get_payment_state(channel_id);
        let payment_count = payment_state.map(|s| s.payment_count).unwrap_or(0) + 1;

        self.host.record_payment(
            channel_id,
            ClientPaymentState {
                balance,
                signature: signature.clone(),
                payment_count,
                last_payment_at: self.host.now_seconds(),
            },
        )?;

        // Build the Payment struct
        if include_funding {
            let params: serde_json::Value = serde_json::from_str(&funding.params_json)
                .map_err(|e| format!("Failed to parse params: {}", e))?;
            let funding_proofs: Vec<Proof> = serde_json::from_str(&funding.funding_proofs_json)
                .map_err(|e| format!("Failed to parse funding proofs: {}", e))?;

            Ok(Payment::with_funding(
                channel_id.to_string(),
                balance,
                signature,
                params,
                funding_proofs,
            ))
        } else {
            Ok(Payment::new(channel_id.to_string(), balance, signature))
        }
    }

    /// Build a complete `X-Cashu-Channel` payment header value.
    ///
    /// Returns a base64-encoded JSON string ready to use as the header value.
    ///
    /// If `include_funding` is true, the header includes `params` and `funding_proofs`
    /// (needed for the first request, or when the server doesn't know this channel yet).
    pub fn build_payment_header(
        &self,
        channel_id: &str,
        balance: u64,
        include_funding: bool,
    ) -> Result<String, String> {
        let payment = self.create_payment_internal(channel_id, balance, include_funding)?;
        let header_json =
            serde_json::to_string(&payment).map_err(|e| format!("Failed to serialize: {}", e))?;
        Ok(base64::prelude::BASE64_STANDARD.encode(header_json))
    }

    /// Get information about a stored channel.
    pub fn get_channel_info(&self, channel_id: &str) -> Option<ClientChannelInfo> {
        let funding = self.host.get_channel_funding(channel_id)?;
        let payment_state = self.host.get_payment_state(channel_id);
        let current_balance = payment_state.as_ref().map(|s| s.balance).unwrap_or(0);
        let payment_count = payment_state.as_ref().map(|s| s.payment_count).unwrap_or(0);

        let state = self.host.get_channel_state(channel_id)?;

        Some(ClientChannelInfo {
            channel_id: channel_id.to_string(),
            capacity: funding.capacity,
            funding_token_amount: funding.funding_token_amount,
            mint_url: funding.mint_url,
            current_balance,
            payment_count,
            state,
        })
    }

    /// Get immutable funding data for an open channel.
    #[cfg(feature = "wallet")]
    pub fn get_channel_funding(&self, channel_id: &str) -> Option<ClientChannelFunding> {
        self.host.get_channel_funding(channel_id)
    }

    /// List all stored channel IDs.
    pub fn list_channels(&self) -> Vec<String> {
        self.host.list_channel_ids()
    }

    /// Close a channel locally.
    ///
    /// Marks the channel as closed so no more payments can be made.
    /// Does not communicate with the server.
    pub fn close_channel(&self, channel_id: &str) -> Result<(), String> {
        self.host.mark_channel_closed(channel_id)
    }

    /// Mark a channel as unusable while retaining it in storage.
    ///
    /// This moves the channel into the `Closing` state so it will no longer be
    /// selected for new payments.
    pub fn mark_channel_unusable(&self, channel_id: &str) -> Result<(), String> {
        self.host.mark_channel_closing(channel_id)
    }

    /// Delete a channel from storage.
    ///
    /// Removes all data associated with the channel.
    pub fn delete_channel(&self, channel_id: &str) -> Result<(), String> {
        self.host.delete_channel(channel_id)
    }

    /// Create a cooperative close request for a channel.
    ///
    /// Creates a payment at the final balance that can be sent to the
    /// server's close endpoint.
    pub fn create_cooperative_close_request(
        &self,
        channel_id: &str,
        final_balance: u64,
    ) -> Result<Payment, String> {
        // Use create_payment which validates and records the payment
        self.create_payment(channel_id, final_balance)
    }

    /// Process a cooperative close response from the server.
    ///
    /// Marks the channel as closed locally.
    pub fn process_cooperative_close_response(&self, response_json: &str) -> Result<(), String> {
        let response: serde_json::Value = serde_json::from_str(response_json)
            .map_err(|e| format!("Failed to parse close response: {}", e))?;

        let channel_id = response["channel_id"]
            .as_str()
            .ok_or("Missing 'channel_id' in close response")?;

        self.host.mark_channel_closed(channel_id)?;

        Ok(())
    }

    // ========================================================================
    // Balance Update Helpers
    // ========================================================================

    /// Create an unsigned balance update for a channel.
    ///
    /// This computes the message hash and tweak scalar needed for signing.
    /// The caller can inspect the `UnsignedBalanceUpdate`, then call
    /// `sign_balance_update()` to produce a `BalanceUpdateMessage`.
    ///
    /// For most use cases, prefer `create_payment()` which handles signing
    /// automatically via the host.
    pub fn create_unsigned_balance_update(
        &self,
        channel_id: &str,
        balance: u64,
        funding: &ClientChannelFunding,
    ) -> Result<UnsignedBalanceUpdate, String> {
        UnsignedBalanceUpdate::new(channel_id, balance, funding)
    }

    /// Sign an unsigned balance update using the host.
    ///
    /// Delegates to `host.sign_with_tweaked_key()` to produce the signature,
    /// then assembles the final `BalanceUpdateMessage`.
    pub fn sign_balance_update(
        &self,
        unsigned: UnsignedBalanceUpdate,
        sender_pubkey_hex: &str,
    ) -> Result<BalanceUpdateMessage, String> {
        let signature_hex = self.host.sign_with_tweaked_key(
            sender_pubkey_hex,
            &unsigned.message_hex,
            &unsigned.tweak_scalar_hex,
        )?;

        unsigned.sign(&signature_hex)
    }
}

// ============================================================================
// Utility functions
// ============================================================================

/// Base64 decode a string (standard encoding).
pub fn base64_decode(input: &str) -> Result<String, String> {
    let bytes = base64::prelude::BASE64_STANDARD
        .decode(input.trim())
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    String::from_utf8(bytes).map_err(|e| format!("Invalid UTF-8 in base64 decode: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "wallet")]
    use crate::KeysetInfo;
    #[cfg(feature = "wallet")]
    use std::cell::Cell;
    #[cfg(feature = "wallet")]
    use std::collections::HashMap;
    #[cfg(feature = "wallet")]
    use std::rc::Rc;

    struct NoopNetworking;

    impl SpilmanClientNetworking for NoopNetworking {
        fn call_mint_swap(&self, _: &str, _: &str) -> Result<String, String> {
            Err("not used".to_string())
        }

        fn call_mint_restore(&self, _: &str, _: &str) -> Result<String, String> {
            Err("not used".to_string())
        }

        fn call_mint_keysets(&self, _: &str) -> Result<String, String> {
            Err("not used".to_string())
        }

        fn call_mint_keys(&self, _: &str, _: &str) -> Result<String, String> {
            Err("not used".to_string())
        }
    }

    #[cfg(feature = "wallet")]
    #[test]
    fn retryable_keyset_rejection_requires_safe_mint_rejection_stage() {
        let retryable = OpenChannelError {
            stage: OpenChannelFailureStage::MintRejected,
            channel_id: Some("channel".to_string()),
            input_may_be_spent: false,
            message: r#"{"code":12001,"detail":"keyset is not known"}"#.to_string(),
        };
        assert!(retryable.is_retryable_keyset_rejection());

        let ambiguous = OpenChannelError {
            stage: OpenChannelFailureStage::SwapSubmitted,
            channel_id: Some("channel".to_string()),
            input_may_be_spent: true,
            message: r#"{"code":12001,"detail":"keyset is not known"}"#.to_string(),
        };
        assert!(!ambiguous.is_retryable_keyset_rejection());
    }

    #[cfg(feature = "wallet")]
    #[test]
    fn retryable_keyset_rejection_rejects_non_keyset_mint_errors() {
        let error = OpenChannelError {
            stage: OpenChannelFailureStage::MintRejected,
            channel_id: Some("channel".to_string()),
            input_may_be_spent: false,
            message: r#"{"code":11001,"detail":"proofs already spent"}"#.to_string(),
        };
        assert!(!error.is_retryable_keyset_rejection());
    }

    #[cfg(feature = "wallet")]
    struct KeysetsNetworking {
        keysets_json: String,
        keysets_calls: Rc<Cell<u32>>,
    }

    #[cfg(feature = "wallet")]
    impl SpilmanClientNetworking for KeysetsNetworking {
        fn call_mint_swap(&self, _: &str, _: &str) -> Result<String, String> {
            Err("not used".to_string())
        }

        fn call_mint_restore(&self, _: &str, _: &str) -> Result<String, String> {
            Err("not used".to_string())
        }

        fn call_mint_keysets(&self, _: &str) -> Result<String, String> {
            self.keysets_calls.set(self.keysets_calls.get() + 1);
            Ok(self.keysets_json.clone())
        }

        fn call_mint_keys(&self, _: &str, _: &str) -> Result<String, String> {
            Err("not used".to_string())
        }
    }

    #[cfg(feature = "wallet")]
    struct RefreshKeysetsNetworking {
        keysets_json: String,
        keys_by_id: HashMap<String, String>,
        keysets_calls: Rc<Cell<u32>>,
        keys_calls: Rc<Cell<u32>>,
    }

    #[cfg(feature = "wallet")]
    impl SpilmanClientNetworking for RefreshKeysetsNetworking {
        fn call_mint_swap(&self, _: &str, _: &str) -> Result<String, String> {
            Err("not used".to_string())
        }

        fn call_mint_restore(&self, _: &str, _: &str) -> Result<String, String> {
            Err("not used".to_string())
        }

        fn call_mint_keysets(&self, _: &str) -> Result<String, String> {
            self.keysets_calls.set(self.keysets_calls.get() + 1);
            Ok(self.keysets_json.clone())
        }

        fn call_mint_keys(&self, _: &str, keyset_id: &str) -> Result<String, String> {
            self.keys_calls.set(self.keys_calls.get() + 1);
            self.keys_by_id
                .get(keyset_id)
                .cloned()
                .ok_or_else(|| format!("missing keys for {keyset_id}"))
        }
    }

    #[cfg(feature = "wallet")]
    fn mock_keyset_info_with_unit(
        amounts: Vec<u64>,
        input_fee_ppk: u64,
        unit: CurrencyUnit,
        secret_hex: &str,
    ) -> KeysetInfo {
        use cashu::nuts::{Keys, SecretKey};
        use cashu::Amount;
        use std::collections::BTreeMap;

        let mut keys_map = BTreeMap::new();
        let dummy_pubkey = SecretKey::from_hex(secret_hex).unwrap().public_key();
        for amount in amounts {
            keys_map.insert(Amount::from(amount), dummy_pubkey);
        }
        let active_keys = Keys::new(keys_map);
        let keyset_id = Id::v1_from_keys(&active_keys);
        KeysetInfo::new(keyset_id, unit, active_keys, input_fee_ppk, None)
    }

    #[cfg(feature = "wallet")]
    fn keys_response_json(keyset_info: &KeysetInfo) -> String {
        serde_json::json!({
            "keysets": [{
                "id": keyset_info.keyset_id.to_string(),
                "keys": keyset_info.active_keys,
            }]
        })
        .to_string()
    }

    #[cfg(feature = "wallet")]
    fn proof_json(keyset_id: Id, amount: u64) -> String {
        let proof = Proof {
            amount: cashu::Amount::from(amount),
            keyset_id,
            secret: cashu::secret::Secret::new("input-secret".to_string()),
            c: "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"
                .parse()
                .unwrap(),
            witness: None,
            dleq: None,
            p2pk_e: None,
        };
        serde_json::to_string(&vec![proof]).unwrap()
    }

    #[cfg(feature = "wallet")]
    #[test]
    fn refresh_keysets_response_caches_all_units_and_inactive_keysets() {
        let old_sat = mock_keyset_info_with_unit(
            vec![1, 2, 4, 8],
            100,
            CurrencyUnit::Sat,
            "0101010101010101010101010101010101010101010101010101010101010101",
        );
        let active_sat = mock_keyset_info_with_unit(
            vec![1, 3, 9],
            200,
            CurrencyUnit::Sat,
            "0202020202020202020202020202020202020202020202020202020202020202",
        );
        let active_msat = mock_keyset_info_with_unit(
            vec![1, 5, 25],
            300,
            CurrencyUnit::Msat,
            "0303030303030303030303030303030303030303030303030303030303030303",
        );
        let keysets_json = serde_json::json!({
            "keysets": [
                {
                    "id": old_sat.keyset_id.to_string(),
                    "unit": "sat",
                    "active": false,
                    "input_fee_ppk": 100,
                },
                {
                    "id": active_sat.keyset_id.to_string(),
                    "unit": "sat",
                    "active": true,
                    "input_fee_ppk": 200,
                },
                {
                    "id": active_msat.keyset_id.to_string(),
                    "unit": "msat",
                    "active": true,
                    "input_fee_ppk": 300,
                }
            ]
        })
        .to_string();
        let mut keys_by_id = HashMap::new();
        keys_by_id.insert(old_sat.keyset_id.to_string(), keys_response_json(&old_sat));
        keys_by_id.insert(
            active_sat.keyset_id.to_string(),
            keys_response_json(&active_sat),
        );
        keys_by_id.insert(
            active_msat.keyset_id.to_string(),
            keys_response_json(&active_msat),
        );
        let keysets_calls = Rc::new(Cell::new(0));
        let keys_calls = Rc::new(Cell::new(0));
        let bridge = SpilmanClientBridge::new(
            crate::ConfigurableClientHost::new_in_memory(),
            RefreshKeysetsNetworking {
                keysets_json: keysets_json.clone(),
                keys_by_id,
                keysets_calls: Rc::clone(&keysets_calls),
                keys_calls: Rc::clone(&keys_calls),
            },
        );

        let response = bridge
            .refresh_keysets_response("https://mint.example")
            .unwrap();
        assert_eq!(response, keysets_json);
        assert_eq!(keysets_calls.get(), 1);
        assert_eq!(keys_calls.get(), 3);

        let sat_keysets =
            bridge.cached_keysets_for_unit("https://mint.example", &CurrencyUnit::Sat);
        assert_eq!(sat_keysets.len(), 2);
        assert!(sat_keysets
            .iter()
            .any(|(id, entry)| *id == old_sat.keyset_id && !entry.active));
        assert!(sat_keysets
            .iter()
            .any(|(id, entry)| *id == active_sat.keyset_id && entry.active));

        let active_sat_ids =
            bridge.cached_active_keyset_ids("https://mint.example", &CurrencyUnit::Sat);
        assert_eq!(active_sat_ids, vec![active_sat.keyset_id]);
        let active_msat_ids =
            bridge.cached_active_keyset_ids("https://mint.example", &CurrencyUnit::Msat);
        assert_eq!(active_msat_ids, vec![active_msat.keyset_id]);

        let cached_info = bridge
            .cached_keyset_info("https://mint.example", &old_sat.keyset_id)
            .unwrap();
        let cached_info = crate::parse_keyset_info_from_json(&cached_info).unwrap();
        assert_eq!(cached_info.keyset_id, old_sat.keyset_id);
        assert_eq!(cached_info.input_fee_ppk, 100);
    }

    #[cfg(feature = "wallet")]
    #[test]
    fn proof_input_keysets_use_cache_without_network() {
        let input_keyset = crate::params::mock_keyset_info(vec![1, 2, 4, 8], 900);
        let host = crate::ConfigurableClientHost::new_in_memory();
        host.set_keyset(
            "https://mint.example",
            input_keyset.keyset_id,
            ClientKeysetCacheEntry {
                info_json: serde_json::to_string(&input_keyset).unwrap(),
                active: false,
                unit: CurrencyUnit::Sat,
            },
        )
        .unwrap();
        let bridge = SpilmanClientBridge::new(host, NoopNetworking);

        let input_keysets = bridge
            .fetch_proof_input_keysets(
                "https://mint.example",
                "sat",
                &proof_json(input_keyset.keyset_id, 8),
            )
            .unwrap();
        let input_keysets: Vec<cashu::nuts::KeySetInfo> =
            serde_json::from_str(&input_keysets).unwrap();

        assert_eq!(input_keysets.len(), 1);
        assert_eq!(input_keysets[0].id, input_keyset.keyset_id);
        assert_eq!(input_keysets[0].input_fee_ppk, 900);
        assert!(!input_keysets[0].active);
    }

    #[cfg(feature = "wallet")]
    #[test]
    fn token_input_keysets_use_cache_without_network() {
        let input_keyset = crate::params::mock_keyset_info(vec![1, 2, 4, 8], 500);
        let host = crate::ConfigurableClientHost::new_in_memory();
        host.set_keyset(
            "https://mint.example",
            input_keyset.keyset_id,
            ClientKeysetCacheEntry {
                info_json: serde_json::to_string(&input_keyset).unwrap(),
                active: false,
                unit: CurrencyUnit::Sat,
            },
        )
        .unwrap();
        let bridge = SpilmanClientBridge::new(host, NoopNetworking);

        let input_keysets = bridge
            .fetch_token_input_keysets("https://mint.example", "sat")
            .unwrap();
        let input_keysets: Vec<cashu::nuts::KeySetInfo> =
            serde_json::from_str(&input_keysets).unwrap();

        assert_eq!(input_keysets.len(), 1);
        assert_eq!(input_keysets[0].id, input_keyset.keyset_id);
        assert_eq!(input_keysets[0].input_fee_ppk, 500);
        assert!(!input_keysets[0].active);
    }

    #[cfg(feature = "wallet")]
    #[test]
    fn token_input_keysets_fetch_when_cache_empty() {
        let input_keyset = crate::params::mock_keyset_info(vec![1, 2, 4, 8], 600);
        let keysets_calls = Rc::new(Cell::new(0));
        let networking = KeysetsNetworking {
            keysets_json: serde_json::json!({
                "keysets": [{
                    "id": input_keyset.keyset_id.to_string(),
                    "unit": "sat",
                    "active": false,
                    "input_fee_ppk": 600,
                }]
            })
            .to_string(),
            keysets_calls: Rc::clone(&keysets_calls),
        };
        let bridge =
            SpilmanClientBridge::new(crate::ConfigurableClientHost::new_in_memory(), networking);

        let input_keysets = bridge
            .fetch_token_input_keysets("https://mint.example", "sat")
            .unwrap();
        let input_keysets: Vec<cashu::nuts::KeySetInfo> =
            serde_json::from_str(&input_keysets).unwrap();

        assert_eq!(keysets_calls.get(), 1);
        assert_eq!(input_keysets.len(), 1);
        assert_eq!(input_keysets[0].id, input_keyset.keyset_id);
        assert_eq!(input_keysets[0].input_fee_ppk, 600);
    }

    #[cfg(feature = "wallet")]
    #[test]
    fn proof_input_keysets_fetch_missing_from_keysets_endpoint() {
        let input_keyset = crate::params::mock_keyset_info(vec![1, 2, 4, 8], 700);
        let keysets_calls = Rc::new(Cell::new(0));
        let networking = KeysetsNetworking {
            keysets_json: serde_json::json!({
                "keysets": [{
                    "id": input_keyset.keyset_id.to_string(),
                    "unit": "sat",
                    "active": false,
                    "input_fee_ppk": 700,
                }]
            })
            .to_string(),
            keysets_calls: Rc::clone(&keysets_calls),
        };
        let bridge =
            SpilmanClientBridge::new(crate::ConfigurableClientHost::new_in_memory(), networking);

        let input_keysets = bridge
            .fetch_proof_input_keysets(
                "https://mint.example",
                "sat",
                &proof_json(input_keyset.keyset_id, 8),
            )
            .unwrap();
        let input_keysets: Vec<cashu::nuts::KeySetInfo> =
            serde_json::from_str(&input_keysets).unwrap();

        assert_eq!(keysets_calls.get(), 1);
        assert_eq!(input_keysets.len(), 1);
        assert_eq!(input_keysets[0].id, input_keyset.keyset_id);
        assert_eq!(input_keysets[0].input_fee_ppk, 700);
    }

    #[cfg(feature = "wallet")]
    #[test]
    fn proof_input_keysets_reject_wrong_unit_cache_entry() {
        let input_keyset = crate::params::mock_keyset_info(vec![1, 2, 4, 8], 900);
        let host = crate::ConfigurableClientHost::new_in_memory();
        host.set_keyset(
            "https://mint.example",
            input_keyset.keyset_id,
            ClientKeysetCacheEntry {
                info_json: serde_json::to_string(&input_keyset).unwrap(),
                active: false,
                unit: CurrencyUnit::Msat,
            },
        )
        .unwrap();
        let bridge = SpilmanClientBridge::new(host, NoopNetworking);

        let err = bridge
            .fetch_proof_input_keysets(
                "https://mint.example",
                "sat",
                &proof_json(input_keyset.keyset_id, 8),
            )
            .unwrap_err();

        assert!(err.contains("unit mismatch"));
    }

    struct FailingLifecycleHost;

    impl SpilmanClientHost for FailingLifecycleHost {
        fn save_opening_from_swap_channel(
            &self,
            _: &str,
            _: ClientChannelOpeningFromSwap,
        ) -> Result<(), String> {
            Ok(())
        }

        fn mark_channel_open(&self, _: &str, _: &str) -> Result<(), String> {
            Ok(())
        }

        fn mark_channel_opening_failed(
            &self,
            _: &str,
            _: ClientOpeningFailure,
        ) -> Result<(), String> {
            Err("mark_channel_opening_failed failed".to_string())
        }

        fn get_channel_opening_from_swap(&self, _: &str) -> Option<ClientChannelOpeningFromSwap> {
            None
        }

        fn get_channel_funding(&self, _: &str) -> Option<ClientChannelFunding> {
            None
        }

        fn get_payment_state(&self, _: &str) -> Option<ClientPaymentState> {
            None
        }

        fn record_payment(&self, _: &str, _: ClientPaymentState) -> Result<(), String> {
            Err("record_payment failed".to_string())
        }

        fn get_channel_state(&self, _: &str) -> Option<ClientChannelState> {
            Some(ClientChannelState::Open)
        }

        fn mark_channel_closed(&self, _: &str) -> Result<(), String> {
            Err("mark_channel_closed failed".to_string())
        }

        fn mark_channel_closing(&self, _: &str) -> Result<(), String> {
            Err("mark_channel_closing failed".to_string())
        }

        fn list_channel_ids(&self) -> Vec<String> {
            vec!["ch1".to_string()]
        }

        fn delete_channel(&self, _: &str) -> Result<(), String> {
            Err("delete_channel failed".to_string())
        }

        fn now_seconds(&self) -> u64 {
            0
        }

        fn compute_channel_secret(&self, _: &str, _: &str) -> Result<String, String> {
            Err("not used".to_string())
        }

        fn sign_with_tweaked_key(&self, _: &str, _: &str, _: &str) -> Result<String, String> {
            Err("not used".to_string())
        }
    }

    #[test]
    fn close_channel_surfaces_host_error() {
        let bridge = SpilmanClientBridge::new(FailingLifecycleHost, NoopNetworking);
        let err = bridge.close_channel("ch1").unwrap_err();
        assert!(err.contains("mark_channel_closed failed"));
    }

    #[test]
    fn mark_channel_unusable_surfaces_host_error() {
        let bridge = SpilmanClientBridge::new(FailingLifecycleHost, NoopNetworking);
        let err = bridge.mark_channel_unusable("ch1").unwrap_err();
        assert!(err.contains("mark_channel_closing failed"));
    }

    #[test]
    fn delete_channel_surfaces_host_error() {
        let bridge = SpilmanClientBridge::new(FailingLifecycleHost, NoopNetworking);
        let err = bridge.delete_channel("ch1").unwrap_err();
        assert!(err.contains("delete_channel failed"));
    }

    #[test]
    fn cooperative_close_response_surfaces_host_error() {
        let bridge = SpilmanClientBridge::new(FailingLifecycleHost, NoopNetworking);
        let err = bridge
            .process_cooperative_close_response(r#"{"channel_id":"ch1"}"#)
            .unwrap_err();
        assert!(err.contains("mark_channel_closed failed"));
    }
}
