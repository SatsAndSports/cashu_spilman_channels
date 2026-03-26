//! Client-side Spilman channel bridge
//!
//! This module provides a high-level client-side API for managing Spilman payment channels,
//! mirroring the server-side `SpilmanBridge` / `SpilmanHost` pattern.
//!
//! The `SpilmanClientHost` trait provides storage and mint communication callbacks,
//! while `SpilmanClientBridge` orchestrates channel creation, payment signing, and
//! header construction.
//!
//! # Example (pseudocode)
//! ```ignore
//! let host = MyClientHost::new();
//! let bridge = SpilmanClientBridge::new(host, None)?;
//!
//! // Open a channel from an existing Cashu token
//! let result = bridge.open_channel_from_token(token, receiver_pubkey, expiry_timestamp, keyset_info, 64)?;
//!
//! // Make payments
//! let header = bridge.build_payment_header(&result.channel_id, 10, true)?;  // first request
//! let header = bridge.build_payment_header(&result.channel_id, 20, false)?; // subsequent
//! ```

use base64::Engine;
use serde::{Deserialize, Serialize};

use super::bindings::{attach_signature_to_balance_update, create_unsigned_balance_update};
#[cfg(feature = "wallet")]
use super::bindings::{complete_funding_swap, compute_channel_from_token, create_funding_swap};

// ============================================================================
// SpilmanClientHost trait
// ============================================================================

/// Trait for client-side host callbacks.
///
/// Provides mint communication and channel storage. This is the client-side
/// counterpart of the server-side `SpilmanHost` trait.
///
/// Implementations are responsible for:
/// - Making HTTP calls to the mint's `/v1/swap` endpoint
/// - Persisting channel state (in-memory, database, etc.)
pub trait SpilmanClientHost {
    /// Execute a swap with the mint.
    ///
    /// Posts `swap_request_json` to `{mint_url}/v1/swap` and returns the
    /// response body as a JSON string.
    fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String>;

    /// Save channel state. Called after successful channel creation.
    ///
    /// The `channel_json` is an opaque JSON blob managed by the bridge.
    /// The `channel_secret_hex` is the hashed ECDH secret (32 bytes, hex),
    /// passed separately so the host can store it with appropriate protection.
    fn save_channel(&self, channel_id: &str, channel_json: &str, channel_secret_hex: &str);

    /// Retrieve channel state by channel ID.
    ///
    /// Returns `None` if the channel is not found. The returned `ChannelData`
    /// contains the opaque channel JSON and the channel secret, matching
    /// what was passed to `save_channel`.
    fn get_channel(&self, channel_id: &str) -> Option<ChannelData>;

    /// List all stored channel IDs.
    fn list_channel_ids(&self) -> Vec<String>;

    /// Delete a channel from storage.
    fn delete_channel(&self, channel_id: &str);

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
    /// Sender public key used for this channel.
    /// The caller passes this to `open_channel_from_token` and gets it back
    /// here so it can be associated with the channel.
    pub sender_pubkey_hex: String,
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
    /// Serialized channel parameters used to reconstruct the channel state.
    pub params_json: String,
}

/// Channel data returned by `SpilmanClientHost::get_channel`.
///
/// Separates the opaque channel JSON from the sensitive channel secret,
/// allowing hosts to store them differently (e.g., encrypt the secret).
#[derive(Debug, Clone)]
pub struct ChannelData {
    /// Opaque channel state JSON (managed by the bridge).
    pub channel_json: String,
    /// The hashed ECDH channel secret (32 bytes, hex-encoded).
    pub channel_secret_hex: String,
}

/// Internal channel state stored via the host.
///
/// This is serialized as the `channel_json` blob in `ChannelData`.
/// The `channel_secret_hex` is stored separately via the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredChannel {
    channel_id: String,
    params_json: String,
    keyset_info_json: String,
    funding_proofs_json: String,
    capacity: u64,
    funding_token_amount: u64,
    mint_url: String,
    /// Sender public key for this channel (per-channel, not from bridge).
    sender_pubkey_hex: String,
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
pub struct SpilmanClientBridge<H: SpilmanClientHost> {
    host: H,
}

#[cfg(feature = "wallet")]
fn normalize_mint_error_string(raw: String) -> String {
    serde_json::from_str::<serde_json::Value>(&raw)
        .map(|value| value.to_string())
        .unwrap_or(raw)
}

impl<H: SpilmanClientHost> SpilmanClientBridge<H> {
    /// Create a new client bridge.
    ///
    /// The bridge is stateless and keyless — it delegates all key operations
    /// to the host. The caller passes `sender_pubkey_hex` per channel when
    /// opening channels.
    pub fn new(host: H) -> Self {
        Self { host }
    }

    /// Open a new channel from a Cashu token.
    ///
    /// This performs the full funding flow:
    /// 1. Compute ECDH channel secret via `host.compute_channel_secret()`
    /// 2. Parse the token and compute channel parameters
    /// 3. Create a funding swap request (deterministic 2-of-2 locked outputs)
    /// 4. Submit the swap to the mint via `host.call_mint_swap()`
    /// 5. Unblind signatures and verify DLEQ proofs
    /// 6. Save the channel via `host.save_channel()`
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
    ) -> Result<OpenChannelResult, String> {
        // Step 1: Compute channel secret via host (ECDH delegation)
        let channel_secret_hex = self
            .host
            .compute_channel_secret(sender_pubkey_hex, receiver_pubkey_hex)?;

        // Step 2: Parse token and compute channel parameters
        let compute_result = compute_channel_from_token(
            token_string,
            receiver_pubkey_hex,
            sender_pubkey_hex,
            &channel_secret_hex,
            expiry_timestamp,
            keyset_info_json,
            max_amount,
        )?;

        let compute_json: serde_json::Value = serde_json::from_str(&compute_result)
            .map_err(|e| format!("Failed to parse compute result: {}", e))?;

        let capacity = compute_json["capacity"]
            .as_u64()
            .ok_or("Missing 'capacity' in compute result")?;
        let funding_token_amount = compute_json["funding_token_amount"]
            .as_u64()
            .ok_or("Missing 'funding_token_amount' in compute result")?;
        let mint_url = compute_json["mint_url"]
            .as_str()
            .ok_or("Missing 'mint_url' in compute result")?
            .to_string();
        let params_json = compute_json["params_json"]
            .as_str()
            .ok_or("Missing 'params_json' in compute result")?;
        let proofs_json = compute_json["proofs_json"]
            .as_str()
            .ok_or("Missing 'proofs_json' in compute result")?;

        // Step 3: Create funding swap request
        let swap_result = create_funding_swap(
            params_json,
            &channel_secret_hex,
            keyset_info_json,
            proofs_json,
        )?;

        let swap_json: serde_json::Value = serde_json::from_str(&swap_result)
            .map_err(|e| format!("Failed to parse swap result: {}", e))?;

        let swap_request_json = swap_json["swap_request_json"]
            .as_str()
            .ok_or("Missing 'swap_request_json' in swap result")?;
        let funding_secrets_json = swap_json["funding_secrets_json"]
            .as_str()
            .ok_or("Missing 'funding_secrets_json' in swap result")?;

        // Step 4: Submit swap to mint
        let swap_response_json = self
            .host
            .call_mint_swap(&mint_url, swap_request_json)
            .map_err(normalize_mint_error_string)?;

        // Step 5: Unblind signatures and verify DLEQ
        let complete_result =
            complete_funding_swap(&swap_response_json, funding_secrets_json, keyset_info_json)?;

        let complete_json: serde_json::Value = serde_json::from_str(&complete_result)
            .map_err(|e| format!("Failed to parse complete result: {}", e))?;

        let funding_proofs_json = complete_json["funding_proofs_json"]
            .as_str()
            .ok_or("Missing 'funding_proofs_json' in complete result")?;

        // Compute channel ID
        let channel_id = super::bindings::channel_parameters_get_channel_id(
            params_json,
            &channel_secret_hex,
            keyset_info_json,
        )?;

        // Step 6: Save channel state
        let stored = StoredChannel {
            channel_id: channel_id.clone(),
            params_json: params_json.to_string(),
            keyset_info_json: keyset_info_json.to_string(),
            funding_proofs_json: funding_proofs_json.to_string(),
            capacity,
            funding_token_amount,
            mint_url: mint_url.clone(),
            sender_pubkey_hex: sender_pubkey_hex.to_string(),
        };

        let channel_json = serde_json::to_string(&stored)
            .map_err(|e| format!("Failed to serialize channel state: {}", e))?;

        self.host
            .save_channel(&channel_id, &channel_json, &channel_secret_hex);

        Ok(OpenChannelResult {
            channel_id,
            capacity,
            funding_token_amount,
            mint_url,
            sender_pubkey_hex: sender_pubkey_hex.to_string(),
        })
    }

    /// Create a signed balance update for a channel.
    ///
    /// Returns JSON with `{channel_id, amount, signature}`.
    ///
    /// The `balance` is the cumulative amount the receiver (Charlie) can claim.
    /// It must increase monotonically across calls.
    ///
    /// Signing is delegated to the host via `sign_with_tweaked_key()`.
    pub fn sign_balance_update(&self, channel_id: &str, balance: u64) -> Result<String, String> {
        let (stored, channel_secret_hex) = self.load_channel(channel_id)?;

        // Step 1: Create unsigned balance update (computes message hash + tweak)
        let unsigned_json = create_unsigned_balance_update(
            &stored.params_json,
            &stored.keyset_info_json,
            &channel_secret_hex,
            &stored.funding_proofs_json,
            balance,
        )?;

        let unsigned: serde_json::Value = serde_json::from_str(&unsigned_json)
            .map_err(|e| format!("Failed to parse unsigned update: {}", e))?;

        let unsigned_swap_request_json = unsigned["unsigned_swap_request_json"]
            .as_str()
            .ok_or("Missing 'unsigned_swap_request_json'")?;
        let message_hex = unsigned["message_hex"]
            .as_str()
            .ok_or("Missing 'message_hex'")?;
        let tweak_scalar_hex = unsigned["tweak_scalar_hex"]
            .as_str()
            .ok_or("Missing 'tweak_scalar_hex'")?;
        let channel_id_from_update = unsigned["channel_id"]
            .as_str()
            .ok_or("Missing 'channel_id'")?;
        let amount = unsigned["amount"].as_u64().ok_or("Missing 'amount'")?;

        // Step 2: Delegate signing to the host (use per-channel sender pubkey)
        let signature_hex = self.host.sign_with_tweaked_key(
            &stored.sender_pubkey_hex,
            message_hex,
            tweak_scalar_hex,
        )?;

        // Step 3: Attach signature and build the BalanceUpdateMessage
        attach_signature_to_balance_update(
            unsigned_swap_request_json,
            &signature_hex,
            channel_id_from_update,
            amount,
        )
    }

    /// Build a complete `X-Cashu-Channel` payment header value.
    ///
    /// Returns a base64-encoded JSON string ready to use as the header value.
    ///
    /// If `include_funding` is true, the header includes `params` and `funding_proofs`
    /// (needed for the first request, or when the server doesn't know this channel yet).
    /// Subsequent requests can set `include_funding` to false for smaller headers.
    ///
    /// Signing is delegated to the host via `sign_with_tweaked_key()`.
    pub fn build_payment_header(
        &self,
        channel_id: &str,
        balance: u64,
        include_funding: bool,
    ) -> Result<String, String> {
        // Sign the balance update (uses host.sign_with_tweaked_key internally)
        let update_json = self.sign_balance_update(channel_id, balance)?;

        let update: serde_json::Value = serde_json::from_str(&update_json)
            .map_err(|e| format!("Failed to parse balance update: {}", e))?;

        // Build the payment header JSON
        let mut header = serde_json::json!({
            "channel_id": update["channel_id"],
            "balance": update["amount"],
            "signature": update["signature"]
        });

        if include_funding {
            let (stored, _) = self.load_channel(channel_id)?;

            // Parse params_json into a JSON object for inclusion
            let params: serde_json::Value = serde_json::from_str(&stored.params_json)
                .map_err(|e| format!("Failed to parse params: {}", e))?;
            let funding_proofs: serde_json::Value =
                serde_json::from_str(&stored.funding_proofs_json)
                    .map_err(|e| format!("Failed to parse funding proofs: {}", e))?;

            header["params"] = params;
            header["funding_proofs"] = funding_proofs;
        }

        // Base64 encode
        let header_str = header.to_string();
        Ok(base64::prelude::BASE64_STANDARD.encode(header_str))
    }

    /// Get information about a stored channel.
    pub fn get_channel_info(&self, channel_id: &str) -> Option<ClientChannelInfo> {
        let data = self.host.get_channel(channel_id)?;
        let stored: StoredChannel = serde_json::from_str(&data.channel_json).ok()?;
        Some(ClientChannelInfo {
            channel_id: stored.channel_id,
            capacity: stored.capacity,
            funding_token_amount: stored.funding_token_amount,
            mint_url: stored.mint_url,
            params_json: stored.params_json,
        })
    }

    /// List all stored channel IDs.
    pub fn list_channels(&self) -> Vec<String> {
        self.host.list_channel_ids()
    }

    /// Remove a channel from storage.
    pub fn remove_channel(&self, channel_id: &str) {
        self.host.delete_channel(channel_id);
    }

    /// Create a cooperative close request for a channel.
    ///
    /// This creates a signed balance update for the `final_balance` and
    /// returns a JSON string ready to be sent to the server's close endpoint.
    pub fn create_cooperative_close_request(
        &self,
        channel_id: &str,
        final_balance: u64,
    ) -> Result<String, String> {
        // Sign the final balance update
        let update_json = self.sign_balance_update(channel_id, final_balance)?;

        let update: serde_json::Value = serde_json::from_str(&update_json)
            .map_err(|e| format!("Failed to parse balance update: {}", e))?;

        // Build the close request JSON
        let request = serde_json::json!({
            "balance": update["amount"],
            "signature": update["signature"]
        });

        Ok(request.to_string())
    }

    /// Process a cooperative close response from the server.
    ///
    /// This marks the channel as closed locally and removes it from storage.
    pub fn process_cooperative_close_response(&self, response_json: &str) -> Result<(), String> {
        // Parse the response to verify it's valid JSON
        let response: serde_json::Value = serde_json::from_str(response_json)
            .map_err(|e| format!("Failed to parse close response: {}", e))?;

        let channel_id = response["channel_id"]
            .as_str()
            .ok_or("Missing 'channel_id' in close response")?;

        // For now, we just delete the channel locally.
        // In the future, we might want to store the refund proofs.
        self.host.delete_channel(channel_id);

        Ok(())
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    fn load_channel(&self, channel_id: &str) -> Result<(StoredChannel, String), String> {
        let data = self
            .host
            .get_channel(channel_id)
            .ok_or_else(|| format!("Channel not found: {}", channel_id))?;
        let stored: StoredChannel = serde_json::from_str(&data.channel_json)
            .map_err(|e| format!("Failed to parse channel state: {}", e))?;
        Ok((stored, data.channel_secret_hex))
    }
}

/// Base64 decode a string (standard encoding).
pub fn base64_decode(input: &str) -> Result<String, String> {
    let bytes = base64::prelude::BASE64_STANDARD
        .decode(input.trim())
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    String::from_utf8(bytes).map_err(|e| format!("Invalid UTF-8 in base64 decode: {}", e))
}
