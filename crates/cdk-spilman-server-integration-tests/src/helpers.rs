//! Test helpers for Spilman payment channel tests.
//!
//! This module provides utilities for:
//! - Generating keypairs
//! - Creating and signing payment headers
//! - Minting funded channels
//! - Fetching ASCII art and channel status

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};

use cashu::nuts::{Proof, SecretKey};
use cdk_spilman::{
    channel_parameters_get_channel_id, compute_channel_secret_from_hex,
    compute_funding_token_amount, construct_proofs, create_funding_outputs,
    create_signed_balance_update, parse_keyset_info_from_json, KeysetInfo,
};

// ============================================================================
// Types
// ============================================================================

/// Keypair with hex-encoded secret and public key
#[derive(Debug, Clone)]
pub struct Keypair {
    pub secret_hex: String,
    pub pubkey_hex: String,
}

/// Channel data returned by mint_funded_channel
#[derive(Debug, Clone)]
pub struct Channel {
    pub alice: Keypair,
    pub channel_params: Value,
    pub channel_params_json: String,
    pub channel_id: String,
    pub channel_secret: String,
    pub proofs: Vec<Proof>,
    pub keyset_info: KeysetInfo,
    pub keyset_info_json: String,
    pub capacity: u64,
    pub output_count: usize,
}

/// Server channel parameters from /channel/params
#[derive(Debug, Clone, Deserialize)]
pub struct ServerChannelParams {
    pub receiver_pubkey: String,
    pub pricing: BTreeMap<String, UnitPricing>,
    pub mints_units_keysets: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    pub min_expiry_in_seconds: u64,
    #[serde(default = "default_pricing_scale")]
    pub pricing_scale: u64,
}

fn default_pricing_scale() -> u64 {
    1
}

/// Pricing info for a unit
#[derive(Debug, Clone, Deserialize)]
pub struct UnitPricing {
    pub min_capacity: u64,
    #[serde(default)]
    pub max_amount_per_output: Option<u64>,
    #[serde(default)]
    pub variables: BTreeMap<String, u64>,
}

/// Response from fetchAsciiArt
#[derive(Debug)]
pub struct AsciiArtResponse {
    pub status: u16,
    pub body: Value,
    pub channel_header: Option<Value>,
}

/// Response body from channel status endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct ChannelStatusBody {
    pub channel_id: String,
    #[serde(default)]
    pub chars_served: Option<u64>,
    pub amount_due: u64,
    pub balance: u64,
    pub capacity: u64,
    pub closed: bool,
    #[serde(default)]
    pub closed_amount: Option<u64>,
}

/// Response from fetchChannelStatus
#[derive(Debug)]
pub struct ChannelStatusResponse {
    pub http_status: u16,
    pub body: Option<ChannelStatusBody>,
}

/// Response from closeChannel
#[derive(Debug)]
pub struct CloseChannelResponse {
    pub http_status: u16,
    pub body: Value,
}

/// Options for customizing channel parameters
#[derive(Debug, Default)]
pub struct MintFundedChannelOptions {
    /// Custom expiry timestamp. Defaults to 1 week from now.
    pub expiry_timestamp: Option<u64>,
    /// Maximum amount per output. Defaults to 64.
    pub maximum_amount: Option<u64>,
}

// ============================================================================
// Keypair Generation
// ============================================================================

/// Generate a random secp256k1 keypair
pub fn generate_keypair() -> Keypair {
    let secret_key = SecretKey::generate();
    let public_key = secret_key.public_key();

    Keypair {
        secret_hex: secret_key.to_secret_hex(),
        pubkey_hex: public_key.to_hex(),
    }
}

/// Derive compressed pubkey from secret key hex
pub fn secret_key_to_pubkey(secret_hex: &str) -> Result<String> {
    let secret_key =
        SecretKey::from_hex(secret_hex).map_err(|e| anyhow!("Invalid secret key: {}", e))?;
    Ok(secret_key.public_key().to_hex())
}

// ============================================================================
// Payment Header Helpers
// ============================================================================

/// Encode payment object to base64 for X-Cashu-Channel header
pub fn encode_payment_header(payment: &Value) -> String {
    let json = serde_json::to_string(payment).expect("Failed to serialize payment");
    base64::engine::general_purpose::STANDARD.encode(json.as_bytes())
}

/// Create a signed payment header for a channel (channel must be pre-registered)
pub fn create_payment_header(channel: &Channel, balance: u64) -> Result<String> {
    let balance_update_json = create_signed_balance_update(
        &channel.channel_params_json,
        &channel.keyset_info_json,
        &channel.alice.secret_hex,
        &serde_json::to_string(&channel.proofs)?,
        balance,
    )
    .map_err(|e| anyhow!("Failed to create balance update: {}", e))?;

    let balance_update: Value = serde_json::from_str(&balance_update_json)?;

    let payment = json!({
        "channel_id": balance_update["channel_id"],
        "balance": balance_update["amount"],
        "signature": balance_update["signature"],
    });

    Ok(encode_payment_header(&payment))
}

// ============================================================================
// HTTP Client Helpers
// ============================================================================

/// HTTP client for making requests to servers
pub struct HttpClient {
    client: reqwest::Client,
    pub base_url: String,
    pub mint_url: String,
}

impl HttpClient {
    /// Create a new HTTP client
    pub fn new(base_url: String, mint_url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url,
            mint_url,
        }
    }

    /// Fetch channel params from server
    pub async fn fetch_channel_params(&self) -> Result<ServerChannelParams> {
        let url = format!("{}/channel/params", self.base_url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch channel params")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Channel params request failed: {}",
                response.status()
            ));
        }

        response
            .json()
            .await
            .context("Failed to parse channel params")
    }

    /// Fetch ASCII art from the server with a payment header
    pub async fn fetch_ascii_art(
        &self,
        payment_header: &str,
        message: &str,
    ) -> Result<AsciiArtResponse> {
        let url = format!("{}/ascii", self.base_url);

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("X-Cashu-Channel", payment_header)
            .json(&json!({ "message": message }))
            .send()
            .await
            .context("Failed to fetch ASCII art")?;

        let status = response.status().as_u16();
        let channel_header = response
            .headers()
            .get("X-Cashu-Channel")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| serde_json::from_str(s).ok());

        let body: Value = response.json().await.unwrap_or(json!({}));

        Ok(AsciiArtResponse {
            status,
            body,
            channel_header,
        })
    }

    /// Fetch ASCII art without payment header
    pub async fn fetch_ascii_art_no_header(&self, message: &str) -> Result<AsciiArtResponse> {
        let url = format!("{}/ascii", self.base_url);

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&json!({ "message": message }))
            .send()
            .await
            .context("Failed to fetch ASCII art")?;

        let status = response.status().as_u16();
        let body: Value = response.json().await.unwrap_or(json!({}));

        Ok(AsciiArtResponse {
            status,
            body,
            channel_header: None,
        })
    }

    /// Fetch ASCII art with raw header value
    pub async fn fetch_ascii_art_raw_header(
        &self,
        header_value: &str,
        message: &str,
    ) -> Result<AsciiArtResponse> {
        let url = format!("{}/ascii", self.base_url);

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("X-Cashu-Channel", header_value)
            .json(&json!({ "message": message }))
            .send()
            .await
            .context("Failed to fetch ASCII art")?;

        let status = response.status().as_u16();
        let body: Value = response.json().await.unwrap_or(json!({}));

        Ok(AsciiArtResponse {
            status,
            body,
            channel_header: None,
        })
    }

    /// Fetch channel status from the server
    pub async fn fetch_channel_status(&self, channel_id: &str) -> Result<ChannelStatusResponse> {
        let url = format!("{}/channel/{}/status", self.base_url, channel_id);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch channel status")?;

        let http_status = response.status().as_u16();
        let body = if response.status().is_success() {
            Some(response.json().await.context("Failed to parse status")?)
        } else {
            None
        };

        Ok(ChannelStatusResponse { http_status, body })
    }

    /// Register a channel with the server (balance=0)
    pub async fn register_channel(&self, channel: &Channel) -> Result<Value> {
        let balance_update_json = create_signed_balance_update(
            &channel.channel_params_json,
            &channel.keyset_info_json,
            &channel.alice.secret_hex,
            &serde_json::to_string(&channel.proofs)?,
            0,
        )
        .map_err(|e| anyhow!("Failed to create balance update: {}", e))?;

        let balance_update: Value = serde_json::from_str(&balance_update_json)?;

        let url = format!("{}/channel/register", self.base_url);
        let body = json!({
            "channel_id": channel.channel_id,
            "balance": 0,
            "signature": balance_update["signature"],
            "params": channel.channel_params,
            "funding_proofs": channel.proofs,
        });

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .context("Failed to register channel")?;

        if !response.status().is_success() {
            let error_body: Value = response.json().await.unwrap_or(json!({}));
            return Err(anyhow!(
                "Registration failed: {}",
                error_body["reason"].as_str().unwrap_or("unknown error")
            ));
        }

        response.json().await.context("Failed to parse response")
    }

    /// Register channel and return response even on error
    pub async fn register_channel_raw(&self, body: &Value) -> Result<(u16, Value)> {
        let url = format!("{}/channel/register", self.base_url);

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await
            .context("Failed to register channel")?;

        let status = response.status().as_u16();
        let body: Value = response.json().await.unwrap_or(json!({}));

        Ok((status, body))
    }

    /// Close a channel cooperatively
    pub async fn close_channel(
        &self,
        channel: &Channel,
        balance: u64,
    ) -> Result<CloseChannelResponse> {
        let balance_update_json = create_signed_balance_update(
            &channel.channel_params_json,
            &channel.keyset_info_json,
            &channel.alice.secret_hex,
            &serde_json::to_string(&channel.proofs)?,
            balance,
        )
        .map_err(|e| anyhow!("Failed to create balance update: {}", e))?;

        let balance_update: Value = serde_json::from_str(&balance_update_json)?;

        let url = format!("{}/channel/{}/close", self.base_url, channel.channel_id);
        let body = json!({
            "balance": balance,
            "signature": balance_update["signature"],
        });

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .context("Failed to close channel")?;

        let http_status = response.status().as_u16();
        let body: Value = response.json().await.unwrap_or(json!({}));

        Ok(CloseChannelResponse { http_status, body })
    }

    /// Close channel with raw body
    pub async fn close_channel_raw(
        &self,
        channel_id: &str,
        body: &Value,
    ) -> Result<CloseChannelResponse> {
        let url = format!("{}/channel/{}/close", self.base_url, channel_id);

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await
            .context("Failed to close channel")?;

        let http_status = response.status().as_u16();
        let body: Value = response.json().await.unwrap_or(json!({}));

        Ok(CloseChannelResponse { http_status, body })
    }

    /// Unilateral close
    pub async fn unilateral_close(&self, channel_id: &str) -> Result<CloseChannelResponse> {
        let url = format!("{}/channel/{}/unilateral-close", self.base_url, channel_id);

        let response = self
            .client
            .post(&url)
            .send()
            .await
            .context("Failed to unilateral close")?;

        let http_status = response.status().as_u16();
        let body: Value = response.json().await.unwrap_or(json!({}));

        Ok(CloseChannelResponse { http_status, body })
    }
}

// ============================================================================
// Mint Interaction Helpers
// ============================================================================

/// Fetch keyset info from mint
pub async fn fetch_keyset_info(mint_url: &str, keyset_id: &str) -> Result<(KeysetInfo, String)> {
    let client = reqwest::Client::new();

    // Fetch keys
    let keys_url = format!("{}/v1/keys/{}", mint_url, keyset_id);
    let keys_response: Value = client
        .get(&keys_url)
        .send()
        .await?
        .json()
        .await
        .context("Failed to fetch keys")?;

    // Fetch keysets for metadata
    let keysets_url = format!("{}/v1/keysets", mint_url);
    let keysets_response: Value = client
        .get(&keysets_url)
        .send()
        .await?
        .json()
        .await
        .context("Failed to fetch keysets")?;

    let keyset = keysets_response["keysets"]
        .as_array()
        .ok_or_else(|| anyhow!("Invalid keysets response"))?
        .iter()
        .find(|k| k["id"].as_str() == Some(keyset_id))
        .ok_or_else(|| anyhow!("Keyset {} not found", keyset_id))?;

    let input_fee_ppk = keyset["input_fee_ppk"].as_u64().unwrap_or(0);

    // Build keys map
    let keys_obj = keys_response["keysets"][0]["keys"]
        .as_object()
        .ok_or_else(|| anyhow!("Invalid keys response"))?;

    let mut keys: BTreeMap<String, String> = BTreeMap::new();
    for (amount, pubkey) in keys_obj {
        if let Some(pk) = pubkey.as_str() {
            keys.insert(amount.clone(), pk.to_string());
        }
    }

    // Build JSON for WASM compatibility
    let keyset_info_json = json!({
        "keysetId": keyset_id,
        "unit": keyset["unit"].as_str().unwrap_or("sat"),
        "keys": keys,
        "inputFeePpk": input_fee_ppk,
    });

    let json_str = serde_json::to_string(&keyset_info_json)?;
    let keyset_info = parse_keyset_info_from_json(&json_str)
        .map_err(|e| anyhow!("Failed to parse keyset info: {}", e))?;

    Ok((keyset_info, json_str))
}

/// Get the first active keyset for a given unit from the mint
pub async fn get_first_keyset_id(mint_url: &str, unit: &str) -> Result<String> {
    let client = reqwest::Client::new();
    let url = format!("{}/v1/keysets", mint_url);

    let response: Value = client
        .get(&url)
        .send()
        .await?
        .json()
        .await
        .context("Failed to fetch keysets")?;

    let keysets = response["keysets"]
        .as_array()
        .ok_or_else(|| anyhow!("Invalid keysets response"))?;

    for keyset in keysets {
        if keyset["unit"].as_str() == Some(unit) && keyset["active"].as_bool() == Some(true) {
            if let Some(id) = keyset["id"].as_str() {
                return Ok(id.to_string());
            }
        }
    }

    Err(anyhow!("No active {} keyset found at {}", unit, mint_url))
}

// ============================================================================
// Channel Funding
// ============================================================================

/// Mint a funded channel with the specified unit and capacity
pub async fn mint_funded_channel(
    client: &HttpClient,
    server_params: &ServerChannelParams,
    unit: &str,
    capacity: u64,
    options: MintFundedChannelOptions,
) -> Result<Channel> {
    let http = reqwest::Client::new();
    let mint_url = &client.mint_url;

    // Get keyset ID for this unit
    let keyset_id = get_first_keyset_id(mint_url, unit).await?;

    // Generate Alice's keypair
    let alice = generate_keypair();

    // Fetch keyset info from mint
    let (keyset_info, keyset_info_json) = fetch_keyset_info(mint_url, &keyset_id).await?;

    // Build channel parameters
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let setup_timestamp = now;
    let expiry_timestamp = options.expiry_timestamp.unwrap_or(now + 7 * 24 * 60 * 60); // Default: 1 week
    let maximum_amount = options.maximum_amount.unwrap_or(64);

    // Compute the minimum funding_token_amount for the desired capacity
    let funding_token_amount =
        compute_funding_token_amount(capacity, &keyset_info_json, maximum_amount)
            .map_err(|e| anyhow!("Failed to compute funding token amount: {}", e))?;

    let channel_params = json!({
        "mint": mint_url,
        "unit": unit,
        "capacity": capacity,
        "funding_token_amount": funding_token_amount,
        "keyset_id": keyset_id,
        "input_fee_ppk": keyset_info.input_fee_ppk,
        "maximum_amount": maximum_amount,
        "setup_timestamp": setup_timestamp,
        "sender_pubkey": alice.pubkey_hex,
        "receiver_pubkey": server_params.receiver_pubkey,
        "expiry_timestamp": expiry_timestamp,
    });
    let channel_params_json = serde_json::to_string(&channel_params)?;

    // Generate funding outputs
    let funding_outputs_json =
        create_funding_outputs(&channel_params_json, &alice.secret_hex, &keyset_info_json)
            .map_err(|e| anyhow!("Failed to create funding outputs: {}", e))?;
    let funding_outputs: Value = serde_json::from_str(&funding_outputs_json)?;

    let funding_token_nominal = funding_outputs["funding_token_nominal"]
        .as_u64()
        .ok_or_else(|| anyhow!("Missing funding_token_nominal"))?;

    // Create mint quote
    let quote_url = format!("{}/v1/mint/quote/bolt11", mint_url);
    let quote_response: Value = http
        .post(&quote_url)
        .json(&json!({
            "amount": funding_token_nominal,
            "unit": unit,
        }))
        .send()
        .await?
        .json()
        .await?;

    let quote_id = quote_response["quote"]
        .as_str()
        .ok_or_else(|| anyhow!("Missing quote ID"))?;

    // Wait for payment (FakeWallet auto-pays)
    let status_url = format!("{}/v1/mint/quote/bolt11/{}", mint_url, quote_id);
    for _ in 0..60 {
        let status: Value = http.get(&status_url).send().await?.json().await?;
        if status["state"].as_str() == Some("PAID") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // Mint with our blinded messages
    let blinded_messages = funding_outputs["blinded_messages"]
        .as_array()
        .ok_or_else(|| anyhow!("Missing blinded_messages"))?;

    let outputs: Vec<Value> = blinded_messages
        .iter()
        .map(|bm| {
            json!({
                "amount": bm["amount"],
                "id": bm["id"],
                "B_": bm["B_"],
            })
        })
        .collect();

    let mint_url_endpoint = format!("{}/v1/mint/bolt11", mint_url);
    let mint_response: Value = http
        .post(&mint_url_endpoint)
        .json(&json!({
            "quote": quote_id,
            "outputs": outputs,
        }))
        .send()
        .await?
        .json()
        .await?;

    // Construct proofs (unblind signatures)
    let signatures_json = serde_json::to_string(&mint_response["signatures"])?;
    let secrets_json = serde_json::to_string(&funding_outputs["secrets_with_blinding"])?;

    let proofs_json = construct_proofs(&signatures_json, &secrets_json, &keyset_info_json)
        .map_err(|e| anyhow!("Failed to construct proofs: {}", e))?;
    let proofs: Vec<Proof> = serde_json::from_str(&proofs_json)?;

    // Compute channel secret and channel ID
    let channel_secret =
        compute_channel_secret_from_hex(&alice.secret_hex, &server_params.receiver_pubkey)
            .map_err(|e| anyhow!("Failed to compute channel secret: {}", e))?;

    let channel_id =
        channel_parameters_get_channel_id(&channel_params_json, &channel_secret, &keyset_info_json)
            .map_err(|e| anyhow!("Failed to get channel ID: {}", e))?;

    // Get output count from blinded_messages
    let output_count = blinded_messages.len();

    Ok(Channel {
        alice,
        channel_params,
        channel_params_json,
        channel_id,
        channel_secret,
        proofs,
        keyset_info,
        keyset_info_json,
        capacity,
        output_count,
    })
}

/// Get current Unix timestamp
pub fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
