//! Core functions for FFI bindings (WASM, PyO3, etc.)
//!
//! These functions take string inputs and return string outputs,
//! making them easy to wrap with any FFI system.

use super::{
    compute_channel_secret as ecdh, ChannelParameters, CommitmentOutputs,
    DeterministicOutputsForOneContext, EstablishedChannel, KeysetInfo, SpilmanChannelSender,
};
#[cfg(feature = "wallet")]
use cashu::dhke::construct_proofs as dhke_construct_proofs;
#[cfg(feature = "wallet")]
use cashu::nuts::{BlindSignature, BlindSignatureDleq};
use cashu::nuts::{CurrencyUnit, Id, Keys, Proof, PublicKey, SecretKey, SwapRequest, Token};
#[cfg(feature = "wallet")]
use cashu::secret::Secret;
use cashu::util::{hex, unix_time};
use cashu::Amount;
use std::collections::BTreeMap;
use std::str::FromStr;

/// Parse KeysetInfo from JSON
///
/// Expected format:
/// {
///   "keysetId": "00...",
///   "unit": "sat",
///   "keys": { "1": "02...", "2": "02...", ... },
///   "inputFeePpk": 100,
///   "amounts": [1048576, 524288, ...]  // optional, computed from keys if missing
/// }
pub fn parse_keyset_info_from_json(json_str: &str) -> Result<KeysetInfo, String> {
    let json: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("Invalid keyset JSON: {}", e))?;

    // Parse keyset_id (handle both camelCase and snake_case)
    let keyset_id_str = json["keysetId"]
        .as_str()
        .or_else(|| json["keyset_id"].as_str())
        .ok_or("Missing or invalid 'keysetId' field")?;
    let keyset_id: Id = keyset_id_str
        .parse()
        .map_err(|e| format!("Invalid keyset_id: {}", e))?;

    // Parse unit
    let unit_str = json["unit"]
        .as_str()
        .ok_or("Missing or invalid 'unit' field")?;
    let unit = CurrencyUnit::from_str(unit_str).map_err(|e| format!("Invalid unit: {}", e))?;

    // Parse input_fee_ppk (handle both camelCase and snake_case)
    let input_fee_ppk = json["inputFeePpk"]
        .as_u64()
        .or_else(|| json["input_fee_ppk"].as_u64())
        .ok_or("Missing or invalid 'inputFeePpk' field")?;

    // Parse final_expiry (handle both camelCase and snake_case)
    let final_expiry = json["finalExpiry"]
        .as_u64()
        .or_else(|| json["final_expiry"].as_u64());

    // Parse keys map: { "1": "02...", "2": "02...", ... }
    let keys_obj = json["keys"]
        .as_object()
        .ok_or("Missing or invalid 'keys' field")?;

    let mut keys_map: BTreeMap<Amount, PublicKey> = BTreeMap::new();
    for (amount_str, pubkey_val) in keys_obj {
        let amount: u64 = amount_str
            .parse()
            .map_err(|e| format!("Invalid amount '{}': {}", amount_str, e))?;
        let pubkey_hex = pubkey_val
            .as_str()
            .ok_or_else(|| format!("Invalid pubkey for amount {}", amount))?;
        let pubkey = PublicKey::from_str(pubkey_hex)
            .map_err(|e| format!("Invalid pubkey hex for amount {}: {}", amount, e))?;
        keys_map.insert(Amount::from(amount), pubkey);
    }

    let active_keys = Keys::new(keys_map);

    Ok(KeysetInfo::new(
        keyset_id,
        unit,
        active_keys,
        input_fee_ppk,
        final_expiry,
    ))
}

/// Get channel_id from params JSON, channel secret, and keyset info (all as strings)
///
/// This is effectively a method on ChannelParameters, but takes JSON input
/// for FFI compatibility.
pub fn channel_parameters_get_channel_id(
    params_json: &str,
    channel_secret_hex: &str,
    keyset_info_json: &str,
) -> Result<String, String> {
    // Parse the channel secret
    let channel_secret_bytes = hex::decode(channel_secret_hex)
        .map_err(|e| format!("Invalid channel secret hex: {}", e))?;

    if channel_secret_bytes.len() != 32 {
        return Err(format!(
            "Shared secret must be 32 bytes, got {}",
            channel_secret_bytes.len()
        ));
    }

    let mut channel_secret = [0u8; 32];
    channel_secret.copy_from_slice(&channel_secret_bytes);

    // Parse real KeysetInfo from JSON
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    // Use from_json_with_channel_secret to construct params
    let params =
        ChannelParameters::from_json_with_channel_secret(params_json, keyset_info, channel_secret)
            .map_err(|e| format!("Failed to parse params: {}", e))?;

    Ok(params.get_channel_id())
}

/// Compute channel secret from hex-encoded secret key and public key
///
/// Returns the channel secret as a hex string (32 bytes).
pub fn compute_channel_secret_from_hex(
    my_secret_hex: &str,
    their_pubkey_hex: &str,
) -> Result<String, String> {
    let my_secret =
        SecretKey::from_hex(my_secret_hex).map_err(|e| format!("Invalid secret key: {}", e))?;

    let their_pubkey: PublicKey = their_pubkey_hex
        .parse()
        .map_err(|e| format!("Invalid pubkey: {}", e))?;

    let channel_secret = ecdh(&my_secret, &their_pubkey);
    Ok(hex::encode(channel_secret))
}

/// Compute the minimum funding_token_amount needed for a given capacity
///
/// Uses the double-inverse computation:
/// 1. capacity → post-stage-1 nominal (accounting for stage 2 fees)
/// 2. post-stage-1 nominal → funding token nominal (accounting for stage 1 fees)
///
/// Clients should call this before building channel params to determine the
/// funding_token_amount field value.
///
/// Returns the minimum funding_token_amount as a u64 (JSON number string).
pub fn compute_funding_token_amount(
    capacity: u64,
    keyset_info_json: &str,
    maximum_amount: u64,
) -> Result<u64, String> {
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    ChannelParameters::get_minimum_funding_token_amount(capacity, &keyset_info, maximum_amount)
        .map_err(|e| format!("Failed to compute funding token amount: {}", e))
}

/// Create plain (non-P2PK) blinded messages for a given amount
///
/// This creates standard blinded messages with random secrets, suitable for
/// minting via `/v1/mint/bolt11`. The resulting proofs can then be wrapped
/// in a Cashu token and passed to `open_channel_from_token` for funding.
///
/// Returns JSON with:
/// - `blinded_messages`: Array of blinded messages (ready for mint request)
/// - `secrets_with_blinding`: Array of {secret, blinding_factor, amount} for unblinding later
#[cfg(feature = "wallet")]
pub fn create_plain_blinded_messages(
    amount_sat: u64,
    keyset_info_json: &str,
) -> Result<String, String> {
    use cashu::amount::SplitTarget;
    use cashu::nuts::PreMintSecrets;

    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    // amounts must be ascending (smallest first) for FeeAndAmounts::split() to work correctly
    let mut amounts_asc = keyset_info.amounts_largest_first.clone();
    amounts_asc.reverse();
    let fee_and_amounts: cashu::amount::FeeAndAmounts =
        (keyset_info.input_fee_ppk, amounts_asc).into();

    let premint_secrets = PreMintSecrets::random(
        keyset_info.keyset_id,
        Amount::from(amount_sat),
        &SplitTarget::None,
        &fee_and_amounts,
    )
    .map_err(|e| format!("Failed to create blinded messages: {}", e))?;

    // Serialize blinded messages (same format as create_funding_outputs)
    let blinded_messages_json: Vec<serde_json::Value> = premint_secrets
        .blinded_messages()
        .iter()
        .map(|bm| {
            serde_json::json!({
                "amount": u64::from(bm.amount),
                "id": bm.keyset_id.to_string(),
                "B_": bm.blinded_secret.to_hex()
            })
        })
        .collect();

    // Serialize secrets with blinding factors (same format as create_funding_outputs)
    let secrets_json: Vec<serde_json::Value> = premint_secrets
        .secrets
        .iter()
        .map(|pm| {
            serde_json::json!({
                "secret": pm.secret.to_string(),
                "blinding_factor": pm.r.to_secret_hex(),
                "amount": u64::from(pm.amount)
            })
        })
        .collect();

    let result = serde_json::json!({
        "blinded_messages": blinded_messages_json,
        "secrets_with_blinding": secrets_json
    });

    Ok(result.to_string())
}

/// Create funding outputs from params and keyset info
///
/// Returns JSON with:
/// - `funding_token_nominal`: Total nominal value needed
/// - `blinded_messages`: Array of blinded messages (ready for mint request)
/// - `secrets_with_blinding`: Array of {secret, blinding_factor, amount} for unblinding later
pub fn create_funding_outputs(
    params_json: &str,
    alice_secret_hex: &str,
    keyset_info_json: &str,
) -> Result<String, String> {
    // Parse the keyset info
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    // Parse Alice's secret key
    let alice_secret =
        SecretKey::from_hex(alice_secret_hex).map_err(|e| format!("Invalid secret key: {}", e))?;

    // Create ChannelParameters from JSON
    let params =
        ChannelParameters::from_json_with_secret_key(params_json, keyset_info, &alice_secret)
            .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;

    // Get the funding token nominal amount
    let funding_token_nominal = params
        .get_total_funding_token_amount()
        .map_err(|e| format!("Failed to compute funding token amount: {}", e))?;

    // Create deterministic outputs for "funding" context
    let funding_outputs = DeterministicOutputsForOneContext::new(
        "funding".to_string(),
        funding_token_nominal,
        params,
    )
    .map_err(|e| format!("Failed to create funding outputs: {}", e))?;

    // Get blinded messages
    let blinded_messages = funding_outputs
        .get_blinded_messages(None)
        .map_err(|e| format!("Failed to get blinded messages: {}", e))?;

    // Get secrets with blinding factors
    let secrets_with_blinding = funding_outputs
        .get_secrets_with_blinding()
        .map_err(|e| format!("Failed to get secrets with blinding: {}", e))?;

    // Serialize blinded messages to JSON
    let blinded_messages_json: Vec<serde_json::Value> = blinded_messages
        .iter()
        .map(|bm| {
            serde_json::json!({
                "amount": u64::from(bm.amount),
                "id": bm.keyset_id.to_string(),
                "B_": bm.blinded_secret.to_hex()
            })
        })
        .collect();

    // Serialize secrets with blinding to JSON
    let secrets_json: Vec<serde_json::Value> = secrets_with_blinding
        .iter()
        .map(|swb| {
            serde_json::json!({
                "secret": swb.secret.to_string(),
                "blinding_factor": swb.blinding_factor.to_secret_hex(),
                "amount": swb.amount
            })
        })
        .collect();

    // Build result JSON
    let result = serde_json::json!({
        "funding_token_nominal": funding_token_nominal,
        "blinded_messages": blinded_messages_json,
        "secrets_with_blinding": secrets_json
    });

    Ok(result.to_string())
}

/// Construct proofs from blind signatures and secrets with blinding
///
/// Returns JSON array of proofs ready for use
#[cfg(feature = "wallet")]
pub fn construct_proofs(
    blind_signatures_json: &str,
    secrets_with_blinding_json: &str,
    keyset_info_json: &str,
) -> Result<String, String> {
    // Parse keyset info to get the keys
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;
    let keys = keyset_info.active_keys.clone();

    // Parse blind signatures from mint
    let blind_sigs_raw: Vec<serde_json::Value> = serde_json::from_str(blind_signatures_json)
        .map_err(|e| format!("Failed to parse blind signatures: {}", e))?;

    let mut blind_signatures: Vec<BlindSignature> = Vec::new();
    for sig in blind_sigs_raw {
        let amount = sig["amount"]
            .as_u64()
            .ok_or("Missing 'amount' in blind signature")?;
        let id_str = sig["id"]
            .as_str()
            .ok_or("Missing 'id' in blind signature")?;
        let c_str = sig["C_"]
            .as_str()
            .ok_or("Missing 'C_' in blind signature")?;

        let keyset_id: Id = id_str
            .parse()
            .map_err(|e| format!("Invalid keyset id: {}", e))?;
        let c = PublicKey::from_str(c_str).map_err(|e| format!("Invalid C_ pubkey: {}", e))?;

        // Parse DLEQ - required for Spilman channels
        let dleq_obj = sig["dleq"]
            .as_object()
            .ok_or("Missing 'dleq' in blind signature - DLEQ proofs are required")?;
        let e_str = dleq_obj
            .get("e")
            .and_then(|v| v.as_str())
            .ok_or("Missing 'e' in dleq")?;
        let s_str = dleq_obj
            .get("s")
            .and_then(|v| v.as_str())
            .ok_or("Missing 's' in dleq")?;
        let e = SecretKey::from_hex(e_str).map_err(|e| format!("Invalid dleq.e: {}", e))?;
        let s = SecretKey::from_hex(s_str).map_err(|e| format!("Invalid dleq.s: {}", e))?;
        let dleq = BlindSignatureDleq { e, s };

        blind_signatures.push(BlindSignature {
            amount: Amount::from(amount),
            keyset_id,
            c,
            dleq: Some(dleq),
        });
    }

    // Parse secrets with blinding factors
    let secrets_raw: Vec<serde_json::Value> = serde_json::from_str(secrets_with_blinding_json)
        .map_err(|e| format!("Failed to parse secrets with blinding: {}", e))?;

    let mut secrets: Vec<Secret> = Vec::new();
    let mut rs: Vec<SecretKey> = Vec::new();

    for swb in secrets_raw {
        let secret_str = swb["secret"]
            .as_str()
            .ok_or("Missing 'secret' in secrets_with_blinding")?;
        let blinding_factor_hex = swb["blinding_factor"]
            .as_str()
            .ok_or("Missing 'blinding_factor' in secrets_with_blinding")?;

        let secret: Secret = secret_str
            .parse()
            .map_err(|e| format!("Invalid secret: {}", e))?;
        let r = SecretKey::from_hex(blinding_factor_hex)
            .map_err(|e| format!("Invalid blinding factor: {}", e))?;

        secrets.push(secret);
        rs.push(r);
    }

    // Construct the proofs
    let proofs = dhke_construct_proofs(blind_signatures, rs, secrets, &keys)
        .map_err(|e| format!("Failed to construct proofs: {}", e))?;

    // Serialize proofs to JSON
    let proofs_json =
        serde_json::to_string(&proofs).map_err(|e| format!("Failed to serialize proofs: {}", e))?;

    Ok(proofs_json)
}

/// Create a signed balance update for a channel
pub fn create_signed_balance_update(
    params_json: &str,
    keyset_info_json: &str,
    alice_secret_hex: &str,
    proofs_json: &str,
    balance: u64,
) -> Result<String, String> {
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;
    let alice_secret =
        SecretKey::from_hex(alice_secret_hex).map_err(|e| format!("Invalid secret key: {}", e))?;
    let params =
        ChannelParameters::from_json_with_secret_key(params_json, keyset_info, &alice_secret)
            .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;
    let funding_proofs: Vec<Proof> =
        serde_json::from_str(proofs_json).map_err(|e| format!("Failed to parse proofs: {}", e))?;
    let channel = EstablishedChannel::new(params, funding_proofs)
        .map_err(|e| format!("EstablishedChannel::new failed: {}", e))?;
    let sender = SpilmanChannelSender::new(alice_secret, channel);

    let (balance_update, _) = sender
        .create_signed_balance_update(balance)
        .map_err(|e| format!("create_signed_balance_update failed: {}", e))?;

    let result = serde_json::json!({
        "channel_id": balance_update.channel_id,
        "amount": balance_update.amount,
        "signature": balance_update.signature.to_string()
    });

    Ok(result.to_string())
}

// ============================================================================
// SWAP-TO-FUNDING FUNCTIONS
// ============================================================================
// These functions allow creating channel funding from existing wallet tokens
// (via swap) instead of minting fresh tokens.

/// Compute channel parameters from a Cashu token
///
/// Given a token string (cashuA.../cashuB...), computes the channel capacity,
/// funding token nominal amount, and change amount. Also builds the channel
/// parameters ready for use.
///
/// # Arguments
/// * `token_string` - The Cashu token (cashuA... or cashuB...)
/// * `receiver_pubkey_hex` - Receiver's public key (hex)
/// * `sender_pubkey_hex` - Sender's public key (hex)
/// * `channel_secret_hex` - Pre-computed ECDH channel secret (32 bytes, hex)
/// * `expiry_timestamp` - Unix timestamp for channel expiry (refund becomes available)
/// * `keyset_info_json` - Keyset info from mint (JSON)
/// * `maximum_amount_for_one_output` - Max amount per output from server policy
///
/// # Returns
/// JSON with:
/// - `capacity`: Channel capacity (final value after all fees)
/// - `funding_token_amount`: Nominal value of the funding token
/// - `input_value`: Total value of input proofs
/// - `mint_url`: Mint URL from the token
/// - `params_json`: Serialized channel params for use in later functions
/// - `proofs_json`: The parsed proofs from the token (for create_funding_swap)
pub fn compute_channel_from_token(
    token_string: &str,
    receiver_pubkey_hex: &str,
    sender_pubkey_hex: &str,
    channel_secret_hex: &str,
    expiry_timestamp: u64,
    keyset_info_json: &str,
    maximum_amount_for_one_output: u64,
) -> Result<String, String> {
    // Parse the token
    let token: Token = token_string
        .parse()
        .map_err(|e| format!("Failed to parse token: {}", e))?;

    // Get total value from token (doesn't need keyset info)
    let input_value: u64 = token
        .value()
        .map_err(|e| format!("Failed to get token value: {}", e))?
        .into();

    // Get mint URL
    let mint_url = token
        .mint_url()
        .map_err(|e| format!("Failed to get mint URL: {}", e))?;

    // Get unit from token
    let unit = token.unit().unwrap_or(CurrencyUnit::Sat);

    // Parse keyset info
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    // Parse proofs using keyset info
    // We need to create a KeySetInfo (nut02) for the token's proofs() method
    let nut02_keyset_info = cashu::nuts::KeySetInfo {
        id: keyset_info.keyset_id,
        unit: unit.clone(),
        active: true,
        input_fee_ppk: keyset_info.input_fee_ppk,
        final_expiry: None,
    };
    let proofs = token
        .proofs(&[nut02_keyset_info])
        .map_err(|e| format!("Failed to parse proofs: {}", e))?;

    // Assert all proofs are from the same keyset
    for proof in &proofs {
        if proof.keyset_id != keyset_info.keyset_id {
            return Err(format!(
                "All proofs must be from the same keyset. Expected {}, got {}",
                keyset_info.keyset_id, proof.keyset_id
            ));
        }
    }

    let max_amt = maximum_amount_for_one_output;

    // Step 1: funding_token_amount = forward_fees(input_value) - value after swap's input fees
    // This is the nominal value of the funding token after swapping wallet proofs
    let funding_token_amount = keyset_info
        .deterministic_value_after_fees(input_value, max_amt)
        .map_err(|e| format!("Failed to compute funding_token_amount: {}", e))?;

    // Step 2: capacity = forward(forward(funding_token_amount)) - value after both close stages
    let v2 = keyset_info
        .deterministic_value_after_fees(funding_token_amount, max_amt)
        .map_err(|e| format!("Failed to compute v2: {}", e))?;
    let capacity = keyset_info
        .deterministic_value_after_fees(v2, max_amt)
        .map_err(|e| format!("Failed to compute capacity: {}", e))?;

    // Parse sender pubkey
    let sender_pubkey: PublicKey = sender_pubkey_hex
        .parse()
        .map_err(|e| format!("Invalid sender pubkey: {}", e))?;

    // Parse receiver pubkey
    let receiver_pubkey: PublicKey = receiver_pubkey_hex
        .parse()
        .map_err(|e| format!("Invalid receiver pubkey: {}", e))?;

    // Parse channel secret
    let channel_secret_bytes = hex::decode(channel_secret_hex)
        .map_err(|e| format!("Invalid channel secret hex: {}", e))?;
    if channel_secret_bytes.len() != 32 {
        return Err(format!(
            "Channel secret must be 32 bytes, got {}",
            channel_secret_bytes.len()
        ));
    }
    let mut channel_secret = [0u8; 32];
    channel_secret.copy_from_slice(&channel_secret_bytes);

    // Create channel parameters with pre-computed channel secret
    let params = ChannelParameters::new(
        sender_pubkey,
        receiver_pubkey,
        mint_url.to_string(),
        unit,
        capacity,
        funding_token_amount,
        expiry_timestamp,
        unix_time(),
        keyset_info.clone(),
        max_amt,
        channel_secret,
    )
    .map_err(|e| format!("Failed to create channel params: {}", e))?;

    // Serialize proofs
    let proofs_json =
        serde_json::to_string(&proofs).map_err(|e| format!("Failed to serialize proofs: {}", e))?;

    // Serialize params
    let params_json = params.get_channel_id_params_json();

    // Build result
    let result = serde_json::json!({
        "capacity": capacity,
        "funding_token_amount": funding_token_amount,
        "input_value": input_value,
        "mint_url": mint_url.to_string(),
        "params_json": params_json,
        "proofs_json": proofs_json
    });

    Ok(result.to_string())
}

/// Create a swap request for funding a channel from existing proofs
///
/// Takes input proofs and creates a swap request with deterministic
/// funding outputs (2-of-2 locked).
///
/// # Arguments
/// * `params_json` - Channel params JSON (from compute_channel_from_token)
/// * `channel_secret_hex` - Pre-computed ECDH channel secret (32 bytes, hex)
/// * `keyset_info_json` - Keyset info (JSON)
/// * `input_proofs_json` - Input proofs from the token (JSON array)
///
/// # Returns
/// JSON with:
/// - `swap_request_json`: The swap request to send to mint (JSON)
/// - `funding_secrets_json`: Secrets for unblinding funding outputs (JSON array)
/// - `funding_count`: Number of funding outputs
/// Reconstruct the deterministic funding outputs from channel parameters.
///
/// This is the shared helper used by `create_funding_swap`,
/// `create_funding_restore_request`, and `complete_funding_restore`.
fn reconstruct_funding_outputs(
    params_json: &str,
    channel_secret_hex: &str,
    keyset_info_json: &str,
) -> Result<DeterministicOutputsForOneContext, String> {
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    let channel_secret_bytes = hex::decode(channel_secret_hex)
        .map_err(|e| format!("Invalid channel secret hex: {}", e))?;
    if channel_secret_bytes.len() != 32 {
        return Err(format!(
            "Channel secret must be 32 bytes, got {}",
            channel_secret_bytes.len()
        ));
    }
    let mut channel_secret = [0u8; 32];
    channel_secret.copy_from_slice(&channel_secret_bytes);

    let params =
        ChannelParameters::from_json_with_channel_secret(params_json, keyset_info, channel_secret)
            .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;

    let funding_token_nominal = params
        .get_total_funding_token_amount()
        .map_err(|e| format!("Failed to compute funding token amount: {}", e))?;

    DeterministicOutputsForOneContext::new("funding".to_string(), funding_token_nominal, params)
        .map_err(|e| format!("Failed to create funding outputs: {}", e))
}

/// Create a funding swap request from channel parameters and input proofs.
pub fn create_funding_swap(
    params_json: &str,
    channel_secret_hex: &str,
    keyset_info_json: &str,
    input_proofs_json: &str,
) -> Result<String, String> {
    let funding_outputs =
        reconstruct_funding_outputs(params_json, channel_secret_hex, keyset_info_json)?;

    // Parse input proofs
    let input_proofs: Vec<Proof> = serde_json::from_str(input_proofs_json)
        .map_err(|e| format!("Failed to parse input proofs: {}", e))?;

    // Get funding blinded messages
    let funding_blinded_messages = funding_outputs
        .get_blinded_messages(None)
        .map_err(|e| format!("Failed to get funding blinded messages: {}", e))?;

    // Get funding secrets with blinding
    let funding_secrets = funding_outputs
        .get_secrets_with_blinding()
        .map_err(|e| format!("Failed to get funding secrets: {}", e))?;

    // Create swap request
    let swap_request = SwapRequest::new(input_proofs, funding_blinded_messages);

    // Serialize swap request
    let swap_request_json = serde_json::to_string(&swap_request)
        .map_err(|e| format!("Failed to serialize swap request: {}", e))?;

    // Serialize funding secrets
    let funding_secrets_json: Vec<serde_json::Value> = funding_secrets
        .iter()
        .map(|swb| {
            serde_json::json!({
                "secret": swb.secret.to_string(),
                "blinding_factor": swb.blinding_factor.to_secret_hex(),
                "amount": swb.amount
            })
        })
        .collect();

    let funding_secrets_str = serde_json::to_string(&funding_secrets_json)
        .map_err(|e| format!("Failed to serialize funding secrets: {}", e))?;

    // Build result
    let result = serde_json::json!({
        "swap_request_json": swap_request_json,
        "funding_secrets_json": funding_secrets_str,
        "funding_count": funding_secrets.len()
    });

    Ok(result.to_string())
}

/// Create a NUT-09 restore request for funding outputs.
///
/// Reconstructs the deterministic blinded messages from channel parameters
/// and serializes them as a restore request JSON for POST to `/v1/restore`.
///
/// # Arguments
/// * `params_json` - Channel parameters JSON
/// * `channel_secret_hex` - Channel secret (64-char hex)
/// * `keyset_info_json` - Keyset info (JSON)
///
/// # Returns
/// JSON string: `{"outputs": [...]}`
#[cfg(feature = "wallet")]
pub fn create_funding_restore_request(
    params_json: &str,
    channel_secret_hex: &str,
    keyset_info_json: &str,
) -> Result<String, String> {
    let funding_outputs =
        reconstruct_funding_outputs(params_json, channel_secret_hex, keyset_info_json)?;

    let blinded_messages = funding_outputs
        .get_blinded_messages(None)
        .map_err(|e| format!("Failed to get blinded messages: {}", e))?;

    // Serialize as restore request
    let restore_request = serde_json::json!({
        "outputs": blinded_messages
    });

    serde_json::to_string(&restore_request)
        .map_err(|e| format!("Failed to serialize restore request: {}", e))
}

/// Complete a funding restore by unblinding the mint's NUT-09 response.
///
/// Reconstructs the deterministic secrets from channel parameters (no need
/// for externally-provided secrets since they are fully deterministic),
/// then delegates to `complete_funding_swap` to unblind and verify DLEQ.
///
/// # Arguments
/// * `restore_response_json` - Mint's restore response: `{"outputs": [...], "signatures": [...]}`
/// * `params_json` - Channel parameters JSON
/// * `channel_secret_hex` - Channel secret (64-char hex)
/// * `keyset_info_json` - Keyset info (JSON)
///
/// # Returns
/// JSON with `funding_proofs_json` (same as `complete_funding_swap`)
#[cfg(feature = "wallet")]
pub fn complete_funding_restore(
    restore_response_json: &str,
    params_json: &str,
    channel_secret_hex: &str,
    keyset_info_json: &str,
) -> Result<String, String> {
    // Parse restore response to extract signatures
    let restore_response: serde_json::Value = serde_json::from_str(restore_response_json)
        .map_err(|e| format!("Failed to parse restore response: {}", e))?;

    let signatures = restore_response
        .get("signatures")
        .ok_or("Missing 'signatures' in restore response")?;

    // Wrap signatures in swap-response format for reuse by complete_funding_swap
    let swap_response = serde_json::json!({
        "signatures": signatures
    });
    let swap_response_json = serde_json::to_string(&swap_response)
        .map_err(|e| format!("Failed to serialize swap response: {}", e))?;

    // Reconstruct funding secrets deterministically
    let funding_outputs =
        reconstruct_funding_outputs(params_json, channel_secret_hex, keyset_info_json)?;

    let funding_secrets = funding_outputs
        .get_secrets_with_blinding()
        .map_err(|e| format!("Failed to get funding secrets: {}", e))?;

    // Serialize funding secrets (same format as create_funding_swap)
    let funding_secrets_json: Vec<serde_json::Value> = funding_secrets
        .iter()
        .map(|swb| {
            serde_json::json!({
                "secret": swb.secret.to_string(),
                "blinding_factor": swb.blinding_factor.to_secret_hex(),
                "amount": swb.amount
            })
        })
        .collect();

    let funding_secrets_str = serde_json::to_string(&funding_secrets_json)
        .map_err(|e| format!("Failed to serialize funding secrets: {}", e))?;

    // Delegate to complete_funding_swap
    complete_funding_swap(&swap_response_json, &funding_secrets_str, keyset_info_json)
}

/// Complete a funding swap by unblinding the mint's response
///
/// Takes the mint's swap response and unblinding the funding proofs.
/// Also verifies DLEQ proofs on all signatures.
///
/// # Arguments
/// * `swap_response_json` - Mint's swap response (JSON with "signatures" array)
/// * `funding_secrets_json` - Funding secrets from create_funding_swap (JSON array)
/// * `keyset_info_json` - Keyset info (JSON)
///
/// # Returns
/// JSON with:
/// - `funding_proofs_json`: Funding proofs for channel (JSON array)
#[cfg(feature = "wallet")]
pub fn complete_funding_swap(
    swap_response_json: &str,
    funding_secrets_json: &str,
    keyset_info_json: &str,
) -> Result<String, String> {
    // Parse keyset info
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;
    let keys = keyset_info.active_keys.clone();

    // Parse swap response to get signatures
    let response: serde_json::Value = serde_json::from_str(swap_response_json)
        .map_err(|e| format!("Failed to parse swap response: {}", e))?;

    let signatures_raw = response["signatures"]
        .as_array()
        .ok_or("Missing 'signatures' in swap response")?;

    // Parse funding secrets
    let funding_secrets_raw: Vec<serde_json::Value> = serde_json::from_str(funding_secrets_json)
        .map_err(|e| format!("Failed to parse funding secrets: {}", e))?;

    let funding_count = funding_secrets_raw.len();

    // Verify signature count matches
    if signatures_raw.len() != funding_count {
        return Err(format!(
            "Signature count mismatch: expected {}, got {}",
            funding_count,
            signatures_raw.len()
        ));
    }

    // Helper to parse and verify signatures
    let parse_signatures = |sigs: &[serde_json::Value]| -> Result<Vec<BlindSignature>, String> {
        let mut result = Vec::new();
        for (i, sig) in sigs.iter().enumerate() {
            let amount = sig["amount"]
                .as_u64()
                .ok_or_else(|| format!("Missing 'amount' in signature {}", i))?;
            let id_str = sig["id"]
                .as_str()
                .ok_or_else(|| format!("Missing 'id' in signature {}", i))?;
            let c_str = sig["C_"]
                .as_str()
                .ok_or_else(|| format!("Missing 'C_' in signature {}", i))?;

            let keyset_id: Id = id_str
                .parse()
                .map_err(|e| format!("Invalid keyset id in signature {}: {}", i, e))?;
            let c = PublicKey::from_str(c_str)
                .map_err(|e| format!("Invalid C_ in signature {}: {}", i, e))?;

            // Parse DLEQ - required for Spilman channels
            let dleq_obj = sig["dleq"].as_object().ok_or_else(|| {
                format!(
                    "Missing 'dleq' in signature {} - DLEQ proofs are required",
                    i
                )
            })?;
            let e_str = dleq_obj
                .get("e")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("Missing 'e' in dleq for signature {}", i))?;
            let s_str = dleq_obj
                .get("s")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("Missing 's' in dleq for signature {}", i))?;
            let e = SecretKey::from_hex(e_str)
                .map_err(|e| format!("Invalid dleq.e in signature {}: {}", i, e))?;
            let s = SecretKey::from_hex(s_str)
                .map_err(|e| format!("Invalid dleq.s in signature {}: {}", i, e))?;
            let dleq = BlindSignatureDleq { e, s };

            result.push(BlindSignature {
                amount: Amount::from(amount),
                keyset_id,
                c,
                dleq: Some(dleq),
            });
        }
        Ok(result)
    };

    // Helper to parse secrets
    let parse_secrets =
        |secrets: &[serde_json::Value]| -> Result<(Vec<Secret>, Vec<SecretKey>), String> {
            let mut result_secrets = Vec::new();
            let mut result_rs = Vec::new();
            for (i, swb) in secrets.iter().enumerate() {
                let secret_str = swb["secret"]
                    .as_str()
                    .ok_or_else(|| format!("Missing 'secret' in secrets {}", i))?;
                let blinding_factor_hex = swb["blinding_factor"]
                    .as_str()
                    .ok_or_else(|| format!("Missing 'blinding_factor' in secrets {}", i))?;

                let secret: Secret = secret_str
                    .parse()
                    .map_err(|e| format!("Invalid secret {}: {}", i, e))?;
                let r = SecretKey::from_hex(blinding_factor_hex)
                    .map_err(|e| format!("Invalid blinding factor {}: {}", i, e))?;

                result_secrets.push(secret);
                result_rs.push(r);
            }
            Ok((result_secrets, result_rs))
        };

    // Parse funding signatures and secrets
    let funding_blind_sigs = parse_signatures(signatures_raw)?;
    let (funding_secrets, funding_rs) = parse_secrets(&funding_secrets_raw)?;

    // Construct funding proofs (includes DLEQ verification)
    #[cfg(feature = "wallet")]
    let funding_proofs =
        dhke_construct_proofs(funding_blind_sigs, funding_rs, funding_secrets, &keys).map_err(
            |e| {
                format!(
                    "Failed to construct funding proofs (DLEQ verification failed?): {}",
                    e
                )
            },
        )?;

    #[cfg(not(feature = "wallet"))]
    let funding_proofs: Vec<Proof> = Vec::new(); // Stub for non-wallet builds
    #[cfg(not(feature = "wallet"))]
    let _ = (funding_blind_sigs, funding_rs, funding_secrets, keys); // suppress unused warnings

    // Serialize results
    let funding_proofs_json = serde_json::to_string(&funding_proofs)
        .map_err(|e| format!("Failed to serialize funding proofs: {}", e))?;

    let result = serde_json::json!({
        "funding_proofs_json": funding_proofs_json
    });

    Ok(result.to_string())
}

// ============================================================================
// TEST/DEMO HELPERS
// ============================================================================
// These functions consolidate common patterns used across language bindings
// (Go, Python, TypeScript) in tests and demos.

/// Build a cashuA token string from proofs JSON and a mint URL.
///
/// Takes a JSON array of proofs and wraps them in the cashuA token format:
/// `"cashuA" + base64url({ token: [{ mint, proofs }], unit: "sat" })`
///
/// # Arguments
/// * `mint_url` - The mint URL to embed in the token
/// * `proofs_json` - JSON array of proofs (from construct_proofs or mint response)
///
/// # Returns
/// A cashuA token string (e.g. "cashuAeyJ0b2...")
pub fn build_cashu_a_token(mint_url: &str, proofs_json: &str) -> Result<String, String> {
    use cashu::mint_url::MintUrl;
    use cashu::nuts::nut00::TokenV3;

    let proofs: Vec<Proof> =
        serde_json::from_str(proofs_json).map_err(|e| format!("Failed to parse proofs: {}", e))?;

    let mint_url = MintUrl::from_str(mint_url).map_err(|e| format!("Invalid mint URL: {}", e))?;

    let token = TokenV3::new(mint_url, proofs, None, Some(CurrencyUnit::Sat))
        .map_err(|e| format!("Failed to create TokenV3: {}", e))?;

    Ok(token.to_string())
}

/// Build a cashuB (v4) token string from proofs JSON, a mint URL, and a unit.
///
/// Takes a JSON array of proofs and wraps them in the cashuB token format
/// (CBOR-encoded, `"cashuB" + base64url(...)`).
///
/// # Arguments
/// * `mint_url` - The mint URL to embed in the token
/// * `unit` - The currency unit (e.g. "sat", "msat", "usd")
/// * `proofs_json` - JSON array of proofs (must include witness fields if present)
///
/// # Returns
/// A cashuB token string (e.g. "cashuBpGF0...")
pub fn build_cashu_b_token(
    mint_url: &str,
    unit: &str,
    proofs_json: &str,
) -> Result<String, String> {
    use cashu::mint_url::MintUrl;

    let proofs: Vec<Proof> =
        serde_json::from_str(proofs_json).map_err(|e| format!("Failed to parse proofs: {}", e))?;

    let mint_url = MintUrl::from_str(mint_url).map_err(|e| format!("Invalid mint URL: {}", e))?;

    let currency_unit =
        CurrencyUnit::from_str(unit).unwrap_or(CurrencyUnit::Custom(unit.to_string()));

    let token = Token::new(mint_url, proofs, None, currency_unit);

    Ok(token.to_string())
}

/// Mint plain proofs from a Cashu mint via HTTP.
///
/// Performs the full minting flow:
/// 1. Creates plain blinded messages for the given amount
/// 2. Requests a mint quote via POST /v1/mint/quote/bolt11
/// 3. Polls until the quote is PAID (up to 60 attempts, 100ms apart)
/// 4. Mints tokens via POST /v1/mint/bolt11
/// 5. Constructs and returns the proofs
///
/// The caller provides HTTP capabilities via the `call_http` callback:
/// - `call_http("POST", url, body_json)` -> response body as JSON string
/// - `call_http("GET", url, "")` -> response body as JSON string
///
/// This function is intended for tests and demos (especially with fakewallet
/// mints that auto-pay invoices).
///
/// # Arguments
/// * `mint_url` - The mint URL (e.g. "http://localhost:3338")
/// * `amount_sat` - Amount to mint in satoshis
/// * `keyset_info_json` - Keyset info JSON (from fetch_active_keyset)
/// * `call_http` - HTTP callback: (method, url, body) -> response_json
///
/// # Returns
/// JSON array of proofs ready for use
#[cfg(feature = "wallet")]
pub fn mint_proofs_from_mint(
    mint_url: &str,
    amount_sat: u64,
    keyset_info_json: &str,
    call_http: &dyn Fn(&str, &str, &str) -> Result<String, String>,
) -> Result<String, String> {
    // 1. Create plain blinded messages
    let result_json = create_plain_blinded_messages(amount_sat, keyset_info_json)?;
    let result: serde_json::Value = serde_json::from_str(&result_json)
        .map_err(|e| format!("Failed to parse blinded messages result: {}", e))?;
    let blinded_messages = &result["blinded_messages"];
    let secrets_with_blinding = result["secrets_with_blinding"].to_string();

    // 2. Request a mint quote
    let quote_body = serde_json::json!({
        "amount": amount_sat,
        "unit": "sat"
    })
    .to_string();

    let quote_url = format!("{}/v1/mint/quote/bolt11", mint_url);
    let quote_resp = call_http("POST", &quote_url, &quote_body)?;
    let quote: serde_json::Value = serde_json::from_str(&quote_resp)
        .map_err(|e| format!("Failed to parse mint quote response: {}", e))?;
    let quote_id = quote["quote"]
        .as_str()
        .ok_or("Missing 'quote' in mint quote response")?;

    // 3. Poll until paid (fakewallet auto-pays)
    let poll_url = format!("{}/v1/mint/quote/bolt11/{}", mint_url, quote_id);
    for i in 0..60 {
        let poll_resp = call_http("GET", &poll_url, "")?;
        let poll: serde_json::Value = serde_json::from_str(&poll_resp)
            .map_err(|e| format!("Failed to parse poll response: {}", e))?;
        if poll["state"].as_str() == Some("PAID") {
            break;
        }
        if i == 59 {
            return Err("Timeout waiting for mint quote to be paid".to_string());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // 4. Mint tokens
    let mint_body = serde_json::json!({
        "quote": quote_id,
        "outputs": blinded_messages
    })
    .to_string();

    let mint_token_url = format!("{}/v1/mint/bolt11", mint_url);
    let mint_resp = call_http("POST", &mint_token_url, &mint_body)?;
    let mint_result: serde_json::Value = serde_json::from_str(&mint_resp)
        .map_err(|e| format!("Failed to parse mint response: {}", e))?;
    let signatures = mint_result["signatures"]
        .as_array()
        .ok_or("Missing 'signatures' in mint response")?;
    let signatures_json = serde_json::to_string(signatures)
        .map_err(|e| format!("Failed to serialize signatures: {}", e))?;

    // 5. Construct proofs
    construct_proofs(&signatures_json, &secrets_with_blinding, keyset_info_json)
}

// ============================================================================
// EXTERNAL SIGNER SUPPORT
// ============================================================================
// These functions support the SpilmanClientBridge's delegated signing flow,
// where the host provides a signing callback instead of the bridge holding
// a secret key directly.

/// Utility function for SpilmanClientHost implementations to sign with a tweaked key.
///
/// Given a secret key, a message hash, and a tweak scalar, computes:
///   tweaked_key = effective_secret + tweak
/// where effective_secret handles BIP-340 parity (negated if pubkey has odd Y),
/// then produces a BIP-340 Schnorr signature over the message.
///
/// This is a convenience function — hosts can implement signing however they want,
/// but this provides the standard implementation for hosts that hold raw secret keys.
///
/// # Arguments
/// * `secret_key_hex` - The signer's secret key (32 bytes, hex-encoded)
/// * `message_hex` - SHA-256 hash of the message to sign (32 bytes, hex-encoded)
/// * `tweak_scalar_hex` - The P2BK blinding scalar to add (32 bytes, hex-encoded)
///
/// # Returns
/// The BIP-340 Schnorr signature (64 bytes, hex-encoded)
pub fn sign_with_tweaked_key_util(
    secret_key_hex: &str,
    message_hex: &str,
    tweak_scalar_hex: &str,
) -> Result<String, String> {
    use bitcoin::secp256k1::{Keypair, Message, Parity, Scalar, Secp256k1};

    let secp = Secp256k1::new();

    // Parse the secret key
    let secret =
        SecretKey::from_hex(secret_key_hex).map_err(|e| format!("Invalid secret key: {}", e))?;

    // Parse the tweak scalar
    let tweak_bytes =
        hex::decode(tweak_scalar_hex).map_err(|e| format!("Invalid tweak hex: {}", e))?;
    if tweak_bytes.len() != 32 {
        return Err(format!("Tweak must be 32 bytes, got {}", tweak_bytes.len()));
    }
    let mut tweak_arr = [0u8; 32];
    tweak_arr.copy_from_slice(&tweak_bytes);
    let tweak =
        Scalar::from_be_bytes(tweak_arr).map_err(|e| format!("Invalid tweak scalar: {}", e))?;

    // Parse the message hash
    let msg_bytes = hex::decode(message_hex).map_err(|e| format!("Invalid message hex: {}", e))?;
    if msg_bytes.len() != 32 {
        return Err(format!(
            "Message hash must be 32 bytes, got {}",
            msg_bytes.len()
        ));
    }
    let msg = Message::from_digest_slice(&msg_bytes)
        .map_err(|e| format!("Invalid message digest: {}", e))?;

    // Handle BIP-340 parity: if pubkey has odd Y, negate secret before adding tweak
    let pubkey = secret.public_key();
    let inner_pubkey: &bitcoin::secp256k1::PublicKey = &pubkey;
    let (_, parity) = inner_pubkey.x_only_public_key();

    let inner_secret: bitcoin::secp256k1::SecretKey = *secret;
    let effective_secret = if parity == Parity::Odd {
        inner_secret.negate()
    } else {
        inner_secret
    };

    // Add the tweak: tweaked_key = effective_secret + tweak
    let tweaked = effective_secret
        .add_tweak(&tweak)
        .map_err(|e| format!("Failed to add tweak: {}", e))?;

    // Sign with the tweaked key
    let keypair = Keypair::from_secret_key(&secp, &tweaked);
    let signature = secp.sign_schnorr(&msg, &keypair);

    Ok(signature.to_string())
}

/// Create an unsigned balance update for a channel.
///
/// Like `create_signed_balance_update`, but stops before signing.
/// Returns the unsigned swap request along with the message hash and tweak scalar
/// needed for external signing.
///
/// # Arguments
/// * `params_json` - Channel parameters JSON
/// * `keyset_info_json` - Keyset info JSON
/// * `channel_secret_hex` - The hashed ECDH channel secret (32 bytes, hex)
/// * `proofs_json` - Funding proofs JSON
/// * `balance` - New balance for Charlie
///
/// # Returns
/// JSON with:
/// - `channel_id`: Channel ID string
/// - `amount`: The balance amount
/// - `unsigned_swap_request_json`: The unsigned swap request (JSON)
/// - `message_hex`: SHA-256 hash of the SIG_ALL message (32 bytes, hex)
/// - `tweak_scalar_hex`: The P2BK blinding scalar for sender_stage1 (32 bytes, hex)
pub fn create_unsigned_balance_update(
    params_json: &str,
    keyset_info_json: &str,
    channel_secret_hex: &str,
    proofs_json: &str,
    balance: u64,
) -> Result<String, String> {
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;
    let channel_secret_bytes = hex::decode(channel_secret_hex)
        .map_err(|e| format!("Invalid channel secret hex: {}", e))?;
    if channel_secret_bytes.len() != 32 {
        return Err(format!(
            "Channel secret must be 32 bytes, got {}",
            channel_secret_bytes.len()
        ));
    }
    let mut channel_secret_arr = [0u8; 32];
    channel_secret_arr.copy_from_slice(&channel_secret_bytes);
    let params = ChannelParameters::from_json_with_channel_secret(
        params_json,
        keyset_info,
        channel_secret_arr,
    )
    .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;
    let funding_proofs: Vec<Proof> =
        serde_json::from_str(proofs_json).map_err(|e| format!("Failed to parse proofs: {}", e))?;

    // Create commitment outputs for this balance
    let commitment_outputs = CommitmentOutputs::for_balance(balance, &params)
        .map_err(|e| format!("CommitmentOutputs::for_balance failed: {}", e))?;

    // Create the unsigned swap request
    let channel = EstablishedChannel::new(params.clone(), funding_proofs)
        .map_err(|e| format!("EstablishedChannel::new failed: {}", e))?;
    let swap_request = commitment_outputs
        .create_swap_request(channel.funding_proofs.clone(), None)
        .map_err(|e| format!("create_swap_request failed: {}", e))?;

    // Compute the SIG_ALL message hash
    let message_hex = super::balance_update::sig_all_message_hash_hex(&swap_request);

    // Compute the tweak scalar (P2BK blinding for sender_stage1)
    let tweak = params
        .derive_sender_blinding_scalar_for_stage1()
        .map_err(|e| format!("Failed to derive blinding scalar: {}", e))?;
    let tweak_scalar_hex = hex::encode(tweak.to_be_bytes());

    // Serialize the unsigned swap request
    let unsigned_swap_request_json = serde_json::to_string(&swap_request)
        .map_err(|e| format!("Failed to serialize swap request: {}", e))?;

    let channel_id = params.get_channel_id();

    let result = serde_json::json!({
        "channel_id": channel_id,
        "amount": balance,
        "unsigned_swap_request_json": unsigned_swap_request_json,
        "message_hex": message_hex,
        "tweak_scalar_hex": tweak_scalar_hex,
    });

    Ok(result.to_string())
}

/// Attach an externally-produced signature to an unsigned balance update.
///
/// Takes an unsigned swap request and a BIP-340 Schnorr signature, attaches
/// the signature to the first input's witness, and returns a BalanceUpdateMessage.
///
/// # Arguments
/// * `unsigned_swap_request_json` - The unsigned swap request (from `create_unsigned_balance_update`)
/// * `signature_hex` - BIP-340 Schnorr signature (64 bytes, hex-encoded)
/// * `channel_id` - Channel ID string
/// * `amount` - The balance amount
///
/// # Returns
/// JSON with:
/// - `channel_id`: Channel ID string
/// - `amount`: The balance amount
/// - `signature`: The composite signature string (from the BalanceUpdateMessage)
pub fn attach_signature_to_balance_update(
    unsigned_swap_request_json: &str,
    signature_hex: &str,
    channel_id: &str,
    amount: u64,
) -> Result<String, String> {
    // Parse the unsigned swap request
    let mut swap_request: SwapRequest = serde_json::from_str(unsigned_swap_request_json)
        .map_err(|e| format!("Failed to parse swap request: {}", e))?;

    // Validate the signature string (must parse as a valid Schnorr signature)
    let _sig: bitcoin::secp256k1::schnorr::Signature = signature_hex.parse().map_err(
        |e: <bitcoin::secp256k1::schnorr::Signature as FromStr>::Err| {
            format!("Invalid signature hex: {}", e)
        },
    )?;

    // Attach the signature to the first input's witness
    super::balance_update::attach_signature_to_first_input(&mut swap_request, signature_hex)
        .map_err(|e| format!("attach_signature_to_first_input failed: {}", e))?;

    // Extract the composite signature from the now-signed swap request
    let balance_update = super::balance_update::BalanceUpdateMessage::from_signed_swap_request(
        channel_id.to_string(),
        amount,
        &swap_request,
    )
    .map_err(|e| format!("from_signed_swap_request failed: {}", e))?;

    let result = serde_json::json!({
        "channel_id": balance_update.channel_id,
        "amount": balance_update.amount,
        "signature": balance_update.signature.to_string()
    });

    Ok(result.to_string())
}
