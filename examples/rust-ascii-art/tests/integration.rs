//! Integration tests for Spilman payment channels.
//!
//! These tests require a Cashu mint running at MINT_URL (default: http://localhost:3338).
//!
//! Run with: MINT_URL=http://localhost:3338 cargo test --test integration -- --nocapture

use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use cashu::nuts::SecretKey;
use cdk_spilman::{
    channel_parameters_get_channel_id, compute_channel_secret_from_hex,
    compute_funding_token_amount, create_funding_outputs,
};

fn get_mint_url() -> String {
    env::var("MINT_URL").unwrap_or_else(|_| "http://localhost:3338".to_string())
}

/// Test that we can connect to the mint and get info
#[test]
fn test_mint_connectivity() {
    let mint_url = get_mint_url();
    let client = reqwest::blocking::Client::new();

    let response = client
        .get(format!("{}/v1/info", mint_url))
        .send()
        .expect("Failed to connect to mint");

    assert!(response.status().is_success(), "Mint returned error status");

    let info: serde_json::Value = response.json().expect("Failed to parse mint info");
    println!(
        "Connected to mint: {} (version {})",
        info["name"].as_str().unwrap_or("unknown"),
        info["version"].as_str().unwrap_or("unknown")
    );
}

/// Fetch the active keyset for a unit from the mint, returning JSON for the bindings
fn fetch_active_keyset_json(mint_url: &str, unit: &str) -> Option<(String, serde_json::Value)> {
    let client = reqwest::blocking::Client::new();

    // Get keysets
    let keysets_resp: serde_json::Value = client
        .get(format!("{}/v1/keysets", mint_url))
        .send()
        .ok()?
        .json()
        .ok()?;

    let keysets = keysets_resp["keysets"].as_array()?;

    // Find active keyset for unit
    let active_keyset = keysets
        .iter()
        .find(|k| k["unit"].as_str() == Some(unit) && k["active"].as_bool() == Some(true))?;

    let keyset_id = active_keyset["id"].as_str()?;
    let input_fee_ppk = active_keyset["input_fee_ppk"].as_u64().unwrap_or(0);

    // Get keys for this keyset
    let keys_resp: serde_json::Value = client
        .get(format!("{}/v1/keys/{}", mint_url, keyset_id))
        .send()
        .ok()?
        .json()
        .ok()?;

    let keys_obj = keys_resp["keysets"].as_array()?.first()?["keys"].as_object()?;

    // Build keyset info JSON (format expected by bindings)
    let keyset_info = serde_json::json!({
        "keysetId": keyset_id,
        "unit": unit,
        "keys": keys_obj,
        "inputFeePpk": input_fee_ppk,
        "amounts": keys_obj.keys()
            .filter_map(|k: &String| k.parse::<u64>().ok())
            .collect::<Vec<u64>>()
    });

    Some((keyset_id.to_string(), keyset_info))
}

/// Test the client-side channel setup flow.
/// This requires a mint to fetch keyset info, but doesn't require minting tokens.
#[test]
fn test_funding_outputs_and_channel_id() {
    let mint_url = get_mint_url();

    // 1. Generate sender keypair
    let alice_secret = SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    println!(
        "Generated sender pubkey: {}...",
        &sender_pubkey.to_hex()[..16]
    );

    // 2. Generate receiver keypair (normally this comes from the server)
    let receiver_secret = SecretKey::generate();
    let receiver_pubkey = receiver_secret.public_key();
    println!(
        "Generated receiver pubkey: {}...",
        &receiver_pubkey.to_hex()[..16]
    );

    // 3. Fetch active keyset from mint
    let (keyset_id, keyset_info) =
        fetch_active_keyset_json(&mint_url, "sat").expect("Failed to fetch keyset from mint");
    let keyset_json = serde_json::to_string(&keyset_info).expect("Failed to serialize keyset");
    println!("Fetched keyset: {}", keyset_id);

    // 4. Compute channel secret
    let channel_secret_hex =
        compute_channel_secret_from_hex(&alice_secret.to_secret_hex(), &receiver_pubkey.to_hex())
            .expect("Failed to compute channel secret");
    println!("Computed channel secret: {}...", &channel_secret_hex[..16]);

    // 5. Build channel parameters (JSON format for bindings)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let capacity = 100u64;
    let maximum_amount = 64u64;
    let funding_token_amount = compute_funding_token_amount(capacity, &keyset_json, maximum_amount)
        .expect("Failed to compute funding token amount");

    let params = serde_json::json!({
        "sender_pubkey": sender_pubkey.to_hex(),
        "receiver_pubkey": receiver_pubkey.to_hex(),
        "mint": mint_url,
        "unit": "sat",
        "capacity": capacity,
        "maximum_amount": maximum_amount,
        "funding_token_amount": funding_token_amount,
        "expiry_timestamp": now + 7200,
        "setup_timestamp": now,
        "keyset_id": keyset_id,
        "input_fee_ppk": keyset_info["inputFeePpk"].as_u64().unwrap_or(0)
    });
    let params_json = serde_json::to_string(&params).expect("Failed to serialize params");

    // 6. Get channel ID
    let channel_id =
        channel_parameters_get_channel_id(&params_json, &channel_secret_hex, &keyset_json)
            .expect("Failed to get channel ID");
    println!("Channel ID: {}", channel_id);

    // 7. Create funding outputs
    let funding_json =
        create_funding_outputs(&params_json, &alice_secret.to_secret_hex(), &keyset_json)
            .expect("Failed to create funding outputs");

    let funding: serde_json::Value =
        serde_json::from_str(&funding_json).expect("Failed to parse funding outputs");

    let funding_nominal = funding["funding_token_nominal"].as_u64().unwrap_or(0);
    let blinded_messages = funding["blinded_messages"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);

    println!(
        "Funding nominal: {} sat, outputs: {}",
        funding_nominal, blinded_messages
    );

    // Verify we got reasonable outputs
    assert!(
        funding_nominal >= 100,
        "Expected funding >= 100, got {}",
        funding_nominal
    );
    assert!(
        blinded_messages > 0,
        "Expected at least one blinded message"
    );
}

/// Test channel ID computation is deterministic
#[test]
fn test_channel_id_deterministic() {
    let mint_url = get_mint_url();

    let alice_secret = SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let receiver_secret = SecretKey::generate();
    let receiver_pubkey = receiver_secret.public_key();

    let (keyset_id, keyset_info) =
        fetch_active_keyset_json(&mint_url, "sat").expect("Failed to fetch keyset from mint");
    let keyset_json = serde_json::to_string(&keyset_info).expect("Failed to serialize keyset");

    let channel_secret_hex =
        compute_channel_secret_from_hex(&alice_secret.to_secret_hex(), &receiver_pubkey.to_hex())
            .expect("Failed to compute channel secret");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let capacity = 100u64;
    let maximum_amount = 64u64;
    let funding_token_amount = compute_funding_token_amount(capacity, &keyset_json, maximum_amount)
        .expect("Failed to compute funding token amount");

    let params = serde_json::json!({
        "sender_pubkey": sender_pubkey.to_hex(),
        "receiver_pubkey": receiver_pubkey.to_hex(),
        "mint": mint_url,
        "unit": "sat",
        "capacity": capacity,
        "maximum_amount": maximum_amount,
        "funding_token_amount": funding_token_amount,
        "expiry_timestamp": now + 7200,
        "setup_timestamp": now,
        "keyset_id": keyset_id,
        "input_fee_ppk": keyset_info["inputFeePpk"].as_u64().unwrap_or(0)
    });
    let params_json = serde_json::to_string(&params).expect("Failed to serialize params");

    // Compute channel ID twice
    let channel_id_1 =
        channel_parameters_get_channel_id(&params_json, &channel_secret_hex, &keyset_json)
            .expect("Failed to get channel ID");
    let channel_id_2 =
        channel_parameters_get_channel_id(&params_json, &channel_secret_hex, &keyset_json)
            .expect("Failed to get channel ID");

    assert_eq!(
        channel_id_1, channel_id_2,
        "Channel ID should be deterministic"
    );

    println!("Channel ID is deterministic: {}", channel_id_1);
}
