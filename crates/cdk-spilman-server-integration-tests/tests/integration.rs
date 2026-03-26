//! Integration tests for Spilman payment channel servers.
//!
//! This test suite runs against ASCII art servers implemented in different languages
//! (TypeScript, Rust, Python, Go). The server type is selected via the SERVER_TYPE
//! environment variable.
//!
//! ## Running Tests
//!
//! ```bash
//! # Test TypeScript server
//! SERVER_TYPE=ts cargo test -p cdk-spilman-server-integration-tests
//!
//! # Test Rust server
//! SERVER_TYPE=rust cargo test -p cdk-spilman-server-integration-tests
//!
//! # Test Python server
//! SERVER_TYPE=python cargo test -p cdk-spilman-server-integration-tests
//!
//! # Test Go server
//! SERVER_TYPE=go cargo test -p cdk-spilman-server-integration-tests
//! ```

use anyhow::Result;
use serde_json::json;

use cdk_spilman_server_integration_tests::context::TestContext;
use cdk_spilman_server_integration_tests::helpers::{
    create_payment_header, encode_payment_header, fetch_keyset_info, now_seconds,
    MintFundedChannelOptions,
};

// ============================================================================
// Channel Params Endpoint Tests
// ============================================================================

mod channel_params {
    use super::*;

    #[tokio::test]
    async fn returns_receiver_pubkey() -> Result<()> {
        let ctx = TestContext::new().await?;

        let pubkey = &ctx.server_params.receiver_pubkey;
        assert!(pubkey.len() == 66, "Pubkey should be 66 chars (compressed)");
        assert!(
            pubkey.starts_with("02") || pubkey.starts_with("03"),
            "Pubkey should start with 02 or 03"
        );

        println!("Receiver pubkey: {}...", &pubkey[..16]);
        Ok(())
    }

    #[tokio::test]
    async fn returns_pricing_for_all_active_units() -> Result<()> {
        let ctx = TestContext::new().await?;

        // Check sat pricing (all servers must support sat)
        let sat_pricing = ctx
            .server_params
            .pricing
            .get("sat")
            .expect("sat pricing required");
        assert!(
            !sat_pricing.variables.is_empty(),
            "sat should have pricing variables"
        );
        assert!(sat_pricing.min_capacity > 0);

        // Check msat pricing (CDK dev mint has msat keysets)
        let msat_pricing = ctx.server_params.pricing.get("msat");
        assert!(msat_pricing.is_some(), "msat pricing expected");

        // Check usd pricing (CDK dev mint has usd keysets)
        let usd_pricing = ctx.server_params.pricing.get("usd");
        assert!(usd_pricing.is_some(), "usd pricing expected");

        let units: Vec<_> = ctx.server_params.pricing.keys().collect();
        println!("Pricing units: {:?}", units);
        Ok(())
    }

    #[tokio::test]
    async fn returns_mints_units_keysets() -> Result<()> {
        let ctx = TestContext::new().await?;

        // Should have at least one mint
        assert!(!ctx.server_params.mints_units_keysets.is_empty());

        // The mint should match our test mint
        let mint_keysets = ctx
            .server_params
            .mints_units_keysets
            .get(ctx.mint_url())
            .expect("Mint should be in mints_units_keysets");

        // Should have sat keysets
        let sat_keysets = mint_keysets.get("sat").expect("sat keysets expected");
        assert!(!sat_keysets.is_empty());

        println!("Mint URL: {}", ctx.mint_url());
        for (unit, ids) in mint_keysets {
            for id in ids {
                let fee_str = match fetch_keyset_info(ctx.mint_url(), id).await {
                    Ok((keyset_info, _)) => format!(" (fee: {} ppk)", keyset_info.input_fee_ppk),
                    Err(_) => String::new(),
                };
                println!("  {}: {}{}", unit, id, fee_str);
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn returns_min_expiry_in_seconds() -> Result<()> {
        let ctx = TestContext::new().await?;

        assert!(ctx.server_params.min_expiry_in_seconds > 0);
        println!(
            "Min expiry: {} seconds",
            ctx.server_params.min_expiry_in_seconds
        );
        Ok(())
    }
}

// ============================================================================
// Channel Status Endpoint Tests
// ============================================================================

mod channel_status {
    use super::*;

    #[tokio::test]
    async fn returns_404_for_unknown_channel() -> Result<()> {
        let ctx = TestContext::new().await?;

        let fake_channel_id = "deadbeef".repeat(8); // 64 char hex string
        let response = ctx.client.fetch_channel_status(&fake_channel_id).await?;

        assert_eq!(response.http_status, 404);
        println!(
            "GET /channel/{}... returned 404 as expected",
            &fake_channel_id[..8]
        );
        Ok(())
    }
}

// ============================================================================
// Channel Register Endpoint Tests
// ============================================================================

mod channel_register {
    use super::*;
    use cdk_spilman::create_signed_balance_update;

    #[tokio::test]
    async fn registers_channel_with_balance_zero() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        println!("Channel ID: {}...", &channel.channel_id[..16]);

        let result = ctx.client.register_channel(&channel).await?;

        assert_eq!(result["success"], true);
        assert_eq!(result["channel_id"], channel.channel_id);
        assert_eq!(result["capacity"], 100);
        assert_eq!(result["already_known"], false);
        println!(
            "Registered: capacity={}, already_known={}",
            result["capacity"], result["already_known"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn is_idempotent() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;

        // First registration
        let result1 = ctx.client.register_channel(&channel).await?;
        assert_eq!(result1["already_known"], false);

        // Second registration
        let result2 = ctx.client.register_channel(&channel).await?;
        assert_eq!(result2["success"], true);
        assert_eq!(result2["already_known"], true);
        println!("Idempotent: first already_known=false, second already_known=true");
        Ok(())
    }

    #[tokio::test]
    async fn rejects_nonzero_balance() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;

        // Create signature for balance=5
        let balance_update_json = create_signed_balance_update(
            &channel.channel_params_json,
            &channel.keyset_info_json,
            &channel.alice.secret_hex,
            &serde_json::to_string(&channel.proofs)?,
            5,
        )
        .map_err(|e| anyhow::anyhow!("{}", e))?;
        let balance_update: serde_json::Value = serde_json::from_str(&balance_update_json)?;

        let body = json!({
            "channel_id": channel.channel_id,
            "balance": 5,
            "signature": balance_update["signature"],
            "params": channel.channel_params,
            "funding_proofs": channel.proofs,
        });

        let (status, result) = ctx.client.register_channel_raw(&body).await?;

        assert_eq!(status, 400);
        assert_eq!(result["error"], "Bad request");
        assert!(result["reason"]
            .as_str()
            .unwrap_or("")
            .contains("balance=0"));
        println!("Rejected non-zero balance: {}", result["reason"]);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_invalid_signature() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;

        let body = json!({
            "channel_id": channel.channel_id,
            "balance": 0,
            "signature": "a".repeat(128),  // Fake signature
            "params": channel.channel_params,
            "funding_proofs": channel.proofs,
        });

        let (status, result) = ctx.client.register_channel_raw(&body).await?;

        assert_eq!(status, 402);
        assert_eq!(result["success"], false);
        assert!(result["reason"]
            .as_str()
            .unwrap_or("")
            .contains("signature"));
        println!("Rejected invalid signature");
        Ok(())
    }

    #[tokio::test]
    async fn allows_subsequent_payments_on_registered_channel() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        // Make a payment on the registered channel
        let payment_header = create_payment_header(&channel, 5)?;
        let response = ctx.client.fetch_ascii_art(&payment_header, "Hello").await?;

        assert_eq!(response.status, 200);
        println!("Payment succeeded on pre-registered channel");
        Ok(())
    }

    #[tokio::test]
    async fn rejects_missing_fields() -> Result<()> {
        let ctx = TestContext::new().await?;

        let body = json!({
            "channel_id": "test",
            "balance": 0,
            // missing signature, params, funding_proofs
        });

        let (status, result) = ctx.client.register_channel_raw(&body).await?;

        assert_eq!(status, 400);
        assert_eq!(result["error"], "Bad request");
        assert!(result["reason"].as_str().unwrap_or("").contains("missing"));
        println!("Rejected missing fields: {}", result["reason"]);
        Ok(())
    }
}

// ============================================================================
// Minting Flow Tests
// ============================================================================

mod minting {
    use super::*;

    #[tokio::test]
    async fn mints_funding_token_with_deterministic_outputs() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;

        println!("Channel ID: {}...", &channel.channel_id[..16]);
        println!("Proofs: {} proofs", channel.proofs.len());

        // Verify proof structure
        for proof in &channel.proofs {
            assert!(u64::from(proof.amount) > 0);
            assert!(proof.dleq.is_some());
        }

        // Calculate total
        let total: u64 = channel.proofs.iter().map(|p| u64::from(p.amount)).sum();
        println!("Total minted: {} sat", total);
        assert!(total >= channel.capacity);

        Ok(())
    }
}

// ============================================================================
// Channel Verification Tests
// ============================================================================

mod verification {
    use super::*;
    use cashu::util::hex;
    use cdk_spilman::{parse_keyset_info_from_json, verify_valid_channel, ChannelParameters};

    #[tokio::test]
    async fn detects_tampered_keyset_keys() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;

        // Parse keyset info to tamper with it
        let mut keyset_json: serde_json::Value = serde_json::from_str(&channel.keyset_info_json)?;

        // Tamper with a key
        let original_key = keyset_json["keys"]["1"].as_str().unwrap().to_string();
        let different_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        keyset_json["keys"]["1"] = serde_json::Value::String(different_pubkey.to_string());
        println!(
            "Tampered key: {}... -> {}...",
            &original_key[..16],
            &different_pubkey[..16]
        );

        // Parse tampered keyset
        let tampered_json = serde_json::to_string(&keyset_json)?;
        let tampered_keyset =
            parse_keyset_info_from_json(&tampered_json).map_err(|e| anyhow::anyhow!("{}", e))?;

        // Build params with tampered keyset
        let params = ChannelParameters::from_json_with_channel_secret(
            &channel.channel_params_json,
            tampered_keyset,
            {
                let bytes = hex::decode(&channel.channel_secret)?;
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            },
        )
        .map_err(|e| anyhow::anyhow!("{}", e))?;

        let result = verify_valid_channel(&channel.proofs, &params);

        assert!(!result.valid);
        assert!(!result.errors.is_empty());
        // First error should be InvalidKeysetId
        let first_error = serde_json::to_value(&result.errors[0])?;
        assert_eq!(first_error["type"], "InvalidKeysetId");
        println!("Tampered keyset detected");
        Ok(())
    }

    #[tokio::test]
    async fn detects_tampered_dleq_proofs() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;

        // Tamper with DLEQ proof
        let mut tampered_proofs = channel.proofs.clone();
        if let Some(dleq) = &mut tampered_proofs[0].dleq {
            // Flip last byte of e
            let e_hex = dleq.e.to_secret_hex();
            let last_char = e_hex.chars().last().unwrap();
            let new_char = if last_char == 'a' { 'b' } else { 'a' };
            let new_e_hex = format!("{}{}", &e_hex[..e_hex.len() - 1], new_char);
            dleq.e = cashu::nuts::SecretKey::from_hex(&new_e_hex)?;
        }

        // Build params
        let keyset = parse_keyset_info_from_json(&channel.keyset_info_json)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        let params = ChannelParameters::from_json_with_channel_secret(
            &channel.channel_params_json,
            keyset,
            {
                let bytes = hex::decode(&channel.channel_secret)?;
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            },
        )
        .map_err(|e| anyhow::anyhow!("{}", e))?;

        let result = verify_valid_channel(&tampered_proofs, &params);

        assert!(!result.valid);
        let error_types: Vec<_> = result
            .errors
            .iter()
            .map(|e| {
                serde_json::to_value(e).unwrap()["type"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert!(error_types.contains(&"InvalidDleq".to_string()));
        println!("Tampered DLEQ detected");
        Ok(())
    }

    #[tokio::test]
    async fn collects_multiple_error_types() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;

        // Tamper with multiple things
        let mut keyset_json: serde_json::Value = serde_json::from_str(&channel.keyset_info_json)?;

        // Error 1: InvalidKeysetId - substitute a different valid pubkey for unused amount
        let different_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        keyset_json["keys"]["1"] = serde_json::Value::String(different_pubkey.to_string());

        let tampered_json = serde_json::to_string(&keyset_json)?;
        let tampered_keyset =
            parse_keyset_info_from_json(&tampered_json).map_err(|e| anyhow::anyhow!("{}", e))?;

        // Error 2: Tamper with DLEQ
        let mut tampered_proofs = channel.proofs.clone();
        if let Some(dleq) = &mut tampered_proofs[0].dleq {
            let e_hex = dleq.e.to_secret_hex();
            let last_char = e_hex.chars().last().unwrap();
            let new_char = if last_char == 'a' { 'b' } else { 'a' };
            let new_e_hex = format!("{}{}", &e_hex[..e_hex.len() - 1], new_char);
            dleq.e = cashu::nuts::SecretKey::from_hex(&new_e_hex)?;
        }

        let params = ChannelParameters::from_json_with_channel_secret(
            &channel.channel_params_json,
            tampered_keyset,
            {
                let bytes = hex::decode(&channel.channel_secret)?;
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            },
        )
        .map_err(|e| anyhow::anyhow!("{}", e))?;

        let result = verify_valid_channel(&tampered_proofs, &params);

        assert!(!result.valid);
        let error_types: Vec<_> = result
            .errors
            .iter()
            .map(|e| {
                serde_json::to_value(e).unwrap()["type"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();

        assert!(error_types.contains(&"InvalidKeysetId".to_string()));
        assert!(error_types.contains(&"InvalidDleq".to_string()));
        println!("Multiple errors collected: {:?}", error_types);
        Ok(())
    }
}

// ============================================================================
// Payment Flow Tests
// ============================================================================

mod payment {
    use super::*;

    #[tokio::test]
    async fn makes_payment_and_verifies_status() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        let message = "Hi";
        let expected_cost = message.len() as u64 * ctx.get_price_per_char("sat");
        println!(
            "Message: \"{}\" ({} chars, cost={} sats)",
            message,
            message.len(),
            expected_cost
        );

        let payment_header = create_payment_header(&channel, expected_cost)?;
        let response = ctx.client.fetch_ascii_art(&payment_header, message).await?;

        assert_eq!(response.status, 200);
        assert!(response.body["art"].is_string());
        println!("ASCII art generated");

        // Verify status
        let status = ctx.client.fetch_channel_status(&channel.channel_id).await?;
        assert_eq!(status.http_status, 200);
        let body = status.body.unwrap();
        assert_eq!(body.amount_due, expected_cost);
        assert_eq!(body.balance, expected_cost);
        assert_eq!(body.capacity, channel.capacity);
        assert!(!body.closed);
        println!(
            "Status verified: amount_due={}, balance={}",
            body.amount_due, body.balance
        );
        Ok(())
    }

    #[tokio::test]
    async fn makes_payment_with_msat_channel() -> Result<()> {
        let ctx = TestContext::new().await?;

        let capacity = ctx.get_min_capacity("msat");
        let options = MintFundedChannelOptions {
            maximum_amount: Some(8192), // Larger to keep proof count manageable
            ..Default::default()
        };
        let channel = ctx
            .mint_channel_with_options("msat", capacity, options)
            .await?;
        ctx.client.register_channel(&channel).await?;

        let message = "Hi";
        let expected_cost = message.len() as u64 * ctx.get_price_per_char("msat");

        let payment_header = create_payment_header(&channel, expected_cost)?;
        let response = ctx.client.fetch_ascii_art(&payment_header, message).await?;

        assert_eq!(response.status, 200);
        println!("msat payment succeeded: cost={} msat", expected_cost);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_capacity_below_min() -> Result<()> {
        let ctx = TestContext::new().await?;

        let min_capacity = ctx.get_min_capacity("sat");
        let too_small = min_capacity - 1;
        println!("minCapacity={}, using capacity={}", min_capacity, too_small);

        let channel = ctx.mint_channel("sat", too_small).await?;

        let body = json!({
            "channel_id": channel.channel_id,
            "balance": 0,
            "signature": "any",
            "params": channel.channel_params,
            "funding_proofs": channel.proofs,
        });

        let (status, result) = ctx.client.register_channel_raw(&body).await?;

        assert_eq!(status, 402);
        assert!(result["reason"]
            .as_str()
            .unwrap_or("")
            .contains("capacity too small"));
        println!("Rejected: {}", result["reason"]);
        Ok(())
    }

    #[tokio::test]
    async fn prepayment_shows_higher_balance() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        let message = "Hi"; // 2 chars = 2 sats
        let balance = 10; // Pre-pay 10 sats
        let expected_cost = message.len() as u64 * ctx.get_price_per_char("sat");

        let payment_header = create_payment_header(&channel, balance)?;
        let response = ctx.client.fetch_ascii_art(&payment_header, message).await?;

        assert_eq!(response.status, 200);

        // Check payment info (either in header or body.payment)
        let payment_info = response
            .channel_header
            .or_else(|| response.body.get("payment").cloned())
            .expect("Payment info expected");

        assert_eq!(payment_info["balance"], balance);
        assert_eq!(payment_info["amount_due"], expected_cost);
        assert!(payment_info["balance"].as_u64() > payment_info["amount_due"].as_u64());
        println!(
            "Pre-payment: balance={} amount_due={}",
            balance, expected_cost
        );
        Ok(())
    }

    #[tokio::test]
    async fn accepts_usd_channel() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("usd", 100).await?;
        ctx.client.register_channel(&channel).await?;

        let message = "Hi";
        let expected_cost = message.len() as u64 * ctx.get_price_per_char("usd");

        let payment_header = create_payment_header(&channel, expected_cost)?;
        let response = ctx.client.fetch_ascii_art(&payment_header, message).await?;

        assert_eq!(response.status, 200);
        println!("USD channel payment accepted");
        Ok(())
    }

    #[tokio::test]
    async fn returns_402_then_200_with_valid_payment() -> Result<()> {
        let ctx = TestContext::new().await?;

        // Request without payment
        let response = ctx.client.fetch_ascii_art_no_header("Hello").await?;
        assert_eq!(response.status, 402);
        assert!(response.body["reason"]
            .as_str()
            .unwrap_or("")
            .contains("Missing X-Cashu-Channel"));
        println!("Got 402 without payment");

        // Now with payment
        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        let cost = 5 * ctx.get_price_per_char("sat");
        let payment_header = create_payment_header(&channel, cost)?;
        let response = ctx.client.fetch_ascii_art(&payment_header, "Hello").await?;

        assert_eq!(response.status, 200);
        println!("Got 200 with payment");
        Ok(())
    }
}

// ============================================================================
// Validation Error Tests
// ============================================================================

mod validation {
    use super::*;
    use cdk_spilman::create_signed_balance_update;

    #[tokio::test]
    async fn returns_402_when_signature_does_not_match_balance() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        // Create signature for balance=1
        let balance_update_json = create_signed_balance_update(
            &channel.channel_params_json,
            &channel.keyset_info_json,
            &channel.alice.secret_hex,
            &serde_json::to_string(&channel.proofs)?,
            1,
        )
        .map_err(|e| anyhow::anyhow!("{}", e))?;
        let balance_update: serde_json::Value = serde_json::from_str(&balance_update_json)?;

        // Send with balance=2 but signature for balance=1
        let payment = json!({
            "channel_id": balance_update["channel_id"],
            "balance": 2,
            "signature": balance_update["signature"],
        });
        let header = encode_payment_header(&payment);

        let response = ctx.client.fetch_ascii_art(&header, "Hi").await?;

        assert_eq!(response.status, 402);
        assert!(response.body["reason"]
            .as_str()
            .unwrap_or("")
            .contains("invalid signature"));
        println!("Invalid signature rejected");
        Ok(())
    }

    #[tokio::test]
    async fn returns_402_when_balance_exceeds_capacity() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        // First establish channel
        let header1 = create_payment_header(&channel, 1)?;
        let _ = ctx.client.fetch_ascii_art(&header1, "X").await?;

        // Try balance > capacity
        let payment = json!({
            "channel_id": channel.channel_id,
            "balance": 101,
            "signature": "fake",
        });
        let header = encode_payment_header(&payment);

        let response = ctx.client.fetch_ascii_art(&header, "Hi").await?;

        assert_eq!(response.status, 402);
        assert!(response.body["reason"]
            .as_str()
            .unwrap_or("")
            .contains("balance exceeds capacity"));
        println!("Balance exceeds capacity rejected");
        Ok(())
    }

    #[tokio::test]
    async fn returns_402_when_balance_insufficient() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        // First payment: balance=5
        let header1 = create_payment_header(&channel, 5)?;
        let _ = ctx.client.fetch_ascii_art(&header1, "Hello").await?;

        // Second payment: balance=3 but amount_due would be 7
        let header2 = create_payment_header(&channel, 3)?;
        let response = ctx.client.fetch_ascii_art(&header2, "Hi").await?;

        assert_eq!(response.status, 402);
        assert!(response.body["reason"]
            .as_str()
            .unwrap_or("")
            .contains("insufficient balance"));
        println!("Insufficient balance rejected");
        Ok(())
    }

    #[tokio::test]
    async fn returns_402_when_dleq_tampered() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;

        // Tamper with DLEQ
        let mut tampered_proofs: serde_json::Value = serde_json::to_value(&channel.proofs)?;
        let original_e = tampered_proofs[0]["dleq"]["e"]
            .as_str()
            .unwrap()
            .to_string();
        let last_char = original_e.chars().last().unwrap();
        let new_char = if last_char == 'a' { 'b' } else { 'a' };
        tampered_proofs[0]["dleq"]["e"] = serde_json::Value::String(format!(
            "{}{}",
            &original_e[..original_e.len() - 1],
            new_char
        ));

        // Create balance update with tampered proofs
        let balance_update_json = create_signed_balance_update(
            &channel.channel_params_json,
            &channel.keyset_info_json,
            &channel.alice.secret_hex,
            &serde_json::to_string(&tampered_proofs)?,
            0,
        )
        .map_err(|e| anyhow::anyhow!("{}", e))?;
        let balance_update: serde_json::Value = serde_json::from_str(&balance_update_json)?;

        let body = json!({
            "channel_id": channel.channel_id,
            "balance": 0,
            "signature": balance_update["signature"],
            "params": channel.channel_params,
            "funding_proofs": tampered_proofs,
        });

        let (status, result) = ctx.client.register_channel_raw(&body).await?;

        assert_eq!(status, 402);
        let has_dleq_error = result
            .get("validation_errors")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().any(|e| e["type"] == "InvalidDleq"))
            .unwrap_or(false);
        let reason_has_dleq = result["reason"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("dleq");
        assert!(has_dleq_error || reason_has_dleq);
        println!("Tampered DLEQ rejected");
        Ok(())
    }

    #[tokio::test]
    async fn returns_402_when_expiry_too_soon() -> Result<()> {
        let ctx = TestContext::new().await?;

        let too_soon_expiry = now_seconds() + 60; // Only 60 seconds
        println!("Using expiry_timestamp {} (60s from now)", too_soon_expiry);

        let options = MintFundedChannelOptions {
            expiry_timestamp: Some(too_soon_expiry),
            ..Default::default()
        };
        let channel = ctx.mint_channel_with_options("sat", 100, options).await?;

        let balance_update_json = create_signed_balance_update(
            &channel.channel_params_json,
            &channel.keyset_info_json,
            &channel.alice.secret_hex,
            &serde_json::to_string(&channel.proofs)?,
            0,
        )
        .map_err(|e| anyhow::anyhow!("{}", e))?;
        let balance_update: serde_json::Value = serde_json::from_str(&balance_update_json)?;

        let body = json!({
            "channel_id": channel.channel_id,
            "balance": 0,
            "signature": balance_update["signature"],
            "params": channel.channel_params,
            "funding_proofs": channel.proofs,
        });

        let (status, result) = ctx.client.register_channel_raw(&body).await?;

        assert_eq!(status, 402);
        assert!(result["reason"]
            .as_str()
            .unwrap_or("")
            .contains("expiry too soon"));
        println!("Expiry too soon rejected");
        Ok(())
    }

    #[tokio::test]
    async fn returns_402_for_missing_header() -> Result<()> {
        let ctx = TestContext::new().await?;

        let response = ctx.client.fetch_ascii_art_no_header("Hello").await?;

        assert_eq!(response.status, 402);
        assert!(response.body["reason"]
            .as_str()
            .unwrap_or("")
            .contains("Missing X-Cashu-Channel"));
        println!("Missing header rejected");
        Ok(())
    }

    #[tokio::test]
    async fn returns_400_for_invalid_base64() -> Result<()> {
        let ctx = TestContext::new().await?;

        let response = ctx
            .client
            .fetch_ascii_art_raw_header("not-valid-base64!!!", "Hello")
            .await?;

        assert_eq!(response.status, 400);
        assert!(response.body["reason"]
            .as_str()
            .unwrap_or("")
            .contains("invalid base64"));
        println!("Invalid base64 rejected");
        Ok(())
    }

    #[tokio::test]
    async fn returns_402_when_proof_amount_has_no_mint_key() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;

        // Tamper proof amount
        let mut tampered_proofs: serde_json::Value = serde_json::to_value(&channel.proofs)?;
        tampered_proofs[0]["amount"] = serde_json::json!(3); // Not power of 2

        let body = json!({
            "channel_id": channel.channel_id,
            "balance": 0,
            "signature": "fake_signature",
            "params": channel.channel_params,
            "funding_proofs": tampered_proofs,
        });

        let (status, result) = ctx.client.register_channel_raw(&body).await?;

        assert_eq!(status, 402);
        let has_missing_key = result
            .get("validation_errors")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().any(|e| e["type"] == "MissingMintKey"))
            .unwrap_or(false);
        let reason_has_missing = result["reason"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("missing");
        assert!(has_missing_key || reason_has_missing);
        println!("MissingMintKey rejected");
        Ok(())
    }

    #[tokio::test]
    async fn returns_402_when_channel_id_mismatch() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;

        let balance_update_json = create_signed_balance_update(
            &channel.channel_params_json,
            &channel.keyset_info_json,
            &channel.alice.secret_hex,
            &serde_json::to_string(&channel.proofs)?,
            0,
        )
        .map_err(|e| anyhow::anyhow!("{}", e))?;
        let balance_update: serde_json::Value = serde_json::from_str(&balance_update_json)?;

        // Tamper channel_id
        let tampered_id = {
            let mut id = channel.channel_id.clone();
            let last = id.pop().unwrap();
            id.push(if last == 'a' { 'b' } else { 'a' });
            id
        };

        let body = json!({
            "channel_id": tampered_id,
            "balance": 0,
            "signature": balance_update["signature"],
            "params": channel.channel_params,
            "funding_proofs": channel.proofs,
        });

        let (status, result) = ctx.client.register_channel_raw(&body).await?;

        assert_eq!(status, 402);
        assert!(result["reason"]
            .as_str()
            .unwrap_or("")
            .contains("channel_id mismatch"));
        println!("channel_id mismatch rejected");
        Ok(())
    }

    #[tokio::test]
    async fn returns_402_when_keyset_not_from_approved_mint() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;

        // Tamper keyset_id in params
        let mut tampered_params = channel.channel_params.clone();
        tampered_params["keyset_id"] = serde_json::json!("00deadbeef123456");

        let body = json!({
            "channel_id": format!("aaaa{}", &channel.channel_id[4..]),
            "balance": 0,
            "signature": "fake_signature",
            "params": tampered_params,
            "funding_proofs": channel.proofs,
        });

        let (status, result) = ctx.client.register_channel_raw(&body).await?;

        assert_eq!(status, 402);
        assert!(result["reason"]
            .as_str()
            .unwrap_or("")
            .contains("mint or keyset not acceptable"));
        println!("Unknown keyset rejected");
        Ok(())
    }

    #[tokio::test]
    async fn returns_4xx_for_invalid_header_fields() -> Result<()> {
        let ctx = TestContext::new().await?;

        let test_cases = vec![
            (
                "missing channel_id",
                json!({"balance": 1, "signature": "def456"}),
                "channel_id",
            ),
            (
                "empty channel_id",
                json!({"channel_id": "", "balance": 1, "signature": "def456"}),
                "channel_id",
            ),
            (
                "non-string channel_id",
                json!({"channel_id": 12345, "balance": 1, "signature": "def456"}),
                "integer",
            ),
            (
                "missing balance",
                json!({"channel_id": "abc123", "signature": "def456"}),
                "balance",
            ),
            (
                "non-integer balance",
                json!({"channel_id": "abc123", "balance": 1.5, "signature": "def456"}),
                "u64",
            ),
            (
                "missing signature",
                json!({"channel_id": "abc123", "balance": 1}),
                "signature",
            ),
            (
                "empty signature",
                json!({"channel_id": "abc123", "balance": 1, "signature": ""}),
                "signature",
            ),
            (
                "non-string signature",
                json!({"channel_id": "abc123", "balance": 1, "signature": 12345}),
                "string",
            ),
        ];

        for (name, payment, expected_error) in test_cases {
            let header = encode_payment_header(&payment);
            let response = ctx.client.fetch_ascii_art(&header, "Hello").await?;

            assert!(
                response.status == 400 || response.status == 402,
                "{}: expected 4xx, got {}",
                name,
                response.status
            );
            let reason = response.body["reason"]
                .as_str()
                .unwrap_or("")
                .to_lowercase();
            let expected = expected_error.to_lowercase();
            assert!(
                reason.contains(&expected),
                "{}: expected error containing '{}', got '{}'",
                name,
                expected_error,
                response.body["reason"]
            );
            println!("{}: {} with '{}'", name, response.status, expected_error);
        }
        Ok(())
    }

    #[tokio::test]
    async fn rejects_maximum_amount_exceeding_policy() -> Result<()> {
        let ctx = TestContext::new().await?;

        // Get the max_amount_per_output for usd from server params
        let server_params = ctx.client.fetch_channel_params().await?;
        let usd_pricing = server_params
            .pricing
            .get("usd")
            .expect("usd pricing should exist");
        let max_allowed = usd_pricing
            .max_amount_per_output
            .expect("usd should have maxAmountPerOutput set");

        println!("usd maxAmountPerOutput policy: {}", max_allowed);

        // Try to create channel with maximum_amount exceeding limit
        let exceeding_amount = max_allowed + 1;
        let options = MintFundedChannelOptions {
            maximum_amount: Some(exceeding_amount),
            ..Default::default()
        };
        let channel = ctx.mint_channel_with_options("usd", 100, options).await?;

        // Register should fail with MaxAmountExceeded error
        let body = json!({
            "channel_id": channel.channel_id,
            "balance": 0,
            "signature": "any",
            "params": channel.channel_params,
            "funding_proofs": channel.proofs,
        });

        let (status, result) = ctx.client.register_channel_raw(&body).await?;

        assert_eq!(status, 402);
        let reason = result["reason"].as_str().unwrap_or("");
        assert!(
            reason.contains("max_amount") || reason.contains("MaxAmount"),
            "Expected error about max_amount, got: {}",
            reason
        );
        println!(
            "Correctly rejected channel with maximum_amount={} (policy max={}): {}",
            exceeding_amount, max_allowed, reason
        );
        Ok(())
    }

    #[tokio::test]
    async fn large_channel_produces_many_outputs() -> Result<()> {
        let ctx = TestContext::new().await?;

        // Get max_amount_per_output for usd (should be 64)
        let server_params = ctx.client.fetch_channel_params().await?;
        let usd_pricing = server_params
            .pricing
            .get("usd")
            .expect("usd pricing should exist");
        let max_amount = usd_pricing
            .max_amount_per_output
            .expect("usd should have maxAmountPerOutput set");

        // Create large 1000 usd channel with the policy's max_amount
        let capacity = 1000u64;
        let options = MintFundedChannelOptions {
            maximum_amount: Some(max_amount), // Use the policy limit (64)
            ..Default::default()
        };
        let channel = ctx
            .mint_channel_with_options("usd", capacity, options)
            .await?;

        // With capacity=1000 and max_amount=64, we need at least ceil(1000/64) = 16 outputs
        // (actual count may be higher due to fee structure and amount decomposition)
        let min_expected_outputs = (capacity / max_amount) as usize;

        println!(
            "Large usd channel: capacity={}, max_amount={}, output_count={}, min_expected={}",
            capacity, max_amount, channel.output_count, min_expected_outputs
        );

        assert!(
            channel.output_count >= min_expected_outputs,
            "Expected at least {} outputs, got {}",
            min_expected_outputs,
            channel.output_count
        );

        // Verify channel is functional by registering
        ctx.client.register_channel(&channel).await?;
        let status_resp = ctx.client.fetch_channel_status(&channel.channel_id).await?;
        let status_body = status_resp.body.expect("Status body should exist");
        assert_eq!(status_body.capacity, capacity);

        println!(
            "Large channel registered successfully with {} outputs",
            channel.output_count
        );
        Ok(())
    }
}

// ============================================================================
// Status Tracking Tests
// ============================================================================

mod status {
    use super::*;

    #[tokio::test]
    async fn returns_status_with_zeroes_before_payment_then_updated_after() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        // Check status before payment
        let status0 = ctx.client.fetch_channel_status(&channel.channel_id).await?;
        assert_eq!(status0.http_status, 200);
        let body0 = status0.body.unwrap();
        assert_eq!(body0.balance, 0);
        assert_eq!(body0.amount_due, 0);
        assert!(!body0.closed);
        println!("Before payment: balance=0 amount_due=0");

        // Make payment
        let cost1 = 2 * ctx.get_price_per_char("sat");
        let header1 = create_payment_header(&channel, cost1)?;
        let _ = ctx.client.fetch_ascii_art(&header1, "Hi").await?;

        // Check after payment
        let status1 = ctx.client.fetch_channel_status(&channel.channel_id).await?;
        let body1 = status1.body.unwrap();
        assert_eq!(body1.balance, cost1);
        assert_eq!(body1.amount_due, cost1);
        println!("After payment: balance={} amount_due={}", cost1, cost1);

        // Make second payment
        let cost2 = cost1 + 3 * ctx.get_price_per_char("sat");
        let header2 = create_payment_header(&channel, cost2)?;
        let _ = ctx.client.fetch_ascii_art(&header2, "Hey").await?;

        // Check after second payment
        let status2 = ctx.client.fetch_channel_status(&channel.channel_id).await?;
        let body2 = status2.body.unwrap();
        assert_eq!(body2.balance, cost2);
        assert_eq!(body2.amount_due, cost2);
        println!("After 2nd payment: balance={} amount_due={}", cost2, cost2);
        Ok(())
    }

    #[tokio::test]
    async fn does_not_update_status_when_payment_fails() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        // Make successful payment
        let cost = 2 * ctx.get_price_per_char("sat");
        let header = create_payment_header(&channel, cost)?;
        let _ = ctx.client.fetch_ascii_art(&header, "Hi").await?;

        // Check status
        let status1 = ctx.client.fetch_channel_status(&channel.channel_id).await?;
        let body1 = status1.body.unwrap();
        assert_eq!(body1.balance, cost);

        // Make failed payment (balance=0, i.e. no payment — server should reject)
        let bad_header = create_payment_header(&channel, 0)?;

        let bad_response = ctx.client.fetch_ascii_art(&bad_header, "X").await?;
        assert_eq!(bad_response.status, 402);

        // Status should be unchanged
        let status2 = ctx.client.fetch_channel_status(&channel.channel_id).await?;
        let body2 = status2.body.unwrap();
        assert_eq!(body2.balance, cost);
        assert_eq!(body2.amount_due, cost);
        println!("Status unchanged after failed payment");
        Ok(())
    }
}

// ============================================================================
// Channel Closing Tests
// ============================================================================

mod closing {
    use super::*;

    #[tokio::test]
    async fn closes_unused_channel() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        let response = ctx.client.close_channel(&channel, 0).await?;

        assert_eq!(response.http_status, 200);
        assert_eq!(response.body["channel_id"], channel.channel_id);
        assert!(response.body["total_value"].as_u64().unwrap() >= channel.capacity);
        let sender_proofs = match response.body["sender_proofs"].as_str() {
            Some(raw) => {
                serde_json::from_str::<serde_json::Value>(raw).unwrap_or(serde_json::json!([]))
            }
            None => response.body["sender_proofs"].clone(),
        };
        assert!(!sender_proofs.as_array().unwrap().is_empty());
        assert_eq!(response.body["already_closed"], false);

        // Sender gets all funds back
        let sender_sum: u64 = sender_proofs
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["amount"].as_u64().unwrap())
            .sum();
        assert_eq!(sender_sum, response.body["total_value"].as_u64().unwrap());
        println!("Sender recovered all {} sats", sender_sum);

        // Verify closed
        let status = ctx.client.fetch_channel_status(&channel.channel_id).await?;
        assert!(status.body.unwrap().closed);
        Ok(())
    }

    #[tokio::test]
    async fn closes_channel_after_first_payment() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        let cost = ctx.get_price_per_char("sat");
        let header = create_payment_header(&channel, cost)?;
        let _ = ctx.client.fetch_ascii_art(&header, "X").await?;

        let response = ctx.client.close_channel(&channel, cost).await?;

        assert_eq!(response.http_status, 200);
        let sender_proofs = match response.body["sender_proofs"].as_str() {
            Some(raw) => {
                serde_json::from_str::<serde_json::Value>(raw).unwrap_or(serde_json::json!([]))
            }
            None => response.body["sender_proofs"].clone(),
        };
        assert!(!sender_proofs.as_array().unwrap().is_empty());
        println!("Closed after first payment");
        Ok(())
    }

    #[tokio::test]
    async fn closes_used_channel_with_correct_balance() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        let cost = 5 * ctx.get_price_per_char("sat");
        let header = create_payment_header(&channel, cost)?;
        let _ = ctx.client.fetch_ascii_art(&header, "Hello").await?;

        // Get amount_due
        let status = ctx.client.fetch_channel_status(&channel.channel_id).await?;
        let amount_due = status.body.unwrap().amount_due;

        let response = ctx.client.close_channel(&channel, amount_due).await?;

        assert_eq!(response.http_status, 200);

        // Verify closed
        let status_after = ctx.client.fetch_channel_status(&channel.channel_id).await?;
        let body = status_after.body.unwrap();
        assert!(body.closed);
        assert_eq!(body.closed_amount, Some(amount_due));
        println!("Closed with amount_due={}", amount_due);
        Ok(())
    }

    #[tokio::test]
    async fn idempotent_close_succeeds() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        let cost = ctx.get_price_per_char("sat");
        let header = create_payment_header(&channel, cost)?;
        let _ = ctx.client.fetch_ascii_art(&header, "X").await?;

        // First close
        let response1 = ctx.client.close_channel(&channel, cost).await?;
        assert_eq!(response1.body["already_closed"], false);

        // Second close
        let response2 = ctx.client.close_channel(&channel, cost).await?;
        assert_eq!(response2.http_status, 200);
        assert_eq!(response2.body["success"], true);
        assert_eq!(response2.body["already_closed"], true);
        println!("Idempotent close succeeded");
        Ok(())
    }

    #[tokio::test]
    async fn rejects_close_with_different_amount() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        let cost = 2 * ctx.get_price_per_char("sat");
        let header = create_payment_header(&channel, cost)?;
        let _ = ctx.client.fetch_ascii_art(&header, "Hi").await?;

        // First close
        let _ = ctx.client.close_channel(&channel, cost).await?;

        // Try different amount
        let response = ctx.client.close_channel(&channel, cost + 1).await?;

        assert_eq!(response.http_status, 400);
        assert!(response.body["error"]
            .as_str()
            .unwrap()
            .contains("already closed"));
        println!("Different amount rejected");
        Ok(())
    }

    #[tokio::test]
    async fn rejects_payment_on_closed_channel() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        let cost = 2 * ctx.get_price_per_char("sat");
        let header = create_payment_header(&channel, cost)?;
        let _ = ctx.client.fetch_ascii_art(&header, "Hi").await?;

        // Close
        let _ = ctx.client.close_channel(&channel, cost).await?;

        // Try payment
        let header2 = create_payment_header(&channel, cost + 1)?;
        let response = ctx.client.fetch_ascii_art(&header2, "X").await?;

        assert_eq!(response.status, 410);
        assert!(response.body["reason"]
            .as_str()
            .unwrap()
            .contains("channel closed"));
        println!("Payment on closed channel rejected");
        Ok(())
    }

    #[tokio::test]
    async fn rejects_close_with_invalid_signature() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        let cost = ctx.get_price_per_char("sat");
        let header = create_payment_header(&channel, cost)?;
        let _ = ctx.client.fetch_ascii_art(&header, "X").await?;

        let body = json!({
            "balance": cost,
            "signature": "invalid_signature",
        });

        let response = ctx
            .client
            .close_channel_raw(&channel.channel_id, &body)
            .await?;

        assert_eq!(response.http_status, 402);
        assert!(response.body["reason"]
            .as_str()
            .unwrap()
            .contains("invalid signature"));
        println!("Invalid signature rejected");
        Ok(())
    }

    #[tokio::test]
    async fn rejects_close_for_unknown_channel() -> Result<()> {
        let ctx = TestContext::new().await?;

        let fake_id = "deadbeef".repeat(8);
        let body = json!({
            "balance": 0,
            "signature": "any",
        });

        let response = ctx.client.close_channel_raw(&fake_id, &body).await?;

        assert_eq!(response.http_status, 404);
        let resp_type = response.body["type"].as_str().unwrap_or("");
        assert!(
            resp_type.is_empty()
                || resp_type == "unknown_channel"
                || resp_type == "validation_failed",
            "unexpected error type: {}",
            resp_type
        );
        println!("Unknown channel rejected");
        Ok(())
    }

    #[tokio::test]
    async fn rejects_close_with_balance_less_than_amount_due() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        let cost = 5 * ctx.get_price_per_char("sat");
        let header = create_payment_header(&channel, cost)?;
        let _ = ctx.client.fetch_ascii_art(&header, "Hello").await?;

        // Try to close with 0
        let response = ctx.client.close_channel(&channel, 0).await?;

        assert_eq!(response.http_status, 402);
        assert!(response.body["reason"]
            .as_str()
            .unwrap()
            .contains("balance mismatch"));
        println!("Balance < amount_due rejected");
        Ok(())
    }

    #[tokio::test]
    async fn rejects_close_with_nonzero_balance_on_unused_channel() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        // Try to close with balance=10 but amount_due=0
        let response = ctx.client.close_channel(&channel, 10).await?;

        assert_eq!(response.http_status, 402);
        assert!(response.body["reason"]
            .as_str()
            .unwrap()
            .contains("balance mismatch"));
        println!("Nonzero balance on unused channel rejected");
        Ok(())
    }

    #[tokio::test]
    async fn rejects_close_with_balance_greater_than_amount_due() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        let cost = ctx.get_price_per_char("sat");
        let header = create_payment_header(&channel, cost)?;
        let _ = ctx.client.fetch_ascii_art(&header, "X").await?;

        // Try to close with balance > amount_due
        let response = ctx.client.close_channel(&channel, cost + 5).await?;

        assert_eq!(response.http_status, 402);
        assert!(response.body["reason"]
            .as_str()
            .unwrap()
            .contains("balance mismatch"));
        println!("Balance > amount_due rejected");
        Ok(())
    }
}

// ============================================================================
// Unilateral Closing Tests
// ============================================================================

mod unilateral_closing {
    use super::*;

    #[tokio::test]
    async fn server_can_unilaterally_close() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        let cost = 5 * ctx.get_price_per_char("sat");
        let header = create_payment_header(&channel, cost)?;
        let _ = ctx.client.fetch_ascii_art(&header, "Hello").await?;

        let response = ctx.client.unilateral_close(&channel.channel_id).await?;

        assert_eq!(response.http_status, 200);
        assert_eq!(response.body["success"], true);
        assert!(response.body["earnedBeforeStage2Fees"].as_u64().unwrap() >= cost);
        assert_eq!(response.body["already_closed"], false);
        println!("Unilateral close succeeded");
        Ok(())
    }

    #[tokio::test]
    async fn unilateral_close_earns_overpayment() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        let overpayment = 20;
        let header = create_payment_header(&channel, overpayment)?;
        let _ = ctx.client.fetch_ascii_art(&header, "Hello").await?;

        let response = ctx.client.unilateral_close(&channel.channel_id).await?;

        assert_eq!(response.http_status, 200);
        assert!(response.body["earnedBeforeStage2Fees"].as_u64().unwrap() >= overpayment);
        println!(
            "Server earned {} (overpayment={})",
            response.body["earnedBeforeStage2Fees"], overpayment
        );
        Ok(())
    }

    #[tokio::test]
    async fn unilateral_close_is_idempotent() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        let cost = 5 * ctx.get_price_per_char("sat");
        let header = create_payment_header(&channel, cost)?;
        let _ = ctx.client.fetch_ascii_art(&header, "Hello").await?;

        let response1 = ctx.client.unilateral_close(&channel.channel_id).await?;
        assert_eq!(response1.body["already_closed"], false);

        let response2 = ctx.client.unilateral_close(&channel.channel_id).await?;
        assert_eq!(response2.http_status, 200);
        assert_eq!(response2.body["already_closed"], true);
        println!("Idempotent unilateral close");
        Ok(())
    }

    #[tokio::test]
    async fn rejects_unilateral_close_for_unknown_channel() -> Result<()> {
        let ctx = TestContext::new().await?;

        let fake_id = "dead".repeat(16);
        let response = ctx.client.unilateral_close(&fake_id).await?;

        assert_eq!(response.http_status, 404);
        let resp_type = response.body["type"].as_str().unwrap_or("");
        assert!(
            resp_type.is_empty()
                || resp_type == "unknown_channel"
                || resp_type == "validation_failed",
            "unexpected error type: {}",
            resp_type
        );
        println!("Unknown channel rejected");
        Ok(())
    }

    #[tokio::test]
    async fn returns_already_closed_for_channel_with_no_payments() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        // Close cooperatively with 0
        let _ = ctx.client.close_channel(&channel, 0).await?;

        // Unilateral should show already_closed
        let response = ctx.client.unilateral_close(&channel.channel_id).await?;

        assert_eq!(response.http_status, 200);
        assert_eq!(response.body["already_closed"], true);
        assert_eq!(response.body["earnedBeforeStage2Fees"], 0);
        println!("Already closed with earnings=0");
        Ok(())
    }

    #[tokio::test]
    async fn cooperative_close_works_after_unilateral() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        let cost = 5 * ctx.get_price_per_char("sat");
        let header = create_payment_header(&channel, cost)?;
        let _ = ctx.client.fetch_ascii_art(&header, "Hello").await?;

        // Unilateral first
        let _ = ctx.client.unilateral_close(&channel.channel_id).await?;

        // Cooperative should succeed with already_closed
        let response = ctx.client.close_channel(&channel, cost).await?;

        assert_eq!(response.http_status, 200);
        assert_eq!(response.body["already_closed"], true);
        println!("Cooperative after unilateral succeeded");
        Ok(())
    }

    #[tokio::test]
    async fn rejects_payment_after_unilateral_close() -> Result<()> {
        let ctx = TestContext::new().await?;

        let channel = ctx.mint_channel("sat", 100).await?;
        ctx.client.register_channel(&channel).await?;

        let cost = 5 * ctx.get_price_per_char("sat");
        let header = create_payment_header(&channel, cost)?;
        let _ = ctx.client.fetch_ascii_art(&header, "Hello").await?;

        // Unilateral close
        let _ = ctx.client.unilateral_close(&channel.channel_id).await?;

        // Try payment
        let header2 = create_payment_header(&channel, cost + 1)?;
        let response = ctx.client.fetch_ascii_art(&header2, "X").await?;

        assert_eq!(response.status, 410);
        assert!(response.body["reason"]
            .as_str()
            .unwrap()
            .contains("channel closed"));
        println!("Payment after unilateral rejected");
        Ok(())
    }
}
