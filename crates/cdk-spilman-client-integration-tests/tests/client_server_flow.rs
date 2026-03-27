//! Integration tests for client-to-server payment flow.
//!
//! Tests that payments created by `SpilmanClientBridge` are correctly
//! processed by `SpilmanBridge`.

use std::time::{SystemTime, UNIX_EPOCH};

use cashu::nuts::SecretKey;
use cdk_spilman::{
    build_cashu_b_token, ConfigurableClientHost, Payment, SpilmanBridge, SpilmanClientBridge,
};
use cdk_spilman_client_integration_tests::{
    InMemoryMintNetworking, TestMintHelper, TestServerHost,
};

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Test the basic flow:
/// 1. Client opens a channel from a token
/// 2. Client creates a payment with funding data
/// 3. Server processes the payment and registers the channel
/// 4. Client creates subsequent payments
/// 5. Server processes them
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_client_creates_payment_server_processes() {
    // === Setup mint ===
    let mint_helper = TestMintHelper::new().await.unwrap();
    let keyset_info_json = mint_helper.keyset_info_json().unwrap();

    // === Setup server ===
    let receiver_secret = SecretKey::generate();
    let server_host = TestServerHost::new(receiver_secret.clone());

    // Register the keyset with the server
    server_host.add_keyset(
        "https://test-mint",
        mint_helper.keyset_id(),
        keyset_info_json.clone(),
    );

    let server_bridge = SpilmanBridge::new(server_host);

    // === Setup client ===
    let sender_secret = SecretKey::generate();
    let mut client_host = ConfigurableClientHost::new_in_memory();
    client_host.add_key(sender_secret.clone());
    let client_networking = InMemoryMintNetworking::new(mint_helper.mint());
    let client_bridge = SpilmanClientBridge::new(client_host, client_networking);

    // === Mint a token ===
    let proofs = mint_helper.mint_proofs(1000).await.unwrap();
    let token = build_cashu_b_token(
        "https://test-mint",
        "sat",
        &serde_json::to_string(&proofs).unwrap(),
    )
    .expect("build token");

    // === Client opens channel ===
    let expiry = now_seconds() + 3600; // 1 hour from now
    let open_result = client_bridge
        .open_channel_from_token(
            &token,
            &receiver_secret.public_key().to_hex(),
            &sender_secret.public_key().to_hex(),
            expiry,
            &keyset_info_json,
            64,
        )
        .expect("open channel");

    assert!(open_result.capacity > 0);
    eprintln!(
        "Channel opened: id={}, capacity={}",
        open_result.channel_id, open_result.capacity
    );

    // === Client creates first payment with funding ===
    let payment1: Payment = client_bridge
        .create_payment_with_funding(&open_result.channel_id, 10)
        .expect("create payment 1");

    assert_eq!(payment1.channel_id, open_result.channel_id);
    assert_eq!(payment1.balance, 10);
    assert!(payment1.has_funding());
    eprintln!("Payment 1 created: balance={}", payment1.balance);

    // === Server processes first payment ===
    let result1 = server_bridge
        .process_payment(
            &payment1.channel_id,
            payment1.balance,
            &payment1.signature,
            payment1.params.as_ref(),
            payment1.funding_proofs.as_deref(),
            &(),
        )
        .expect("server process payment 1");

    assert_eq!(result1.channel_id, open_result.channel_id);
    assert_eq!(result1.balance, 10);
    eprintln!("Server processed payment 1: balance={}", result1.balance);

    // === Client creates second payment (no funding needed) ===
    let payment2: Payment = client_bridge
        .create_payment(&open_result.channel_id, 25)
        .expect("create payment 2");

    assert_eq!(payment2.balance, 25);
    assert!(!payment2.has_funding());
    eprintln!("Payment 2 created: balance={}", payment2.balance);

    // === Server processes second payment ===
    let result2 = server_bridge
        .process_payment(
            &payment2.channel_id,
            payment2.balance,
            &payment2.signature,
            None, // No funding needed for subsequent payments
            None,
            &(),
        )
        .expect("server process payment 2");

    assert_eq!(result2.balance, 25);
    eprintln!("Server processed payment 2: balance={}", result2.balance);

    // === Verify client state ===
    let info = client_bridge
        .get_channel_info(&open_result.channel_id)
        .expect("get channel info");

    assert_eq!(info.current_balance, 25);
    assert_eq!(info.payment_count, 2);
    eprintln!(
        "Client channel info: balance={}, payments={}",
        info.current_balance, info.payment_count
    );

    // === Verify server state ===
    let server_payment = server_bridge
        .host()
        .get_last_payment(&open_result.channel_id)
        .expect("server should have payment");
    assert_eq!(server_payment.balance, 25);
    eprintln!(
        "Server last payment: balance={}",
        server_payment.balance
    );
}

/// Test that payments can decrease (for cooperative close scenarios).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_balance_can_decrease() {
    // === Setup ===
    let mint_helper = TestMintHelper::new().await.unwrap();
    let keyset_info_json = mint_helper.keyset_info_json().unwrap();

    let receiver_secret = SecretKey::generate();
    let server_host = TestServerHost::new(receiver_secret.clone());
    server_host.add_keyset(
        "https://test-mint",
        mint_helper.keyset_id(),
        keyset_info_json.clone(),
    );
    let server_bridge = SpilmanBridge::new(server_host);

    let sender_secret = SecretKey::generate();
    let mut client_host = ConfigurableClientHost::new_in_memory();
    client_host.add_key(sender_secret.clone());
    let client_networking = InMemoryMintNetworking::new(mint_helper.mint());
    let client_bridge = SpilmanClientBridge::new(client_host, client_networking);

    // === Open channel and make initial payment ===
    let proofs = mint_helper.mint_proofs(500).await.unwrap();
    let token = build_cashu_b_token(
        "https://test-mint",
        "sat",
        &serde_json::to_string(&proofs).unwrap(),
    )
    .expect("build token");

    let open_result = client_bridge
        .open_channel_from_token(
            &token,
            &receiver_secret.public_key().to_hex(),
            &sender_secret.public_key().to_hex(),
            now_seconds() + 3600,
            &keyset_info_json,
            64,
        )
        .expect("open channel");

    // Pay 50 first
    let payment1 = client_bridge
        .create_payment_with_funding(&open_result.channel_id, 50)
        .unwrap();
    server_bridge
        .process_payment(
            &payment1.channel_id,
            payment1.balance,
            &payment1.signature,
            payment1.params.as_ref(),
            payment1.funding_proofs.as_deref(),
            &(),
        )
        .unwrap();

    // Now create a payment with LOWER balance (e.g., cooperative close refund scenario)
    // The client should allow this (we removed monotonic enforcement)
    let payment2 = client_bridge
        .create_payment(&open_result.channel_id, 30)
        .expect("should allow decreased balance");

    assert_eq!(payment2.balance, 30);
    eprintln!("Created payment with decreased balance: 50 -> 30");

    // Server should also accept it (balance updates are just signatures)
    let result = server_bridge
        .process_payment(
            &payment2.channel_id,
            payment2.balance,
            &payment2.signature,
            None,
            None,
            &(),
        )
        .expect("server should accept decreased balance");

    assert_eq!(result.balance, 30);
    eprintln!("Server accepted decreased balance");
}

/// Test that balance cannot exceed capacity.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_balance_cannot_exceed_capacity() {
    // === Setup ===
    let mint_helper = TestMintHelper::new().await.unwrap();
    let keyset_info_json = mint_helper.keyset_info_json().unwrap();

    let receiver_secret = SecretKey::generate();
    let sender_secret = SecretKey::generate();
    let mut client_host = ConfigurableClientHost::new_in_memory();
    client_host.add_key(sender_secret.clone());
    let client_networking = InMemoryMintNetworking::new(mint_helper.mint());
    let client_bridge = SpilmanClientBridge::new(client_host, client_networking);

    // === Open channel ===
    let proofs = mint_helper.mint_proofs(100).await.unwrap();
    let token = build_cashu_b_token(
        "https://test-mint",
        "sat",
        &serde_json::to_string(&proofs).unwrap(),
    )
    .expect("build token");

    let open_result = client_bridge
        .open_channel_from_token(
            &token,
            &receiver_secret.public_key().to_hex(),
            &sender_secret.public_key().to_hex(),
            now_seconds() + 3600,
            &keyset_info_json,
            64,
        )
        .expect("open channel");

    eprintln!("Channel capacity: {}", open_result.capacity);

    // Try to create payment exceeding capacity
    let result = client_bridge.create_payment(&open_result.channel_id, open_result.capacity + 100);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("exceeds"),
        "Error should mention exceeds: {}",
        err
    );
    eprintln!("Correctly rejected payment exceeding capacity: {}", err);
}
