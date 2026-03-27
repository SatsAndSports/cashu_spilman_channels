//! Test server host implementation for integration tests.
//!
//! A minimal `SpilmanHost` implementation that stores state in memory.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use cashu::nuts::{CurrencyUnit, Id, PublicKey, SecretKey};
use cdk_spilman::{
    compute_channel_secret_from_hex, sign_with_tweaked_key_util, ChannelFunding, ChannelPolicy,
    ChannelState, ClosingData, PaymentProof, SpilmanHost,
};

/// A minimal SpilmanHost for testing.
///
/// Stores channel state in memory. Accepts any mint/keyset.
pub struct TestServerHost {
    /// Receiver's secret key
    receiver_secret: SecretKey,
    /// Stored channel funding data
    channels: RefCell<HashMap<String, ChannelFunding>>,
    /// Stored payment proofs (last payment per channel)
    payments: RefCell<HashMap<String, PaymentProof>>,
    /// Channel states
    states: RefCell<HashMap<String, ChannelState>>,
    /// Closing data
    closing_data: RefCell<HashMap<String, ClosingData>>,
    /// Keyset info JSON by keyset ID
    keyset_infos: RefCell<HashMap<Id, String>>,
    /// Active keyset IDs by mint URL
    active_keysets: RefCell<HashMap<String, Vec<Id>>>,
    /// Amount due per channel (for testing pricing)
    amount_due: Cell<u64>,
}

impl TestServerHost {
    /// Create a new test server host.
    pub fn new(receiver_secret: SecretKey) -> Self {
        Self {
            receiver_secret,
            channels: RefCell::new(HashMap::new()),
            payments: RefCell::new(HashMap::new()),
            states: RefCell::new(HashMap::new()),
            closing_data: RefCell::new(HashMap::new()),
            keyset_infos: RefCell::new(HashMap::new()),
            active_keysets: RefCell::new(HashMap::new()),
            amount_due: Cell::new(0),
        }
    }

    /// Register a keyset as active for a mint.
    pub fn add_keyset(&self, mint_url: &str, keyset_id: Id, keyset_info_json: String) {
        self.keyset_infos
            .borrow_mut()
            .insert(keyset_id, keyset_info_json);
        self.active_keysets
            .borrow_mut()
            .entry(mint_url.to_string())
            .or_default()
            .push(keyset_id);
    }

    /// Set the amount due for all channels (for testing).
    pub fn set_amount_due(&self, amount: u64) {
        self.amount_due.set(amount);
    }

    /// Get the last recorded payment for a channel.
    pub fn get_last_payment(&self, channel_id: &str) -> Option<PaymentProof> {
        self.payments.borrow().get(channel_id).cloned()
    }

    /// Get the receiver's public key hex.
    pub fn receiver_pubkey_hex(&self) -> String {
        self.receiver_secret.public_key().to_hex()
    }
}

impl SpilmanHost<()> for TestServerHost {
    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool {
        *receiver_pubkey == self.receiver_secret.public_key()
    }

    fn mint_and_keyset_is_acceptable(&self, _mint: &str, _keyset_id: &Id) -> bool {
        // Accept any mint/keyset for testing
        true
    }

    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
        self.channels.borrow().get(channel_id).cloned()
    }

    fn save_funding(
        &self,
        channel_id: &str,
        funding: ChannelFunding,
        initial_payment: PaymentProof,
    ) {
        self.channels
            .borrow_mut()
            .insert(channel_id.to_string(), funding);
        self.payments
            .borrow_mut()
            .insert(channel_id.to_string(), initial_payment);
        self.states
            .borrow_mut()
            .insert(channel_id.to_string(), ChannelState::Open);
    }

    fn get_amount_due(&self, _channel_id: &str, _context: Option<&()>) -> u64 {
        self.amount_due.get()
    }

    fn record_payment(&self, channel_id: &str, payment: PaymentProof, _context: &()) {
        self.payments
            .borrow_mut()
            .insert(channel_id.to_string(), payment);
    }

    fn get_channel_state(&self, channel_id: &str) -> ChannelState {
        // Return Open for unknown channels to allow new channel creation.
        // The SpilmanBridge will check get_funding() to determine if channel exists.
        self.states
            .borrow()
            .get(channel_id)
            .copied()
            .unwrap_or(ChannelState::Open)
    }

    fn mark_channel_closing(
        &self,
        channel_id: &str,
        expiry_timestamp: u64,
        payment: PaymentProof,
    ) -> Result<(), String> {
        self.states
            .borrow_mut()
            .insert(channel_id.to_string(), ChannelState::Closing);
        self.closing_data.borrow_mut().insert(
            channel_id.to_string(),
            ClosingData {
                expiry_timestamp,
                balance: payment.balance,
                signature: payment.signature,
            },
        );
        Ok(())
    }

    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData> {
        self.closing_data.borrow().get(channel_id).cloned()
    }

    fn get_channel_policy(&self, _unit: &str) -> Option<ChannelPolicy> {
        // Return a permissive policy for testing
        Some(ChannelPolicy {
            min_capacity: 1,
            min_expiry_in_seconds: 60,
            max_amount_per_output: Some(64),
        })
    }

    fn now_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn get_balance_and_signature_for_unilateral_exit(
        &self,
        channel_id: &str,
    ) -> Option<PaymentProof> {
        self.payments.borrow().get(channel_id).cloned()
    }

    fn get_active_keyset_ids(&self, mint: &str, _unit: &CurrencyUnit) -> Vec<Id> {
        self.active_keysets
            .borrow()
            .get(mint)
            .cloned()
            .unwrap_or_default()
    }

    fn get_keyset_info(&self, _mint: &str, keyset_id: &Id) -> Option<String> {
        self.keyset_infos.borrow().get(keyset_id).cloned()
    }

    fn mark_channel_closed(
        &self,
        channel_id: &str,
        _expiry_timestamp: u64,
        _balance: u64,
        _receiver_proofs_json: &str,
        _sender_proofs_json: &str,
        _receiver_sum: u64,
        _sender_sum: u64,
    ) -> Result<(), String> {
        self.states
            .borrow_mut()
            .insert(channel_id.to_string(), ChannelState::Closed);
        Ok(())
    }

    fn compute_channel_secret(
        &self,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
    ) -> Result<String, String> {
        // Verify the receiver pubkey matches ours
        let expected = self.receiver_secret.public_key().to_hex();
        if receiver_pubkey_hex != expected {
            return Err(format!(
                "Receiver pubkey mismatch: expected {}, got {}",
                expected, receiver_pubkey_hex
            ));
        }

        compute_channel_secret_from_hex(&self.receiver_secret.to_secret_hex(), sender_pubkey_hex)
    }

    fn sign_with_tweaked_key(
        &self,
        signer_pubkey_hex: &str,
        message_hex: &str,
        tweak_scalar_hex: &str,
    ) -> Result<String, String> {
        // Verify the signer pubkey matches ours
        let expected = self.receiver_secret.public_key().to_hex();
        if signer_pubkey_hex != expected {
            return Err(format!(
                "Signer pubkey mismatch: expected {}, got {}",
                expected, signer_pubkey_hex
            ));
        }

        sign_with_tweaked_key_util(
            &self.receiver_secret.to_secret_hex(),
            message_hex,
            tweak_scalar_hex,
        )
    }
}
