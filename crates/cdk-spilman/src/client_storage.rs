//! Client-side storage abstraction for Spilman payment channels
//!
//! This module provides storage traits and implementations for managing
//! client-side channel state. It separates immutable funding data from
//! mutable payment state, mirroring the server-side pattern.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Data Structures
// ============================================================================

/// Data saved when a channel enters the OpeningFromSwap state.
///
/// This is persisted *before* the funding swap is submitted to the mint.
/// It contains everything needed to either complete the channel opening
/// (via NUT-09 restore) or recover the input token if the swap never
/// went through.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientChannelOpeningFromSwap {
    /// Serialized channel parameters (JSON)
    pub params_json: String,
    /// Hex-encoded hashed ECDH channel secret (32 bytes)
    pub channel_secret_hex: String,
    /// Serialized keyset info (JSON)
    pub keyset_info_json: String,
    /// Sender's public key for this channel (hex)
    pub sender_pubkey_hex: String,
    /// Maximum value the receiver can claim
    pub capacity: u64,
    /// Nominal funding token amount
    pub funding_token_amount: u64,
    /// Mint URL associated with the channel
    pub mint_url: String,
    /// Original Cashu token (cashuA.../cashuB...) for recovery if the swap fails
    pub input_token: String,
    /// Unix timestamp when channel was created
    pub created_at: u64,
}

/// Immutable funding data for an open channel.
///
/// This is created when the channel transitions from OpeningFromSwap to Open.
/// The `funding_proofs_json` field is always populated (never empty).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientChannelFunding {
    /// Serialized channel parameters (JSON)
    pub params_json: String,
    /// Serialized funding proofs (JSON array) - always populated
    pub funding_proofs_json: String,
    /// Hex-encoded hashed ECDH channel secret (32 bytes)
    pub channel_secret_hex: String,
    /// Serialized keyset info (JSON)
    pub keyset_info_json: String,
    /// Sender's public key for this channel (hex)
    pub sender_pubkey_hex: String,
    /// Maximum value the receiver can claim
    pub capacity: u64,
    /// Nominal funding token amount
    pub funding_token_amount: u64,
    /// Mint URL associated with the channel
    pub mint_url: String,
    /// Unix timestamp when channel was created
    pub created_at: u64,
}

/// Mutable payment state (updated on each payment)
///
/// This tracks the current state of payments made through the channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPaymentState {
    /// Last signed balance (cumulative, monotonically increasing)
    pub balance: u64,
    /// Last signature corresponding to the balance
    pub signature: String,
    /// Number of payments made through this channel
    pub payment_count: u64,
    /// Unix timestamp of the last payment
    pub last_payment_at: u64,
}

/// Channel lifecycle state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ClientChannelState {
    /// Funding swap submitted but not yet confirmed.
    /// The channel parameters and input token are saved for recovery.
    OpeningFromSwap,
    /// Channel is open and can accept payments
    #[default]
    Open,
    /// Channel is retained in storage but is unusable for new payments.
    Closing,
    /// Channel is closed, no more payments allowed
    Closed,
}

impl ClientChannelState {
    /// Returns true if the channel may be used to create new payments.
    pub fn is_payable(self) -> bool {
        matches!(self, Self::Open)
    }
}

// ============================================================================
// Storage Trait
// ============================================================================

/// Storage trait for client channel data
///
/// Implementations handle persistence of channel funding data and payment state.
/// The trait separates immutable funding data from mutable payment state.
pub trait ClientStorage {
    // === Channel Opening (two-phase) ===

    /// Save opening data for a channel entering OpeningFromSwap state.
    fn save_opening_from_swap(&mut self, channel_id: &str, opening: ClientChannelOpeningFromSwap);

    /// Mark a channel as Open by supplying the funding proofs.
    ///
    /// Reads the opening data, constructs funding data with the proofs,
    /// stores the funding, and removes the opening record.
    fn set_open(&mut self, channel_id: &str, funding_proofs_json: &str);

    /// Get opening data for a channel in OpeningFromSwap state.
    fn get_opening_from_swap(&self, channel_id: &str) -> Option<&ClientChannelOpeningFromSwap>;

    /// Get funding data for a channel with stored funding.
    ///
    /// Returns `None` if the channel is not in `Open`, `Closing`, or `Closed`
    /// state.
    fn get_funding(&self, channel_id: &str) -> Option<&ClientChannelFunding>;

    // === Payment State (mutable) ===

    /// Get the current payment state for a channel
    fn get_payment_state(&self, channel_id: &str) -> Option<&ClientPaymentState>;

    /// Save/update payment state for a channel
    fn save_payment_state(&mut self, channel_id: &str, state: ClientPaymentState);

    // === Lifecycle ===

    /// Get the lifecycle state of a channel
    fn get_state(&self, channel_id: &str) -> ClientChannelState;

    /// Mark a channel as closed
    fn set_closed(&mut self, channel_id: &str);

    /// Mark a channel as closing / unusable.
    ///
    /// By convention this is used for channels that were previously `Open` and
    /// should no longer be selected for new payments.
    fn set_closing(&mut self, channel_id: &str);

    // === Management ===

    /// List all stored channel IDs
    fn list_channel_ids(&self) -> Vec<String>;

    /// Delete a channel and all its data
    fn delete(&mut self, channel_id: &str);
}

// ============================================================================
// In-Memory Implementation
// ============================================================================

/// In-memory storage implementation
///
/// Stores all channel data in HashMaps. Data is lost when the process exits.
/// Suitable for testing, demos, and short-lived applications.
#[derive(Debug, Default)]
pub struct MemoryClientStorage {
    opening: HashMap<String, ClientChannelOpeningFromSwap>,
    funding: HashMap<String, ClientChannelFunding>,
    payments: HashMap<String, ClientPaymentState>,
    states: HashMap<String, ClientChannelState>,
}

impl MemoryClientStorage {
    /// Create a new empty in-memory storage
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of stored channels (both opening and open)
    pub fn channel_count(&self) -> usize {
        // Count unique channel IDs across both maps
        let mut ids: std::collections::HashSet<&String> = self.opening.keys().collect();
        ids.extend(self.funding.keys());
        ids.len()
    }
}

impl ClientStorage for MemoryClientStorage {
    fn save_opening_from_swap(&mut self, channel_id: &str, opening: ClientChannelOpeningFromSwap) {
        self.opening.insert(channel_id.to_string(), opening);
        self.states
            .insert(channel_id.to_string(), ClientChannelState::OpeningFromSwap);
    }

    fn set_open(&mut self, channel_id: &str, funding_proofs_json: &str) {
        // Read opening data and construct funding record
        if let Some(opening) = self.opening.remove(channel_id) {
            let funding = ClientChannelFunding {
                params_json: opening.params_json,
                funding_proofs_json: funding_proofs_json.to_string(),
                channel_secret_hex: opening.channel_secret_hex,
                keyset_info_json: opening.keyset_info_json,
                sender_pubkey_hex: opening.sender_pubkey_hex,
                capacity: opening.capacity,
                funding_token_amount: opening.funding_token_amount,
                mint_url: opening.mint_url,
                created_at: opening.created_at,
            };
            self.funding.insert(channel_id.to_string(), funding);
        }
        self.states
            .insert(channel_id.to_string(), ClientChannelState::Open);
    }

    fn get_opening_from_swap(&self, channel_id: &str) -> Option<&ClientChannelOpeningFromSwap> {
        self.opening.get(channel_id)
    }

    fn get_funding(&self, channel_id: &str) -> Option<&ClientChannelFunding> {
        self.funding.get(channel_id)
    }

    fn get_payment_state(&self, channel_id: &str) -> Option<&ClientPaymentState> {
        self.payments.get(channel_id)
    }

    fn save_payment_state(&mut self, channel_id: &str, state: ClientPaymentState) {
        self.payments.insert(channel_id.to_string(), state);
    }

    fn get_state(&self, channel_id: &str) -> ClientChannelState {
        self.states
            .get(channel_id)
            .copied()
            .unwrap_or(ClientChannelState::Closed)
    }

    fn set_closed(&mut self, channel_id: &str) {
        self.states
            .insert(channel_id.to_string(), ClientChannelState::Closed);
    }

    fn set_closing(&mut self, channel_id: &str) {
        self.states
            .insert(channel_id.to_string(), ClientChannelState::Closing);
    }

    fn list_channel_ids(&self) -> Vec<String> {
        let mut ids: std::collections::HashSet<String> = self.opening.keys().cloned().collect();
        ids.extend(self.funding.keys().cloned());
        ids.into_iter().collect()
    }

    fn delete(&mut self, channel_id: &str) {
        self.opening.remove(channel_id);
        self.funding.remove(channel_id);
        self.payments.remove(channel_id);
        self.states.remove(channel_id);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_opening() -> ClientChannelOpeningFromSwap {
        ClientChannelOpeningFromSwap {
            params_json: r#"{"test": true}"#.to_string(),
            channel_secret_hex: "aa".repeat(32),
            keyset_info_json: "{}".to_string(),
            sender_pubkey_hex: "02".to_string() + &"bb".repeat(32),
            capacity: 1000,
            funding_token_amount: 1100,
            mint_url: "https://mint.example.com".to_string(),
            input_token: "cashuAeyJ0ZXN0IjogdHJ1ZX0=".to_string(),
            created_at: 1234567890,
        }
    }

    fn make_test_payment_state(balance: u64) -> ClientPaymentState {
        ClientPaymentState {
            balance,
            signature: "sig".to_string(),
            payment_count: 1,
            last_payment_at: 1234567890,
        }
    }

    #[test]
    fn test_memory_storage_opening_from_swap() {
        let mut storage = MemoryClientStorage::new();
        let channel_id = "test_channel_1";

        // Initially empty
        assert!(storage.get_opening_from_swap(channel_id).is_none());
        assert!(storage.get_funding(channel_id).is_none());
        assert_eq!(storage.channel_count(), 0);

        // Save as opening
        storage.save_opening_from_swap(channel_id, make_test_opening());

        // Opening data retrievable
        let o = storage.get_opening_from_swap(channel_id).unwrap();
        assert_eq!(o.capacity, 1000);
        assert_eq!(o.input_token, "cashuAeyJ0ZXN0IjogdHJ1ZX0=");
        assert_eq!(storage.channel_count(), 1);

        // State should be OpeningFromSwap
        assert_eq!(
            storage.get_state(channel_id),
            ClientChannelState::OpeningFromSwap
        );

        // Funding not yet available
        assert!(storage.get_funding(channel_id).is_none());

        // Mark open with funding proofs
        storage.set_open(channel_id, r#"[{"proof": true}]"#);

        // State should be Open
        assert_eq!(storage.get_state(channel_id), ClientChannelState::Open);

        // Opening data removed
        assert!(storage.get_opening_from_swap(channel_id).is_none());

        // Funding now available with proofs
        let f = storage.get_funding(channel_id).unwrap();
        assert_eq!(f.funding_proofs_json, r#"[{"proof": true}]"#);
        assert_eq!(f.capacity, 1000);
        assert_eq!(f.params_json, r#"{"test": true}"#);
    }

    #[test]
    fn test_memory_storage_payments() {
        let mut storage = MemoryClientStorage::new();
        let channel_id = "test_channel_1";

        storage.save_opening_from_swap(channel_id, make_test_opening());
        storage.set_open(channel_id, "[]");

        // Initially no payment state
        assert!(storage.get_payment_state(channel_id).is_none());

        // Save payment state
        storage.save_payment_state(channel_id, make_test_payment_state(100));

        let state = storage.get_payment_state(channel_id).unwrap();
        assert_eq!(state.balance, 100);
        assert_eq!(state.payment_count, 1);

        // Update payment state
        storage.save_payment_state(channel_id, make_test_payment_state(200));

        let state = storage.get_payment_state(channel_id).unwrap();
        assert_eq!(state.balance, 200);
    }

    #[test]
    fn test_memory_storage_lifecycle() {
        let mut storage = MemoryClientStorage::new();
        let channel_id = "test_channel_1";

        // Unknown channel is Closed
        assert_eq!(storage.get_state(channel_id), ClientChannelState::Closed);

        // After save_opening_from_swap, it's OpeningFromSwap
        storage.save_opening_from_swap(channel_id, make_test_opening());
        assert_eq!(
            storage.get_state(channel_id),
            ClientChannelState::OpeningFromSwap
        );

        // After set_open, it's Open
        storage.set_open(channel_id, "[]");
        assert_eq!(storage.get_state(channel_id), ClientChannelState::Open);

        // After set_closing, it's Closing
        storage.set_closing(channel_id);
        assert_eq!(storage.get_state(channel_id), ClientChannelState::Closing);

        // Mark closed
        storage.set_closed(channel_id);
        assert_eq!(storage.get_state(channel_id), ClientChannelState::Closed);
    }

    #[test]
    fn test_memory_storage_delete() {
        let mut storage = MemoryClientStorage::new();
        let channel_id = "test_channel_1";

        storage.save_opening_from_swap(channel_id, make_test_opening());
        storage.set_open(channel_id, "[]");
        storage.save_payment_state(channel_id, make_test_payment_state(100));
        storage.set_closed(channel_id);

        assert_eq!(storage.channel_count(), 1);

        // Delete
        storage.delete(channel_id);

        assert_eq!(storage.channel_count(), 0);
        assert!(storage.get_funding(channel_id).is_none());
        assert!(storage.get_payment_state(channel_id).is_none());
        assert_eq!(storage.get_state(channel_id), ClientChannelState::Closed);
    }

    #[test]
    fn test_memory_storage_list() {
        let mut storage = MemoryClientStorage::new();

        // Mix of opening and open channels
        storage.save_opening_from_swap("channel_1", make_test_opening());
        storage.save_opening_from_swap("channel_2", make_test_opening());
        storage.set_open("channel_2", "[]");
        storage.save_opening_from_swap("channel_3", make_test_opening());

        let mut ids = storage.list_channel_ids();
        ids.sort();

        assert_eq!(ids, vec!["channel_1", "channel_2", "channel_3"]);
    }

    #[test]
    fn test_closing_preserves_funding_and_payment_state() {
        let mut storage = MemoryClientStorage::new();
        let channel_id = "test_channel_closing";

        storage.save_opening_from_swap(channel_id, make_test_opening());
        storage.set_open(channel_id, r#"[{"proof": true}]"#);
        storage.save_payment_state(channel_id, make_test_payment_state(42));
        storage.set_closing(channel_id);

        assert_eq!(storage.get_state(channel_id), ClientChannelState::Closing);
        assert!(storage.get_funding(channel_id).is_some());
        assert_eq!(storage.get_payment_state(channel_id).unwrap().balance, 42);
        assert!(storage.list_channel_ids().iter().any(|id| id == channel_id));
    }
}
