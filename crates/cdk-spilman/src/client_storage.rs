//! Client-side storage abstraction for Spilman payment channels
//!
//! This module provides storage traits and implementations for managing
//! client-side channel state. It separates immutable funding data from
//! mutable payment state, mirroring the server-side pattern.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use cashu::nuts::{CurrencyUnit, Id};

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

/// Cached mint keyset metadata for client-side channel opening.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientKeysetCacheEntry {
    /// Serialized `KeysetInfo` JSON for this cached mint keyset.
    pub info_json: String,
    /// Whether the mint reports this keyset as active.
    pub active: bool,
    /// Currency unit associated with the keyset.
    pub unit: CurrencyUnit,
}

/// Failure metadata for an opening attempt that the mint explicitly rejected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientOpeningFailure {
    /// Stage reported by the channel-open flow.
    pub stage: String,
    /// Human-readable failure details.
    pub message: String,
    /// Unix timestamp when failure was recorded.
    pub failed_at: u64,
}

/// Channel lifecycle state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ClientChannelState {
    /// Funding swap submitted but not yet confirmed.
    /// The channel parameters and input token are saved for recovery.
    OpeningFromSwap,
    /// Channel opening was explicitly rejected and should not be recovered.
    OpeningFailed,
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
    fn save_opening_from_swap(
        &mut self,
        channel_id: &str,
        opening: ClientChannelOpeningFromSwap,
    ) -> Result<(), String>;

    /// Mark a channel as Open by supplying the funding proofs.
    ///
    /// Reads the opening data, constructs funding data with the proofs,
    /// stores the funding, and removes the opening record.
    fn set_open(&mut self, channel_id: &str, funding_proofs_json: &str) -> Result<(), String>;

    /// Get opening data for a channel in OpeningFromSwap state.
    fn get_opening_from_swap(&self, channel_id: &str) -> Option<ClientChannelOpeningFromSwap>;

    /// Mark an opening attempt as failed while preserving opening metadata.
    fn set_opening_failed(
        &mut self,
        channel_id: &str,
        failure: ClientOpeningFailure,
    ) -> Result<(), String>;

    /// Get failure metadata for a failed opening attempt.
    fn get_opening_failure(&self, channel_id: &str) -> Option<ClientOpeningFailure>;

    /// Get funding data for a channel with stored funding.
    ///
    /// Returns `None` if the channel is not in `Open`, `Closing`, or `Closed`
    /// state.
    fn get_funding(&self, channel_id: &str) -> Option<ClientChannelFunding>;

    // === Payment State (mutable) ===

    /// Get the current payment state for a channel
    fn get_payment_state(&self, channel_id: &str) -> Option<ClientPaymentState>;

    /// Save/update payment state for a channel
    fn save_payment_state(
        &mut self,
        channel_id: &str,
        state: ClientPaymentState,
    ) -> Result<(), String>;

    // === Lifecycle ===

    /// Get the lifecycle state of a channel.
    ///
    /// Returns `None` if the channel is not present in storage.
    fn get_state(&self, channel_id: &str) -> Option<ClientChannelState>;

    /// Mark a channel as closed
    fn set_closed(&mut self, channel_id: &str) -> Result<(), String>;

    /// Mark a channel as closing / unusable.
    ///
    /// By convention this is used for channels that were previously `Open` and
    /// should no longer be selected for new payments.
    fn set_closing(&mut self, channel_id: &str) -> Result<(), String>;

    // === Management ===

    /// List all stored channel IDs
    fn list_channel_ids(&self) -> Vec<String>;

    /// Delete a channel and all its data
    fn delete(&mut self, channel_id: &str) -> Result<(), String>;

    // === Keyset Cache ===

    /// Get cached keyset metadata.
    fn get_keyset(&self, mint: &str, keyset_id: &Id) -> Option<ClientKeysetCacheEntry>;

    /// Insert or update cached keyset metadata.
    fn set_keyset(
        &mut self,
        mint: &str,
        keyset_id: Id,
        entry: ClientKeysetCacheEntry,
    ) -> Result<(), String>;

    /// Get cached active keyset IDs for a mint and unit.
    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id>;
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
    failures: HashMap<String, ClientOpeningFailure>,
    keysets: HashMap<(String, Id), ClientKeysetCacheEntry>,
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
    fn save_opening_from_swap(
        &mut self,
        channel_id: &str,
        opening: ClientChannelOpeningFromSwap,
    ) -> Result<(), String> {
        self.opening.insert(channel_id.to_string(), opening);
        self.states
            .insert(channel_id.to_string(), ClientChannelState::OpeningFromSwap);
        Ok(())
    }

    fn set_open(&mut self, channel_id: &str, funding_proofs_json: &str) -> Result<(), String> {
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
        Ok(())
    }

    fn get_opening_from_swap(&self, channel_id: &str) -> Option<ClientChannelOpeningFromSwap> {
        if self.states.get(channel_id) != Some(&ClientChannelState::OpeningFromSwap) {
            return None;
        }
        self.opening.get(channel_id).cloned()
    }

    fn set_opening_failed(
        &mut self,
        channel_id: &str,
        failure: ClientOpeningFailure,
    ) -> Result<(), String> {
        if !self.opening.contains_key(channel_id) {
            return Err(format!(
                "channel {channel_id} is not in OpeningFromSwap state"
            ));
        }
        self.failures.insert(channel_id.to_string(), failure);
        self.states
            .insert(channel_id.to_string(), ClientChannelState::OpeningFailed);
        Ok(())
    }

    fn get_opening_failure(&self, channel_id: &str) -> Option<ClientOpeningFailure> {
        self.failures.get(channel_id).cloned()
    }

    fn get_funding(&self, channel_id: &str) -> Option<ClientChannelFunding> {
        self.funding.get(channel_id).cloned()
    }

    fn get_payment_state(&self, channel_id: &str) -> Option<ClientPaymentState> {
        self.payments.get(channel_id).cloned()
    }

    fn save_payment_state(
        &mut self,
        channel_id: &str,
        state: ClientPaymentState,
    ) -> Result<(), String> {
        self.payments.insert(channel_id.to_string(), state);
        Ok(())
    }

    fn get_state(&self, channel_id: &str) -> Option<ClientChannelState> {
        self.states.get(channel_id).copied()
    }

    fn set_closed(&mut self, channel_id: &str) -> Result<(), String> {
        self.states
            .insert(channel_id.to_string(), ClientChannelState::Closed);
        Ok(())
    }

    fn set_closing(&mut self, channel_id: &str) -> Result<(), String> {
        self.states
            .insert(channel_id.to_string(), ClientChannelState::Closing);
        Ok(())
    }

    fn list_channel_ids(&self) -> Vec<String> {
        let mut ids: std::collections::HashSet<String> = self.opening.keys().cloned().collect();
        ids.extend(self.funding.keys().cloned());
        ids.into_iter().collect()
    }

    fn delete(&mut self, channel_id: &str) -> Result<(), String> {
        self.opening.remove(channel_id);
        self.funding.remove(channel_id);
        self.payments.remove(channel_id);
        self.failures.remove(channel_id);
        self.states.remove(channel_id);
        Ok(())
    }

    fn get_keyset(&self, mint: &str, keyset_id: &Id) -> Option<ClientKeysetCacheEntry> {
        self.keysets.get(&(mint.to_string(), *keyset_id)).cloned()
    }

    fn set_keyset(
        &mut self,
        mint: &str,
        keyset_id: Id,
        entry: ClientKeysetCacheEntry,
    ) -> Result<(), String> {
        self.keysets.insert((mint.to_string(), keyset_id), entry);
        Ok(())
    }

    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id> {
        self.keysets
            .iter()
            .filter_map(|((entry_mint, id), entry)| {
                (entry_mint == mint && entry.active && &entry.unit == unit).then_some(*id)
            })
            .collect()
    }
}

// ============================================================================
// Test fixtures (shared between in-memory and SQLite storage tests)
// ============================================================================

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    /// Create a minimal `ClientChannelOpeningFromSwap` for tests.
    pub fn make_test_opening() -> ClientChannelOpeningFromSwap {
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

    /// Create a minimal `ClientPaymentState` with the given balance.
    pub fn make_test_payment_state(balance: u64) -> ClientPaymentState {
        ClientPaymentState {
            balance,
            signature: "sig".to_string(),
            payment_count: 1,
            last_payment_at: 1234567890,
        }
    }

    /// Save an opening record and transition the channel to `Open`.
    pub fn seed_open_channel<S: ClientStorage>(
        storage: &mut S,
        channel_id: &str,
        funding_proofs_json: &str,
    ) {
        storage
            .save_opening_from_swap(channel_id, make_test_opening())
            .expect("save opening");
        storage
            .set_open(channel_id, funding_proofs_json)
            .expect("set open");
    }

    /// Seed an open channel, add a payment, and mark it closed.
    pub fn seed_closed_channel<S: ClientStorage>(storage: &mut S, channel_id: &str) {
        seed_open_channel(storage, channel_id, "[]");
        storage
            .save_payment_state(channel_id, make_test_payment_state(100))
            .expect("save payment state");
        storage.set_closed(channel_id).expect("set closed");
    }

    /// Generic conformance test for any [`ClientStorage`] implementation.
    ///
    /// Exercises the full channel lifecycle: empty state, opening, open,
    /// payment, closing, closed, list, and delete.
    pub fn assert_storage_roundtrip<S: ClientStorage>(storage: &mut S) {
        let channel_id = "roundtrip_channel";

        // Empty storage.
        assert_eq!(storage.get_state(channel_id), None);
        assert!(storage.list_channel_ids().is_empty());

        // Save opening.
        storage
            .save_opening_from_swap(channel_id, make_test_opening())
            .expect("save opening");
        assert_eq!(
            storage.get_state(channel_id),
            Some(ClientChannelState::OpeningFromSwap)
        );
        let opening = storage.get_opening_from_swap(channel_id).expect("opening");
        assert_eq!(opening.capacity, 1000);
        assert_eq!(opening.input_token, "cashuAeyJ0ZXN0IjogdHJ1ZX0=");
        assert!(storage.get_funding(channel_id).is_none());

        // Mark open.
        storage
            .set_open(channel_id, r#"[{"proof": true}]"#)
            .expect("set open");
        assert_eq!(
            storage.get_state(channel_id),
            Some(ClientChannelState::Open)
        );
        assert!(storage.get_opening_from_swap(channel_id).is_none());
        let funding = storage.get_funding(channel_id).expect("funding");
        assert_eq!(funding.funding_proofs_json, r#"[{"proof": true}]"#);
        assert_eq!(funding.capacity, 1000);
        assert_eq!(funding.params_json, r#"{"test": true}"#);

        // Payment state.
        assert!(storage.get_payment_state(channel_id).is_none());
        storage
            .save_payment_state(channel_id, make_test_payment_state(100))
            .expect("save payment state");
        let payment = storage
            .get_payment_state(channel_id)
            .expect("payment state");
        assert_eq!(payment.balance, 100);
        assert_eq!(payment.payment_count, 1);

        // Closing preserves funding and payment state.
        storage.set_closing(channel_id).expect("set closing");
        assert_eq!(
            storage.get_state(channel_id),
            Some(ClientChannelState::Closing)
        );
        assert!(storage.get_funding(channel_id).is_some());
        assert_eq!(
            storage
                .get_payment_state(channel_id)
                .expect("payment state")
                .balance,
            100
        );

        // Closed.
        storage.set_closed(channel_id).expect("set closed");
        assert_eq!(
            storage.get_state(channel_id),
            Some(ClientChannelState::Closed)
        );

        // List and delete.
        assert!(storage.list_channel_ids().contains(&channel_id.to_string()));
        storage.delete(channel_id).expect("delete");
        assert!(!storage.list_channel_ids().contains(&channel_id.to_string()));
        assert!(storage.get_funding(channel_id).is_none());
        assert!(storage.get_payment_state(channel_id).is_none());
        assert_eq!(storage.get_state(channel_id), None);
    }

    /// Assert that listing returns every stored channel (both opening and open).
    pub fn assert_storage_list<S: ClientStorage>(storage: &mut S) {
        storage
            .save_opening_from_swap("channel_1", make_test_opening())
            .expect("save channel_1");
        storage
            .save_opening_from_swap("channel_2", make_test_opening())
            .expect("save channel_2");
        storage.set_open("channel_2", "[]").expect("open channel_2");
        storage
            .save_opening_from_swap("channel_3", make_test_opening())
            .expect("save channel_3");

        let mut ids = storage.list_channel_ids();
        ids.sort();

        assert_eq!(
            ids,
            vec![
                "channel_1".to_string(),
                "channel_2".to_string(),
                "channel_3".to_string()
            ]
        );
    }

    /// Assert that deleting a channel removes all its data.
    pub fn assert_storage_delete<S: ClientStorage>(storage: &mut S) {
        let channel_id = "delete_channel";
        seed_closed_channel(storage, channel_id);
        assert!(storage.list_channel_ids().contains(&channel_id.to_string()));

        storage.delete(channel_id).expect("delete");

        assert!(!storage.list_channel_ids().contains(&channel_id.to_string()));
        assert!(storage.get_funding(channel_id).is_none());
        assert!(storage.get_payment_state(channel_id).is_none());
        assert_eq!(storage.get_state(channel_id), None);
    }

    /// Assert that payment state can be saved and updated.
    pub fn assert_storage_payments_can_be_updated<S: ClientStorage>(storage: &mut S) {
        let channel_id = "payment_update_channel";

        seed_open_channel(storage, channel_id, "[]");
        assert!(storage.get_payment_state(channel_id).is_none());

        storage
            .save_payment_state(channel_id, make_test_payment_state(100))
            .expect("save payment state");
        assert_eq!(storage.get_payment_state(channel_id).unwrap().balance, 100);

        storage
            .save_payment_state(channel_id, make_test_payment_state(200))
            .expect("update payment state");
        assert_eq!(storage.get_payment_state(channel_id).unwrap().balance, 200);
    }

    /// Assert that keyset cache entries can be stored and queried by active unit.
    pub fn assert_storage_keyset_cache<S: ClientStorage>(storage: &mut S) {
        let active_id: Id = "001b6c716bf42c7e".parse().unwrap();
        let inactive_id: Id = "00ffedc2dbb87212".parse().unwrap();
        assert_ne!(active_id, inactive_id);
        let active = ClientKeysetCacheEntry {
            info_json: r#"{"keysetId":"active"}"#.to_string(),
            active: true,
            unit: CurrencyUnit::Sat,
        };
        let inactive = ClientKeysetCacheEntry {
            info_json: r#"{"keysetId":"inactive"}"#.to_string(),
            active: false,
            unit: CurrencyUnit::Sat,
        };

        storage
            .set_keyset("https://mint.example", active_id, active.clone())
            .expect("set active keyset");
        storage
            .set_keyset("https://mint.example", inactive_id, inactive)
            .expect("set inactive keyset");

        assert_eq!(
            storage
                .get_keyset("https://mint.example", &active_id)
                .unwrap()
                .info_json,
            active.info_json
        );
        assert_eq!(
            storage.get_active_keyset_ids("https://mint.example", &CurrencyUnit::Sat),
            vec![active_id]
        );
        assert!(storage
            .get_active_keyset_ids("https://mint.example", &CurrencyUnit::Msat)
            .is_empty());
    }

    /// Assert that explicit opening failures are retained separately from recoverable openings.
    pub fn assert_storage_opening_failed<S: ClientStorage>(storage: &mut S) {
        let channel_id = "failed_open_channel";
        storage
            .save_opening_from_swap(channel_id, make_test_opening())
            .expect("save opening");
        assert!(storage.get_opening_from_swap(channel_id).is_some());

        let failure = ClientOpeningFailure {
            stage: "mint_rejected".to_string(),
            message: "unknown keyset".to_string(),
            failed_at: 1234567891,
        };
        storage
            .set_opening_failed(channel_id, failure.clone())
            .expect("mark opening failed");

        assert_eq!(
            storage.get_state(channel_id),
            Some(ClientChannelState::OpeningFailed)
        );
        assert!(storage.get_opening_from_swap(channel_id).is_none());
        assert_eq!(
            storage.get_opening_failure(channel_id).unwrap().message,
            failure.message
        );
        assert!(storage.list_channel_ids().contains(&channel_id.to_string()));
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    #[test]
    fn test_memory_storage_roundtrip() {
        let mut storage = MemoryClientStorage::new();
        assert_storage_roundtrip(&mut storage);
    }

    #[test]
    fn test_memory_storage_payments_can_be_updated() {
        let mut storage = MemoryClientStorage::new();
        assert_storage_payments_can_be_updated(&mut storage);
    }

    #[test]
    fn test_memory_storage_list() {
        let mut storage = MemoryClientStorage::new();
        assert_storage_list(&mut storage);
    }

    #[test]
    fn test_memory_storage_delete_reduces_channel_count() {
        let mut storage = MemoryClientStorage::new();
        assert_storage_delete(&mut storage);
        assert_eq!(storage.channel_count(), 0);
    }

    #[test]
    fn test_memory_storage_keyset_cache() {
        let mut storage = MemoryClientStorage::new();
        assert_storage_keyset_cache(&mut storage);
    }

    #[test]
    fn test_memory_storage_opening_failed() {
        let mut storage = MemoryClientStorage::new();
        assert_storage_opening_failed(&mut storage);
    }
}
