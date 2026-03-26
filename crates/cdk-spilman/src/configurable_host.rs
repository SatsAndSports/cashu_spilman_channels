//! Configurable SpilmanHost
//!
//! A generic, YAML-configurable implementation of [`SpilmanHost`] that tracks
//! usage via named **usage variables** — monotonically increasing integer
//! counters (e.g. `"requests"`, `"bytes"`, `"chars"`).
//!
//! The amount due for a channel is computed as a **linear combination**:
//!
//! ```text
//! amount_due = ceil(sum_over_var(accumulated[var] * price_per_unit[var]) / pricing_scale)
//! ```
//!
//! `pricing_scale` (default 1) lets you define prices with sub-unit precision.
//! For example, `pricing_scale: 1000` with `bytes: 1` means 0.001 sat per byte.
//!
//! The context JSON passed to [`SpilmanHost::get_amount_due`] and
//! [`SpilmanHost::record_payment`] contains the increments for each variable,
//! using the same keys:
//!
//! ```json
//! { "requests": 1, "bytes": 4096 }
//! ```
//!
//! # Example YAML configuration
//!
//! ```yaml
//! mints:
//!   "http://localhost:3338": [sat, msat, usd]
//! min_expiry_seconds: 3600
//!
//! # Optional: defaults to in-memory if omitted.
//! # storage:
//! #   type: sqlite
//! #   path: "./spilman.db"
//!
//! # Optional scaling divisor (default 1).
//! # pricing_scale: 1000
//!
//! pricing:
//!   sat:
//!     min_capacity: 10
//!     variables:
//!       chars: 1
//!       requests: 5
//!   msat:
//!     min_capacity: 10000
//!     variables:
//!       chars: 1000
//!       requests: 5000
//!   usd:
//!     min_capacity: 10
//!     max_amount_per_output: 64
//!     variables:
//!       chars: 1
//!       requests: 5
//! ```

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{
    ChannelFunding, ChannelId, ChannelPolicy, ChannelState, ClosingData, PaymentProof, SpilmanHost,
};
use cashu::nuts::{CurrencyUnit, Id, PublicKey, SecretKey};

// ============================================================================
// Configuration types
// ============================================================================

/// Per-unit pricing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitPricingConfig {
    /// Minimum channel capacity required for this unit.
    pub min_capacity: u64,

    /// Optional maximum amount per blinded output (for testing maximum_amount policy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_amount_per_output: Option<u64>,

    /// Mapping from usage variable name to price-per-unit.
    ///
    /// For example: `{ "chars": 1, "requests": 5 }` means 1 sat per char
    /// and 5 sat per request.
    pub variables: HashMap<String, u64>,
}

/// Storage backend configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum StorageConfig {
    /// In-memory storage (default). All data lost on restart.
    #[default]
    #[serde(rename = "memory")]
    Memory,

    /// SQLite file-backed storage. Persists across restarts.
    #[serde(rename = "sqlite")]
    Sqlite {
        /// Path to the SQLite database file.
        path: String,
    },
}

/// Top-level YAML configuration for [`ConfigurableHost`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigurableHostConfig {
    /// Trusted mints, mapping each mint URL to the set of units trusted at
    /// that mint (e.g. `{ "http://localhost:3338": ["sat", "msat"] }`).
    pub mints: HashMap<String, Vec<String>>,

    /// Minimum channel expiry in seconds.
    #[serde(default = "default_min_expiry")]
    pub min_expiry_seconds: u64,

    /// Scaling divisor for the pricing linear combination.
    ///
    /// The amount due is `ceil(raw_total / pricing_scale)`.  Defaults to 1
    /// (no scaling).  Use a larger value to express sub-unit prices —
    /// e.g. `pricing_scale: 1000` with `bytes: 1` means 0.001 sat per byte.
    #[serde(default = "default_pricing_scale")]
    pub pricing_scale: u64,

    /// Storage backend. Defaults to in-memory if omitted.
    #[serde(default)]
    pub storage: StorageConfig,

    /// Per-unit pricing. Keys are unit names (`"sat"`, `"msat"`, `"usd"`, …).
    pub pricing: HashMap<String, UnitPricingConfig>,
}

fn default_min_expiry() -> u64 {
    3600
}

fn default_pricing_scale() -> u64 {
    1
}

impl ConfigurableHostConfig {
    /// Parse a [`ConfigurableHostConfig`] from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        serde_yml::from_str(yaml).map_err(|e| format!("YAML parse error: {e}"))
    }
}

// ============================================================================
// Storage trait & types
// ============================================================================

/// Per-channel accumulated usage: `variable_name -> value`.
pub type UsageMap = HashMap<String, u64>;

/// Cached mint keyset metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeysetCacheEntry {
    /// Serialized `KeysetInfo` JSON for this cached mint keyset.
    pub info_json: String,
    /// Whether the mint reports this keyset as active.
    pub active: bool,
    /// Currency unit associated with the keyset.
    pub unit: CurrencyUnit,
}

/// Storage backend for [`ConfigurableHost`].
///
/// All methods are synchronous. Implementations must be thread-safe
/// (`Send + Sync`). The default implementation is [`MemoryStorage`];
/// [`SqliteStorage`] provides persistence across restarts.
pub trait SpilmanStorage: Send + Sync {
    // -- channel funding ------------------------------------------------------

    /// Get the stored funding data for a channel.
    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding>;

    /// Save funding data for a new channel.  Must be idempotent: if the
    /// channel already has funding, this call is a no-op.
    fn save_funding(&self, channel_id: &str, funding: ChannelFunding) -> Result<(), String>;

    // -- balance & payments ---------------------------------------------------

    /// Get the current balance for a channel.  Returns `None` if no payment
    /// has been recorded yet.
    fn get_balance(&self, channel_id: &str) -> Option<PaymentProof>;

    /// Update the balance for a channel.  Must be monotonic: only update if
    /// the new balance is strictly greater than the current one (or if no
    /// balance has been set yet).  Returns `Ok(())` even if the balance was
    /// not updated (monotonic no-op).
    fn update_balance(&self, channel_id: &str, payment: PaymentProof) -> Result<(), String>;

    // -- usage variables ------------------------------------------------------

    /// Get the accumulated usage for a channel.
    fn get_usage(&self, channel_id: &str) -> Option<UsageMap>;

    /// Increment usage variables for a channel.
    fn increment_usage(&self, channel_id: &str, increments: &UsageMap) -> Result<(), String>;

    // -- channel state --------------------------------------------------------

    /// Get the current state (Open, Closing, Closed).
    fn get_state(&self, channel_id: &str) -> ChannelState;

    /// Mark a channel as closing.  Returns `Err` if the channel does not
    /// exist or is already closed.
    fn mark_closing(&self, channel_id: &str, closing: ClosingData) -> Result<(), String>;

    /// Get the data for a closing channel.
    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData>;

    /// Mark a channel as closed.  Returns `Err` if already closed.
    fn mark_closed(&self, channel_id: &str, data: ClosedDataView) -> Result<(), String>;

    /// Get the data for a closed channel.
    fn get_closed_data(&self, channel_id: &str) -> Option<ClosedDataView>;

    // -- keyset cache ---------------------------------------------------------

    /// Get a keyset from the cache.
    fn get_keyset(&self, mint: &str, keyset_id: &Id) -> Option<KeysetCacheEntry>;

    /// Insert or update a keyset in the cache.
    fn set_keyset(&self, mint: &str, keyset_id: Id, entry: KeysetCacheEntry) -> Result<(), String>;

    /// Get all active keyset IDs for a given mint and unit.
    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id>;

    /// Returns `{ mint_url: { unit: [keyset_id, …] } }` for all active keysets.
    fn get_mints_units_keysets(&self) -> HashMap<String, HashMap<String, Vec<String>>>;

    /// Returns the set of units that have at least one active keyset.
    fn get_active_units(&self) -> std::collections::HashSet<String>;
}

// ============================================================================
// MemoryStorage
// ============================================================================

/// Thread-safe in-memory storage using `RwLock<HashMap>`.
#[derive(Default)]
pub struct MemoryStorage {
    funding: RwLock<HashMap<ChannelId, ChannelFunding>>,
    balance: RwLock<HashMap<ChannelId, PaymentProof>>,
    usage: RwLock<HashMap<ChannelId, UsageMap>>,
    closing: RwLock<HashMap<ChannelId, ClosingData>>,
    closed: RwLock<HashMap<ChannelId, ClosedDataView>>,
    keysets: RwLock<HashMap<(String, Id), KeysetCacheEntry>>,
}

impl std::fmt::Debug for MemoryStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryStorage").finish_non_exhaustive()
    }
}

impl MemoryStorage {
    /// Create a new, empty in-memory storage.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SpilmanStorage for MemoryStorage {
    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
        self.funding
            .read()
            .expect("funding lock")
            .get(channel_id)
            .cloned()
    }

    fn save_funding(&self, channel_id: &str, funding: ChannelFunding) -> Result<(), String> {
        let mut store = self.funding.write().expect("funding lock");
        if !store.contains_key(channel_id) {
            store.insert(channel_id.to_string(), funding);
        }
        Ok(())
    }

    fn get_balance(&self, channel_id: &str) -> Option<PaymentProof> {
        self.balance
            .read()
            .expect("balance lock")
            .get(channel_id)
            .cloned()
    }

    fn update_balance(&self, channel_id: &str, payment: PaymentProof) -> Result<(), String> {
        let mut store = self.balance.write().expect("balance lock");
        let should_update = store
            .get(channel_id)
            .map(|b| payment.balance > b.balance)
            .unwrap_or(true);
        if should_update {
            store.insert(channel_id.to_string(), payment);
        }
        Ok(())
    }

    fn get_usage(&self, channel_id: &str) -> Option<UsageMap> {
        let store = self.usage.read().expect("usage lock");
        let map = store.get(channel_id)?;
        if map.is_empty() {
            None
        } else {
            Some(map.clone())
        }
    }

    fn increment_usage(&self, channel_id: &str, increments: &UsageMap) -> Result<(), String> {
        let mut store = self.usage.write().expect("usage lock");
        let usage = store.entry(channel_id.to_string()).or_default();
        for (var, delta) in increments {
            *usage.entry(var.clone()).or_insert(0) += delta;
        }
        Ok(())
    }

    fn get_state(&self, channel_id: &str) -> ChannelState {
        if self
            .closed
            .read()
            .expect("closed lock")
            .contains_key(channel_id)
        {
            ChannelState::Closed
        } else if self
            .closing
            .read()
            .expect("closing lock")
            .contains_key(channel_id)
        {
            ChannelState::Closing
        } else {
            ChannelState::Open
        }
    }

    fn mark_closing(&self, channel_id: &str, closing: ClosingData) -> Result<(), String> {
        if self
            .closed
            .read()
            .expect("closed lock")
            .contains_key(channel_id)
        {
            return Err("channel already closed".to_string());
        }
        self.closing
            .write()
            .expect("closing lock")
            .insert(channel_id.to_string(), closing);
        Ok(())
    }

    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData> {
        self.closing
            .read()
            .expect("closing lock")
            .get(channel_id)
            .cloned()
    }

    fn mark_closed(&self, channel_id: &str, data: ClosedDataView) -> Result<(), String> {
        if self
            .closed
            .read()
            .expect("closed lock")
            .contains_key(channel_id)
        {
            return Err("channel already closed".to_string());
        }
        // Insert into closed before removing from closing, so that
        // get_state (which checks closed first) never sees the channel
        // in neither store and briefly reports it as Open.
        self.closed
            .write()
            .expect("closed lock")
            .insert(channel_id.to_string(), data);
        self.closing
            .write()
            .expect("closing lock")
            .remove(channel_id);
        Ok(())
    }

    fn get_closed_data(&self, channel_id: &str) -> Option<ClosedDataView> {
        self.closed
            .read()
            .expect("closed lock")
            .get(channel_id)
            .cloned()
    }

    fn get_keyset(&self, mint: &str, keyset_id: &Id) -> Option<KeysetCacheEntry> {
        self.keysets
            .read()
            .expect("keysets lock")
            .get(&(mint.to_string(), *keyset_id))
            .cloned()
    }

    fn set_keyset(&self, mint: &str, keyset_id: Id, entry: KeysetCacheEntry) -> Result<(), String> {
        self.keysets
            .write()
            .expect("keysets lock")
            .insert((mint.to_string(), keyset_id), entry);
        Ok(())
    }

    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id> {
        // There is no requirement that this be 'up-to-date'. So this is
        // the set of keysets were active the last time the server updated
        // its records of the keysets
        self.keysets
            .read()
            .expect("keysets lock")
            .iter()
            .filter(|((m, _), entry)| m == mint && entry.unit == *unit && entry.active)
            .map(|((_, kid), _)| *kid)
            .collect()
    }

    /// Returns `{ mint_url: { unit: [keyset_id, …] } }` for all active keysets.
    fn get_mints_units_keysets(&self) -> HashMap<String, HashMap<String, Vec<String>>> {
        let mut result: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
        let store = self.keysets.read().expect("keysets lock");
        for ((mint, keyset_id), entry) in store.iter() {
            if !entry.active {
                continue;
            }
            result
                .entry(mint.clone())
                .or_default()
                .entry(entry.unit.to_string())
                .or_default()
                .push(keyset_id.to_string());
        }
        result
    }

    /// Returns the set of units that have at least one active keyset.
    fn get_active_units(&self) -> std::collections::HashSet<String> {
        self.keysets
            .read()
            .expect("keysets lock")
            .values()
            .filter(|e| e.active)
            .map(|e| e.unit.to_string())
            .collect()
    }
}

// ============================================================================
// SqliteStorage
// ============================================================================

/// SQLite-backed persistent storage.
///
/// Schema:
/// - `spilman_channels` — funding, balance, state, closing/closed JSON
/// - `spilman_usage` — normalized: one row per (channel, variable) with atomic
///   `INSERT ... ON CONFLICT DO UPDATE SET count = count + excluded.count`
/// - `spilman_keysets` — cached mint keyset metadata (JSON)
pub struct SqliteStorage {
    conn: std::sync::Mutex<rusqlite::Connection>,
    /// Write-once cache: funding data is never updated or deleted, so cache
    /// entries are populated lazily on first access and never invalidated.
    funding_cache: std::sync::Mutex<HashMap<String, ChannelFunding>>,
}

impl std::fmt::Debug for SqliteStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteStorage").finish_non_exhaustive()
    }
}

impl SqliteStorage {
    /// Open (or create) a SQLite database at the given path.
    pub fn open(path: &str) -> Result<Self, String> {
        let conn = rusqlite::Connection::open(path)
            .map_err(|e| format!("failed to open SQLite at {path}: {e}"))?;
        let storage = Self {
            conn: std::sync::Mutex::new(conn),
            funding_cache: std::sync::Mutex::new(HashMap::new()),
        };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Create an in-memory SQLite database (useful for testing).
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, String> {
        let conn = rusqlite::Connection::open_in_memory()
            .map_err(|e| format!("failed to open in-memory SQLite: {e}"))?;
        let storage = Self {
            conn: std::sync::Mutex::new(conn),
            funding_cache: std::sync::Mutex::new(HashMap::new()),
        };
        storage.init_schema()?;
        Ok(storage)
    }

    fn init_schema(&self) -> Result<(), String> {
        let conn = self.conn.lock().expect("sqlite lock");
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS spilman_channels (
                channel_id    TEXT NOT NULL PRIMARY KEY,
                funding_json  TEXT NOT NULL,
                balance       INTEGER NOT NULL DEFAULT 0,
                signature     TEXT NOT NULL DEFAULT '',
                state         TEXT NOT NULL DEFAULT 'Open',
                closing_json  TEXT,
                closed_json   TEXT
            );

            CREATE TABLE IF NOT EXISTS spilman_usage (
                channel_id TEXT NOT NULL,
                var_name   TEXT NOT NULL,
                count      INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (channel_id, var_name)
            );

            CREATE TABLE IF NOT EXISTS spilman_keysets (
                mint_url   TEXT NOT NULL,
                keyset_id  TEXT NOT NULL,
                entry_json TEXT NOT NULL,
                PRIMARY KEY (mint_url, keyset_id)
            );
            ",
        )
        .map_err(|e| format!("failed to initialize SQLite schema: {e}"))
    }
}

impl SpilmanStorage for SqliteStorage {
    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
        // Check the in-memory cache first.
        {
            let cache = self.funding_cache.lock().expect("funding_cache lock");
            if let Some(f) = cache.get(channel_id) {
                return Some(f.clone());
            }
        }
        // Cache miss — query SQLite and populate on hit.
        let conn = self.conn.lock().expect("sqlite lock");
        let funding: Option<ChannelFunding> = conn
            .query_row(
                "SELECT funding_json FROM spilman_channels WHERE channel_id = ?1",
                [channel_id],
                |row| {
                    let json: String = row.get(0)?;
                    Ok(json)
                },
            )
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok());
        if let Some(ref f) = funding {
            drop(conn);
            self.funding_cache
                .lock()
                .expect("funding_cache lock")
                .insert(channel_id.to_string(), f.clone());
        }
        funding
    }

    fn save_funding(&self, channel_id: &str, funding: ChannelFunding) -> Result<(), String> {
        let conn = self.conn.lock().expect("sqlite lock");
        let json = serde_json::to_string(&funding).expect("ChannelFunding serialization failed");
        conn.execute(
            "INSERT INTO spilman_channels (channel_id, funding_json)
             VALUES (?1, ?2)
             ON CONFLICT(channel_id) DO NOTHING",
            rusqlite::params![channel_id, json],
        )
        .map_err(|e| format!("save_funding: {e}"))?;
        // Populate the cache (write-once, so first insert wins — matches the SQL).
        self.funding_cache
            .lock()
            .expect("funding_cache lock")
            .entry(channel_id.to_string())
            .or_insert(funding);
        Ok(())
    }

    fn get_balance(&self, channel_id: &str) -> Option<PaymentProof> {
        let conn = self.conn.lock().expect("sqlite lock");
        conn.query_row(
            "SELECT balance, signature FROM spilman_channels
             WHERE channel_id = ?1 AND signature != ''",
            [channel_id],
            |row| {
                let balance: i64 = row.get(0)?;
                let signature: String = row.get(1)?;
                Ok(PaymentProof {
                    balance: balance as u64,
                    signature,
                })
            },
        )
        .ok()
    }

    fn update_balance(&self, channel_id: &str, payment: PaymentProof) -> Result<(), String> {
        let conn = self.conn.lock().expect("sqlite lock");
        // Monotonic: only update if strictly greater, OR if this is the
        // first real balance (signature is still the empty-string default).
        // Returns Ok(()) even if 0 rows affected (monotonic no-op).
        conn.execute(
            "UPDATE spilman_channels
             SET balance = ?2, signature = ?3
             WHERE channel_id = ?1
               AND (balance < ?2 OR signature = '')",
            rusqlite::params![channel_id, payment.balance as i64, payment.signature],
        )
        .map_err(|e| format!("update_balance: {e}"))?;
        Ok(())
    }

    fn get_usage(&self, channel_id: &str) -> Option<UsageMap> {
        let conn = self.conn.lock().expect("sqlite lock");
        let mut stmt =
            match conn.prepare("SELECT var_name, count FROM spilman_usage WHERE channel_id = ?1") {
                Ok(s) => s,
                Err(_) => return None,
            };
        let map: UsageMap = stmt
            .query_map([channel_id], |row| {
                let var: String = row.get(0)?;
                let count: i64 = row.get(1)?;
                Ok((var, count as u64))
            })
            .ok()?
            .filter_map(|r| r.ok())
            .collect();

        if map.is_empty() {
            None
        } else {
            Some(map)
        }
    }

    /// Atomically increment usage counters for a channel.
    ///
    /// `increments` maps variable names to their deltas for this request,
    /// e.g. `{"chars": 42, "requests": 1}`.  Each entry produces one
    /// SQL upsert against the `spilman_usage` table (keyed by
    /// `(channel_id, var_name)`): the row is created if it doesn't exist,
    /// or its `count` is bumped by the delta if it does.  All upserts
    /// for the channel run in a single transaction.
    fn increment_usage(&self, channel_id: &str, increments: &UsageMap) -> Result<(), String> {
        let mut conn = self.conn.lock().expect("sqlite lock");
        let tx = conn
            .transaction()
            .map_err(|e| format!("increment_usage: begin transaction: {e}"))?;
        for (var, delta) in increments {
            tx.execute(
                "INSERT INTO spilman_usage (channel_id, var_name, count)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(channel_id, var_name)
                 DO UPDATE SET count = count + excluded.count",
                rusqlite::params![channel_id, var, *delta as i64],
            )
            .map_err(|e| format!("increment_usage({var}): {e}"))?;
        }
        tx.commit()
            .map_err(|e| format!("increment_usage: commit: {e}"))?;
        Ok(())
    }

    fn get_state(&self, channel_id: &str) -> ChannelState {
        let conn = self.conn.lock().expect("sqlite lock");
        conn.query_row(
            "SELECT state FROM spilman_channels WHERE channel_id = ?1",
            [channel_id],
            |row| {
                let state: String = row.get(0)?;
                Ok(state)
            },
        )
        .ok()
        .map(|s| match s.as_str() {
            "Closing" => ChannelState::Closing,
            "Closed" => ChannelState::Closed,
            _ => ChannelState::Open,
        })
        .unwrap_or(ChannelState::Open)
    }

    fn mark_closing(&self, channel_id: &str, closing: ClosingData) -> Result<(), String> {
        let conn = self.conn.lock().expect("sqlite lock");
        let json = serde_json::to_string(&closing).expect("ClosingData serialization failed");
        let rows = conn
            .execute(
                "UPDATE spilman_channels
                 SET state = 'Closing', closing_json = ?2
                 WHERE channel_id = ?1 AND state != 'Closed'",
                rusqlite::params![channel_id, json],
            )
            .map_err(|e| format!("mark_closing: {e}"))?;
        if rows == 0 {
            return Err("channel not found or already closed".to_string());
        }
        Ok(())
    }

    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData> {
        let conn = self.conn.lock().expect("sqlite lock");
        conn.query_row(
            "SELECT closing_json FROM spilman_channels
             WHERE channel_id = ?1 AND state = 'Closing'",
            [channel_id],
            |row| {
                let json: String = row.get(0)?;
                Ok(json)
            },
        )
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
    }

    fn mark_closed(&self, channel_id: &str, data: ClosedDataView) -> Result<(), String> {
        let conn = self.conn.lock().expect("sqlite lock");
        let json = serde_json::to_string(&data).expect("ClosedDataView serialization failed");
        // Single UPDATE with WHERE guard: only transitions non-Closed channels.
        let rows = conn
            .execute(
                "UPDATE spilman_channels
                 SET state = 'Closed', closed_json = ?2, closing_json = NULL
                 WHERE channel_id = ?1 AND state != 'Closed'",
                rusqlite::params![channel_id, json],
            )
            .map_err(|e| format!("mark_closed: {e}"))?;
        if rows == 0 {
            return Err("channel already closed or not found".to_string());
        }
        Ok(())
    }

    fn get_closed_data(&self, channel_id: &str) -> Option<ClosedDataView> {
        let conn = self.conn.lock().expect("sqlite lock");
        conn.query_row(
            "SELECT closed_json FROM spilman_channels
             WHERE channel_id = ?1 AND state = 'Closed'",
            [channel_id],
            |row| {
                let json: String = row.get(0)?;
                Ok(json)
            },
        )
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
    }

    fn get_keyset(&self, mint: &str, keyset_id: &Id) -> Option<KeysetCacheEntry> {
        let conn = self.conn.lock().expect("sqlite lock");
        conn.query_row(
            "SELECT entry_json FROM spilman_keysets WHERE mint_url = ?1 AND keyset_id = ?2",
            rusqlite::params![mint, keyset_id.to_string()],
            |row| {
                let json: String = row.get(0)?;
                Ok(json)
            },
        )
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
    }

    fn set_keyset(&self, mint: &str, keyset_id: Id, entry: KeysetCacheEntry) -> Result<(), String> {
        let conn = self.conn.lock().expect("sqlite lock");
        let json = serde_json::to_string(&entry).expect("KeysetCacheEntry serialization failed");
        conn.execute(
            "INSERT INTO spilman_keysets (mint_url, keyset_id, entry_json)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(mint_url, keyset_id) DO UPDATE SET entry_json = ?3",
            rusqlite::params![mint, keyset_id.to_string(), json],
        )
        .map_err(|e| format!("set_keyset: {e}"))?;
        Ok(())
    }

    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id> {
        let conn = self.conn.lock().expect("sqlite lock");
        let mut stmt = match conn
            .prepare("SELECT keyset_id, entry_json FROM spilman_keysets WHERE mint_url = ?1")
        {
            Ok(s) => s,
            Err(_) => return vec![],
        };

        let unit_str = unit.to_string();
        stmt.query_map([mint], |row| {
            let kid_str: String = row.get(0)?;
            let json: String = row.get(1)?;
            Ok((kid_str, json))
        })
        .ok()
        .map(|rows| {
            rows.filter_map(|r| r.ok())
                .filter_map(|(kid_str, json)| {
                    let entry: KeysetCacheEntry = serde_json::from_str(&json).ok()?;
                    if entry.active && entry.unit.to_string() == unit_str {
                        kid_str.parse::<Id>().ok()
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
    }

    fn get_mints_units_keysets(&self) -> HashMap<String, HashMap<String, Vec<String>>> {
        let conn = self.conn.lock().expect("sqlite lock");
        let mut stmt =
            match conn.prepare("SELECT mint_url, keyset_id, entry_json FROM spilman_keysets") {
                Ok(s) => s,
                Err(_) => return HashMap::new(),
            };

        let mut result: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
        if let Ok(rows) = stmt.query_map([], |row| {
            let mint: String = row.get(0)?;
            let kid: String = row.get(1)?;
            let json: String = row.get(2)?;
            Ok((mint, kid, json))
        }) {
            for row in rows.flatten() {
                let (mint, kid, json) = row;
                if let Ok(entry) = serde_json::from_str::<KeysetCacheEntry>(&json) {
                    // Only active keysets: inactive ones still work for
                    // existing channels, but we don't advertise them to
                    // new clients.
                    if entry.active {
                        result
                            .entry(mint)
                            .or_default()
                            .entry(entry.unit.to_string())
                            .or_default()
                            .push(kid);
                    }
                }
            }
        }
        result
    }

    fn get_active_units(&self) -> std::collections::HashSet<String> {
        let conn = self.conn.lock().expect("sqlite lock");
        let mut stmt = match conn.prepare("SELECT entry_json FROM spilman_keysets") {
            Ok(s) => s,
            Err(_) => return std::collections::HashSet::new(),
        };

        stmt.query_map([], |row| {
            let json: String = row.get(0)?;
            Ok(json)
        })
        .ok()
        .map(|rows| {
            rows.filter_map(|r| r.ok())
                .filter_map(|json| {
                    let entry: KeysetCacheEntry = serde_json::from_str(&json).ok()?;
                    if entry.active {
                        Some(entry.unit.to_string())
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
    }
}

// ============================================================================
// ConfigurableHost
// ============================================================================

/// A generic, YAML-configurable [`SpilmanHost`] implementation.
///
/// Tracks usage via named usage variables and computes pricing as a linear
/// combination.  Pluggable storage: [`MemoryStorage`] (default) or
/// [`SqliteStorage`] for persistence.
///
/// `Clone` is cheap (storage is behind `Arc`), which allows passing the host
/// by value to [`SpilmanBridge::new`] while sharing state with route handlers.
///
/// Construct via [`ConfigurableHost::new`] or [`ConfigurableHost::from_yaml`].
#[derive(Clone)]
pub struct ConfigurableHost {
    config: ConfigurableHostConfig,
    server_pubkey: PublicKey,
    server_secret_hex: String,
    storage: Arc<dyn SpilmanStorage>,
}

impl std::fmt::Debug for ConfigurableHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigurableHost")
            .field("config", &self.config)
            .field("server_pubkey", &self.server_pubkey)
            .finish_non_exhaustive()
    }
}

impl ConfigurableHost {
    /// Create a new host from an already-parsed config and a hex-encoded
    /// secret key.  The storage backend is determined by `config.storage`:
    /// - `StorageConfig::Memory` (default) — in-memory, lost on restart
    /// - `StorageConfig::Sqlite { path }` — SQLite file, persistent
    pub fn new(config: ConfigurableHostConfig, secret_key_hex: &str) -> Result<Self, String> {
        let storage: Arc<dyn SpilmanStorage> = match &config.storage {
            StorageConfig::Memory => Arc::new(MemoryStorage::new()),
            StorageConfig::Sqlite { path } => Arc::new(SqliteStorage::open(path)?),
        };
        Self::with_storage(config, secret_key_hex, storage)
    }

    /// Create a new host with an explicit storage backend, ignoring
    /// `config.storage`.  Useful for testing or custom backends.
    pub fn with_storage(
        config: ConfigurableHostConfig,
        secret_key_hex: &str,
        storage: Arc<dyn SpilmanStorage>,
    ) -> Result<Self, String> {
        let secret_key =
            SecretKey::from_hex(secret_key_hex).map_err(|e| format!("invalid secret key: {e}"))?;
        let server_pubkey = secret_key.public_key();

        // Validate: every unit trusted by at least one mint must have pricing.
        let trusted_units: std::collections::HashSet<&str> = config
            .mints
            .values()
            .flat_map(|units| units.iter().map(String::as_str))
            .collect();
        let priced_units: std::collections::HashSet<&str> =
            config.pricing.keys().map(String::as_str).collect();

        let mut missing: Vec<&str> = trusted_units.difference(&priced_units).copied().collect();
        if !missing.is_empty() {
            missing.sort();
            return Err(format!(
                "units trusted by at least one mint but missing from pricing: {missing:?}"
            ));
        }

        // Warn: pricing entries that no mint trusts are dead config.
        let mut unused: Vec<&str> = priced_units.difference(&trusted_units).copied().collect();
        if !unused.is_empty() {
            unused.sort();
            tracing::warn!("pricing defined for units not trusted by any mint: {unused:?}");
        }

        Ok(Self {
            config,
            server_pubkey,
            server_secret_hex: secret_key_hex.to_string(),
            storage,
        })
    }

    /// Parse YAML and construct the host.
    pub fn from_yaml(yaml: &str, secret_key_hex: &str) -> Result<Self, String> {
        let config = ConfigurableHostConfig::from_yaml(yaml)?;
        Self::new(config, secret_key_hex)
    }

    // -- public accessors -----------------------------------------------------

    /// The server's public key.
    pub fn server_pubkey(&self) -> &PublicKey {
        &self.server_pubkey
    }

    /// The parsed configuration.
    pub fn config(&self) -> &ConfigurableHostConfig {
        &self.config
    }

    /// The pricing scale divisor (always >= 1).
    pub fn pricing_scale(&self) -> u64 {
        self.config.pricing_scale.max(1)
    }

    /// The trusted mints and their accepted units.
    pub fn mints(&self) -> &HashMap<String, Vec<String>> {
        &self.config.mints
    }

    /// Access the underlying storage backend.
    pub fn storage(&self) -> &dyn SpilmanStorage {
        &*self.storage
    }

    // -- keyset management (called by the server at startup / on refresh) -----

    /// Insert or update a keyset in the cache.
    pub fn set_keyset(
        &self,
        mint: &str,
        keyset_id: Id,
        entry: KeysetCacheEntry,
    ) -> Result<(), String> {
        self.storage.set_keyset(mint, keyset_id, entry)
    }

    /// Returns `{ mint: { unit: [keyset_id, …] } }` for active keysets.
    pub fn get_mints_units_keysets(&self) -> HashMap<String, HashMap<String, Vec<String>>> {
        self.storage.get_mints_units_keysets()
    }

    /// Returns the set of units that have at least one active keyset.
    pub fn get_active_units(&self) -> std::collections::HashSet<String> {
        self.storage.get_active_units()
    }

    // -- channel data accessors (for route handlers) --------------------------

    /// Get the stored funding data for a channel (for status endpoints, etc.).
    pub fn get_funding_data(&self, channel_id: &str) -> Option<ChannelFunding> {
        self.storage.get_funding(channel_id)
    }

    /// Get the current balance for a channel.
    pub fn get_balance(&self, channel_id: &str) -> Option<PaymentProof> {
        self.storage.get_balance(channel_id)
    }

    /// Get the accumulated usage for a channel.
    pub fn get_usage(&self, channel_id: &str) -> Option<UsageMap> {
        self.storage.get_usage(channel_id)
    }

    /// Check whether a channel is closed.
    pub fn is_closed(&self, channel_id: &str) -> bool {
        self.storage.get_closed_data(channel_id).is_some()
    }

    /// Get the closed channel data (for idempotent close responses).
    pub fn get_closed_data(&self, channel_id: &str) -> Option<ClosedDataView> {
        self.storage.get_closed_data(channel_id)
    }

    // -- pricing helpers ------------------------------------------------------

    /// Get the unit for a channel from its stored params.
    fn channel_unit(&self, channel_id: &str) -> Option<String> {
        let funding = self.storage.get_funding(channel_id)?;
        let params: serde_json::Value = serde_json::from_str(&funding.params_json).ok()?;
        params.get("unit")?.as_str().map(String::from)
    }

    /// Compute the amount due for a channel given accumulated usage + pending
    /// increments from context.
    fn compute_amount_due(&self, channel_id: &str, context_json: Option<&String>) -> u64 {
        let unit = self.channel_unit(channel_id).unwrap_or_default();
        let unit_pricing = match self.config.pricing.get(&unit) {
            Some(p) => p,
            None => return 0,
        };

        // Get accumulated usage.
        let accumulated = self.storage.get_usage(channel_id).unwrap_or_default();

        // Parse pending increments from context.
        let pending: HashMap<String, u64> = context_json
            .and_then(|c| serde_json::from_str(c).ok())
            .unwrap_or_default();

        // Linear combination over all priced variables.
        let mut total: u64 = 0;
        for (var_name, &price) in &unit_pricing.variables {
            let acc = accumulated.get(var_name).copied().unwrap_or(0);
            let pend = pending.get(var_name).copied().unwrap_or(0);
            total = total.saturating_add((acc + pend).saturating_mul(price));
        }

        // Apply pricing scale: ceil(total / scale).
        let scale = self.pricing_scale();
        total.div_ceil(scale)
    }

    /// Apply usage increments from context to the accumulated store.
    fn apply_usage_increments(&self, channel_id: &str, context_json: &str) {
        let increments: HashMap<String, u64> = match serde_json::from_str(context_json) {
            Ok(m) => m,
            Err(_) => return,
        };
        if let Err(e) = self.storage.increment_usage(channel_id, &increments) {
            tracing::error!("increment_usage failed for {channel_id}: {e}");
        }
    }

    /// Returns pricing filtered to only units with active keysets.
    pub fn get_active_pricing(&self) -> HashMap<String, &UnitPricingConfig> {
        let active_units = self.storage.get_active_units();
        self.config
            .pricing
            .iter()
            .filter(|(unit, _)| active_units.contains(*unit))
            .map(|(unit, cfg)| (unit.clone(), cfg))
            .collect()
    }
}

#[cfg(feature = "configurable-host-reqwest")]
impl ConfigurableHost {
    /// Fetch and cache keysets from every configured mint.
    ///
    /// Iterates over [`mints()`](Self::mints) and calls
    /// [`fetch_and_cache_keysets`](super::configurable_networking::fetch_and_cache_keysets)
    /// for each one.  Errors from individual mints are logged and collected;
    /// the method returns `Ok(())` if at least one mint succeeded, or `Err`
    /// with all failures if every mint failed.
    pub async fn initialize_keysets(&self) -> Result<(), String> {
        use super::configurable_networking::fetch_and_cache_keysets;

        let mint_urls: Vec<String> = self.mints().keys().cloned().collect();
        let mut errors = Vec::new();

        for mint_url in &mint_urls {
            match fetch_and_cache_keysets(self, mint_url).await {
                Ok(()) => {
                    tracing::info!("Cached keysets from {mint_url}");
                }
                Err(e) => {
                    tracing::error!("Failed to fetch keysets from {mint_url}: {e}");
                    errors.push(format!("{mint_url}: {e}"));
                }
            }
        }

        if errors.len() == mint_urls.len() && !mint_urls.is_empty() {
            Err(format!(
                "Failed to fetch keysets from all mints: {}",
                errors.join("; ")
            ))
        } else {
            Ok(())
        }
    }
}

/// Public view of closed channel data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosedDataView {
    /// Expiry timestamp for the channel commitment.
    pub expiry_timestamp: u64,
    /// Final balance that was closed out of the channel.
    pub closed_amount: u64,
    /// Total value remaining after stage 1 fee handling.
    pub value_after_stage1: u64,
    /// Sum of proofs paid to the receiver.
    pub receiver_sum: u64,
    /// Sum of proofs returned to the sender.
    pub sender_sum: u64,
    /// Serialized receiver proofs JSON from the completed close.
    pub receiver_proofs_json: String,
    /// Serialized sender proofs JSON from the completed close.
    pub sender_proofs_json: String,
}

// ============================================================================
// SpilmanHost implementation
// ============================================================================

impl SpilmanHost for ConfigurableHost {
    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool {
        receiver_pubkey == &self.server_pubkey
    }

    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &Id) -> bool {
        let trusted_units = match self.config.mints.get(mint) {
            Some(units) => units,
            None => return false,
        };
        match self.storage.get_keyset(mint, keyset_id) {
            Some(entry) => {
                entry.active && trusted_units.iter().any(|u| u == &entry.unit.to_string())
            }
            None => false,
        }
    }

    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
        self.storage.get_funding(channel_id)
    }

    /// `save_funding` is called once per channel, when it first receives the
    /// funding token from the client.  The guards inside are defensive against
    /// concurrent first-payment races for the same channel.
    fn save_funding(
        &self,
        channel_id: &str,
        funding: ChannelFunding,
        initial_payment: PaymentProof,
    ) {
        if let Err(e) = self.storage.save_funding(channel_id, funding) {
            tracing::error!("save_funding failed for {channel_id}: {e}");
            return;
        }
        if let Err(e) = self.storage.update_balance(channel_id, initial_payment) {
            tracing::error!("update_balance (initial) failed for {channel_id}: {e}");
        }
    }

    fn get_amount_due(&self, channel_id: &str, context: Option<&String>) -> u64 {
        self.compute_amount_due(channel_id, context)
    }

    /// This is called where the server has decided to accept the payment, i.e.
    /// the balance is sufficient to cover the usage. This both keeps a copy
    /// of the payment, and it also updates the usage records for this channel
    /// so that the server keeps track of how much service has been provided on
    /// this channel.
    fn record_payment(&self, channel_id: &str, payment: PaymentProof, context: &String) {
        if let Err(e) = self.storage.update_balance(channel_id, payment) {
            tracing::error!("update_balance failed for {channel_id}: {e}");
            return;
        }
        self.apply_usage_increments(channel_id, context);
    }

    fn get_channel_state(&self, channel_id: &str) -> ChannelState {
        self.storage.get_state(channel_id)
    }

    fn mark_channel_closing(
        &self,
        channel_id: &str,
        expiry_timestamp: u64,
        payment: PaymentProof,
    ) -> Result<(), String> {
        self.storage.mark_closing(
            channel_id,
            ClosingData {
                expiry_timestamp,
                balance: payment.balance,
                signature: payment.signature,
            },
        )
    }

    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData> {
        self.storage.get_closing_data(channel_id)
    }

    fn get_channel_policy(&self, unit: &str) -> Option<ChannelPolicy> {
        let cfg = self.config.pricing.get(unit)?;
        Some(ChannelPolicy {
            min_expiry_in_seconds: self.config.min_expiry_seconds,
            min_capacity: cfg.min_capacity,
            max_amount_per_output: cfg.max_amount_per_output,
        })
    }

    fn now_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs()
    }

    fn get_balance_and_signature_for_unilateral_exit(
        &self,
        channel_id: &str,
    ) -> Option<PaymentProof> {
        self.storage.get_balance(channel_id)
    }

    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id> {
        self.storage.get_active_keyset_ids(mint, unit)
    }

    fn get_keyset_info(&self, mint: &str, keyset_id: &Id) -> Option<String> {
        self.storage
            .get_keyset(mint, keyset_id)
            .map(|e| e.info_json)
    }

    fn compute_channel_secret(
        &self,
        _receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
    ) -> Result<String, String> {
        super::compute_channel_secret_from_hex(&self.server_secret_hex, sender_pubkey_hex)
    }

    fn sign_with_tweaked_key(
        &self,
        _signer_pubkey_hex: &str,
        message_hex: &str,
        tweak_scalar_hex: &str,
    ) -> Result<String, String> {
        super::sign_with_tweaked_key_util(&self.server_secret_hex, message_hex, tweak_scalar_hex)
    }

    fn mark_channel_closed(
        &self,
        channel_id: &str,
        expiry_timestamp: u64,
        balance: u64,
        receiver_proofs_json: &str,
        sender_proofs_json: &str,
        receiver_sum: u64,
        sender_sum: u64,
    ) -> Result<(), String> {
        self.storage.mark_closed(
            channel_id,
            ClosedDataView {
                expiry_timestamp,
                closed_amount: balance,
                value_after_stage1: receiver_sum + sender_sum,
                receiver_sum,
                sender_sum,
                receiver_proofs_json: receiver_proofs_json.to_string(),
                sender_proofs_json: sender_proofs_json.to_string(),
            },
        )
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic secret key for tests (same as dev servers).
    const TEST_SECRET_KEY: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    const TEST_YAML: &str = r#"
mints:
  "http://localhost:3338": [sat, msat, usd]
min_expiry_seconds: 3600

pricing:
  sat:
    min_capacity: 10
    variables:
      chars: 1
      requests: 5
  msat:
    min_capacity: 10000
    variables:
      chars: 1000
      requests: 5000
  usd:
    min_capacity: 10
    max_amount_per_output: 64
    variables:
      chars: 1
      requests: 5
"#;

    fn make_host() -> ConfigurableHost {
        ConfigurableHost::from_yaml(TEST_YAML, TEST_SECRET_KEY).unwrap()
    }

    /// Seed a channel with funding only (no balance, no usage).
    fn seed_channel(host: &ConfigurableHost, channel_id: &str, unit: &str) {
        let params_json = serde_json::json!({
            "unit": unit,
            "capacity": 1000,
        })
        .to_string();
        host.storage()
            .save_funding(
                channel_id,
                ChannelFunding {
                    params_json,
                    funding_proofs_json: "[]".to_string(),
                    channel_secret_hex: "deadbeef".to_string(),
                    keyset_info_json: "{}".to_string(),
                },
            )
            .unwrap();
    }

    // -- config parsing -------------------------------------------------------

    #[test]
    fn test_yaml_parsing() {
        let config = ConfigurableHostConfig::from_yaml(TEST_YAML).unwrap();
        let trusted = &config.mints["http://localhost:3338"];
        assert_eq!(trusted, &vec!["sat", "msat", "usd"]);
        assert_eq!(config.min_expiry_seconds, 3600);
        assert_eq!(config.pricing.len(), 3);

        let sat = &config.pricing["sat"];
        assert_eq!(sat.min_capacity, 10);
        assert_eq!(sat.max_amount_per_output, None);
        assert_eq!(sat.variables["chars"], 1);
        assert_eq!(sat.variables["requests"], 5);

        let usd = &config.pricing["usd"];
        assert_eq!(usd.max_amount_per_output, Some(64));
    }

    #[test]
    fn test_yaml_default_expiry() {
        let yaml = r#"
mints:
  "http://example.com": [sat]
pricing:
  sat:
    min_capacity: 10
    variables:
      requests: 1
"#;
        let config = ConfigurableHostConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.min_expiry_seconds, 3600);
    }

    #[test]
    fn test_yaml_invalid() {
        let result = ConfigurableHostConfig::from_yaml("not: valid: yaml: [");
        assert!(result.is_err());
    }

    #[test]
    fn test_yaml_missing_required_fields() {
        let yaml = r#"
min_expiry_seconds: 3600
"#;
        let result = ConfigurableHostConfig::from_yaml(yaml);
        assert!(result.is_err());
    }

    // -- host construction ----------------------------------------------------

    #[test]
    fn test_host_construction() {
        let host = make_host();
        assert!(host.mints().contains_key("http://localhost:3338"));
        assert_eq!(host.config().min_expiry_seconds, 3600);
    }

    #[test]
    fn test_host_invalid_secret_key() {
        let result = ConfigurableHost::from_yaml(TEST_YAML, "not-hex");
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_pricing_for_trusted_unit() {
        // Mint trusts "sat" and "foo", but pricing only covers "sat".
        let yaml = r#"
mints:
  "http://localhost:3338": [sat, foo]
pricing:
  sat:
    min_capacity: 10
    variables:
      chars: 1
"#;
        let msg = ConfigurableHost::from_yaml(yaml, TEST_SECRET_KEY)
            .err()
            .expect("should fail for missing pricing");
        assert!(
            msg.contains("foo"),
            "error should mention the missing unit: {msg}"
        );
    }

    #[test]
    fn test_unused_pricing_accepted() {
        // Pricing defines "sat" and "usd", but the only mint trusts just "sat".
        // This should succeed (unused pricing is a warning, not an error).
        let yaml = r#"
mints:
  "http://localhost:3338": [sat]
pricing:
  sat:
    min_capacity: 10
    variables:
      chars: 1
  usd:
    min_capacity: 10
    variables:
      chars: 1
"#;
        let host = ConfigurableHost::from_yaml(yaml, TEST_SECRET_KEY);
        assert!(host.is_ok());
    }

    #[test]
    fn test_server_pubkey_derived() {
        let host = make_host();
        let pubkey_hex = host.server_pubkey().to_hex();
        let sk = SecretKey::from_hex(TEST_SECRET_KEY).unwrap();
        assert_eq!(pubkey_hex, sk.public_key().to_hex());
    }

    // -- receiver key ---------------------------------------------------------

    #[test]
    fn test_receiver_key_acceptable() {
        let host = make_host();
        assert!(host.receiver_key_is_acceptable(host.server_pubkey()));
    }

    #[test]
    fn test_receiver_key_wrong() {
        let host = make_host();
        let other_sk =
            SecretKey::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();
        assert!(!host.receiver_key_is_acceptable(&other_sk.public_key()));
    }

    // -- mint & keyset --------------------------------------------------------

    #[test]
    fn test_mint_keyset_acceptable() {
        let host = make_host();
        let fake_id: Id = "001b6c716bf42c7e".parse().unwrap();
        assert!(!host.mint_and_keyset_is_acceptable("http://localhost:3338", &fake_id));

        host.set_keyset(
            "http://localhost:3338",
            fake_id,
            KeysetCacheEntry {
                info_json: "{}".to_string(),
                active: true,
                unit: CurrencyUnit::Sat,
            },
        )
        .unwrap();
        assert!(host.mint_and_keyset_is_acceptable("http://localhost:3338", &fake_id));
    }

    #[test]
    fn test_wrong_mint_rejected() {
        let host = make_host();
        let fake_id: Id = "001b6c716bf42c7e".parse().unwrap();
        host.set_keyset(
            "http://localhost:3338",
            fake_id,
            KeysetCacheEntry {
                info_json: "{}".to_string(),
                active: true,
                unit: CurrencyUnit::Sat,
            },
        )
        .unwrap();
        assert!(host.mint_and_keyset_is_acceptable("http://localhost:3338", &fake_id));
    }

    #[test]
    fn test_untrusted_unit_rejected() {
        // Config only trusts [sat] at this mint — a cached "usd" keyset must
        // be rejected even though the mint itself is trusted.
        let yaml = r#"
mints:
  "http://localhost:3338": [sat]
pricing:
  sat:
    min_capacity: 10
    variables:
      chars: 1
"#;
        let host = ConfigurableHost::from_yaml(yaml, TEST_SECRET_KEY).unwrap();
        let fake_id: Id = "001b6c716bf42c7e".parse().unwrap();
        host.set_keyset(
            "http://localhost:3338",
            fake_id,
            KeysetCacheEntry {
                info_json: "{}".to_string(),
                active: true,
                unit: CurrencyUnit::Usd,
            },
        )
        .unwrap();
        assert!(!host.mint_and_keyset_is_acceptable("http://localhost:3338", &fake_id));

        // But a "sat" keyset at the same mint should be accepted.
        host.set_keyset(
            "http://localhost:3338",
            fake_id,
            KeysetCacheEntry {
                info_json: "{}".to_string(),
                active: true,
                unit: CurrencyUnit::Sat,
            },
        )
        .unwrap();
        assert!(host.mint_and_keyset_is_acceptable("http://localhost:3338", &fake_id));
    }

    // -- amount due (linear combination) --------------------------------------

    #[test]
    fn test_amount_due_no_usage_no_context() {
        let host = make_host();
        seed_channel(&host, "ch1", "sat");
        assert_eq!(host.get_amount_due("ch1", None), 0);
    }

    #[test]
    fn test_amount_due_with_context_only() {
        let host = make_host();
        seed_channel(&host, "ch1", "sat");

        // Context: 10 chars, 1 request -> 10*1 + 1*5 = 15 sat
        let ctx = serde_json::json!({"chars": 10, "requests": 1}).to_string();
        assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 15);
    }

    #[test]
    fn test_amount_due_accumulated_plus_context() {
        let host = make_host();
        seed_channel(&host, "ch1", "sat");

        // Seed accumulated usage: 20 chars, 2 requests.
        let usage: UsageMap = [("chars".to_string(), 20), ("requests".to_string(), 2)].into();
        host.storage().increment_usage("ch1", &usage).unwrap();

        // Context adds 5 chars, 1 request.
        // Total: (20+5)*1 + (2+1)*5 = 25 + 15 = 40 sat
        let ctx = serde_json::json!({"chars": 5, "requests": 1}).to_string();
        assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 40);
    }

    #[test]
    fn test_amount_due_msat_unit() {
        let host = make_host();
        seed_channel(&host, "ch1", "msat");

        let ctx = serde_json::json!({"chars": 10, "requests": 1}).to_string();
        // 10*1000 + 1*5000 = 15000 msat
        assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 15_000);
    }

    #[test]
    fn test_pricing_scale_divides_amount_due() {
        let yaml = r#"
mints:
  "http://localhost:3338": [sat]
pricing_scale: 1000
pricing:
  sat:
    min_capacity: 1
    variables:
      bytes: 1
"#;
        let host = ConfigurableHost::from_yaml(yaml, TEST_SECRET_KEY).unwrap();
        assert_eq!(host.pricing_scale(), 1000);

        seed_channel(&host, "ch1", "sat");

        // 500 bytes * 1 = 500; ceil(500 / 1000) = 1
        let ctx = serde_json::json!({"bytes": 500}).to_string();
        assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 1);

        // 1000 bytes * 1 = 1000; ceil(1000 / 1000) = 1
        let ctx = serde_json::json!({"bytes": 1000}).to_string();
        assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 1);

        // 1001 bytes * 1 = 1001; ceil(1001 / 1000) = 2
        let ctx = serde_json::json!({"bytes": 1001}).to_string();
        assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 2);

        // 0 bytes -> 0
        let ctx = serde_json::json!({"bytes": 0}).to_string();
        assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 0);
    }

    #[test]
    fn test_pricing_scale_defaults_to_one() {
        let host = make_host();
        assert_eq!(host.pricing_scale(), 1);
    }

    #[test]
    fn test_pricing_scale_zero_treated_as_one() {
        let yaml = r#"
mints:
  "http://localhost:3338": [sat]
pricing_scale: 0
pricing:
  sat:
    min_capacity: 1
    variables:
      chars: 1
"#;
        let host = ConfigurableHost::from_yaml(yaml, TEST_SECRET_KEY).unwrap();
        // pricing_scale=0 is clamped to 1
        assert_eq!(host.pricing_scale(), 1);

        seed_channel(&host, "ch1", "sat");
        let ctx = serde_json::json!({"chars": 10}).to_string();
        assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 10);
    }

    #[test]
    fn test_amount_due_unknown_variable_in_context() {
        let host = make_host();
        seed_channel(&host, "ch1", "sat");

        // "bytes" is not in the sat pricing -- should be ignored.
        let ctx = serde_json::json!({"chars": 10, "bytes": 9999}).to_string();
        assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 10);
    }

    #[test]
    fn test_amount_due_unknown_unit() {
        let host = make_host();
        seed_channel(&host, "ch1", "btc"); // not in pricing

        let ctx = serde_json::json!({"chars": 10}).to_string();
        assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 0);
    }

    #[test]
    fn test_amount_due_empty_context() {
        let host = make_host();
        seed_channel(&host, "ch1", "sat");

        let ctx = "{}".to_string();
        assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 0);
    }

    // -- record_payment -------------------------------------------------------

    #[test]
    fn test_record_payment_updates_usage() {
        let host = make_host();
        seed_channel(&host, "ch1", "sat");

        let ctx1 = serde_json::json!({"chars": 10, "requests": 1}).to_string();
        host.record_payment(
            "ch1",
            PaymentProof {
                balance: 15,
                signature: "sig1".to_string(),
            },
            &ctx1,
        );

        let usage = host.get_usage("ch1").unwrap();
        assert_eq!(usage["chars"], 10);
        assert_eq!(usage["requests"], 1);

        let ctx2 = serde_json::json!({"chars": 5, "requests": 1}).to_string();
        host.record_payment(
            "ch1",
            PaymentProof {
                balance: 30,
                signature: "sig2".to_string(),
            },
            &ctx2,
        );

        let usage = host.get_usage("ch1").unwrap();
        assert_eq!(usage["chars"], 15);
        assert_eq!(usage["requests"], 2);
    }

    #[test]
    fn test_record_payment_updates_balance_monotonically() {
        let host = make_host();
        seed_channel(&host, "ch1", "sat");

        let ctx = serde_json::json!({"chars": 5}).to_string();
        host.record_payment(
            "ch1",
            PaymentProof {
                balance: 20,
                signature: "sig20".to_string(),
            },
            &ctx,
        );
        assert_eq!(host.get_balance("ch1").unwrap().balance, 20);

        // Lower balance should NOT overwrite.
        host.record_payment(
            "ch1",
            PaymentProof {
                balance: 10,
                signature: "sig10".to_string(),
            },
            &ctx,
        );
        assert_eq!(host.get_balance("ch1").unwrap().balance, 20);
        assert_eq!(host.get_balance("ch1").unwrap().signature, "sig20");
    }

    // -- channel lifecycle ----------------------------------------------------

    #[test]
    fn test_channel_lifecycle() {
        let host = make_host();
        seed_channel(&host, "ch1", "sat");

        assert_eq!(host.get_channel_state("ch1"), ChannelState::Open);

        host.mark_channel_closing(
            "ch1",
            1000,
            PaymentProof {
                balance: 50,
                signature: "sig".to_string(),
            },
        )
        .unwrap();
        assert_eq!(host.get_channel_state("ch1"), ChannelState::Closing);

        let closing = host.get_closing_data("ch1").unwrap();
        assert_eq!(closing.expiry_timestamp, 1000);
        assert_eq!(closing.balance, 50);

        host.mark_channel_closed("ch1", 1000, 50, "[]", "[]", 40, 10)
            .unwrap();
        assert_eq!(host.get_channel_state("ch1"), ChannelState::Closed);

        assert!(host.get_closing_data("ch1").is_none());

        let closed = host.get_closed_data("ch1").unwrap();
        assert_eq!(closed.closed_amount, 50);
        assert_eq!(closed.receiver_sum, 40);
        assert_eq!(closed.sender_sum, 10);
    }

    #[test]
    fn test_closing_already_closed_channel() {
        let host = make_host();
        seed_channel(&host, "ch1", "sat");

        host.mark_channel_closed("ch1", 1000, 50, "[]", "[]", 40, 10)
            .unwrap();

        let result = host.mark_channel_closing(
            "ch1",
            2000,
            PaymentProof {
                balance: 60,
                signature: "sig".to_string(),
            },
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already closed"));
    }

    #[test]
    fn test_double_close_rejected() {
        let host = make_host();
        seed_channel(&host, "ch1", "sat");

        host.mark_channel_closed("ch1", 1000, 50, "[]", "[]", 40, 10)
            .unwrap();
        let result = host.mark_channel_closed("ch1", 1000, 50, "[]", "[]", 40, 10);
        assert!(result.is_err());
    }

    // -- unilateral exit ------------------------------------------------------

    #[test]
    fn test_unilateral_exit_data() {
        let host = make_host();
        seed_channel(&host, "ch1", "sat");

        assert!(host
            .get_balance_and_signature_for_unilateral_exit("ch1")
            .is_none());

        let ctx = serde_json::json!({"chars": 5}).to_string();
        host.record_payment(
            "ch1",
            PaymentProof {
                balance: 25,
                signature: "sig25".to_string(),
            },
            &ctx,
        );

        let proof = host
            .get_balance_and_signature_for_unilateral_exit("ch1")
            .unwrap();
        assert_eq!(proof.balance, 25);
        assert_eq!(proof.signature, "sig25");
    }

    // -- save_funding ---------------------------------------------------------

    #[test]
    fn test_save_funding() {
        let host = make_host();

        let funding = ChannelFunding {
            params_json: r#"{"unit":"sat","capacity":100}"#.to_string(),
            funding_proofs_json: "[]".to_string(),
            channel_secret_hex: "abcd".to_string(),
            keyset_info_json: "{}".to_string(),
        };
        host.save_funding(
            "ch1",
            funding.clone(),
            PaymentProof {
                balance: 0,
                signature: "sig0".to_string(),
            },
        );

        let f = host.get_funding("ch1").unwrap();
        assert_eq!(f.params_json, r#"{"unit":"sat","capacity":100}"#);
        assert_eq!(host.get_balance("ch1").unwrap().balance, 0);

        // Second save with same channel_id should NOT overwrite.
        let funding2 = ChannelFunding {
            params_json: r#"{"unit":"msat","capacity":999}"#.to_string(),
            funding_proofs_json: "[1]".to_string(),
            channel_secret_hex: "ffff".to_string(),
            keyset_info_json: "{}".to_string(),
        };
        host.save_funding(
            "ch1",
            funding2,
            PaymentProof {
                balance: 0,
                signature: "sig0b".to_string(),
            },
        );
        let f2 = host.get_funding("ch1").unwrap();
        assert_eq!(f2.params_json, r#"{"unit":"sat","capacity":100}"#); // unchanged
    }

    // -- keyset cache ---------------------------------------------------------

    #[test]
    fn test_keyset_cache() {
        let host = make_host();
        let ks1: Id = "001b6c716bf42c7e".parse().unwrap();
        let ks2: Id = "00ffedc2dbb87212".parse().unwrap();
        let ks3: Id = "00818d176a78e7f0".parse().unwrap();

        host.set_keyset(
            "http://localhost:3338",
            ks1,
            KeysetCacheEntry {
                info_json: r#"{"keysetId":"001b6c716bf42c7e"}"#.to_string(),
                active: true,
                unit: CurrencyUnit::Sat,
            },
        )
        .unwrap();
        host.set_keyset(
            "http://localhost:3338",
            ks2,
            KeysetCacheEntry {
                info_json: r#"{"keysetId":"00ffedc2dbb87212"}"#.to_string(),
                active: false,
                unit: CurrencyUnit::Sat,
            },
        )
        .unwrap();
        host.set_keyset(
            "http://localhost:3338",
            ks3,
            KeysetCacheEntry {
                info_json: r#"{"keysetId":"00818d176a78e7f0"}"#.to_string(),
                active: true,
                unit: CurrencyUnit::Msat,
            },
        )
        .unwrap();

        let active_sat = host
            .storage()
            .get_active_keyset_ids("http://localhost:3338", &CurrencyUnit::Sat);
        assert_eq!(active_sat, vec![ks1]);

        let mints = host.get_mints_units_keysets();
        assert!(mints["http://localhost:3338"]["sat"].contains(&ks1.to_string()));
        assert!(mints["http://localhost:3338"]["msat"].contains(&ks3.to_string()));
        assert!(!mints["http://localhost:3338"]
            .get("sat")
            .unwrap()
            .contains(&ks2.to_string()));
    }

    // -- channel policy -------------------------------------------------------

    #[test]
    fn test_channel_policy_returns_per_unit() {
        let host = make_host();

        let sat_policy = host.get_channel_policy("sat").unwrap();
        assert_eq!(sat_policy.min_expiry_in_seconds, 3600);
        assert_eq!(sat_policy.min_capacity, 10);
        assert!(sat_policy.max_amount_per_output.is_none());

        // Unknown unit returns None.
        assert!(host.get_channel_policy("unknown").is_none());
    }

    // -- crypto ---------------------------------------------------------------

    #[test]
    fn test_compute_channel_secret() {
        let host = make_host();
        let alice_sk =
            SecretKey::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();
        let alice_pub = alice_sk.public_key().to_hex();
        let charlie_pub = host.server_pubkey().to_hex();

        let secret = host
            .compute_channel_secret(&charlie_pub, &alice_pub)
            .unwrap();
        assert_eq!(secret.len(), 64); // 32 bytes hex
    }

    #[test]
    fn test_get_active_pricing() {
        let host = make_host();

        assert!(host.get_active_pricing().is_empty());

        let ks1: Id = "001b6c716bf42c7e".parse().unwrap();
        host.set_keyset(
            "http://localhost:3338",
            ks1,
            KeysetCacheEntry {
                info_json: "{}".to_string(),
                active: true,
                unit: CurrencyUnit::Sat,
            },
        )
        .unwrap();
        let pricing = host.get_active_pricing();
        assert_eq!(pricing.len(), 1);
        assert!(pricing.contains_key("sat"));
        assert_eq!(pricing["sat"].variables["chars"], 1);
    }

    // -- clone shares state ---------------------------------------------------

    #[test]
    fn test_clone_shares_stores() {
        let host = make_host();
        let host2 = host.clone();

        seed_channel(&host, "ch1", "sat");

        // The clone should see the same data.
        assert!(host2.get_funding("ch1").is_some());
    }

    // -- StorageConfig parsing ------------------------------------------------

    #[test]
    fn test_storage_config_defaults_to_memory() {
        let config = ConfigurableHostConfig::from_yaml(TEST_YAML).unwrap();
        assert!(matches!(config.storage, StorageConfig::Memory));
    }

    #[test]
    fn test_storage_config_sqlite_parsing() {
        let yaml = r#"
mints:
  "http://localhost:3338": [sat]
pricing:
  sat:
    min_capacity: 10
    variables:
      chars: 1
storage:
  type: sqlite
  path: "/tmp/test.db"
"#;
        let config = ConfigurableHostConfig::from_yaml(yaml).unwrap();
        match &config.storage {
            StorageConfig::Sqlite { path } => assert_eq!(path, "/tmp/test.db"),
            other => panic!("expected Sqlite, got {other:?}"),
        }
    }

    #[test]
    fn test_storage_config_memory_explicit() {
        let yaml = r#"
mints:
  "http://localhost:3338": [sat]
pricing:
  sat:
    min_capacity: 10
    variables:
      chars: 1
storage:
  type: memory
"#;
        let config = ConfigurableHostConfig::from_yaml(yaml).unwrap();
        assert!(matches!(config.storage, StorageConfig::Memory));
    }

    // =========================================================================
    // SqliteStorage direct tests
    // =========================================================================

    mod sqlite_tests {
        use super::*;

        fn make_sqlite() -> SqliteStorage {
            SqliteStorage::open_in_memory().unwrap()
        }

        #[test]
        fn test_funding_roundtrip() {
            let s = make_sqlite();
            assert!(s.get_funding("ch1").is_none());

            let funding = ChannelFunding {
                params_json: r#"{"unit":"sat"}"#.to_string(),
                funding_proofs_json: "[]".to_string(),
                channel_secret_hex: "abcd".to_string(),
                keyset_info_json: "{}".to_string(),
            };
            s.save_funding("ch1", funding.clone()).unwrap();

            let f = s.get_funding("ch1").unwrap();
            assert_eq!(f.params_json, r#"{"unit":"sat"}"#);
            assert_eq!(f.channel_secret_hex, "abcd");

            // Idempotent: second save should not overwrite.
            let funding2 = ChannelFunding {
                params_json: r#"{"unit":"msat"}"#.to_string(),
                funding_proofs_json: "[1]".to_string(),
                channel_secret_hex: "ffff".to_string(),
                keyset_info_json: "{}".to_string(),
            };
            s.save_funding("ch1", funding2).unwrap();
            let f2 = s.get_funding("ch1").unwrap();
            assert_eq!(f2.params_json, r#"{"unit":"sat"}"#); // unchanged
        }

        #[test]
        fn test_balance_monotonic() {
            let s = make_sqlite();
            // Need a channel row first.
            s.save_funding(
                "ch1",
                ChannelFunding {
                    params_json: "{}".to_string(),
                    funding_proofs_json: "[]".to_string(),
                    channel_secret_hex: "aa".to_string(),
                    keyset_info_json: "{}".to_string(),
                },
            )
            .unwrap();

            assert!(s.get_balance("ch1").is_none()); // balance is 0, signature is ''

            s.update_balance(
                "ch1",
                PaymentProof {
                    balance: 20,
                    signature: "sig20".to_string(),
                },
            )
            .unwrap();
            assert_eq!(s.get_balance("ch1").unwrap().balance, 20);

            // Lower balance should NOT overwrite.
            s.update_balance(
                "ch1",
                PaymentProof {
                    balance: 10,
                    signature: "sig10".to_string(),
                },
            )
            .unwrap();
            assert_eq!(s.get_balance("ch1").unwrap().balance, 20);
            assert_eq!(s.get_balance("ch1").unwrap().signature, "sig20");

            // Higher balance should overwrite.
            s.update_balance(
                "ch1",
                PaymentProof {
                    balance: 30,
                    signature: "sig30".to_string(),
                },
            )
            .unwrap();
            assert_eq!(s.get_balance("ch1").unwrap().balance, 30);
        }

        #[test]
        fn test_usage_increment() {
            let s = make_sqlite();
            assert!(s.get_usage("ch1").is_none());

            let mut inc1 = UsageMap::new();
            inc1.insert("chars".to_string(), 10);
            inc1.insert("requests".to_string(), 1);
            s.increment_usage("ch1", &inc1).unwrap();

            let u = s.get_usage("ch1").unwrap();
            assert_eq!(u["chars"], 10);
            assert_eq!(u["requests"], 1);

            // Increment again.
            let mut inc2 = UsageMap::new();
            inc2.insert("chars".to_string(), 5);
            inc2.insert("requests".to_string(), 2);
            s.increment_usage("ch1", &inc2).unwrap();

            let u2 = s.get_usage("ch1").unwrap();
            assert_eq!(u2["chars"], 15);
            assert_eq!(u2["requests"], 3);
        }

        #[test]
        fn test_channel_lifecycle() {
            let s = make_sqlite();
            s.save_funding(
                "ch1",
                ChannelFunding {
                    params_json: "{}".to_string(),
                    funding_proofs_json: "[]".to_string(),
                    channel_secret_hex: "aa".to_string(),
                    keyset_info_json: "{}".to_string(),
                },
            )
            .unwrap();

            assert_eq!(s.get_state("ch1"), ChannelState::Open);

            s.mark_closing(
                "ch1",
                ClosingData {
                    expiry_timestamp: 1000,
                    balance: 50,
                    signature: "sig50".to_string(),
                },
            )
            .unwrap();
            assert_eq!(s.get_state("ch1"), ChannelState::Closing);

            let closing = s.get_closing_data("ch1").unwrap();
            assert_eq!(closing.expiry_timestamp, 1000);
            assert_eq!(closing.balance, 50);

            s.mark_closed(
                "ch1",
                ClosedDataView {
                    expiry_timestamp: 1000,
                    closed_amount: 50,
                    value_after_stage1: 50,
                    receiver_sum: 40,
                    sender_sum: 10,
                    receiver_proofs_json: "[]".to_string(),
                    sender_proofs_json: "[]".to_string(),
                },
            )
            .unwrap();
            assert_eq!(s.get_state("ch1"), ChannelState::Closed);

            // closing_json should be cleared
            assert!(s.get_closing_data("ch1").is_none());

            let closed = s.get_closed_data("ch1").unwrap();
            assert_eq!(closed.closed_amount, 50);
            assert_eq!(closed.receiver_sum, 40);
            assert_eq!(closed.sender_sum, 10);
        }

        #[test]
        fn test_double_close_rejected() {
            let s = make_sqlite();
            s.save_funding(
                "ch1",
                ChannelFunding {
                    params_json: "{}".to_string(),
                    funding_proofs_json: "[]".to_string(),
                    channel_secret_hex: "aa".to_string(),
                    keyset_info_json: "{}".to_string(),
                },
            )
            .unwrap();

            let data = ClosedDataView {
                expiry_timestamp: 1000,
                closed_amount: 50,
                value_after_stage1: 50,
                receiver_sum: 40,
                sender_sum: 10,
                receiver_proofs_json: "[]".to_string(),
                sender_proofs_json: "[]".to_string(),
            };
            s.mark_closed("ch1", data.clone()).unwrap();
            let result = s.mark_closed("ch1", data);
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("already closed"));
        }

        #[test]
        fn test_keyset_roundtrip() {
            let s = make_sqlite();
            let kid: Id = "001b6c716bf42c7e".parse().unwrap();

            assert!(s.get_keyset("http://mint", &kid).is_none());

            s.set_keyset(
                "http://mint",
                kid,
                KeysetCacheEntry {
                    info_json: r#"{"id":"001b6c716bf42c7e"}"#.to_string(),
                    active: true,
                    unit: CurrencyUnit::Sat,
                },
            )
            .unwrap();

            let entry = s.get_keyset("http://mint", &kid).unwrap();
            assert_eq!(entry.unit, CurrencyUnit::Sat);
            assert!(entry.active);

            // Update: mark inactive.
            s.set_keyset(
                "http://mint",
                kid,
                KeysetCacheEntry {
                    info_json: r#"{"id":"001b6c716bf42c7e"}"#.to_string(),
                    active: false,
                    unit: CurrencyUnit::Sat,
                },
            )
            .unwrap();
            let entry2 = s.get_keyset("http://mint", &kid).unwrap();
            assert!(!entry2.active);
        }

        #[test]
        fn test_active_keyset_ids() {
            let s = make_sqlite();
            let ks1: Id = "001b6c716bf42c7e".parse().unwrap();
            let ks2: Id = "00ffedc2dbb87212".parse().unwrap();

            s.set_keyset(
                "http://mint",
                ks1,
                KeysetCacheEntry {
                    info_json: "{}".to_string(),
                    active: true,
                    unit: CurrencyUnit::Sat,
                },
            )
            .unwrap();
            s.set_keyset(
                "http://mint",
                ks2,
                KeysetCacheEntry {
                    info_json: "{}".to_string(),
                    active: false,
                    unit: CurrencyUnit::Sat,
                },
            )
            .unwrap();

            let active = s.get_active_keyset_ids("http://mint", &CurrencyUnit::Sat);
            assert_eq!(active, vec![ks1]);
        }

        #[test]
        fn test_mints_units_keysets() {
            let s = make_sqlite();
            let ks1: Id = "001b6c716bf42c7e".parse().unwrap();
            let ks2: Id = "00818d176a78e7f0".parse().unwrap();

            s.set_keyset(
                "http://mint",
                ks1,
                KeysetCacheEntry {
                    info_json: "{}".to_string(),
                    active: true,
                    unit: CurrencyUnit::Sat,
                },
            )
            .unwrap();
            s.set_keyset(
                "http://mint",
                ks2,
                KeysetCacheEntry {
                    info_json: "{}".to_string(),
                    active: true,
                    unit: CurrencyUnit::Msat,
                },
            )
            .unwrap();

            let muk = s.get_mints_units_keysets();
            assert!(muk["http://mint"]["sat"].contains(&ks1.to_string()));
            assert!(muk["http://mint"]["msat"].contains(&ks2.to_string()));
        }

        #[test]
        fn test_active_units() {
            let s = make_sqlite();
            let ks1: Id = "001b6c716bf42c7e".parse().unwrap();

            assert!(s.get_active_units().is_empty());

            s.set_keyset(
                "http://mint",
                ks1,
                KeysetCacheEntry {
                    info_json: "{}".to_string(),
                    active: true,
                    unit: CurrencyUnit::Sat,
                },
            )
            .unwrap();

            let units = s.get_active_units();
            assert!(units.contains("sat"));
            assert_eq!(units.len(), 1);
        }

        #[test]
        fn test_end_to_end_with_configurable_host() {
            // End-to-end: construct a ConfigurableHost with SqliteStorage
            let config = ConfigurableHostConfig::from_yaml(TEST_YAML).unwrap();
            let storage = Arc::new(SqliteStorage::open_in_memory().unwrap());
            let host =
                ConfigurableHost::with_storage(config, TEST_SECRET_KEY, storage.clone()).unwrap();

            seed_channel(&host, "ch1", "sat");
            assert!(host.get_funding("ch1").is_some());

            let ctx = serde_json::json!({"chars": 10, "requests": 1}).to_string();
            host.record_payment(
                "ch1",
                PaymentProof {
                    balance: 15,
                    signature: "sig15".to_string(),
                },
                &ctx,
            );

            assert_eq!(host.get_balance("ch1").unwrap().balance, 15);
            assert_eq!(host.get_usage("ch1").unwrap()["chars"], 10);
        }

        #[test]
        fn test_file_persistence() {
            // Verify data survives across two separate SqliteStorage instances
            // pointing at the same file.
            let dir = std::env::temp_dir().join("spilman_test_persist");
            let _ = std::fs::create_dir_all(&dir);
            let path = dir.join("test.db");
            let path_str = path.to_str().unwrap();

            // Clean up from any previous run.
            let _ = std::fs::remove_file(&path);

            // Session 1: create and populate.
            {
                let s = SqliteStorage::open(path_str).unwrap();
                s.save_funding(
                    "ch1",
                    ChannelFunding {
                        params_json: r#"{"unit":"sat"}"#.to_string(),
                        funding_proofs_json: "[]".to_string(),
                        channel_secret_hex: "abcd".to_string(),
                        keyset_info_json: "{}".to_string(),
                    },
                )
                .unwrap();
                s.update_balance(
                    "ch1",
                    PaymentProof {
                        balance: 42,
                        signature: "sig42".to_string(),
                    },
                )
                .unwrap();
                let mut inc = UsageMap::new();
                inc.insert("chars".to_string(), 100);
                s.increment_usage("ch1", &inc).unwrap();
            }

            // Session 2: reopen and verify.
            {
                let s = SqliteStorage::open(path_str).unwrap();
                let f = s.get_funding("ch1").unwrap();
                assert_eq!(f.channel_secret_hex, "abcd");
                assert_eq!(s.get_balance("ch1").unwrap().balance, 42);
                assert_eq!(s.get_usage("ch1").unwrap()["chars"], 100);
            }

            // Clean up.
            let _ = std::fs::remove_file(&path);
        }
    }
}
