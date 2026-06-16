//! SQLite-backed persistent storage for client-side Spilman channel state.
//!
//! Available when the `client-sqlite` feature is enabled.
//!
//! The schema is intentionally simple: one table with JSON columns for the
//! immutable opening/funding data and the mutable payment state. This mirrors
//! the server-side [`crate::configurable_host::SqliteStorage`] design.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusqlite::{params, OptionalExtension};

use super::client_storage::{
    ClientChannelFunding, ClientChannelOpeningFromSwap, ClientChannelState, ClientPaymentState,
    ClientStorage,
};

/// SQLite-backed implementation of [`ClientStorage`].
///
/// Persists channel opening data, funding data, payment state, and lifecycle
/// state in a SQLite database. The database is created automatically if it
/// does not exist.
///
/// This implementation is `Send + Sync`, can be cloned cheaply, and can be
/// shared across threads.
#[derive(Clone)]
pub struct SqliteClientStorage {
    conn: Arc<Mutex<rusqlite::Connection>>,
    db_path: Option<String>,
}

impl std::fmt::Debug for SqliteClientStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteClientStorage")
            .finish_non_exhaustive()
    }
}

impl SqliteClientStorage {
    /// Open (or create) a SQLite database at the given path.
    ///
    /// # Errors
    /// Returns an error if the database cannot be opened or the schema cannot
    /// be initialized.
    pub fn open(path: &str) -> Result<Self, String> {
        let conn = rusqlite::Connection::open(path)
            .map_err(|e| format!("failed to open SQLite client storage at {path}: {e}"))?;
        Self::configure_connection(&conn, true)?;
        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path: Some(path.to_string()),
        };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Create an in-memory SQLite database (useful for testing).
    ///
    /// # Errors
    /// Returns an error if the in-memory database cannot be created or the
    /// schema cannot be initialized.
    pub fn open_in_memory() -> Result<Self, String> {
        let conn = rusqlite::Connection::open_in_memory()
            .map_err(|e| format!("failed to open in-memory SQLite client storage: {e}"))?;
        Self::configure_connection(&conn, false)?;
        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path: None,
        };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Return the backing database path if this storage was opened from a file.
    pub fn path(&self) -> Option<&str> {
        self.db_path.as_deref()
    }

    fn configure_connection(conn: &rusqlite::Connection, enable_wal: bool) -> Result<(), String> {
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(|e| format!("failed to configure SQLite busy timeout: {e}"))?;
        if enable_wal {
            conn.pragma_update(None, "journal_mode", "WAL")
                .map_err(|e| format!("failed to enable SQLite WAL mode: {e}"))?;
        }
        Ok(())
    }

    fn init_schema(&self) -> Result<(), String> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| format!("sqlite lock poisoned: {e}"))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS spilman_client_channels (
                channel_id   TEXT PRIMARY KEY,
                state        TEXT NOT NULL,
                opening_json TEXT,
                funding_json TEXT,
                payment_json TEXT
            );",
        )
        .map_err(|e| format!("failed to initialize SQLite client storage schema: {e}"))
    }

    fn state_to_string(state: ClientChannelState) -> &'static str {
        match state {
            ClientChannelState::OpeningFromSwap => "OpeningFromSwap",
            ClientChannelState::Open => "Open",
            ClientChannelState::Closing => "Closing",
            ClientChannelState::Closed => "Closed",
        }
    }

    fn state_from_string(s: &str) -> Option<ClientChannelState> {
        match s {
            "OpeningFromSwap" => Some(ClientChannelState::OpeningFromSwap),
            "Open" => Some(ClientChannelState::Open),
            "Closing" => Some(ClientChannelState::Closing),
            "Closed" => Some(ClientChannelState::Closed),
            _ => None,
        }
    }
}

impl ClientStorage for SqliteClientStorage {
    fn save_opening_from_swap(
        &mut self,
        channel_id: &str,
        opening: ClientChannelOpeningFromSwap,
    ) -> Result<(), String> {
        let opening_json =
            serde_json::to_string(&opening).map_err(|e| format!("serialize opening: {e}"))?;
        let conn = self
            .conn
            .lock()
            .map_err(|e| format!("sqlite lock poisoned: {e}"))?;
        conn.execute(
            "INSERT OR REPLACE INTO spilman_client_channels
             (channel_id, state, opening_json, funding_json, payment_json)
             VALUES (?1, ?2, ?3, NULL, NULL)",
            params![
                channel_id,
                Self::state_to_string(ClientChannelState::OpeningFromSwap),
                opening_json
            ],
        )
        .map_err(|e| format!("save_opening_from_swap: {e}"))?;
        Ok(())
    }

    fn set_open(&mut self, channel_id: &str, funding_proofs_json: &str) -> Result<(), String> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| format!("sqlite lock poisoned: {e}"))?;
        let tx = conn
            .transaction()
            .map_err(|e| format!("set_open: begin transaction: {e}"))?;

        let opening_json: Option<String> = tx
            .query_row(
                "SELECT opening_json FROM spilman_client_channels
                 WHERE channel_id = ?1 AND state = ?2",
                params![
                    channel_id,
                    Self::state_to_string(ClientChannelState::OpeningFromSwap)
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("set_open: query opening: {e}"))?;

        let opening_json = opening_json.ok_or_else(|| {
            format!(
                "channel {channel_id} is not in {} state",
                Self::state_to_string(ClientChannelState::OpeningFromSwap)
            )
        })?;

        let opening: ClientChannelOpeningFromSwap = serde_json::from_str(&opening_json)
            .map_err(|e| format!("set_open: deserialize opening: {e}"))?;

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
        let funding_json =
            serde_json::to_string(&funding).map_err(|e| format!("serialize funding: {e}"))?;

        tx.execute(
            "UPDATE spilman_client_channels
             SET state = ?2, opening_json = NULL, funding_json = ?3, payment_json = NULL
             WHERE channel_id = ?1",
            params![
                channel_id,
                Self::state_to_string(ClientChannelState::Open),
                funding_json
            ],
        )
        .map_err(|e| format!("set_open: update funding: {e}"))?;

        tx.commit().map_err(|e| format!("set_open: commit: {e}"))
    }

    fn get_opening_from_swap(&self, channel_id: &str) -> Option<ClientChannelOpeningFromSwap> {
        let conn = self.conn.lock().ok()?;
        let opening_json: Option<String> = conn
            .query_row(
                "SELECT opening_json FROM spilman_client_channels
                 WHERE channel_id = ?1 AND state = ?2",
                params![
                    channel_id,
                    Self::state_to_string(ClientChannelState::OpeningFromSwap)
                ],
                |row| row.get(0),
            )
            .optional()
            .ok()?;
        opening_json.and_then(|json| serde_json::from_str(&json).ok())
    }

    fn get_funding(&self, channel_id: &str) -> Option<ClientChannelFunding> {
        let conn = self.conn.lock().ok()?;
        let funding_json: Option<String> = conn
            .query_row(
                "SELECT funding_json FROM spilman_client_channels
                 WHERE channel_id = ?1
                   AND state IN ('Open', 'Closing', 'Closed')",
                [channel_id],
                |row| row.get(0),
            )
            .optional()
            .ok()?;
        funding_json.and_then(|json| serde_json::from_str(&json).ok())
    }

    fn get_payment_state(&self, channel_id: &str) -> Option<ClientPaymentState> {
        let conn = self.conn.lock().ok()?;
        let payment_json: Option<String> = conn
            .query_row(
                "SELECT payment_json FROM spilman_client_channels
                 WHERE channel_id = ?1 AND payment_json IS NOT NULL",
                [channel_id],
                |row| row.get(0),
            )
            .optional()
            .ok()?;
        payment_json.and_then(|json| serde_json::from_str(&json).ok())
    }

    fn save_payment_state(
        &mut self,
        channel_id: &str,
        state: ClientPaymentState,
    ) -> Result<(), String> {
        let payment_json =
            serde_json::to_string(&state).map_err(|e| format!("serialize payment state: {e}"))?;
        let conn = self
            .conn
            .lock()
            .map_err(|e| format!("sqlite lock poisoned: {e}"))?;
        let rows = conn
            .execute(
                "UPDATE spilman_client_channels
                 SET payment_json = ?2
                 WHERE channel_id = ?1",
                params![channel_id, payment_json],
            )
            .map_err(|e| format!("save_payment_state: {e}"))?;
        if rows == 0 {
            return Err(format!("channel not found: {channel_id}"));
        }
        Ok(())
    }

    fn get_state(&self, channel_id: &str) -> Option<ClientChannelState> {
        let conn = self.conn.lock().ok()?;
        let state: Option<String> = conn
            .query_row(
                "SELECT state FROM spilman_client_channels WHERE channel_id = ?1",
                [channel_id],
                |row| row.get(0),
            )
            .optional()
            .ok()?;
        state.as_deref().and_then(Self::state_from_string)
    }

    fn set_closed(&mut self, channel_id: &str) -> Result<(), String> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| format!("sqlite lock poisoned: {e}"))?;
        let rows = conn
            .execute(
                "UPDATE spilman_client_channels
                 SET state = 'Closed'
                 WHERE channel_id = ?1 AND state != 'Closed'",
                [channel_id],
            )
            .map_err(|e| format!("set_closed: {e}"))?;
        if rows == 0 {
            return Err(format!("channel not found or already closed: {channel_id}"));
        }
        Ok(())
    }

    fn set_closing(&mut self, channel_id: &str) -> Result<(), String> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| format!("sqlite lock poisoned: {e}"))?;
        // Idempotent: if already Closing, treat as success.
        let current: Option<String> = conn
            .query_row(
                "SELECT state FROM spilman_client_channels WHERE channel_id = ?1",
                [channel_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("set_closing: query state: {e}"))?;
        if current.as_deref() == Some("Closing") {
            return Ok(());
        }
        let rows = conn
            .execute(
                "UPDATE spilman_client_channels
                 SET state = 'Closing'
                 WHERE channel_id = ?1 AND state = 'Open'",
                [channel_id],
            )
            .map_err(|e| format!("set_closing: {e}"))?;
        if rows == 0 {
            return Err(format!("channel not found or not open: {channel_id}"));
        }
        Ok(())
    }

    fn list_channel_ids(&self) -> Vec<String> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        let mut stmt = match conn.prepare("SELECT channel_id FROM spilman_client_channels") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map([], |row| row.get(0))
            .ok()
            .map(|rows| rows.filter_map(|r| r.ok()).collect())
            .unwrap_or_default()
    }

    fn delete(&mut self, channel_id: &str) -> Result<(), String> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| format!("sqlite lock poisoned: {e}"))?;
        conn.execute(
            "DELETE FROM spilman_client_channels WHERE channel_id = ?1",
            [channel_id],
        )
        .map_err(|e| format!("delete: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_storage::fixtures::*;

    #[test]
    fn test_sqlite_storage_roundtrip() {
        let mut storage = SqliteClientStorage::open_in_memory().unwrap();
        assert_storage_roundtrip(&mut storage);
    }

    #[test]
    fn test_sqlite_storage_payments_can_be_updated() {
        let mut storage = SqliteClientStorage::open_in_memory().unwrap();
        assert_storage_payments_can_be_updated(&mut storage);
    }

    #[test]
    fn test_sqlite_storage_list() {
        let mut storage = SqliteClientStorage::open_in_memory().unwrap();
        assert_storage_list(&mut storage);
    }

    #[test]
    fn test_sqlite_storage_delete() {
        let mut storage = SqliteClientStorage::open_in_memory().unwrap();
        assert_storage_delete(&mut storage);
    }

    #[test]
    fn test_sqlite_storage_payment_state_requires_channel() {
        let mut storage = SqliteClientStorage::open_in_memory().unwrap();
        let err = storage
            .save_payment_state("missing", make_test_payment_state(100))
            .unwrap_err();
        assert!(err.contains("not found"));
    }

    #[test]
    fn test_sqlite_storage_set_open_missing_channel_errors() {
        let mut storage = SqliteClientStorage::open_in_memory().unwrap();
        let err = storage.set_open("missing", "[]").unwrap_err();
        assert!(err.contains("is not in OpeningFromSwap state"));
    }

    #[test]
    fn test_sqlite_storage_persists_across_reopen() {
        let dir = std::env::temp_dir().join(format!(
            "cdk_spilman_sqlite_client_test_{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("client_storage.db");
        let path_str = path.to_str().unwrap();

        {
            let mut storage = SqliteClientStorage::open(path_str).unwrap();
            seed_open_channel(&mut storage, "ch1", r#"[{"proof": true}]"#);
            storage
                .save_payment_state("ch1", make_test_payment_state(42))
                .unwrap();
            storage.set_closing("ch1").unwrap();
        }

        {
            let storage = SqliteClientStorage::open(path_str).unwrap();
            assert_eq!(storage.get_state("ch1"), Some(ClientChannelState::Closing));
            let funding = storage.get_funding("ch1").unwrap();
            assert_eq!(funding.funding_proofs_json, r#"[{"proof": true}]"#);
            assert_eq!(storage.get_payment_state("ch1").unwrap().balance, 42);
            assert!(storage.get_opening_from_swap("ch1").is_none());
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sqlite_storage_clone_shares_state() {
        let mut storage = SqliteClientStorage::open_in_memory().unwrap();
        let clone = storage.clone();

        seed_open_channel(&mut storage, "ch1", "[]");

        assert!(clone.get_funding("ch1").is_some());
        assert_eq!(clone.get_state("ch1"), Some(ClientChannelState::Open));
    }

    #[test]
    fn test_sqlite_storage_path_reports_file_or_memory() {
        let storage = SqliteClientStorage::open_in_memory().unwrap();
        assert_eq!(storage.path(), None);

        let dir = std::env::temp_dir().join(format!(
            "cdk_spilman_sqlite_client_path_test_{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("client_storage.db");
        let path_str = path.to_str().unwrap();

        let storage = SqliteClientStorage::open(path_str).unwrap();
        assert_eq!(storage.path(), Some(path_str));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sqlite_storage_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SqliteClientStorage>();
    }
}
