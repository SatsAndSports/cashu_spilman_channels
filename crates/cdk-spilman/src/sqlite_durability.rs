//! Durability policy for writable, file-backed wallet connections.
//!
//! EXTRA includes FULL's WAL commit synchronization and also synchronizes the
//! containing directory after deleting a rollback journal. This does not make
//! transactions across separate databases atomic, or compensate for storage
//! hardware/filesystems that do not honor synchronization requests.

use std::path::Path;

/// Open a wallet database and verify its durability policy before any writes.
///
/// Retains the existing journal mode. OFF and MEMORY are not durable and are
/// rejected, including `:memory:` databases; tests can open those explicitly.
/// Read-only inspection must use a read-only connection instead of this helper.
pub fn open_wallet_database(path: impl AsRef<Path>) -> rusqlite::Result<rusqlite::Connection> {
    let conn = rusqlite::Connection::open(path)?;
    configure_wallet_connection(&conn)?;
    Ok(conn)
}

/// Apply and verify the policy on a file-backed connection outside a transaction.
pub fn configure_wallet_connection(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.pragma_update(None, "synchronous", "EXTRA")?;
    let synchronous: i64 = conn.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    let journal: String = conn.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if synchronous != 3 || !matches!(journal.as_str(), "delete" | "truncate" | "persist" | "wal") {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_policy_for_every_supported_journal_mode() {
        // An empty filename creates a private temporary on-disk database.
        let conn = rusqlite::Connection::open("").unwrap();
        for mode in ["DELETE", "TRUNCATE", "PERSIST"] {
            conn.pragma_update(None, "journal_mode", mode).unwrap();
            conn.pragma_update(None, "synchronous", "OFF").unwrap();
            configure_wallet_connection(&conn).unwrap();
            assert_eq!(
                conn.pragma_query_value(None, "synchronous", |r| r.get::<_, i64>(0))
                    .unwrap(),
                3
            );
        }
        for mode in ["OFF", "MEMORY"] {
            conn.pragma_update(None, "journal_mode", mode).unwrap();
            assert!(configure_wallet_connection(&conn).is_err());
        }
        assert!(open_wallet_database(":memory:").is_err());
    }
}
