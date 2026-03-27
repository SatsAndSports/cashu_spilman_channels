//! In-memory networking implementation that calls the mint directly.
//!
//! This avoids HTTP round-trips by calling `mint.process_swap_request()` directly.

use std::sync::Arc;

use cdk::mint::Mint;
use cdk::nuts::SwapRequest;
use cdk_spilman::{SpilmanClientNetworking, SpilmanNetworking};

/// Networking implementation that calls an in-memory mint directly.
///
/// Implements both `SpilmanClientNetworking` (for client) and
/// `SpilmanNetworking` (for server close operations).
///
/// This uses `block_in_place` to safely execute async code from sync trait methods.
pub struct InMemoryMintNetworking {
    mint: Arc<Mint>,
    runtime: tokio::runtime::Handle,
}

impl InMemoryMintNetworking {
    /// Create a new in-memory networking instance.
    ///
    /// Must be called from within a Tokio runtime context.
    pub fn new(mint: Arc<Mint>) -> Self {
        Self {
            mint,
            runtime: tokio::runtime::Handle::current(),
        }
    }

    /// Internal implementation of swap call.
    ///
    /// Uses `block_in_place` to safely call async code from a sync context
    /// within a tokio multi-threaded runtime.
    fn do_swap(&self, swap_request_json: &str) -> Result<String, String> {
        let swap_request: SwapRequest = serde_json::from_str(swap_request_json)
            .map_err(|e| format!("Failed to parse swap request: {}", e))?;

        let mint = Arc::clone(&self.mint);
        let handle = self.runtime.clone();

        // Use block_in_place to allow blocking within the tokio runtime
        // This works with #[tokio::test] which uses a multi-threaded runtime
        let response = tokio::task::block_in_place(|| {
            handle.block_on(async move {
                mint.process_swap_request(swap_request)
                    .await
                    .map_err(|e| format!("Mint swap failed: {}", e))
            })
        })?;

        serde_json::to_string(&response)
            .map_err(|e| format!("Failed to serialize swap response: {}", e))
    }
}

impl SpilmanClientNetworking for InMemoryMintNetworking {
    fn call_mint_swap(&self, _mint_url: &str, swap_request_json: &str) -> Result<String, String> {
        self.do_swap(swap_request_json)
    }
}

impl SpilmanNetworking for InMemoryMintNetworking {
    fn call_mint_swap(&self, _mint_url: &str, swap_request_json: &str) -> Result<String, String> {
        self.do_swap(swap_request_json)
    }

    fn refresh_all_keysets(&self, _mint: &str) -> Result<(), String> {
        // No-op for in-memory mint - keysets are always fresh
        Ok(())
    }
}
