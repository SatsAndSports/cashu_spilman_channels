//! Test context and fixtures for integration tests.
//!
//! Provides a `TestContext` that holds the test environment (mint + server)
//! and provides convenient access to helpers.
//!
//! # Parallel Test Execution
//!
//! Tests run in parallel by default. To ensure only ONE mint and ONE server
//! are spawned (even when 50+ tests start simultaneously), we use `tokio::sync::OnceCell`.
//!
//! The `OnceCell::get_or_try_init()` method guarantees that:
//! - The initialization closure runs exactly once
//! - All concurrent callers wait for initialization to complete
//! - All callers receive a reference to the same `TestEnvironment`
//!
//! This means the first test to call `TestContext::new()` spawns the mint and server,
//! while all other tests wait and then share that same infrastructure.
//!
//! # Process Cleanup
//!
//! The `TestEnvironment` is stored in a static, and Rust does NOT call `Drop` on
//! statics at program exit. To ensure spawned processes are cleaned up, we register
//! an `atexit` handler that takes ownership of the `TestEnvironment` and drops it,
//! which kills all spawned process groups.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use anyhow::Result;
use tokio::sync::OnceCell;

use crate::helpers::{
    mint_funded_channel, Channel, HttpClient, MintFundedChannelOptions, ServerChannelParams,
};
use crate::orchestration::{ServerType, TestEnvironment};

/// Global test environment - shared across ALL tests running in parallel.
///
/// Uses `tokio::sync::OnceCell` to ensure thread-safe lazy initialization:
/// - First caller initializes (spawns mint + server)
/// - All other callers wait and receive the same instance
/// - No duplicate processes, no race conditions
///
/// The `Option` wrapper allows us to take ownership at cleanup time via `take()`.
/// The `Mutex` provides interior mutability for the `Option`.
static TEST_ENV: OnceCell<Mutex<Option<TestEnvironment>>> = OnceCell::const_new();

/// Whether we've registered the atexit handler
static ATEXIT_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Cleanup function called at program exit via `atexit`.
///
/// This is necessary because Rust does NOT call `Drop` on statics at program exit.
/// By registering this with `atexit`, we ensure process groups are killed.
extern "C" fn cleanup_test_environment() {
    if let Some(mutex) = TEST_ENV.get() {
        if let Ok(mut guard) = mutex.lock() {
            if let Some(env) = guard.take() {
                // Dropping the TestEnvironment triggers Drop on MintProcess and ServerProcess,
                // which sends SIGTERM/SIGKILL to their process groups
                drop(env);
            }
        }
    }
}

/// Register the atexit handler (only once)
#[allow(unsafe_code)]
fn register_atexit_handler() {
    // Use compare_exchange to ensure we only register once
    if ATEXIT_REGISTERED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        // SAFETY: cleanup_test_environment is a valid extern "C" function
        // that doesn't panic and handles its own synchronization via Mutex
        unsafe {
            libc::atexit(cleanup_test_environment);
        }
    }
}

/// Test context providing access to server and helpers.
///
/// Each test creates its own `TestContext`, but they all share the same
/// underlying `TestEnvironment` (mint + server processes).
pub struct TestContext {
    pub client: HttpClient,
    pub server_params: ServerChannelParams,
    pub server_type: ServerType,
}

impl TestContext {
    /// Create a new test context, initializing the global environment if needed.
    ///
    /// Safe to call from multiple tests in parallel - only one environment
    /// will be created, and all tests will share it.
    pub async fn new() -> Result<Self> {
        let mutex = get_or_init_environment().await?;

        // Extract needed data from the environment while holding the lock briefly
        let (client, server_type) = {
            let guard = mutex
                .lock()
                .map_err(|e| anyhow::anyhow!("Failed to lock test environment: {}", e))?;

            let env = guard
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Test environment was already cleaned up"))?;

            let client = HttpClient::new(
                env.server().base_url.to_string(),
                env.mint().url.to_string(),
            );
            let server_type = env.server().server_type;

            (client, server_type)
            // guard is dropped here at the end of the block
        };

        // Now we can await without holding the lock
        let server_params = client.fetch_channel_params().await?;

        Ok(Self {
            client,
            server_params,
            server_type,
        })
    }

    /// Get the mint URL
    pub fn mint_url(&self) -> &str {
        &self.client.mint_url
    }

    /// Get the server base URL
    pub fn server_url(&self) -> &str {
        &self.client.base_url
    }

    /// Get price per character for a unit (raw, before scaling).
    pub fn get_price_per_char(&self, unit: &str) -> u64 {
        self.server_params
            .pricing
            .get(unit)
            .and_then(|p| p.variables.get("chars").copied())
            .unwrap_or(1)
    }

    /// Get the pricing scale divisor.
    pub fn pricing_scale(&self) -> u64 {
        self.server_params.pricing_scale.max(1)
    }

    /// Get minimum capacity for a unit
    pub fn get_min_capacity(&self, unit: &str) -> u64 {
        self.server_params
            .pricing
            .get(unit)
            .map(|p| p.min_capacity)
            .unwrap_or(10)
    }

    /// Calculate amount due for characters served: ceil(chars * price / scale).
    pub fn get_amount_due(&self, chars_served: u64, unit: &str) -> u64 {
        let raw = chars_served * self.get_price_per_char(unit);
        raw.div_ceil(self.pricing_scale())
    }

    /// Mint a funded channel with default options
    pub async fn mint_channel(&self, unit: &str, capacity: u64) -> Result<Channel> {
        mint_funded_channel(
            &self.client,
            &self.server_params,
            unit,
            capacity,
            MintFundedChannelOptions::default(),
        )
        .await
    }

    /// Mint a funded channel with custom options
    pub async fn mint_channel_with_options(
        &self,
        unit: &str,
        capacity: u64,
        options: MintFundedChannelOptions,
    ) -> Result<Channel> {
        mint_funded_channel(&self.client, &self.server_params, unit, capacity, options).await
    }
}

/// Get or initialize the global test environment.
///
/// Thread-safe: uses `OnceCell::get_or_try_init()` which guarantees that
/// the initialization closure runs exactly once, even when called concurrently
/// from multiple test threads.
async fn get_or_init_environment() -> Result<&'static Mutex<Option<TestEnvironment>>> {
    TEST_ENV
        .get_or_try_init(|| async {
            let server_type = ServerType::from_env()?;
            tracing::info!(
                "Initializing test environment for {} server",
                server_type.name()
            );
            let env = TestEnvironment::new(server_type).await?;

            // Register atexit handler to clean up when the test binary exits
            register_atexit_handler();

            Ok(Mutex::new(Some(env)))
        })
        .await
}

/// Macro to create a test with TestContext
#[macro_export]
macro_rules! test_with_context {
    ($name:ident, $body:expr) => {
        #[tokio::test]
        async fn $name() -> anyhow::Result<()> {
            let ctx = $crate::context::TestContext::new().await?;
            $body(ctx).await
        }
    };
}
