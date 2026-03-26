//! Minimal standalone test mint used by Spilman demos and integration tests.

use std::collections::{HashMap, HashSet};
use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use axum::Router;
use bip39::Mnemonic;
use cdk::mint::{Mint, MintBuilder, MintMeltLimits};
use cdk::nuts::nut00::KnownMethod;
use cdk::nuts::{CurrencyUnit, MintVersion, PaymentMethod};
use cdk::types::FeeReserve;
use cdk_axum::create_mint_router;
use cdk_common::common::QuoteTTL;
use cdk_fake_wallet::FakeWallet;
use cdk_sqlite::mint::memory;

const DEFAULT_TEST_MINT_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const DEFAULT_TEST_MINT_NAME: &str = "Spilman Test Mint";
const DEFAULT_TEST_MINT_DESCRIPTION: &str =
    "Standalone fakewallet+sqlite test mint for Spilman integration flows";
const DEFAULT_INPUT_FEE_PPK: u64 = 400;
const MAX_INPUT_FEE_PPK: u64 = 999;
const DEFAULT_PAYMENT_DELAY_SECONDS: u64 = 1;

/// Runtime configuration for the standalone test mint.
#[derive(Debug, Clone)]
pub struct TestMintConfig {
    /// Host interface to bind.
    pub listen_host: String,
    /// TCP port to bind.
    pub listen_port: u16,
    /// Public base URL advertised by `/v1/info`.
    pub base_url: String,
    /// Mint name exposed by `/v1/info`.
    pub name: String,
    /// Mint description exposed by `/v1/info`.
    pub description: String,
    /// Quote TTLs persisted into mint state.
    pub quote_ttl: QuoteTTL,
    /// Minimum mint amount for supported units.
    pub min_mint: u64,
    /// Maximum mint amount for supported units.
    pub max_mint: u64,
    /// Minimum melt amount for supported units.
    pub min_melt: u64,
    /// Maximum melt amount for supported units.
    pub max_melt: u64,
    /// FakeWallet auto-payment delay in seconds.
    pub payment_delay_seconds: u64,
    /// Default per-unit input fee in ppk when no env override is present.
    pub default_input_fee_ppk: u64,
}

impl Default for TestMintConfig {
    fn default() -> Self {
        Self {
            listen_host: "127.0.0.1".to_string(),
            listen_port: 3338,
            base_url: "http://127.0.0.1:3338".to_string(),
            name: DEFAULT_TEST_MINT_NAME.to_string(),
            description: DEFAULT_TEST_MINT_DESCRIPTION.to_string(),
            quote_ttl: QuoteTTL::new(10_000, 10_000),
            min_mint: 1,
            max_mint: 1_000_000,
            min_melt: 1,
            max_melt: 1_000_000,
            payment_delay_seconds: DEFAULT_PAYMENT_DELAY_SECONDS,
            default_input_fee_ppk: DEFAULT_INPUT_FEE_PPK,
        }
    }
}

impl TestMintConfig {
    /// Create config for a specific port with a loopback base URL.
    pub fn for_port(port: u16) -> Self {
        Self {
            listen_port: port,
            base_url: format!("http://127.0.0.1:{port}"),
            ..Self::default()
        }
    }
}

fn supported_units() -> [CurrencyUnit; 3] {
    [CurrencyUnit::Sat, CurrencyUnit::Msat, CurrencyUnit::Usd]
}

fn fee_override_names(unit: &CurrencyUnit) -> [String; 2] {
    let unit_suffix = unit.to_string().to_uppercase();
    [
        format!("TEST_MINT_FEE_PPK_{unit_suffix}"),
        format!("CDK_MINTD_INPUT_FEE_PPK_{unit_suffix}"),
    ]
}

fn input_fee_ppk_for_unit(config: &TestMintConfig, unit: &CurrencyUnit) -> u64 {
    for env_name in fee_override_names(unit) {
        if let Ok(raw) = env::var(&env_name) {
            match raw.parse::<u64>() {
                Ok(value) if value <= MAX_INPUT_FEE_PPK => {
                    return value;
                }
                Ok(value) => {
                    tracing::warn!(
                        "Ignoring {}={} because input_fee_ppk must be <= {}",
                        env_name,
                        value,
                        MAX_INPUT_FEE_PPK
                    );
                }
                Err(_) => {
                    tracing::warn!(
                        "Ignoring {}={} because it is not a valid u64",
                        env_name,
                        raw
                    );
                }
            }
        }
    }

    config.default_input_fee_ppk
}

fn mint_limits(config: &TestMintConfig) -> MintMeltLimits {
    MintMeltLimits {
        mint_min: config.min_mint.into(),
        mint_max: config.max_mint.into(),
        melt_min: config.min_melt.into(),
        melt_max: config.max_melt.into(),
    }
}

async fn build_fake_wallet(unit: CurrencyUnit, delay_seconds: u64) -> FakeWallet {
    let fee_reserve = FeeReserve {
        min_fee_reserve: 0.into(),
        percent_fee_reserve: 0.0,
    };

    FakeWallet::new(
        fee_reserve,
        HashMap::default(),
        HashSet::default(),
        delay_seconds,
        unit,
    )
}

fn fixed_seed() -> Result<Vec<u8>> {
    let mnemonic = Mnemonic::from_str(DEFAULT_TEST_MINT_MNEMONIC)
        .context("Failed to parse fixed standalone mint mnemonic")?;
    Ok(mnemonic.to_seed_normalized("").to_vec())
}

/// Build and start the standalone test mint.
pub async fn build_test_mint(config: &TestMintConfig) -> Result<Mint> {
    let db = Arc::new(memory::empty().await?);
    let version = MintVersion::new(
        "cdk-spilman-test-mintd".to_string(),
        env!("CARGO_PKG_VERSION").to_string(),
    );

    let mut builder = MintBuilder::new(db.clone())
        .with_name(config.name.clone())
        .with_description(config.description.clone())
        .with_urls(vec![config.base_url.clone()])
        .with_version(version)
        .with_keyset_v2(Some(true));

    let limits = mint_limits(config);

    for unit in supported_units() {
        let fake_wallet = build_fake_wallet(unit.clone(), config.payment_delay_seconds).await;
        builder
            .add_payment_processor(
                unit.clone(),
                PaymentMethod::Known(KnownMethod::Bolt11),
                limits,
                Arc::new(fake_wallet),
            )
            .await?;
        builder.set_unit_fee(&unit, input_fee_ppk_for_unit(config, &unit))?;
    }

    let seed = fixed_seed()?;
    let mint = builder.build_with_seed(db.clone(), &seed).await?;
    mint.set_quote_ttl(config.quote_ttl.clone()).await?;

    let active_keysets = mint.get_active_keysets();
    for unit in supported_units() {
        if !active_keysets.contains_key(&unit) {
            return Err(anyhow!("missing active keyset for unit {}", unit));
        }
    }

    mint.start().await?;
    Ok(mint)
}

/// Build the axum router for the standalone test mint.
pub async fn build_router(mint: Arc<Mint>) -> Result<Router> {
    create_mint_router(
        mint,
        vec![PaymentMethod::Known(KnownMethod::Bolt11).to_string()],
    )
    .await
}

/// Serve the standalone test mint until a shutdown signal is received.
pub async fn serve_mint_with_shutdown(
    config: TestMintConfig,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let mint = Arc::new(build_test_mint(&config).await?);
    let router = build_router(Arc::clone(&mint)).await?;

    let socket_addr = SocketAddr::new(
        config
            .listen_host
            .parse()
            .with_context(|| format!("Invalid listen_host {}", config.listen_host))?,
        config.listen_port,
    );
    let listener = tokio::net::TcpListener::bind(socket_addr).await?;

    tracing::info!(
        "Standalone test mint listening on {}",
        listener.local_addr()?
    );

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    mint.stop().await?;
    Ok(())
}

/// Serve the standalone test mint until interrupted.
pub async fn serve_mint(config: TestMintConfig) -> Result<()> {
    serve_mint_with_shutdown(config, async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};

            let mut terminate = signal(SignalKind::terminate()).expect("signal handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
        }

        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    })
    .await
}
