//! Deterministic real Cashu V2 mint keyset used by protocol test vectors.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use bip39::Mnemonic;
use cdk::mint::{MintBuilder, MintMeltLimits};
use cdk::nuts::{CurrencyUnit, PaymentMethod};
use cdk::Mint;
use cdk_common::common::FeeReserve;
use cdk_common::nut00::KnownMethod;
use cdk_fake_wallet::FakeWallet;

/// Fixed public BIP-39 test mnemonic used solely to reproduce this keyset.
pub const REAL_TEST_MINT_KEYSET_V2_MNEMONIC: &str =
    "nut nut nut nut nut nut nut nut nut nut nut crunch";

/// Public data for a real deterministic Cashu V2 mint keyset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealMintKeysetV2 {
    /// Mint-assigned active SAT keyset identifier.
    pub keyset_id: String,
    /// Input fee in parts per thousand.
    pub input_fee_ppk: u64,
    /// Denomination and compressed SEC1 public key pairs, sorted by denomination.
    pub public_keys: Vec<(u64, String)>,
}

/// Build the deterministic CDK V2 mint used by the test fixtures.
pub async fn build_real_test_mint_v2() -> Result<Mint> {
    let db = Arc::new(cdk_sqlite::mint::memory::empty().await?);
    let mut builder = MintBuilder::new(db.clone()).with_keyset_v2(Some(true));
    let fee_reserve = FeeReserve {
        min_fee_reserve: 0.into(),
        percent_fee_reserve: 0.0,
    };
    let wallet = FakeWallet::new(
        fee_reserve,
        HashMap::default(),
        HashSet::default(),
        0,
        CurrencyUnit::Sat,
    );

    builder
        .add_payment_processor(
            CurrencyUnit::Sat,
            PaymentMethod::Known(KnownMethod::Bolt11),
            MintMeltLimits::new(1, u64::MAX),
            Arc::new(wallet),
        )
        .await?;
    builder.set_unit_fee(&CurrencyUnit::Sat, 0)?;

    let mnemonic = Mnemonic::from_str(REAL_TEST_MINT_KEYSET_V2_MNEMONIC)
        .map_err(|error| anyhow!("invalid real test mint mnemonic: {error}"))?;
    Ok(builder
        .build_with_seed(db, &mnemonic.to_seed_normalized(""))
        .await?)
}

/// Build a deterministic CDK V2 mint and return its active SAT public keyset.
///
/// The resulting private keys are deliberately test-only. Production vector
/// data contains only the corresponding public keyset.
pub async fn generate_real_test_mint_keyset_v2() -> Result<RealMintKeysetV2> {
    let mint = build_real_test_mint_v2().await?;
    let keyset_id = *mint
        .get_active_keysets()
        .get(&CurrencyUnit::Sat)
        .ok_or_else(|| anyhow!("deterministic mint has no active SAT keyset"))?;
    let keyset = mint
        .keyset_pubkeys(&keyset_id)?
        .keysets
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("deterministic mint has no active SAT public keys"))?;
    let mut public_keys: Vec<(u64, String)> = keyset
        .keys
        .iter()
        .map(|(amount, public_key)| (u64::from(*amount), public_key.to_hex()))
        .collect();
    public_keys.sort_unstable_by_key(|(amount, _)| *amount);

    Ok(RealMintKeysetV2 {
        keyset_id: keyset_id.to_string(),
        input_fee_ppk: 0,
        public_keys,
    })
}
