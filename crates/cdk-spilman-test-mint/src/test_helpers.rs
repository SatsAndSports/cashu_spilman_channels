//! Test mint utilities
//!
//! Creates an in-memory mint for testing, similar to cdk-spilman-interop-tests.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bip39::Mnemonic;
use cdk::dhke::construct_proofs;
use cdk::mint::{MintBuilder, MintMeltLimits};
use cdk::nuts::{
    CurrencyUnit, Id, Keys, MintQuoteBolt11Request, MintQuoteBolt11Response, MintQuoteState,
    PaymentMethod, PreMintSecrets, Proof,
};
use cdk::{Amount, Mint};
use cdk_common::amount::SplitTarget;
use cdk_common::common::{FeeReserve, QuoteTTL};
use cdk_common::nut00::KnownMethod;
use cdk_fake_wallet::FakeWallet;
use serde_json::json;

/// Default test fee in parts per thousand.
/// Using 0 to simplify fee calculations in tests.
pub const DEFAULT_TEST_FEE_PPK: u64 = 0;

/// Create an in-memory test mint with FakeWallet backend.
pub async fn create_test_mint() -> Result<Mint> {
    let db = Arc::new(cdk_sqlite::mint::memory::empty().await?);
    let mut mint_builder = MintBuilder::new(db.clone());

    let fee_reserve = FeeReserve {
        min_fee_reserve: 1.into(),
        percent_fee_reserve: 1.0,
    };

    let ln_fake_backend = FakeWallet::new(
        fee_reserve,
        HashMap::default(),
        HashSet::default(),
        2,
        CurrencyUnit::Sat,
    );

    mint_builder
        .add_payment_processor(
            CurrencyUnit::Sat,
            PaymentMethod::Known(KnownMethod::Bolt11),
            MintMeltLimits::new(1, 10_000),
            Arc::new(ln_fake_backend),
        )
        .await?;

    mint_builder.set_unit_fee(&CurrencyUnit::Sat, DEFAULT_TEST_FEE_PPK)?;

    let mnemonic = Mnemonic::generate(12)?;

    mint_builder = mint_builder
        .with_name("test mint".to_string())
        .with_description("test mint for client integration".to_string())
        .with_urls(vec!["https://test-mint".to_string()]);

    let mint = mint_builder
        .build_with_seed(db.clone(), &mnemonic.to_seed_normalized(""))
        .await?;

    mint.set_quote_ttl(QuoteTTL::new(10_000, 10_000)).await?;
    mint.start().await?;

    Ok(mint)
}

/// Mint test proofs with the given amount.
pub async fn mint_test_proofs(mint: &Mint, amount: u64) -> Result<Vec<Proof>> {
    let amount = Amount::from(amount);

    // Get mint quote
    let mint_quote: MintQuoteBolt11Response<_> = mint
        .get_mint_quote(
            MintQuoteBolt11Request {
                amount,
                unit: CurrencyUnit::Sat,
                description: None,
                pubkey: None,
            }
            .into(),
        )
        .await?
        .into();

    // Wait for quote to be paid (FakeWallet auto-pays)
    loop {
        let check: MintQuoteBolt11Response<_> = mint
            .check_mint_quotes(&[cdk_common::QuoteId::from_str(&mint_quote.quote)?])
            .await?
            .first()
            .ok_or_else(|| anyhow::anyhow!("missing mint quote status"))?
            .clone()
            .into();

        if check.state == MintQuoteState::Paid {
            break;
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    // Get keyset
    let keyset_id = *mint
        .get_active_keysets()
        .get(&CurrencyUnit::Sat)
        .ok_or_else(|| anyhow::anyhow!("missing active SAT keyset"))?;

    let keys = mint
        .keyset_pubkeys(&keyset_id)?
        .keysets
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing keyset pubkeys"))?
        .keys
        .clone();

    // Create premint secrets
    let fees: (u64, Vec<u64>) = (0, keys.iter().map(|a| a.0.to_u64()).collect());
    let premint_secrets =
        PreMintSecrets::random(keyset_id, amount, &SplitTarget::None, &fees.into())?;

    // Mint tokens
    let request = cdk::nuts::MintRequest {
        quote: mint_quote.quote,
        outputs: premint_secrets.blinded_messages(),
        signature: None,
    };

    let mint_res = mint
        .process_mint_request(cdk::mint::MintInput::Single(request.try_into()?))
        .await?;

    // Construct proofs
    Ok(construct_proofs(
        mint_res.signatures,
        premint_secrets.rs(),
        premint_secrets.secrets(),
        &keys,
    )?)
}

/// Helper struct with cached keyset info for testing.
pub struct TestMintHelper {
    mint: Arc<Mint>,
    active_sat_keyset_id: Id,
    public_keys: Keys,
    input_fee_ppk: u64,
}

impl std::fmt::Debug for TestMintHelper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestMintHelper")
            .field("input_fee_ppk", &self.input_fee_ppk)
            .finish_non_exhaustive()
    }
}

impl TestMintHelper {
    /// Create a new TestMintHelper with an in-memory mint.
    pub async fn new() -> Result<Self> {
        let mint = Arc::new(create_test_mint().await?);

        let active_sat_keyset_id = *mint
            .get_active_keysets()
            .get(&CurrencyUnit::Sat)
            .ok_or_else(|| anyhow::anyhow!("missing active SAT keyset"))?;

        let keysets_response = mint.keysets();
        let keyset_info = keysets_response
            .keysets
            .iter()
            .find(|k| k.id == active_sat_keyset_id)
            .ok_or_else(|| anyhow::anyhow!("missing keyset info"))?;
        let input_fee_ppk = keyset_info.input_fee_ppk;

        let lookup = mint.keyset_pubkeys(&active_sat_keyset_id)?;
        let public_keys = lookup
            .keysets
            .first()
            .ok_or_else(|| anyhow::anyhow!("missing keyset pubkeys"))?
            .keys
            .clone();

        Ok(Self {
            mint,
            active_sat_keyset_id,
            public_keys,
            input_fee_ppk,
        })
    }

    /// Get the underlying mint as an Arc.
    pub fn mint(&self) -> Arc<Mint> {
        Arc::clone(&self.mint)
    }

    /// Get the active SAT keyset ID.
    pub fn keyset_id(&self) -> Id {
        self.active_sat_keyset_id
    }

    /// Get the public keys for the active SAT keyset.
    pub fn public_keys(&self) -> &Keys {
        &self.public_keys
    }

    /// Get the input fee ppk.
    pub fn input_fee_ppk(&self) -> u64 {
        self.input_fee_ppk
    }

    /// Mint proofs with the given amount.
    pub async fn mint_proofs(&self, amount: u64) -> Result<Vec<Proof>> {
        mint_test_proofs(&self.mint, amount).await
    }

    /// Get keyset info JSON for the active SAT keyset.
    pub fn keyset_info_json(&self) -> Result<String> {
        let keys_map: HashMap<String, String> = self
            .public_keys
            .iter()
            .map(|(amt, pk)| (amt.to_string(), pk.to_hex()))
            .collect();

        let json = json!({
            "keysetId": self.active_sat_keyset_id.to_string(),
            "unit": "sat",
            "keys": keys_map,
            "inputFeePpk": self.input_fee_ppk,
        });

        Ok(serde_json::to_string(&json)?)
    }
}
