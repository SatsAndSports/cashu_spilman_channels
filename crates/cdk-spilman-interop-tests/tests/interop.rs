#![allow(unexpected_cfgs)]
//! Upstream `cdk` interoperability coverage for `cdk-spilman`.

use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bip39::Mnemonic;
use cdk::dhke::{blind_message, construct_proofs};
use cdk::mint::{MintBuilder, MintMeltLimits};
use cdk::nuts::nut10::Secret as Nut10Secret;
use cdk::nuts::{
    BatchCheckMintQuoteRequest, BatchMintRequest, BlindedMessage, CheckStateRequest,
    CheckStateResponse, CurrencyUnit, Id, KeySet, Keys, KeysetResponse, MeltQuoteBolt11Response,
    MeltRequest, MintInfo, MintQuoteBolt11Request, MintQuoteBolt11Response, MintQuoteState,
    MintRequest, MintResponse, PaymentMethod, PreMintSecrets, Proof, RestoreRequest,
    RestoreResponse, SpendingConditions, SwapRequest, SwapResponse,
};
use cdk::secret::Secret;
use cdk::util::unix_time;
use cdk::wallet::{MintConnector, ReceiveOptions, SendOptions, WalletBuilder};
use cdk::{Amount, Mint};
use cdk_common::amount::SplitTarget;
use cdk_common::common::{FeeReserve, QuoteTTL};
use cdk_common::nut00::KnownMethod;
use cdk_common::{MeltQuoteRequest, MeltQuoteResponse, MintQuoteRequest};
use cdk_fake_wallet::FakeWallet;
use cdk_spilman::{
    complete_funding_swap, compute_channel_from_token, create_funding_swap, ChannelFunding,
    ChannelParameters, ChannelPolicy, ChannelState, CloseError, ClosingData, CommitmentOutputs,
    DeterministicOutputsForOneContext, EstablishedChannel, KeysetInfo, PaymentProof, SpilmanBridge,
    SpilmanChannelSender, SpilmanHost, SpilmanNetworking,
};
use cdk_sqlite::wallet::memory;
use rand::random;

const DEFAULT_TEST_FEE_PPK: u64 = 400;

struct TestMintHelper {
    mint: Mint,
    active_sat_keyset_id: Id,
    public_keys_of_the_active_sat_keyset: Keys,
    unit: CurrencyUnit,
    input_fee_ppk: u64,
    final_expiry: Option<u64>,
}

impl TestMintHelper {
    async fn new() -> anyhow::Result<Self> {
        let mint = create_test_mint().await?;

        let active_sat_keyset_id = mint
            .get_active_keysets()
            .get(&CurrencyUnit::Sat)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing active SAT keyset"))?;

        let keysets_response = mint.keysets();
        let keyset_info = keysets_response
            .keysets
            .iter()
            .find(|k| k.id == active_sat_keyset_id)
            .ok_or_else(|| anyhow::anyhow!("missing keyset info"))?;
        let input_fee_ppk = keyset_info.input_fee_ppk;
        let final_expiry = keyset_info.final_expiry;
        let unit = keyset_info.unit.clone();

        let lookup = mint.keyset_pubkeys(&active_sat_keyset_id)?;
        let active_sat_keyset = lookup
            .keysets
            .first()
            .ok_or_else(|| anyhow::anyhow!("missing active SAT keyset pubkeys"))?;
        let public_keys_of_the_active_sat_keyset = active_sat_keyset.keys.clone();

        Ok(Self {
            mint,
            active_sat_keyset_id,
            public_keys_of_the_active_sat_keyset,
            unit,
            input_fee_ppk,
            final_expiry,
        })
    }

    fn mint(&self) -> &Mint {
        &self.mint
    }

    async fn mint_proofs(&self, amount: Amount) -> anyhow::Result<Vec<Proof>> {
        mint_test_proofs(&self.mint, amount).await
    }

    fn split_amount(&self, amount: Amount) -> anyhow::Result<Vec<Amount>> {
        let mut available_amounts_sorted: Vec<u64> = self
            .public_keys_of_the_active_sat_keyset
            .iter()
            .map(|(amt, _)| amt.to_u64())
            .collect();
        available_amounts_sorted.sort_by(|a, b| b.cmp(a));

        let mut result = Vec::new();
        let mut remaining = amount.to_u64();

        for amt in available_amounts_sorted {
            if remaining >= amt {
                result.push(Amount::from(amt));
                remaining -= amt;
            }
        }

        if remaining != 0 {
            return Err(anyhow::anyhow!("failed to split amount exactly"));
        }

        Ok(result)
    }

    fn create_blinded_message(
        &self,
        amount: Amount,
        spending_conditions: &SpendingConditions,
    ) -> anyhow::Result<(BlindedMessage, cdk::nuts::SecretKey, Secret)> {
        let nut10_secret: Nut10Secret = spending_conditions.clone().into();
        let secret: Secret = nut10_secret.try_into()?;
        let (blinded_point, blinding_factor) = blind_message(&secret.to_bytes(), None)?;
        let blinded_msg = BlindedMessage::new(amount, self.active_sat_keyset_id, blinded_point);

        Ok((blinded_msg, blinding_factor, secret))
    }
}

async fn create_test_mint() -> anyhow::Result<Mint> {
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
        .with_description("test mint for upstream cdk interop".to_string())
        .with_urls(vec!["https://test-mint".to_string()]);

    let mint = mint_builder
        .build_with_seed(db.clone(), &mnemonic.to_seed_normalized(""))
        .await?;

    mint.set_quote_ttl(QuoteTTL::new(10_000, 10_000)).await?;
    mint.start().await?;

    Ok(mint)
}

async fn mint_test_proofs(mint: &Mint, amount: Amount) -> anyhow::Result<Vec<Proof>> {
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

    let fees: (u64, Vec<u64>) = (0, keys.iter().map(|a| a.0.to_u64()).collect());
    let premint_secrets =
        PreMintSecrets::random(keyset_id, amount, &SplitTarget::None, &fees.into())?;

    let request = cdk::nuts::MintRequest {
        quote: mint_quote.quote,
        outputs: premint_secrets.blinded_messages(),
        signature: None,
    };

    let mint_res = mint
        .process_mint_request(cdk::mint::MintInput::Single(request.try_into()?))
        .await?;

    Ok(construct_proofs(
        mint_res.signatures,
        premint_secrets.rs(),
        premint_secrets.secrets(),
        &keys,
    )?)
}

async fn create_test_blinded_messages(
    mint: &Mint,
    amount: Amount,
) -> anyhow::Result<(Vec<BlindedMessage>, PreMintSecrets)> {
    let keyset_id = *mint
        .get_active_keysets()
        .get(&CurrencyUnit::Sat)
        .ok_or_else(|| anyhow::anyhow!("missing active SAT keyset"))?;
    let split_target = SplitTarget::default();
    let fee_and_amounts = (0, (0..32).map(|x| 2u64.pow(x)).collect::<Vec<_>>()).into();

    let pre_mint = PreMintSecrets::random(keyset_id, amount, &split_target, &fee_and_amounts)?;
    Ok((pre_mint.blinded_messages().to_vec(), pre_mint))
}

fn unzip3<A, B, C>(vec: Vec<(A, B, C)>) -> (Vec<A>, Vec<B>, Vec<C>) {
    let mut vec_a = Vec::new();
    let mut vec_b = Vec::new();
    let mut vec_c = Vec::new();

    for (a, b, c) in vec {
        vec_a.push(a);
        vec_b.push(b);
        vec_c.push(c);
    }

    (vec_a, vec_b, vec_c)
}

#[derive(Clone)]
struct DirectMintConnection {
    mint: Mint,
}

impl DirectMintConnection {
    fn new(mint: Mint) -> Self {
        Self { mint }
    }
}

impl Debug for DirectMintConnection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "DirectMintConnection")
    }
}

#[async_trait]
impl MintConnector for DirectMintConnection {
    #[cfg(all(feature = "bip353", not(target_arch = "wasm32")))]
    async fn resolve_dns_txt(&self, _domain: &str) -> Result<Vec<String>, cdk::Error> {
        Err(cdk::Error::UnsupportedPaymentMethod)
    }

    async fn fetch_lnurl_pay_request(
        &self,
        _url: &str,
    ) -> Result<cdk::wallet::LnurlPayResponse, cdk::Error> {
        Err(cdk::Error::UnsupportedPaymentMethod)
    }

    async fn fetch_lnurl_invoice(
        &self,
        _url: &str,
    ) -> Result<cdk::wallet::LnurlPayInvoiceResponse, cdk::Error> {
        Err(cdk::Error::UnsupportedPaymentMethod)
    }

    async fn get_mint_keys(&self) -> Result<Vec<KeySet>, cdk::Error> {
        Ok(self.mint.pubkeys().keysets)
    }

    async fn get_mint_keyset(&self, keyset_id: Id) -> Result<KeySet, cdk::Error> {
        self.mint
            .keyset(&keyset_id)
            .ok_or(cdk::Error::UnknownKeySet)
    }

    async fn get_mint_keysets(&self) -> Result<KeysetResponse, cdk::Error> {
        Ok(self.mint.keysets())
    }

    async fn post_mint_quote(
        &self,
        _request: MintQuoteRequest,
    ) -> Result<cdk_common::MintQuoteResponse<String>, cdk::Error> {
        Err(cdk::Error::UnsupportedPaymentMethod)
    }

    async fn post_batch_check_mint_quote_status(
        &self,
        _method: &PaymentMethod,
        _request: BatchCheckMintQuoteRequest<String>,
    ) -> Result<Vec<MintQuoteBolt11Response<String>>, cdk::Error> {
        Err(cdk::Error::UnsupportedPaymentMethod)
    }

    async fn post_batch_mint(
        &self,
        _method: &PaymentMethod,
        _request: BatchMintRequest<String>,
    ) -> Result<MintResponse, cdk::Error> {
        Err(cdk::Error::UnsupportedPaymentMethod)
    }

    async fn get_mint_quote_status(
        &self,
        _method: PaymentMethod,
        _quote_id: &str,
    ) -> Result<cdk_common::MintQuoteResponse<String>, cdk::Error> {
        Err(cdk::Error::UnsupportedPaymentMethod)
    }

    async fn post_mint(
        &self,
        _method: &PaymentMethod,
        _request: MintRequest<String>,
    ) -> Result<MintResponse, cdk::Error> {
        Err(cdk::Error::UnsupportedPaymentMethod)
    }

    async fn post_melt_quote(
        &self,
        _request: MeltQuoteRequest,
    ) -> Result<MeltQuoteResponse<String>, cdk::Error> {
        Err(cdk::Error::UnsupportedPaymentMethod)
    }

    async fn get_melt_quote_status(
        &self,
        _method: PaymentMethod,
        _quote_id: &str,
    ) -> Result<MeltQuoteResponse<String>, cdk::Error> {
        Err(cdk::Error::UnsupportedPaymentMethod)
    }

    async fn post_melt(
        &self,
        _method: &PaymentMethod,
        _request: MeltRequest<String>,
    ) -> Result<MeltQuoteBolt11Response<String>, cdk::Error> {
        Err(cdk::Error::UnsupportedPaymentMethod)
    }

    async fn post_swap(&self, request: SwapRequest) -> Result<SwapResponse, cdk::Error> {
        self.mint.process_swap_request(request).await
    }

    async fn get_mint_info(&self) -> Result<MintInfo, cdk::Error> {
        Ok(self.mint.mint_info().await?.clone().time(unix_time()))
    }

    async fn post_check_state(
        &self,
        request: CheckStateRequest,
    ) -> Result<CheckStateResponse, cdk::Error> {
        self.mint.check_state(&request).await
    }

    async fn post_restore(&self, request: RestoreRequest) -> Result<RestoreResponse, cdk::Error> {
        self.mint.restore(request).await
    }

    async fn get_auth_wallet(&self) -> Option<cdk::wallet::AuthWallet> {
        None
    }

    async fn set_auth_wallet(&self, _wallet: Option<cdk::wallet::AuthWallet>) {}
}

#[tokio::test]
async fn test_spilman_2of2_spending_with_blinded_keys() -> anyhow::Result<()> {
    let test_mint = TestMintHelper::new().await?;
    let mint = test_mint.mint();

    let alice_secret = cdk::nuts::SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = cdk::nuts::SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    let keyset_id = test_mint.active_sat_keyset_id;
    let keys = test_mint.public_keys_of_the_active_sat_keyset.clone();
    let input_fee_ppk = test_mint.input_fee_ppk;

    let keyset_info = KeysetInfo::new(
        keyset_id,
        test_mint.unit.clone(),
        keys.clone(),
        input_fee_ppk,
        test_mint.final_expiry,
    );

    let capacity = 10u64;
    let future_expiry = unix_time() + 3600;
    let funding_token_amount =
        ChannelParameters::get_minimum_funding_token_amount(capacity, &keyset_info, 64)?;

    let params = ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "http://localhost:3338".to_string(),
        CurrencyUnit::Sat,
        capacity,
        funding_token_amount,
        future_expiry,
        unix_time(),
        keyset_info.clone(),
        64,
        &alice_secret,
    )?;

    let funding_amount = params.get_total_funding_token_amount()?;
    let _funding_outputs = DeterministicOutputsForOneContext::new(
        "funding".to_string(),
        funding_amount,
        params.clone(),
    )?;
    let input_proofs = test_mint.mint_proofs(Amount::from(funding_amount)).await?;

    let num_input_proofs = input_proofs.len() as u64;
    let actual_fee = (input_fee_ppk * num_input_proofs).div_ceil(1000);
    let available_for_outputs = funding_amount - actual_fee;

    let adjusted_funding_outputs = DeterministicOutputsForOneContext::new(
        "funding".to_string(),
        available_for_outputs,
        params.clone(),
    )?;

    let adjusted_blinded_messages = adjusted_funding_outputs.get_blinded_messages(None)?;
    let swap_request = SwapRequest::new(input_proofs.clone(), adjusted_blinded_messages);
    let swap_response = mint.process_swap_request(swap_request).await?;

    let secrets_with_blinding = adjusted_funding_outputs.get_secrets_with_blinding()?;
    let blinding_factors = secrets_with_blinding
        .iter()
        .map(|s| s.blinding_factor.clone())
        .collect();
    let secrets = secrets_with_blinding
        .iter()
        .map(|s| s.secret.clone())
        .collect();
    let p2pk_proofs = construct_proofs(swap_response.signatures, blinding_factors, secrets, &keys)?;

    let spend_fee = (input_fee_ppk * p2pk_proofs.len() as u64).div_ceil(1000);
    let final_output_amount = available_for_outputs - spend_fee;
    let (new_outputs, _) =
        create_test_blinded_messages(mint, Amount::from(final_output_amount)).await?;

    let mut swap_request_2of2 = SwapRequest::new(p2pk_proofs, new_outputs);
    let alice_blinded_secret = params.get_sender_blinded_secret_key_for_stage1(&alice_secret)?;
    let charlie_blinded_secret =
        params.get_receiver_blinded_secret_key_for_stage1(&charlie_secret)?;
    swap_request_2of2.sign_sig_all(alice_blinded_secret)?;
    swap_request_2of2.sign_sig_all(charlie_blinded_secret)?;

    mint.process_swap_request(swap_request_2of2).await?;
    Ok(())
}

#[tokio::test]
async fn test_swap_to_funding() -> anyhow::Result<()> {
    use cdk::nuts::nut00::token::Token;

    let test_mint = TestMintHelper::new().await?;
    let mint = test_mint.mint();

    let alice_secret = cdk::nuts::SecretKey::generate();
    let charlie_secret = cdk::nuts::SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    let keyset_id = test_mint.active_sat_keyset_id;
    let keys = test_mint.public_keys_of_the_active_sat_keyset.clone();
    let input_fee_ppk = test_mint.input_fee_ppk;

    let keyset_info_json = serde_json::json!({
        "keysetId": keyset_id.to_string(),
        "unit": "sat",
        "inputFeePpk": input_fee_ppk,
        "keys": keys.iter().map(|(amt, pk)| {
            (u64::from(*amt).to_string(), pk.to_hex())
        }).collect::<std::collections::HashMap<_, _>>()
    })
    .to_string();

    let input_amount = Amount::from(100u64);
    let input_proofs = test_mint.mint_proofs(input_amount).await?;
    let token = Token::new(
        "http://localhost:3338".parse().unwrap(),
        input_proofs.clone(),
        None,
        CurrencyUnit::Sat,
    );
    let token_string = token.to_string();

    let expiry_timestamp = unix_time() + 3600;
    let max_amount = 64u64;
    let channel_secret_hex = cdk_spilman::compute_channel_secret_from_hex(
        &alice_secret.to_secret_hex(),
        &receiver_pubkey.to_hex(),
    )
    .map_err(anyhow::Error::msg)?;

    let compute_result = compute_channel_from_token(
        &token_string,
        &receiver_pubkey.to_hex(),
        &alice_secret.public_key().to_hex(),
        &channel_secret_hex,
        expiry_timestamp,
        &keyset_info_json,
        max_amount,
    )
    .map_err(anyhow::Error::msg)?;
    let compute_json: serde_json::Value = serde_json::from_str(&compute_result)?;
    let params_json = compute_json["params_json"].as_str().unwrap();
    let proofs_json = compute_json["proofs_json"].as_str().unwrap();

    let swap_result = create_funding_swap(
        params_json,
        &channel_secret_hex,
        &keyset_info_json,
        proofs_json,
    )
    .map_err(anyhow::Error::msg)?;
    let swap_json: serde_json::Value = serde_json::from_str(&swap_result)?;
    let swap_request_json = swap_json["swap_request_json"].as_str().unwrap();
    let funding_secrets_json = swap_json["funding_secrets_json"].as_str().unwrap();
    let funding_count = swap_json["funding_count"].as_u64().unwrap() as usize;

    let swap_request: SwapRequest = serde_json::from_str(swap_request_json)?;
    let swap_response = mint.process_swap_request(swap_request).await?;
    let swap_response_json = serde_json::to_string(&swap_response)?;

    let complete_result =
        complete_funding_swap(&swap_response_json, funding_secrets_json, &keyset_info_json)
            .map_err(anyhow::Error::msg)?;
    let complete_json: serde_json::Value = serde_json::from_str(&complete_result)?;
    let funding_proofs_json = complete_json["funding_proofs_json"].as_str().unwrap();
    let funding_proofs: Vec<Proof> = serde_json::from_str(funding_proofs_json)?;

    assert_eq!(funding_proofs.len(), funding_count);
    assert!(!funding_proofs.is_empty());
    Ok(())
}

#[tokio::test]
async fn test_spilman_refund_spending_with_blinded_key() -> anyhow::Result<()> {
    let test_mint = TestMintHelper::new().await?;
    let mint = test_mint.mint();

    let alice_secret = cdk::nuts::SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = cdk::nuts::SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    let keyset_id = test_mint.active_sat_keyset_id;
    let keys = test_mint.public_keys_of_the_active_sat_keyset.clone();
    let input_fee_ppk = test_mint.input_fee_ppk;

    let keyset_info = KeysetInfo::new(
        keyset_id,
        test_mint.unit.clone(),
        keys.clone(),
        input_fee_ppk,
        test_mint.final_expiry,
    );

    let capacity = 10u64;
    let future_expiry = unix_time() + 3600;
    let funding_token_amount =
        ChannelParameters::get_minimum_funding_token_amount(capacity, &keyset_info, 64)?;

    let params = ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "http://localhost:3338".to_string(),
        CurrencyUnit::Sat,
        capacity,
        funding_token_amount,
        future_expiry,
        unix_time(),
        keyset_info,
        64,
        &alice_secret,
    )?;

    let blinded_alice = params.get_sender_blinded_pubkey_for_stage1()?;
    let blinded_charlie = params.get_receiver_blinded_pubkey_for_stage1()?;
    let blinded_alice_refund = params.get_sender_blinded_pubkey_for_stage1_refund()?;

    assert_ne!(blinded_alice.to_hex(), blinded_alice_refund.to_hex());

    let past_expiry = unix_time() - 3600;
    let spending_conditions = SpendingConditions::new_p2pk(
        blinded_alice,
        Some(cdk_common::nuts::Conditions {
            locktime: Some(past_expiry),
            pubkeys: Some(vec![blinded_charlie]),
            refund_keys: Some(vec![blinded_alice_refund]),
            num_sigs: Some(2),
            sig_flag: cdk_common::nuts::SigFlag::SigAll,
            num_sigs_refund: Some(1),
        }),
    );

    let input_proofs = test_mint.mint_proofs(Amount::from(capacity)).await?;
    let num_input_proofs = input_proofs.len() as u64;
    let actual_fee = (input_fee_ppk * num_input_proofs).div_ceil(1000);
    let available_for_outputs = capacity - actual_fee;

    let output_amount = Amount::from(available_for_outputs);
    let split_amounts = test_mint.split_amount(output_amount)?;
    let created = split_amounts
        .iter()
        .map(|&amt| test_mint.create_blinded_message(amt, &spending_conditions))
        .collect::<Result<Vec<_>, _>>()?;
    let (p2pk_outputs, blinding_factors, secrets) = unzip3(created);

    let swap_request = SwapRequest::new(input_proofs, p2pk_outputs);
    let swap_response = mint.process_swap_request(swap_request).await?;
    let p2pk_proofs = construct_proofs(swap_response.signatures, blinding_factors, secrets, &keys)?;

    let refund_fee = (input_fee_ppk * p2pk_proofs.len() as u64).div_ceil(1000);
    let refund_output_amount = available_for_outputs - refund_fee;
    let (new_outputs, _) =
        create_test_blinded_messages(mint, Amount::from(refund_output_amount)).await?;

    let mut swap_request_refund = SwapRequest::new(p2pk_proofs, new_outputs);
    let alice_refund_blinded_secret =
        params.get_sender_blinded_secret_key_for_stage1_refund(&alice_secret)?;
    swap_request_refund.sign_sig_all(alice_refund_blinded_secret)?;

    mint.process_swap_request(swap_request_refund).await?;
    Ok(())
}

#[test]
fn test_stage2_blinded_pubkeys_differ_from_stage1_and_raw() -> anyhow::Result<()> {
    let alice_secret = cdk::nuts::SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = cdk::nuts::SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    let mut keys = std::collections::BTreeMap::new();
    keys.insert(
        cdk_common::Amount::from(1u64),
        cdk_common::nuts::PublicKey::from_hex(
            "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104",
        )?,
    );
    let keyset_keys = cdk_common::nuts::Keys::new(keys);
    let keyset_id = cdk_common::nuts::Id::v1_from_keys(&keyset_keys);
    let keyset_info = KeysetInfo::new(keyset_id, CurrencyUnit::Sat, keyset_keys, 0, None);

    let params = ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "http://localhost:3338".to_string(),
        CurrencyUnit::Sat,
        100,
        100,
        unix_time() + 3600,
        unix_time(),
        keyset_info,
        64,
        &alice_secret,
    )?;

    let alice_raw = sender_pubkey.to_hex();
    let charlie_raw = receiver_pubkey.to_hex();
    let alice_stage1 = params.get_sender_blinded_pubkey_for_stage1()?.to_hex();
    let charlie_stage1 = params.get_receiver_blinded_pubkey_for_stage1()?.to_hex();
    let alice_stage2_64_0 = params
        .get_sender_blinded_pubkey_for_stage2_output(64, 0)?
        .to_hex();
    let charlie_stage2_64_0 = params
        .get_receiver_blinded_pubkey_for_stage2_output(64, 0)?
        .to_hex();
    let alice_refund = params
        .get_sender_blinded_pubkey_for_stage1_refund()?
        .to_hex();

    assert_ne!(alice_stage2_64_0, alice_raw);
    assert_ne!(charlie_stage2_64_0, charlie_raw);
    assert_ne!(alice_stage2_64_0, alice_stage1);
    assert_ne!(charlie_stage2_64_0, charlie_stage1);
    assert_ne!(alice_stage2_64_0, charlie_stage2_64_0);
    assert_ne!(alice_stage2_64_0, alice_refund);

    let alice_stage2_64_1 = params
        .get_sender_blinded_pubkey_for_stage2_output(64, 1)?
        .to_hex();
    let alice_stage2_32_0 = params
        .get_sender_blinded_pubkey_for_stage2_output(32, 0)?
        .to_hex();

    assert_ne!(alice_stage2_64_0, alice_stage2_64_1);
    assert_ne!(alice_stage2_64_0, alice_stage2_32_0);
    Ok(())
}

#[test]
fn test_sender_can_derive_secret_keys_for_stage2_outputs() -> anyhow::Result<()> {
    let alice_secret = cdk::nuts::SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = cdk::nuts::SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    let mut keys = std::collections::BTreeMap::new();
    for amount in [1u64, 2, 4, 8, 16, 32, 64] {
        let mint_secret = cdk::nuts::SecretKey::generate();
        keys.insert(cdk_common::Amount::from(amount), mint_secret.public_key());
    }

    let keyset_keys = cdk_common::nuts::Keys::new(keys);
    let keyset_id = cdk_common::nuts::Id::v1_from_keys(&keyset_keys);
    let keyset_info = KeysetInfo::new(keyset_id, CurrencyUnit::Sat, keyset_keys, 0, None);

    let capacity = 100u64;
    let params = ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "http://localhost:3338".to_string(),
        CurrencyUnit::Sat,
        capacity,
        capacity,
        unix_time() + 3600,
        unix_time(),
        keyset_info,
        64,
        &alice_secret,
    )?;

    let sender_outputs =
        DeterministicOutputsForOneContext::new("sender".to_string(), capacity, params.clone())?;
    let secrets_with_blinding = sender_outputs.get_secrets_with_blinding()?;

    let mut index_by_amount: HashMap<u64, usize> = HashMap::new();
    for output in &secrets_with_blinding {
        let amount = output.amount;
        let index = *index_by_amount.get(&amount).unwrap_or(&0);
        index_by_amount.insert(amount, index + 1);

        let blinded_secret =
            params.get_sender_blinded_secret_key_for_stage2_output(&alice_secret, amount, index)?;
        let derived_pubkey = blinded_secret.public_key();

        let secret_str = output.secret.to_string();
        let secret_json: serde_json::Value = serde_json::from_str(&secret_str)?;
        assert!(secret_json.is_array());
        assert_eq!(secret_json[0].as_str(), Some("P2PK"));

        let locked_pubkey_hex = secret_json[1]["data"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("secret missing locked pubkey"))?;
        assert_eq!(derived_pubkey.to_hex(), locked_pubkey_hex);
    }

    let key_64_0 = params
        .get_sender_blinded_secret_key_for_stage2_output(&alice_secret, 64, 0)?
        .public_key()
        .to_hex();
    let key_32_0 = params
        .get_sender_blinded_secret_key_for_stage2_output(&alice_secret, 32, 0)?
        .public_key()
        .to_hex();
    let key_64_1 = params
        .get_sender_blinded_secret_key_for_stage2_output(&alice_secret, 64, 1)?
        .public_key()
        .to_hex();

    assert_ne!(key_64_0, key_32_0);
    assert_ne!(key_64_0, key_64_1);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage2ReceiverProofMode {
    P2pkEOnly,
    SignatureOnly,
    SignatureAndP2pkE,
}

async fn create_stage2_receiver_proof_fixture(
    proof_mode: Stage2ReceiverProofMode,
) -> anyhow::Result<(Mint, cdk::nuts::SecretKey, Vec<Proof>)> {
    let test_mint = TestMintHelper::new().await?;
    let mint = test_mint.mint().clone();

    let alice_secret = cdk::nuts::SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = cdk::nuts::SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    let keyset_id = test_mint.active_sat_keyset_id;
    let keys = test_mint.public_keys_of_the_active_sat_keyset.clone();
    let input_fee_ppk = test_mint.input_fee_ppk;
    let keyset_info = KeysetInfo::new(
        keyset_id,
        test_mint.unit.clone(),
        keys.clone(),
        input_fee_ppk,
        test_mint.final_expiry,
    );

    let mint_amount = 100u64;
    let input_proofs = test_mint.mint_proofs(Amount::from(mint_amount)).await?;
    let num_input_proofs = input_proofs.len() as u64;
    let actual_fee = (input_fee_ppk * num_input_proofs).div_ceil(1000);
    let actual_funding = mint_amount - actual_fee;

    let capacity = 10u64;
    let balance = 5u64;
    let future_expiry = unix_time() + 3600;

    let params = ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "http://localhost:3338".to_string(),
        CurrencyUnit::Sat,
        capacity,
        actual_funding,
        future_expiry,
        unix_time(),
        keyset_info.clone(),
        64,
        &alice_secret,
    )?;

    let funding_outputs = DeterministicOutputsForOneContext::new(
        "funding".to_string(),
        actual_funding,
        params.clone(),
    )?;
    let funding_blinded_messages = funding_outputs.get_blinded_messages(None)?;
    let swap_request = SwapRequest::new(input_proofs, funding_blinded_messages);
    let swap_response = mint.process_swap_request(swap_request).await?;

    let secrets_with_blinding = funding_outputs.get_secrets_with_blinding()?;
    let blinding_factors = secrets_with_blinding
        .iter()
        .map(|s| s.blinding_factor.clone())
        .collect();
    let secrets = secrets_with_blinding
        .iter()
        .map(|s| s.secret.clone())
        .collect();
    let funding_proofs =
        construct_proofs(swap_response.signatures, blinding_factors, secrets, &keys)?;

    let commitment_outputs = CommitmentOutputs::for_balance(balance, &params)?;
    let mut close_swap = commitment_outputs.create_swap_request(funding_proofs, None)?;

    let alice_blinded_secret = params.get_sender_blinded_secret_key_for_stage1(&alice_secret)?;
    let charlie_blinded_secret =
        params.get_receiver_blinded_secret_key_for_stage1(&charlie_secret)?;
    close_swap.sign_sig_all(alice_blinded_secret)?;
    close_swap.sign_sig_all(charlie_blinded_secret)?;

    let close_response = mint.process_swap_request(close_swap).await?;
    let proofs_with_meta = commitment_outputs.unblind_all(close_response.signatures, &keys)?;

    let receiver_proofs = proofs_with_meta
        .into_iter()
        .filter(|p| p.is_receiver)
        .map(|proof_meta| {
            let mut proof = proof_meta.proof;
            match proof_mode {
                Stage2ReceiverProofMode::P2pkEOnly => {}
                Stage2ReceiverProofMode::SignatureOnly => {
                    let signing_key = params
                        .get_receiver_blinded_secret_key_for_stage2_output(
                            &charlie_secret,
                            proof_meta.amount,
                            proof_meta.index,
                        )
                        .expect("stage2 signing key");
                    proof.p2pk_e = None;
                    proof.sign_p2pk(signing_key).expect("sign stage2 proof");
                }
                Stage2ReceiverProofMode::SignatureAndP2pkE => {
                    let signing_key = params
                        .get_receiver_blinded_secret_key_for_stage2_output(
                            &charlie_secret,
                            proof_meta.amount,
                            proof_meta.index,
                        )
                        .expect("stage2 signing key");
                    proof.sign_p2pk(signing_key).expect("sign stage2 proof");
                }
            }
            proof
        })
        .collect();

    Ok((mint, charlie_secret, receiver_proofs))
}

async fn assert_wallet_can_receive_and_spend_stage2_receiver_proofs(
    mint: Mint,
    receiver_proofs: Vec<Proof>,
    receive_options: ReceiveOptions,
) -> anyhow::Result<()> {
    let connector = DirectMintConnection::new(mint.clone());
    let store = Arc::new(memory::empty().await?);
    let seed = random::<[u8; 64]>();
    let wallet = WalletBuilder::new()
        .mint_url("http://localhost:3338".parse().unwrap())
        .unit(CurrencyUnit::Sat)
        .localstore(store)
        .seed(seed)
        .client(connector)
        .build()?;

    let received_amount = wallet
        .receive_proofs(receiver_proofs, receive_options, None, None)
        .await?;
    let prepared = wallet
        .prepare_send(Amount::from(1u64), SendOptions::default())
        .await?;
    let _token = prepared.confirm(None).await?;
    assert!(received_amount > Amount::ZERO);
    Ok(())
}

#[tokio::test]
async fn test_stage2_receiver_can_sign_and_spend_with_wallet() -> anyhow::Result<()> {
    let (mint, charlie_secret, receiver_proofs) =
        create_stage2_receiver_proof_fixture(Stage2ReceiverProofMode::P2pkEOnly).await?;
    assert_wallet_can_receive_and_spend_stage2_receiver_proofs(
        mint,
        receiver_proofs,
        ReceiveOptions {
            p2pk_signing_keys: vec![charlie_secret],
            ..Default::default()
        },
    )
    .await
}

#[tokio::test]
async fn test_stage2_receiver_signature_only_can_spend_with_wallet() -> anyhow::Result<()> {
    let (mint, _charlie_secret, receiver_proofs) =
        create_stage2_receiver_proof_fixture(Stage2ReceiverProofMode::SignatureOnly).await?;
    assert_wallet_can_receive_and_spend_stage2_receiver_proofs(
        mint,
        receiver_proofs,
        ReceiveOptions::default(),
    )
    .await
}

#[tokio::test]
async fn test_stage2_receiver_signature_and_p2pk_e_can_spend_with_wallet() -> anyhow::Result<()> {
    let (mint, _charlie_secret, receiver_proofs) =
        create_stage2_receiver_proof_fixture(Stage2ReceiverProofMode::SignatureAndP2pkE).await?;
    assert_wallet_can_receive_and_spend_stage2_receiver_proofs(
        mint,
        receiver_proofs,
        ReceiveOptions::default(),
    )
    .await
}

// ====================================================================
// Client bridge test: end-to-end client+server flow
// ====================================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_client_bridge() -> anyhow::Result<()> {
    use cdk::nuts::nut00::token::Token;
    use cdk::nuts::PublicKey;
    use cdk_spilman::{
        base64_decode, BridgeError, ClientChannelFunding, ClientChannelOpeningFromSwap,
        ClientChannelState, ClientPaymentState, SpilmanClientBridge, SpilmanClientHost,
        SpilmanClientNetworking,
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    // ====================================================================
    // Test Client Networking: handles mint swap calls
    // ====================================================================

    struct TestClientNetworking {
        mint: Arc<Mint>,
    }

    impl SpilmanClientNetworking for TestClientNetworking {
        fn call_mint_swap(
            &self,
            _mint_url: &str,
            swap_request_json: &str,
        ) -> Result<String, String> {
            let swap_request: SwapRequest = serde_json::from_str(swap_request_json)
                .map_err(|e| format!("Failed to parse swap request: {}", e))?;
            let mint = Arc::clone(&self.mint);
            let response = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(async { mint.process_swap_request(swap_request).await })
            })
            .map_err(|e| {
                serde_json::to_string(&cdk_common::error::ErrorResponse::from(e))
                    .unwrap_or_else(|ser_err| format!("Mint swap failed: {ser_err}"))
            })?;
            serde_json::to_string(&response)
                .map_err(|e| format!("Failed to serialize swap response: {}", e))
        }

        fn call_mint_restore(
            &self,
            _mint_url: &str,
            restore_request_json: &str,
        ) -> Result<String, String> {
            let restore_request: RestoreRequest = serde_json::from_str(restore_request_json)
                .map_err(|e| format!("Failed to parse restore request: {}", e))?;
            let mint = Arc::clone(&self.mint);
            let response = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(async { mint.restore(restore_request).await })
            })
            .map_err(|e| {
                serde_json::to_string(&cdk_common::error::ErrorResponse::from(e))
                    .unwrap_or_else(|ser_err| format!("Mint restore failed: {ser_err}"))
            })?;
            serde_json::to_string(&response)
                .map_err(|e| format!("Failed to serialize restore response: {}", e))
        }

        fn call_mint_keysets(&self, _mint_url: &str) -> Result<String, String> {
            let response = self.mint.keysets();
            serde_json::to_string(&response)
                .map_err(|e| format!("Failed to serialize keysets response: {}", e))
        }

        fn call_mint_keys(&self, _mint_url: &str, keyset_id: &str) -> Result<String, String> {
            let id: cdk::nuts::Id = keyset_id
                .parse()
                .map_err(|e| format!("Invalid keyset ID: {}", e))?;
            let response = self
                .mint
                .keyset_pubkeys(&id)
                .map_err(|e| format!("Failed to get keyset pubkeys: {}", e))?;
            serde_json::to_string(&response)
                .map_err(|e| format!("Failed to serialize keys response: {}", e))
        }
    }

    // ====================================================================
    // Test Client Host: storage and crypto
    // ====================================================================

    struct TestClientHost {
        opening: Mutex<HashMap<String, ClientChannelOpeningFromSwap>>,
        funding: Mutex<HashMap<String, ClientChannelFunding>>,
        payments: Mutex<HashMap<String, ClientPaymentState>>,
        states: Mutex<HashMap<String, ClientChannelState>>,
        keys: Mutex<HashMap<String, String>>,
    }

    impl TestClientHost {
        fn register_key(&self, secret_hex: &str, pubkey_hex: &str) {
            self.keys
                .lock()
                .unwrap()
                .insert(pubkey_hex.to_string(), secret_hex.to_string());
        }
    }

    impl SpilmanClientHost for TestClientHost {
        fn save_opening_from_swap_channel(
            &self,
            channel_id: &str,
            opening: ClientChannelOpeningFromSwap,
        ) {
            self.opening
                .lock()
                .unwrap()
                .insert(channel_id.to_string(), opening);
        }

        fn mark_channel_open(&self, channel_id: &str, funding_proofs_json: &str) {
            if let Some(opening) = self.opening.lock().unwrap().remove(channel_id) {
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
                self.funding
                    .lock()
                    .unwrap()
                    .insert(channel_id.to_string(), funding);
            }
        }

        fn get_channel_funding(&self, channel_id: &str) -> Option<ClientChannelFunding> {
            self.funding.lock().unwrap().get(channel_id).cloned()
        }

        fn get_channel_opening_from_swap(
            &self,
            channel_id: &str,
        ) -> Option<ClientChannelOpeningFromSwap> {
            self.opening.lock().unwrap().get(channel_id).cloned()
        }

        fn get_payment_state(&self, channel_id: &str) -> Option<ClientPaymentState> {
            self.payments.lock().unwrap().get(channel_id).cloned()
        }

        fn record_payment(&self, channel_id: &str, state: ClientPaymentState) {
            self.payments
                .lock()
                .unwrap()
                .insert(channel_id.to_string(), state);
        }

        fn get_channel_state(&self, channel_id: &str) -> ClientChannelState {
            self.states
                .lock()
                .unwrap()
                .get(channel_id)
                .copied()
                .unwrap_or(ClientChannelState::Open)
        }

        fn mark_channel_closed(&self, channel_id: &str) {
            self.states
                .lock()
                .unwrap()
                .insert(channel_id.to_string(), ClientChannelState::Closed);
        }

        fn mark_channel_closing(&self, channel_id: &str) {
            self.states
                .lock()
                .unwrap()
                .insert(channel_id.to_string(), ClientChannelState::Closing);
        }

        fn list_channel_ids(&self) -> Vec<String> {
            self.funding.lock().unwrap().keys().cloned().collect()
        }

        fn delete_channel(&self, channel_id: &str) {
            self.funding.lock().unwrap().remove(channel_id);
            self.payments.lock().unwrap().remove(channel_id);
            self.states.lock().unwrap().remove(channel_id);
        }

        fn now_seconds(&self) -> u64 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        }

        fn sign_with_tweaked_key(
            &self,
            signer_pubkey_hex: &str,
            message_hex: &str,
            tweak_scalar_hex: &str,
        ) -> Result<String, String> {
            let secret_hex = self
                .keys
                .lock()
                .unwrap()
                .get(signer_pubkey_hex)
                .cloned()
                .ok_or_else(|| format!("No key registered for pubkey: {}", signer_pubkey_hex))?;
            cdk_spilman::sign_with_tweaked_key_util(&secret_hex, message_hex, tweak_scalar_hex)
        }

        fn compute_channel_secret(
            &self,
            sender_pubkey_hex: &str,
            receiver_pubkey_hex: &str,
        ) -> Result<String, String> {
            let secret_hex = self
                .keys
                .lock()
                .unwrap()
                .get(sender_pubkey_hex)
                .cloned()
                .ok_or_else(|| format!("No key registered for pubkey: {}", sender_pubkey_hex))?;
            cdk_spilman::compute_channel_secret_from_hex(&secret_hex, receiver_pubkey_hex)
        }
    }

    // ====================================================================
    // Test Server Host: wraps keyset info + stores channels
    // ====================================================================

    struct TestServerHost {
        keyset_ids: Vec<Id>,
        keyset_infos: HashMap<Id, String>,
        funding_data: Mutex<HashMap<String, (String, String, String, String)>>,
        payments: Mutex<HashMap<String, PaymentProof>>,
        charlie_secret_hex: String,
        amount_due: Arc<AtomicU64>,
    }

    impl SpilmanHost<String> for TestServerHost {
        fn receiver_key_is_acceptable(&self, _receiver_pubkey: &PublicKey) -> bool {
            true
        }
        fn mint_and_keyset_is_acceptable(&self, _mint: &str, _keyset_id: &Id) -> bool {
            true
        }
        fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
            self.funding_data
                .lock()
                .unwrap()
                .get(channel_id)
                .cloned()
                .map(
                    |(params_json, funding_proofs_json, channel_secret_hex, keyset_info_json)| {
                        ChannelFunding {
                            params_json,
                            funding_proofs_json,
                            channel_secret_hex,
                            keyset_info_json,
                        }
                    },
                )
        }
        fn save_funding(
            &self,
            channel_id: &str,
            funding: ChannelFunding,
            _initial_payment: PaymentProof,
        ) {
            self.funding_data.lock().unwrap().insert(
                channel_id.to_string(),
                (
                    funding.params_json,
                    funding.funding_proofs_json,
                    funding.channel_secret_hex,
                    funding.keyset_info_json,
                ),
            );
        }
        fn get_amount_due(&self, _channel_id: &str, _context_json: Option<&String>) -> u64 {
            self.amount_due.load(Ordering::Relaxed)
        }
        fn record_payment(&self, channel_id: &str, payment: PaymentProof, _context_json: &String) {
            self.payments
                .lock()
                .unwrap()
                .insert(channel_id.to_string(), payment);
        }
        fn get_channel_state(&self, _channel_id: &str) -> ChannelState {
            ChannelState::Open
        }
        fn mark_channel_closing(
            &self,
            _channel_id: &str,
            _expiry_timestamp: u64,
            _payment: PaymentProof,
        ) -> Result<(), String> {
            Ok(())
        }
        fn get_closing_data(&self, _channel_id: &str) -> Option<ClosingData> {
            None
        }
        fn get_channel_policy(&self, _unit: &str) -> Option<ChannelPolicy> {
            Some(ChannelPolicy {
                min_expiry_in_seconds: 3600,
                min_capacity: 10,
                max_amount_per_output: None,
            })
        }
        fn now_seconds(&self) -> u64 {
            unix_time()
        }
        fn get_balance_and_signature_for_unilateral_exit(
            &self,
            channel_id: &str,
        ) -> Option<PaymentProof> {
            self.payments.lock().unwrap().get(channel_id).cloned()
        }
        fn get_active_keyset_ids(&self, _mint: &str, _unit: &CurrencyUnit) -> Vec<Id> {
            self.keyset_ids.clone()
        }
        fn get_keyset_info(&self, _mint: &str, keyset_id: &Id) -> Option<String> {
            self.keyset_infos.get(keyset_id).cloned()
        }
        fn mark_channel_closed(
            &self,
            _channel_id: &str,
            _expiry_timestamp: u64,
            _balance: u64,
            _receiver_proofs_json: &str,
            _sender_proofs_json: &str,
            _receiver_sum: u64,
            _sender_sum: u64,
        ) -> Result<(), String> {
            Ok(())
        }
        fn compute_channel_secret(
            &self,
            _receiver_pubkey_hex: &str,
            sender_pubkey_hex: &str,
        ) -> Result<String, String> {
            cdk_spilman::compute_channel_secret_from_hex(
                &self.charlie_secret_hex,
                sender_pubkey_hex,
            )
        }
        fn sign_with_tweaked_key(
            &self,
            _signer_pubkey_hex: &str,
            message_hex: &str,
            tweak_scalar_hex: &str,
        ) -> Result<String, String> {
            cdk_spilman::sign_with_tweaked_key_util(
                &self.charlie_secret_hex,
                message_hex,
                tweak_scalar_hex,
            )
        }
    }

    impl SpilmanNetworking for TestServerHost {
        fn call_mint_swap(
            &self,
            _mint_url: &str,
            _swap_request_json: &str,
        ) -> Result<String, String> {
            Err("not used in this test".to_string())
        }
        fn refresh_all_keysets(&self, _mint: &str) -> Result<(), String> {
            Ok(())
        }
    }

    // ====================================================================
    // Setup
    // ====================================================================

    let charlie_secret = cdk::nuts::SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    let shared_mint = Arc::new(create_test_mint().await?);

    let active_keyset_id = shared_mint
        .get_active_keysets()
        .get(&CurrencyUnit::Sat)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing SAT keyset"))?;
    let keyset_pubkeys = shared_mint.keyset_pubkeys(&active_keyset_id)?;
    let keyset = keyset_pubkeys
        .keysets
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing keyset"))?;
    let shared_keys = keyset.keys.clone();
    let shared_fee_ppk = shared_mint
        .keysets()
        .keysets
        .iter()
        .find(|k| k.id == active_keyset_id)
        .ok_or_else(|| anyhow::anyhow!("missing keyset info"))?
        .input_fee_ppk;

    let keyset_info_json = serde_json::json!({
        "keysetId": active_keyset_id.to_string(),
        "unit": "sat",
        "inputFeePpk": shared_fee_ppk,
        "keys": shared_keys.iter().map(|(amt, pk)| {
            (u64::from(*amt).to_string(), pk.to_hex())
        }).collect::<HashMap<_, _>>()
    })
    .to_string();

    let input_amount = Amount::from(100u64);
    let proofs = mint_test_proofs(&shared_mint, input_amount).await?;
    let token = Token::new(
        "http://localhost:3338".parse().unwrap(),
        proofs,
        None,
        CurrencyUnit::Sat,
    );
    let token_string = token.to_string();

    let alice_secret = cdk::nuts::SecretKey::generate();
    let sender_pubkey_hex = alice_secret.public_key().to_hex();

    let client_host = TestClientHost {
        opening: Mutex::new(HashMap::new()),
        funding: Mutex::new(HashMap::new()),
        payments: Mutex::new(HashMap::new()),
        states: Mutex::new(HashMap::new()),
        keys: Mutex::new(HashMap::new()),
    };
    client_host.register_key(&alice_secret.to_secret_hex(), &sender_pubkey_hex);

    let client_networking = TestClientNetworking {
        mint: Arc::clone(&shared_mint),
    };
    let client_bridge = SpilmanClientBridge::new(client_host, client_networking);

    // ====================================================================
    // Open channel from token
    // ====================================================================

    let expiry_timestamp = unix_time() + 7200;
    let max_amount = 64u64;

    let open_result = client_bridge
        .open_channel_from_token(
            &token_string,
            &receiver_pubkey.to_hex(),
            &sender_pubkey_hex,
            expiry_timestamp,
            &keyset_info_json,
            max_amount,
        )
        .map_err(anyhow::Error::msg)?;

    assert!(open_result.capacity > 0);
    assert!(open_result.capacity <= 100);

    let channels = client_bridge.list_channels();
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[0], open_result.channel_id);

    let info = client_bridge
        .get_channel_info(&open_result.channel_id)
        .ok_or_else(|| anyhow::anyhow!("missing channel info"))?;
    assert_eq!(info.capacity, open_result.capacity);

    // ====================================================================
    // Create payment (tests signature creation)
    // ====================================================================

    // Use create_payment_with_funding for the first payment
    let payment = client_bridge
        .create_payment_with_funding(&open_result.channel_id, 10)
        .map_err(anyhow::Error::msg)?;

    assert_eq!(payment.channel_id, open_result.channel_id);
    assert_eq!(payment.balance, 10);
    assert!(!payment.signature.is_empty());
    assert!(payment.has_funding());

    // ====================================================================
    // Build payment header (with funding)
    // ====================================================================

    let header_with_funding = client_bridge
        .build_payment_header(&open_result.channel_id, 10, true)
        .map_err(anyhow::Error::msg)?;

    let decoded = base64_decode(&header_with_funding).map_err(anyhow::Error::msg)?;
    let header_json: serde_json::Value = serde_json::from_str(&decoded)?;

    assert_eq!(
        header_json["channel_id"].as_str().unwrap(),
        open_result.channel_id
    );
    assert_eq!(header_json["balance"].as_u64().unwrap(), 10);
    assert!(header_json["signature"].as_str().is_some());
    assert!(header_json["params"].is_object());
    assert!(header_json["funding_proofs"].is_array());

    // ====================================================================
    // Build payment header (without funding)
    // ====================================================================

    let header_no_funding = client_bridge
        .build_payment_header(&open_result.channel_id, 20, false)
        .map_err(anyhow::Error::msg)?;

    let decoded2 = base64_decode(&header_no_funding).map_err(anyhow::Error::msg)?;
    let header_json2: serde_json::Value = serde_json::from_str(&decoded2)?;

    assert_eq!(header_json2["balance"].as_u64().unwrap(), 20);
    assert!(header_json2.get("params").is_none());
    assert!(header_json2.get("funding_proofs").is_none());

    // ====================================================================
    // Feed headers into server-side SpilmanBridge (end-to-end!)
    // ====================================================================

    let mut keyset_infos = HashMap::new();
    keyset_infos.insert(active_keyset_id, keyset_info_json.clone());

    let amount_due = Arc::new(AtomicU64::new(0));
    let server_host = TestServerHost {
        keyset_ids: vec![active_keyset_id],
        keyset_infos,
        funding_data: Mutex::new(HashMap::new()),
        payments: Mutex::new(HashMap::new()),
        charlie_secret_hex: charlie_secret.to_secret_hex(),
        amount_due: amount_due.clone(),
    };

    let server_bridge = SpilmanBridge::new(server_host);

    let payment_result = server_bridge
        .process_payment_via_base64_header(
            &header_with_funding,
            &serde_json::json!({"type": "test"}).to_string(),
        )
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    assert_eq!(payment_result.channel_id, open_result.channel_id);
    assert_eq!(payment_result.balance, 10);
    assert_eq!(payment_result.capacity, open_result.capacity);

    let payment_result2 = server_bridge
        .process_payment_via_base64_header(
            &header_no_funding,
            &serde_json::json!({"type": "test"}).to_string(),
        )
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    assert_eq!(payment_result2.balance, 20);

    // ====================================================================
    // Amount due checks
    // ====================================================================

    amount_due.store(15, Ordering::Relaxed);

    let due = server_bridge
        .verify_payment_covers_amount_due_via_base64_header(
            &header_no_funding,
            &serde_json::json!({"type": "test"}).to_string(),
        )
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    assert_eq!(due, 15);

    let ok = server_bridge
        .payment_covers_amount_due_via_base64_header(
            &header_no_funding,
            &serde_json::json!({"type": "test"}).to_string(),
        )
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    assert!(ok);

    let ok = server_bridge
        .payment_covers_amount_due_via_base64_header(
            &header_with_funding,
            &serde_json::json!({"type": "test"}).to_string(),
        )
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    assert!(!ok);

    let err = server_bridge
        .verify_payment_covers_amount_due_via_base64_header(
            &header_with_funding,
            &serde_json::json!({"type": "test"}).to_string(),
        )
        .unwrap_err();
    match err {
        BridgeError::InsufficientBalance {
            balance,
            amount_due,
        } => {
            assert_eq!(balance, 10);
            assert_eq!(amount_due, 15);
        }
        other => panic!("Unexpected error: {:?}", other),
    }

    // Marking a channel unusable keeps it in storage but blocks new payments.
    client_bridge.mark_channel_unusable(&open_result.channel_id);
    let info = client_bridge
        .get_channel_info(&open_result.channel_id)
        .ok_or_else(|| anyhow::anyhow!("missing channel info after mark_channel_unusable"))?;
    assert_eq!(info.state, ClientChannelState::Closing);
    let err = client_bridge
        .create_payment(&open_result.channel_id, 21)
        .expect_err("closing channel should reject new payments");
    assert!(err.contains("not usable for payments"));

    // ====================================================================
    // Delete channel
    // ====================================================================

    client_bridge.delete_channel(&open_result.channel_id);
    assert!(client_bridge
        .get_channel_info(&open_result.channel_id)
        .is_none());
    assert_eq!(client_bridge.list_channels().len(), 0);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_client_bridge_preserves_structured_mint_error() -> anyhow::Result<()> {
    use cdk::nuts::nut00::token::Token;
    use cdk_spilman::{
        ClientChannelFunding, ClientChannelOpeningFromSwap, ClientChannelState, ClientPaymentState,
        SpilmanClientBridge, SpilmanClientHost, SpilmanClientNetworking,
    };
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Networking that always returns an error
    struct FailingClientNetworking {
        mint_error_json: String,
    }

    impl SpilmanClientNetworking for FailingClientNetworking {
        fn call_mint_swap(&self, _: &str, _: &str) -> Result<String, String> {
            Err(self.mint_error_json.clone())
        }

        fn call_mint_restore(&self, _: &str, _: &str) -> Result<String, String> {
            Err(self.mint_error_json.clone())
        }

        fn call_mint_keysets(&self, _: &str) -> Result<String, String> {
            Err(self.mint_error_json.clone())
        }

        fn call_mint_keys(&self, _: &str, _: &str) -> Result<String, String> {
            Err(self.mint_error_json.clone())
        }
    }

    // Host that stores nothing (swap will fail before storage is used)
    struct FailingClientHost {
        keys: Mutex<HashMap<String, String>>,
    }

    impl FailingClientHost {
        fn register_key(&self, secret_hex: &str, pubkey_hex: &str) {
            self.keys
                .lock()
                .expect("key lock")
                .insert(pubkey_hex.to_string(), secret_hex.to_string());
        }
    }

    impl SpilmanClientHost for FailingClientHost {
        fn save_opening_from_swap_channel(&self, _: &str, _: ClientChannelOpeningFromSwap) {}

        fn mark_channel_open(&self, _: &str, _: &str) {}

        fn get_channel_funding(&self, _: &str) -> Option<ClientChannelFunding> {
            None
        }

        fn get_channel_opening_from_swap(&self, _: &str) -> Option<ClientChannelOpeningFromSwap> {
            None
        }

        fn get_payment_state(&self, _: &str) -> Option<ClientPaymentState> {
            None
        }

        fn record_payment(&self, _: &str, _: ClientPaymentState) {}

        fn get_channel_state(&self, _: &str) -> ClientChannelState {
            ClientChannelState::Open
        }

        fn mark_channel_closed(&self, _: &str) {}

        fn mark_channel_closing(&self, _: &str) {}

        fn list_channel_ids(&self) -> Vec<String> {
            Vec::new()
        }

        fn delete_channel(&self, _: &str) {}

        fn now_seconds(&self) -> u64 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        }

        fn sign_with_tweaked_key(&self, _: &str, _: &str, _: &str) -> Result<String, String> {
            Err("not used in this test".to_string())
        }

        fn compute_channel_secret(
            &self,
            sender_pubkey_hex: &str,
            receiver_pubkey_hex: &str,
        ) -> Result<String, String> {
            let secret_hex = self
                .keys
                .lock()
                .expect("key lock")
                .get(sender_pubkey_hex)
                .cloned()
                .ok_or_else(|| format!("No key registered for pubkey: {}", sender_pubkey_hex))?;
            cdk_spilman::compute_channel_secret_from_hex(&secret_hex, receiver_pubkey_hex)
        }
    }

    let receiver_pubkey = cdk::nuts::SecretKey::generate().public_key();
    let shared_mint = Arc::new(create_test_mint().await?);

    let active_keyset_id = shared_mint
        .get_active_keysets()
        .get(&CurrencyUnit::Sat)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing SAT keyset"))?;
    let keyset_pubkeys = shared_mint.keyset_pubkeys(&active_keyset_id)?;
    let keyset = keyset_pubkeys
        .keysets
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing keyset"))?;
    let shared_keys = keyset.keys.clone();
    let shared_fee_ppk = shared_mint
        .keysets()
        .keysets
        .iter()
        .find(|k| k.id == active_keyset_id)
        .ok_or_else(|| anyhow::anyhow!("missing keyset info"))?
        .input_fee_ppk;

    let keyset_info_json = serde_json::json!({
        "keysetId": active_keyset_id.to_string(),
        "unit": "sat",
        "inputFeePpk": shared_fee_ppk,
        "keys": shared_keys.iter().map(|(amt, pk)| {
            (u64::from(*amt).to_string(), pk.to_hex())
        }).collect::<HashMap<_, _>>()
    })
    .to_string();

    let proofs = mint_test_proofs(&shared_mint, Amount::from(100u64)).await?;
    let token = Token::new(
        "http://localhost:3338".parse().unwrap(),
        proofs,
        None,
        CurrencyUnit::Sat,
    );
    let token_string = token.to_string();

    let alice_secret = cdk::nuts::SecretKey::generate();
    let sender_pubkey_hex = alice_secret.public_key().to_hex();

    let host = FailingClientHost {
        keys: Mutex::new(HashMap::new()),
    };
    host.register_key(&alice_secret.to_secret_hex(), &sender_pubkey_hex);

    let networking = FailingClientNetworking {
        mint_error_json: serde_json::to_string_pretty(&serde_json::json!({
            "code": 12001,
            "detail": "Unknown Keyset"
        }))?,
    };

    let bridge = SpilmanClientBridge::new(host, networking);
    let err = bridge
        .open_channel_from_token(
            &token_string,
            &receiver_pubkey.to_hex(),
            &sender_pubkey_hex,
            unix_time() + 7200,
            &keyset_info_json,
            64,
        )
        .expect_err("open_channel_from_token should return the mint error");

    let err_json: serde_json::Value = serde_json::from_str(&err)?;
    assert_eq!(err_json["code"], serde_json::json!(12001));
    assert_eq!(err_json["detail"], serde_json::json!("Unknown Keyset"));

    Ok(())
}

// ====================================================================
// Close-balance tests: cooperative and unilateral close with overpayment
// ====================================================================

mod close_balance_tests {
    use super::*;
    use cdk::nuts::{CurrencyUnit as CU, PublicKey};
    use cdk_spilman as bindings;
    use std::cell::{Cell, RefCell};
    use std::sync::Mutex;

    pub(super) struct OverpaymentTestHost {
        pub mint: Arc<Mint>,
        keyset_id: Id,
        keyset_infos: HashMap<Id, String>,
        funding_data: Mutex<HashMap<String, (String, String, String, String)>>,
        pub channel_state: RefCell<ChannelState>,
        closing_data: RefCell<Option<ClosingData>>,
        stored_payment: RefCell<Option<PaymentProof>>,
        amount_due: Cell<u64>,
        charlie_secret_hex: String,
        pub swap_call_count: Cell<u32>,
        pub closed_data: RefCell<Option<(u64, u64, String, String)>>,
    }

    impl SpilmanHost<String> for OverpaymentTestHost {
        fn receiver_key_is_acceptable(&self, _receiver_pubkey: &PublicKey) -> bool {
            true
        }
        fn mint_and_keyset_is_acceptable(&self, _mint: &str, _keyset_id: &Id) -> bool {
            true
        }
        fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
            self.funding_data
                .lock()
                .unwrap()
                .get(channel_id)
                .cloned()
                .map(
                    |(params_json, funding_proofs_json, channel_secret_hex, keyset_info_json)| {
                        ChannelFunding {
                            params_json,
                            funding_proofs_json,
                            channel_secret_hex,
                            keyset_info_json,
                        }
                    },
                )
        }
        fn save_funding(
            &self,
            channel_id: &str,
            funding: ChannelFunding,
            _initial_payment: PaymentProof,
        ) {
            self.funding_data.lock().unwrap().insert(
                channel_id.to_string(),
                (
                    funding.params_json,
                    funding.funding_proofs_json,
                    funding.channel_secret_hex,
                    funding.keyset_info_json,
                ),
            );
        }
        fn get_amount_due(&self, _channel_id: &str, _context_json: Option<&String>) -> u64 {
            self.amount_due.get()
        }
        fn record_payment(&self, _channel_id: &str, payment: PaymentProof, _context_json: &String) {
            *self.stored_payment.borrow_mut() = Some(payment);
        }
        fn get_channel_state(&self, _channel_id: &str) -> ChannelState {
            self.channel_state.borrow().clone()
        }
        fn mark_channel_closing(
            &self,
            _channel_id: &str,
            expiry_timestamp: u64,
            payment: PaymentProof,
        ) -> Result<(), String> {
            *self.channel_state.borrow_mut() = ChannelState::Closing;
            *self.stored_payment.borrow_mut() = Some(payment.clone());
            *self.closing_data.borrow_mut() = Some(ClosingData {
                expiry_timestamp,
                balance: payment.balance,
                signature: payment.signature,
            });
            Ok(())
        }
        fn get_closing_data(&self, _channel_id: &str) -> Option<ClosingData> {
            self.closing_data.borrow().clone()
        }
        fn get_channel_policy(&self, _unit: &str) -> Option<ChannelPolicy> {
            Some(ChannelPolicy {
                min_expiry_in_seconds: 3600,
                min_capacity: 10,
                max_amount_per_output: None,
            })
        }
        fn now_seconds(&self) -> u64 {
            unix_time()
        }
        fn get_balance_and_signature_for_unilateral_exit(
            &self,
            _channel_id: &str,
        ) -> Option<PaymentProof> {
            self.stored_payment.borrow().clone()
        }
        fn get_active_keyset_ids(&self, _mint: &str, _unit: &CU) -> Vec<Id> {
            vec![self.keyset_id]
        }
        fn get_keyset_info(&self, _mint: &str, keyset_id: &Id) -> Option<String> {
            self.keyset_infos.get(keyset_id).cloned()
        }
        fn mark_channel_closed(
            &self,
            _channel_id: &str,
            _expiry_timestamp: u64,
            balance: u64,
            receiver_proofs_json: &str,
            sender_proofs_json: &str,
            receiver_sum: u64,
            sender_sum: u64,
        ) -> Result<(), String> {
            *self.channel_state.borrow_mut() = ChannelState::Closed;
            *self.closed_data.borrow_mut() = Some((
                balance,
                receiver_sum + sender_sum,
                receiver_proofs_json.to_string(),
                sender_proofs_json.to_string(),
            ));
            Ok(())
        }
        fn compute_channel_secret(
            &self,
            _receiver_pubkey_hex: &str,
            sender_pubkey_hex: &str,
        ) -> Result<String, String> {
            bindings::compute_channel_secret_from_hex(&self.charlie_secret_hex, sender_pubkey_hex)
        }
        fn sign_with_tweaked_key(
            &self,
            _signer_pubkey_hex: &str,
            message_hex: &str,
            tweak_scalar_hex: &str,
        ) -> Result<String, String> {
            bindings::sign_with_tweaked_key_util(
                &self.charlie_secret_hex,
                message_hex,
                tweak_scalar_hex,
            )
        }
    }

    impl SpilmanNetworking for OverpaymentTestHost {
        fn refresh_all_keysets(&self, _mint: &str) -> Result<(), String> {
            Ok(())
        }
        fn call_mint_swap(
            &self,
            _mint_url: &str,
            swap_request_json: &str,
        ) -> Result<String, String> {
            self.swap_call_count.set(self.swap_call_count.get() + 1);
            let swap_request: SwapRequest = serde_json::from_str(swap_request_json)
                .map_err(|e| format!("Failed to parse swap request: {}", e))?;
            let mint = Arc::clone(&self.mint);
            let response = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(async { mint.process_swap_request(swap_request).await })
            })
            .map_err(|e| serde_json::json!({"detail": e.to_string(), "code": 0}).to_string())?;
            serde_json::to_string(&response)
                .map_err(|e| format!("Failed to serialize swap response: {}", e))
        }
    }

    fn keyset_info_json_from_mint(mint: &Mint, keyset_id: Id) -> String {
        let pubkeys = mint.keyset_pubkeys(&keyset_id).expect("keyset pubkeys");
        let keyset = pubkeys.keysets.first().expect("keyset");
        let keys = &keyset.keys;
        let fee_ppk = mint
            .keysets()
            .keysets
            .iter()
            .find(|k| k.id == keyset_id)
            .expect("keyset info")
            .input_fee_ppk;
        serde_json::json!({
            "keysetId": keyset_id.to_string(),
            "unit": "sat",
            "inputFeePpk": fee_ppk,
            "keys": keys.iter().map(|(amt, pk)| {
                (u64::from(*amt).to_string(), pk.to_hex())
            }).collect::<HashMap<String, String>>()
        })
        .to_string()
    }

    pub(super) struct OverpaymentScenario {
        pub bridge: SpilmanBridge<OverpaymentTestHost, String>,
        pub shared_mint: Arc<Mint>,
        pub channel_id: String,
        pub overpayment_balance: u64,
        pub amount_due: u64,
        pub close_signature: String,
    }

    pub(super) async fn setup_overpayment_scenario() -> OverpaymentScenario {
        let shared_mint = Arc::new(create_test_mint().await.unwrap());

        let keyset_id = shared_mint
            .get_active_keysets()
            .get(&CurrencyUnit::Sat)
            .cloned()
            .expect("SAT keyset");
        let keyset_info_json = keyset_info_json_from_mint(&shared_mint, keyset_id);
        let keyset_keys: Keys = {
            let pubkeys = shared_mint.keyset_pubkeys(&keyset_id).unwrap();
            pubkeys.keysets.first().unwrap().keys.clone()
        };
        let fee_ppk = shared_mint
            .keysets()
            .keysets
            .iter()
            .find(|k| k.id == keyset_id)
            .unwrap()
            .input_fee_ppk;

        let alice_secret = cdk::nuts::SecretKey::generate();
        let sender_pubkey = alice_secret.public_key();
        let charlie_secret = cdk::nuts::SecretKey::generate();
        let receiver_pubkey = charlie_secret.public_key();

        let mint_amount = 200u64;
        let input_proofs = mint_test_proofs(&shared_mint, Amount::from(mint_amount))
            .await
            .expect("mint proofs");
        let num_inputs = input_proofs.len() as u64;
        let actual_fee = (fee_ppk * num_inputs).div_ceil(1000);
        let actual_funding = mint_amount - actual_fee;

        let capacity = 100u64;
        let expiry_timestamp = unix_time() + 7200;
        let keyset_info = KeysetInfo::new(
            keyset_id,
            CurrencyUnit::Sat,
            keyset_keys.clone(),
            fee_ppk,
            None,
        );

        let params = ChannelParameters::new_with_secret_key(
            sender_pubkey,
            receiver_pubkey,
            "http://localhost:3338".to_string(),
            CurrencyUnit::Sat,
            capacity,
            actual_funding,
            expiry_timestamp,
            unix_time(),
            keyset_info,
            64,
            &alice_secret,
        )
        .expect("channel params");
        let channel_id = params.get_channel_id();
        let channel_secret = params.channel_secret;

        let funding_outputs = DeterministicOutputsForOneContext::new(
            "funding".to_string(),
            actual_funding,
            params.clone(),
        )
        .expect("funding outputs");
        let funding_messages = funding_outputs
            .get_blinded_messages(None)
            .expect("blinded messages");
        let swap_request = SwapRequest::new(input_proofs, funding_messages);
        let swap_response = shared_mint
            .process_swap_request(swap_request)
            .await
            .expect("funding swap");

        let swb = funding_outputs
            .get_secrets_with_blinding()
            .expect("secrets");
        let blinding_factors = swb.iter().map(|s| s.blinding_factor.clone()).collect();
        let secrets = swb.iter().map(|s| s.secret.clone()).collect();
        let funding_proofs = construct_proofs(
            swap_response.signatures,
            blinding_factors,
            secrets,
            &keyset_keys,
        )
        .expect("construct proofs");

        let channel =
            EstablishedChannel::new(params.clone(), funding_proofs.clone()).expect("channel");
        let sender = SpilmanChannelSender::new(alice_secret.clone(), channel);

        let overpayment_balance = 50u64;
        let (overpay_update, _) = sender
            .create_signed_balance_update(overpayment_balance)
            .unwrap();

        let amount_due = 10u64;
        let (close_update, _) = sender.create_signed_balance_update(amount_due).unwrap();

        let params_json = params.get_channel_id_params_json();
        let funding_proofs_json = serde_json::to_string(&funding_proofs).unwrap();
        let channel_secret_hex = hex::encode(channel_secret);

        let mut keyset_infos = HashMap::new();
        keyset_infos.insert(keyset_id, keyset_info_json);

        let mut funding_data_map = HashMap::new();
        funding_data_map.insert(
            channel_id.clone(),
            (
                params_json,
                funding_proofs_json,
                channel_secret_hex,
                keyset_infos.get(&keyset_id).unwrap().clone(),
            ),
        );

        let host = OverpaymentTestHost {
            mint: Arc::clone(&shared_mint),
            keyset_id,
            keyset_infos,
            funding_data: Mutex::new(funding_data_map),
            channel_state: RefCell::new(ChannelState::Open),
            closing_data: RefCell::new(None),
            stored_payment: RefCell::new(Some(PaymentProof {
                balance: overpayment_balance,
                signature: overpay_update.signature.to_string(),
            })),
            amount_due: Cell::new(amount_due),
            charlie_secret_hex: charlie_secret.to_secret_hex(),
            swap_call_count: Cell::new(0),
            closed_data: RefCell::new(None),
        };

        let bridge = SpilmanBridge::new(host);

        OverpaymentScenario {
            bridge,
            shared_mint,
            channel_id,
            overpayment_balance,
            amount_due,
            close_signature: close_update.signature.to_string(),
        }
    }

    pub(super) async fn verify_receiver_proofs_spendable(
        receiver_proofs_json: &str,
        shared_mint: &Arc<Mint>,
    ) -> Amount {
        let receiver_proofs: Vec<serde_json::Value> =
            serde_json::from_str(receiver_proofs_json).expect("receiver proofs JSON");
        assert!(!receiver_proofs.is_empty(), "Receiver should get proofs");
        for (i, proof) in receiver_proofs.iter().enumerate() {
            let p2pk_e = proof.get("p2pk_e");
            assert!(
                p2pk_e.is_some() && !p2pk_e.unwrap().is_null(),
                "Receiver proof {} should include p2pk_e",
                i
            );
            let witness = proof.get("witness");
            assert!(
                witness.is_some() && !witness.unwrap().is_null(),
                "Receiver proof {} should have witness",
                i
            );
        }

        let typed_receiver_proofs: Vec<Proof> =
            serde_json::from_str(receiver_proofs_json).expect("parse receiver proofs");

        let connector = DirectMintConnection::new((**shared_mint).clone());
        let store = Arc::new(memory::empty().await.expect("wallet store"));
        let seed = random::<[u8; 64]>();
        let wallet = WalletBuilder::new()
            .mint_url("http://localhost:3338".parse().unwrap())
            .unit(CurrencyUnit::Sat)
            .localstore(store)
            .seed(seed)
            .client(connector)
            .build()
            .expect("wallet build");

        let received_amount = wallet
            .receive_proofs(typed_receiver_proofs, ReceiveOptions::default(), None, None)
            .await
            .expect("wallet should accept signed receiver proofs");
        assert!(received_amount > Amount::ZERO);
        received_amount
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_cooperative_close_with_overpayment() -> anyhow::Result<()> {
    let s = close_balance_tests::setup_overpayment_scenario().await;

    let payment_json = serde_json::json!({
        "channel_id": s.channel_id,
        "balance": s.amount_due,
        "signature": s.close_signature,
    })
    .to_string();

    let result = s
        .bridge
        .execute_cooperative_close(&payment_json, s.bridge.host());
    let success = result.expect("Cooperative close should succeed");

    assert_eq!(s.bridge.host().swap_call_count.get(), 1);
    assert!(matches!(
        *s.bridge.host().channel_state.borrow(),
        ChannelState::Closed
    ));

    let closed = s.bridge.host().closed_data.borrow();
    let (closed_balance, _closed_total, ref receiver_proofs_json, ref _sender_proofs_json) = closed
        .as_ref()
        .expect("mark_channel_closed should have been called");

    assert_eq!(
        *closed_balance, s.amount_due,
        "Closed balance should be amount_due ({}), not overpayment ({})",
        s.amount_due, s.overpayment_balance
    );
    assert!(success.receiver_sum > 0);
    assert!(success.receiver_sum < 20);

    close_balance_tests::verify_receiver_proofs_spendable(receiver_proofs_json, &s.shared_mint)
        .await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_unilateral_close_uses_latest_payment_balance() -> anyhow::Result<()> {
    let s = close_balance_tests::setup_overpayment_scenario().await;

    let result = s
        .bridge
        .execute_unilateral_close(&s.channel_id, s.bridge.host());
    let success = result.expect("Unilateral close should succeed");

    assert_eq!(s.bridge.host().swap_call_count.get(), 1);
    assert!(matches!(
        *s.bridge.host().channel_state.borrow(),
        ChannelState::Closed
    ));

    let closed = s.bridge.host().closed_data.borrow();
    let (closed_balance, _closed_total, ref receiver_proofs_json, ref _sender_proofs_json) = closed
        .as_ref()
        .expect("mark_channel_closed should have been called");

    assert_eq!(
        *closed_balance, s.overpayment_balance,
        "Closed balance should be latest payment ({}), not amount_due ({})",
        s.overpayment_balance, s.amount_due
    );
    assert!(success.receiver_sum > 0);
    assert!(success.receiver_sum > 30);

    close_balance_tests::verify_receiver_proofs_spendable(receiver_proofs_json, &s.shared_mint)
        .await;
    Ok(())
}

// ====================================================================
// Keyset-rotation retry tests: cooperative and unilateral close
// ====================================================================

mod retry_tests {
    use super::*;
    use cdk::nuts::PublicKey;
    use cdk_spilman as bindings;
    use std::cell::{Cell, RefCell};
    use std::sync::Mutex;

    pub(super) struct RetryTestHost {
        pub mint: Arc<Mint>,
        pub active_keyset_ids: RefCell<Vec<Id>>,
        pub fresh_keyset_id: Id,
        pub keyset_infos: HashMap<Id, String>,
        pub funding_data: Mutex<HashMap<String, (String, String, String, String)>>,
        pub channel_state: RefCell<ChannelState>,
        pub closing_data: RefCell<Option<ClosingData>>,
        pub stored_payment: RefCell<Option<PaymentProof>>,
        pub amount_due: Cell<u64>,
        pub charlie_secret_hex: String,
        pub swap_call_count: Cell<u32>,
        pub refresh_count: Cell<u32>,
        pub closed_data: RefCell<Option<(u64, u64, String, String)>>,
        /// The NUT-00 error JSON from the most recent failed swap, if any.
        pub last_swap_error: RefCell<Option<String>>,
    }

    impl SpilmanHost<String> for RetryTestHost {
        fn receiver_key_is_acceptable(&self, _receiver_pubkey: &PublicKey) -> bool {
            true
        }
        fn mint_and_keyset_is_acceptable(&self, _mint: &str, _keyset_id: &Id) -> bool {
            true
        }
        fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
            self.funding_data
                .lock()
                .unwrap()
                .get(channel_id)
                .cloned()
                .map(
                    |(params_json, funding_proofs_json, channel_secret_hex, keyset_info_json)| {
                        ChannelFunding {
                            params_json,
                            funding_proofs_json,
                            channel_secret_hex,
                            keyset_info_json,
                        }
                    },
                )
        }
        fn save_funding(
            &self,
            channel_id: &str,
            funding: ChannelFunding,
            _initial_payment: PaymentProof,
        ) {
            self.funding_data.lock().unwrap().insert(
                channel_id.to_string(),
                (
                    funding.params_json,
                    funding.funding_proofs_json,
                    funding.channel_secret_hex,
                    funding.keyset_info_json,
                ),
            );
        }
        fn get_amount_due(&self, _channel_id: &str, _context_json: Option<&String>) -> u64 {
            self.amount_due.get()
        }
        fn record_payment(&self, _channel_id: &str, payment: PaymentProof, _context_json: &String) {
            *self.stored_payment.borrow_mut() = Some(payment);
        }
        fn get_channel_state(&self, _channel_id: &str) -> ChannelState {
            self.channel_state.borrow().clone()
        }
        fn mark_channel_closing(
            &self,
            _channel_id: &str,
            expiry_timestamp: u64,
            payment: PaymentProof,
        ) -> Result<(), String> {
            *self.channel_state.borrow_mut() = ChannelState::Closing;
            *self.stored_payment.borrow_mut() = Some(payment.clone());
            *self.closing_data.borrow_mut() = Some(ClosingData {
                expiry_timestamp,
                balance: payment.balance,
                signature: payment.signature,
            });
            Ok(())
        }
        fn get_closing_data(&self, _channel_id: &str) -> Option<ClosingData> {
            self.closing_data.borrow().clone()
        }
        fn get_channel_policy(&self, _unit: &str) -> Option<ChannelPolicy> {
            Some(ChannelPolicy {
                min_expiry_in_seconds: 3600,
                min_capacity: 10,
                max_amount_per_output: None,
            })
        }
        fn now_seconds(&self) -> u64 {
            unix_time()
        }
        fn get_balance_and_signature_for_unilateral_exit(
            &self,
            _channel_id: &str,
        ) -> Option<PaymentProof> {
            self.stored_payment.borrow().clone()
        }
        fn get_active_keyset_ids(&self, _mint: &str, _unit: &CurrencyUnit) -> Vec<Id> {
            self.active_keyset_ids.borrow().clone()
        }
        fn get_keyset_info(&self, _mint: &str, keyset_id: &Id) -> Option<String> {
            self.keyset_infos.get(keyset_id).cloned()
        }
        fn mark_channel_closed(
            &self,
            _channel_id: &str,
            _expiry_timestamp: u64,
            balance: u64,
            receiver_proofs_json: &str,
            sender_proofs_json: &str,
            receiver_sum: u64,
            sender_sum: u64,
        ) -> Result<(), String> {
            *self.channel_state.borrow_mut() = ChannelState::Closed;
            *self.closed_data.borrow_mut() = Some((
                balance,
                receiver_sum + sender_sum,
                receiver_proofs_json.to_string(),
                sender_proofs_json.to_string(),
            ));
            Ok(())
        }
        fn compute_channel_secret(
            &self,
            _receiver_pubkey_hex: &str,
            sender_pubkey_hex: &str,
        ) -> Result<String, String> {
            bindings::compute_channel_secret_from_hex(&self.charlie_secret_hex, sender_pubkey_hex)
        }
        fn sign_with_tweaked_key(
            &self,
            _signer_pubkey_hex: &str,
            message_hex: &str,
            tweak_scalar_hex: &str,
        ) -> Result<String, String> {
            bindings::sign_with_tweaked_key_util(
                &self.charlie_secret_hex,
                message_hex,
                tweak_scalar_hex,
            )
        }
    }

    impl SpilmanNetworking for RetryTestHost {
        fn refresh_all_keysets(&self, _mint: &str) -> Result<(), String> {
            *self.active_keyset_ids.borrow_mut() = vec![self.fresh_keyset_id];
            self.refresh_count.set(self.refresh_count.get() + 1);
            Ok(())
        }
        fn call_mint_swap(
            &self,
            _mint_url: &str,
            swap_request_json: &str,
        ) -> Result<String, String> {
            self.swap_call_count.set(self.swap_call_count.get() + 1);
            let swap_request: SwapRequest = serde_json::from_str(swap_request_json)
                .map_err(|e| format!("Failed to parse swap request: {}", e))?;
            let mint = Arc::clone(&self.mint);
            let response = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(async { mint.process_swap_request(swap_request).await })
            })
            .map_err(|e| {
                // Convert the cdk Error to a NUT-00 ErrorResponse so the
                // error string carries the proper {code, detail} JSON,
                // matching what a real mint HTTP endpoint would return.
                let error_response = cdk_common::error::ErrorResponse::from(e);
                let error_json = serde_json::to_string(&error_response)
                    .unwrap_or_else(|ser_err| format!("{{\"detail\":\"{}\",\"code\":0}}", ser_err));
                eprintln!(
                    "[RetryTestHost] mint rejected swap (NUT-00): {}",
                    error_json
                );
                *self.last_swap_error.borrow_mut() = Some(error_json.clone());
                error_json
            })?;
            serde_json::to_string(&response)
                .map_err(|e| format!("Failed to serialize swap response: {}", e))
        }
    }

    fn keyset_info_json_from_mint(mint: &Mint, keyset_id: Id) -> String {
        let pubkeys = mint.keyset_pubkeys(&keyset_id).expect("keyset pubkeys");
        let keyset = pubkeys.keysets.first().expect("keyset");
        let keys = &keyset.keys;
        let fee_ppk = mint
            .keysets()
            .keysets
            .iter()
            .find(|k| k.id == keyset_id)
            .expect("keyset info")
            .input_fee_ppk;
        serde_json::json!({
            "keysetId": keyset_id.to_string(),
            "unit": "sat",
            "inputFeePpk": fee_ppk,
            "keys": keys.iter().map(|(amt, pk)| {
                (u64::from(*amt).to_string(), pk.to_hex())
            }).collect::<HashMap<String, String>>()
        })
        .to_string()
    }

    pub(super) struct RetryScenario {
        pub bridge: SpilmanBridge<RetryTestHost, String>,
        pub channel_id: String,
        pub balance: u64,
        pub close_signature: String,
    }

    pub(super) async fn setup_retry_scenario() -> RetryScenario {
        let shared_mint = Arc::new(create_test_mint().await.unwrap());

        let keyset_a_id = shared_mint
            .get_active_keysets()
            .get(&CurrencyUnit::Sat)
            .cloned()
            .expect("SAT keyset");
        let keyset_a_info_json = keyset_info_json_from_mint(&shared_mint, keyset_a_id);
        let keyset_a_keys: Keys = {
            let pubkeys = shared_mint.keyset_pubkeys(&keyset_a_id).unwrap();
            pubkeys.keysets.first().unwrap().keys.clone()
        };
        let keyset_a_fee_ppk = shared_mint
            .keysets()
            .keysets
            .iter()
            .find(|k| k.id == keyset_a_id)
            .unwrap()
            .input_fee_ppk;

        let alice_secret = cdk::nuts::SecretKey::generate();
        let sender_pubkey = alice_secret.public_key();
        let charlie_secret = cdk::nuts::SecretKey::generate();
        let receiver_pubkey = charlie_secret.public_key();

        let keyset_info_a = KeysetInfo::new(
            keyset_a_id,
            CurrencyUnit::Sat,
            keyset_a_keys.clone(),
            keyset_a_fee_ppk,
            None,
        );
        let capacity = 10u64;
        let expiry_timestamp = unix_time() + 7200;
        let mint_amount = 100u64;

        let input_proofs = mint_test_proofs(&shared_mint, Amount::from(mint_amount))
            .await
            .expect("mint proofs");
        let num_inputs = input_proofs.len() as u64;
        let actual_fee = (keyset_a_fee_ppk * num_inputs).div_ceil(1000);
        let actual_funding = mint_amount - actual_fee;

        let params = ChannelParameters::new_with_secret_key(
            sender_pubkey,
            receiver_pubkey,
            "http://localhost:3338".to_string(),
            CurrencyUnit::Sat,
            capacity,
            actual_funding,
            expiry_timestamp,
            unix_time(),
            keyset_info_a,
            64,
            &alice_secret,
        )
        .expect("channel params");
        let channel_id = params.get_channel_id();
        let channel_secret = params.channel_secret;

        let adjusted_outputs = DeterministicOutputsForOneContext::new(
            "funding".to_string(),
            actual_funding,
            params.clone(),
        )
        .expect("funding outputs");
        let adjusted_messages = adjusted_outputs
            .get_blinded_messages(None)
            .expect("blinded msgs");
        let swap_request = SwapRequest::new(input_proofs, adjusted_messages);
        let swap_response = shared_mint
            .process_swap_request(swap_request)
            .await
            .expect("funding swap");

        let swb = adjusted_outputs
            .get_secrets_with_blinding()
            .expect("secrets");
        let blinding_factors = swb.iter().map(|s| s.blinding_factor.clone()).collect();
        let secrets = swb.iter().map(|s| s.secret.clone()).collect();
        let funding_proofs = construct_proofs(
            swap_response.signatures,
            blinding_factors,
            secrets,
            &keyset_a_keys,
        )
        .expect("construct proofs");

        let channel =
            EstablishedChannel::new(params.clone(), funding_proofs.clone()).expect("channel");
        let sender = SpilmanChannelSender::new(alice_secret.clone(), channel);
        let balance = 5u64;
        let (balance_update, _) = sender.create_signed_balance_update(balance).unwrap();

        // Rotate keyset: A -> inactive, B -> active
        let keyset_b_info = shared_mint
            .rotate_keyset(
                CurrencyUnit::Sat,
                vec![1, 2, 4, 8, 16, 32, 64],
                keyset_a_fee_ppk,
                false,
                None,
            )
            .await
            .expect("rotate keyset");
        let keyset_b_id = keyset_b_info.id;
        let keyset_b_info_json = keyset_info_json_from_mint(&shared_mint, keyset_b_id);

        let mut keyset_infos = HashMap::new();
        keyset_infos.insert(keyset_a_id, keyset_a_info_json);
        keyset_infos.insert(keyset_b_id, keyset_b_info_json);

        let params_json = params.get_channel_id_params_json();
        let funding_proofs_json = serde_json::to_string(&funding_proofs).unwrap();
        let channel_secret_hex = hex::encode(channel_secret);

        let mut funding_data_map = HashMap::new();
        funding_data_map.insert(
            channel_id.clone(),
            (
                params_json,
                funding_proofs_json,
                channel_secret_hex,
                keyset_infos.get(&keyset_a_id).unwrap().clone(),
            ),
        );

        let host = RetryTestHost {
            mint: Arc::clone(&shared_mint),
            active_keyset_ids: RefCell::new(vec![keyset_a_id]),
            fresh_keyset_id: keyset_b_id,
            keyset_infos,
            funding_data: Mutex::new(funding_data_map),
            channel_state: RefCell::new(ChannelState::Open),
            closing_data: RefCell::new(None),
            stored_payment: RefCell::new(Some(PaymentProof {
                balance,
                signature: balance_update.signature.to_string(),
            })),
            amount_due: Cell::new(balance),
            charlie_secret_hex: charlie_secret.to_secret_hex(),
            swap_call_count: Cell::new(0),
            refresh_count: Cell::new(0),
            closed_data: RefCell::new(None),
            last_swap_error: RefCell::new(None),
        };

        let bridge = SpilmanBridge::new(host);

        RetryScenario {
            bridge,
            channel_id,
            balance,
            close_signature: balance_update.signature.to_string(),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_cooperative_close_full_retry_with_real_mint() -> anyhow::Result<()> {
    let s = retry_tests::setup_retry_scenario().await;

    let payment_json = serde_json::json!({
        "channel_id": s.channel_id,
        "balance": s.balance,
        "signature": s.close_signature,
    })
    .to_string();

    let result = s
        .bridge
        .execute_cooperative_close(&payment_json, s.bridge.host());
    let success = result.expect("Cooperative close should succeed after retry");

    assert_eq!(s.bridge.host().swap_call_count.get(), 2);
    assert_eq!(s.bridge.host().refresh_count.get(), 1);
    assert!(matches!(
        *s.bridge.host().channel_state.borrow(),
        ChannelState::Closed
    ));

    let closed = s.bridge.host().closed_data.borrow();
    let (closed_balance, closed_total, ref receiver_proofs, ref sender_proofs) = closed
        .as_ref()
        .expect("mark_channel_closed should have been called");
    assert_eq!(*closed_balance, s.balance);
    assert!(*closed_total > 0);

    let receiver: Vec<serde_json::Value> = serde_json::from_str(receiver_proofs)?;
    let sender: Vec<serde_json::Value> = serde_json::from_str(sender_proofs)?;
    assert!(!receiver.is_empty());

    for (i, proof) in receiver.iter().enumerate() {
        let witness = proof.get("witness");
        assert!(
            witness.is_some() && !witness.unwrap().is_null(),
            "Receiver proof {} should have witness",
            i
        );
    }

    assert_eq!(success.channel_id, s.channel_id);
    assert!(success.total_value > 0);
    assert!(success.receiver_sum > 0);
    let _ = sender;

    // Verify the first swap attempt produced a proper NUT-00 error with a
    // keyset-related error code (12001 = keyset not known, 12002 = keyset
    // inactive).  Before this change, the error was always `"code": 0`.
    let last_err_json = s.bridge.host().last_swap_error.borrow();
    let last_err_json = last_err_json
        .as_ref()
        .expect("first swap should have recorded a NUT-00 error");
    let err_value: serde_json::Value =
        serde_json::from_str(last_err_json).expect("error should be valid JSON");
    let nut00_code = err_value
        .get("code")
        .and_then(|v| v.as_u64())
        .expect("NUT-00 error should contain a 'code' field");
    eprintln!(
        "[test] first swap NUT-00 error: code={}, detail={:?}",
        nut00_code,
        err_value.get("detail").and_then(|v| v.as_str())
    );
    assert!(
        nut00_code == 12001 || nut00_code == 12002,
        "Expected NUT-00 keyset error code (12001 or 12002), got {}",
        nut00_code
    );

    Ok(())
}

struct JsonFailingNetworking {
    swap_call_count: std::cell::Cell<u32>,
    refresh_count: std::cell::Cell<u32>,
}

impl SpilmanNetworking for JsonFailingNetworking {
    fn call_mint_swap(&self, _: &str, _: &str) -> Result<String, String> {
        let attempt = self.swap_call_count.get();
        self.swap_call_count.set(attempt + 1);

        match attempt {
            0 => Err(r#"{"code":12002,"detail":"Inactive Keyset"}"#.to_string()),
            _ => Err(r#"{"code":12001,"detail":"Unknown Keyset"}"#.to_string()),
        }
    }

    fn refresh_all_keysets(&self, _: &str) -> Result<(), String> {
        self.refresh_count.set(self.refresh_count.get() + 1);
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_cooperative_close_retry_preserves_structured_mint_errors() -> anyhow::Result<()> {
    let s = retry_tests::setup_retry_scenario().await;
    let net = JsonFailingNetworking {
        swap_call_count: std::cell::Cell::new(0),
        refresh_count: std::cell::Cell::new(0),
    };

    let payment_json = serde_json::json!({
        "channel_id": s.channel_id,
        "balance": s.balance,
        "signature": s.close_signature,
    })
    .to_string();

    let err = s
        .bridge
        .execute_cooperative_close(&payment_json, &net)
        .expect_err("close should fail after retry");

    assert_eq!(net.swap_call_count.get(), 2);
    assert_eq!(net.refresh_count.get(), 1);

    match err {
        CloseError::MintRejectedAfterRetry {
            original_error,
            retry_error,
            status,
        } => {
            assert_eq!(status, 502);
            assert!(
                original_error.is_object(),
                "original error should be JSON object"
            );
            assert!(retry_error.is_object(), "retry error should be JSON object");
            assert_eq!(original_error["code"], serde_json::json!(12002));
            assert_eq!(
                original_error["detail"],
                serde_json::json!("Inactive Keyset")
            );
            assert_eq!(retry_error["code"], serde_json::json!(12001));
            assert_eq!(retry_error["detail"], serde_json::json!("Unknown Keyset"));
        }
        other => panic!("expected MintRejectedAfterRetry, got {other:?}"),
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_unilateral_close_full_retry_with_real_mint() -> anyhow::Result<()> {
    let s = retry_tests::setup_retry_scenario().await;

    let result = s
        .bridge
        .execute_unilateral_close(&s.channel_id, s.bridge.host());
    let success = result.expect("Unilateral close should succeed after retry");

    assert_eq!(s.bridge.host().swap_call_count.get(), 2);
    assert_eq!(s.bridge.host().refresh_count.get(), 1);
    assert!(matches!(
        *s.bridge.host().channel_state.borrow(),
        ChannelState::Closed
    ));

    let closed = s.bridge.host().closed_data.borrow();
    let (closed_balance, closed_total, ref receiver_proofs, ref sender_proofs) = closed
        .as_ref()
        .expect("mark_channel_closed should have been called");
    assert_eq!(*closed_balance, s.balance);
    assert!(*closed_total > 0);

    let receiver: Vec<serde_json::Value> = serde_json::from_str(receiver_proofs)?;
    let sender: Vec<serde_json::Value> = serde_json::from_str(sender_proofs)?;
    assert!(!receiver.is_empty());

    for (i, proof) in receiver.iter().enumerate() {
        let witness = proof.get("witness");
        assert!(
            witness.is_some() && !witness.unwrap().is_null(),
            "Receiver proof {} should have witness",
            i
        );
    }

    assert_eq!(success.channel_id, s.channel_id);
    assert!(success.total_value > 0);
    assert!(success.receiver_sum > 0);
    let _ = sender;
    Ok(())
}

/// Verify that a real mint returns well-formed NUT-00 errors (with the
/// correct `code` field) when a swap request is invalid.
///
/// Uses `MINT_URL` from the environment, falling back to
/// `http://localhost:3338`.  The test is `#[ignore]`-d because it requires
/// a running HTTP mint — run it via `scripts/run_with_mint.sh` or the
/// `test-nut00-errors` Makefile target.
///
/// ```bash
/// # Auto-spawn the test mint:
/// scripts/run_with_mint.sh cargo test -p cdk-spilman-interop-tests \
///     test_mint_swap_error_returns_nut00_codes -- --ignored --nocapture
///
/// # Or point at an external mint:
/// MINT_URL=http://localhost:3338 cargo test -p cdk-spilman-interop-tests \
///     test_mint_swap_error_returns_nut00_codes -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore]
async fn test_mint_swap_error_returns_nut00_codes() -> anyhow::Result<()> {
    let mint_url =
        std::env::var("MINT_URL").unwrap_or_else(|_| "http://localhost:3338".to_string());
    eprintln!("[nut00] testing against mint at {mint_url}");

    // 1. Fetch the active sat keyset ID from the mint.
    let client = reqwest::Client::new();
    let keysets_resp: serde_json::Value = client
        .get(format!("{mint_url}/v1/keysets"))
        .send()
        .await?
        .json()
        .await?;
    let active_keyset_id = keysets_resp["keysets"]
        .as_array()
        .and_then(|ks| {
            ks.iter()
                .find(|k| k["unit"].as_str() == Some("sat") && k["active"].as_bool() == Some(true))
        })
        .and_then(|k| k["id"].as_str())
        .expect("mint should have an active sat keyset")
        .to_string();

    // 2. Send a swap with the correct keyset ID but a fabricated proof.
    //    The mint should reject it with NUT-00 code 10001 (proof verification
    //    failed).
    let bad_swap = serde_json::json!({
        "inputs": [{
            "amount": 1,
            "id": active_keyset_id,
            "secret": "407915bc212be61a77e3e6d2aeb4c727980bda51cd06a6afc29e2861768a7837",
            "C": "020000000000000000000000000000000000000000000000000000000000000001"
        }],
        "outputs": [{
            "amount": 1,
            "id": active_keyset_id,
            "B_": "020000000000000000000000000000000000000000000000000000000000000001"
        }]
    });

    let resp = client
        .post(format!("{mint_url}/v1/swap"))
        .header("Content-Type", "application/json")
        .json(&bad_swap)
        .send()
        .await?;

    let status = resp.status();
    assert!(
        status.is_client_error(),
        "Expected 4xx from mint, got {status}"
    );

    let body: serde_json::Value = resp.json().await?;
    eprintln!("[nut00] bad-proof swap error response: {body}");

    let code = body
        .get("code")
        .and_then(|v| v.as_u64())
        .expect("NUT-00 response should contain a 'code' field");
    eprintln!("[nut00] NUT-00 error code: {code}");

    // 10001 = "Proof verification failed" per the NUT error codes spec.
    assert_eq!(
        code, 10001,
        "Expected NUT-00 code 10001 (proof verification failed), got {code}"
    );

    // 3. Now try with a completely fake keyset ID.  The mint should return
    //    12001 (keyset not known) — or a generic error if it doesn't
    //    recognise the keyset before checking proofs.
    let bad_keyset_swap = serde_json::json!({
        "inputs": [{
            "amount": 1,
            "id": "00deadbeef000000",
            "secret": "407915bc212be61a77e3e6d2aeb4c727980bda51cd06a6afc29e2861768a7837",
            "C": "020000000000000000000000000000000000000000000000000000000000000001"
        }],
        "outputs": [{
            "amount": 1,
            "id": "00deadbeef000000",
            "B_": "020000000000000000000000000000000000000000000000000000000000000001"
        }]
    });

    let resp2 = client
        .post(format!("{mint_url}/v1/swap"))
        .header("Content-Type", "application/json")
        .json(&bad_keyset_swap)
        .send()
        .await?;

    assert!(
        resp2.status().is_client_error(),
        "Expected 4xx from mint for unknown keyset, got {}",
        resp2.status()
    );

    let body2: serde_json::Value = resp2.json().await?;
    eprintln!("[nut00] unknown-keyset swap error response: {body2}");

    let code2 = body2
        .get("code")
        .and_then(|v| v.as_u64())
        .expect("NUT-00 response should contain a 'code' field");
    eprintln!("[nut00] NUT-00 error code for unknown keyset: {code2}");

    // The spec says 12001, but some mints may return a generic error.
    // Log whatever we get — the primary goal is visibility.
    if code2 == 12001 {
        eprintln!("[nut00] Got expected NUT-00 code 12001 (keyset not known)");
    } else {
        eprintln!(
            "[nut00] Got NUT-00 code {code2} instead of 12001 — \
             mint may not distinguish unknown keysets at this layer"
        );
    }

    Ok(())
}

// ============================================================================
// Selective Retry Tests
// ============================================================================

/// A networking mock that always returns a specific NUT-00 error code.
/// Used to test selective retry behavior based on error codes.
struct SelectiveRetryTestNetworking {
    /// The NUT-00 error code to return on swap failures.
    error_code: u16,
    /// The error detail message.
    error_detail: String,
    /// Count of swap attempts.
    swap_call_count: std::cell::Cell<u32>,
    /// Count of keyset refresh calls.
    refresh_count: std::cell::Cell<u32>,
}

impl SelectiveRetryTestNetworking {
    fn new(error_code: u16, error_detail: &str) -> Self {
        Self {
            error_code,
            error_detail: error_detail.to_string(),
            swap_call_count: std::cell::Cell::new(0),
            refresh_count: std::cell::Cell::new(0),
        }
    }
}

impl SpilmanNetworking for SelectiveRetryTestNetworking {
    fn call_mint_swap(&self, _: &str, _: &str) -> Result<String, String> {
        self.swap_call_count.set(self.swap_call_count.get() + 1);
        Err(format!(
            r#"{{"code":{},"detail":"{}"}}"#,
            self.error_code, self.error_detail
        ))
    }

    fn refresh_all_keysets(&self, _: &str) -> Result<(), String> {
        self.refresh_count.set(self.refresh_count.get() + 1);
        Ok(())
    }
}

/// Test that non-keyset errors (like 11001 TokenAlreadySpent) fail immediately
/// without triggering a retry.
#[tokio::test(flavor = "multi_thread")]
async fn test_close_no_retry_on_token_spent_error() -> anyhow::Result<()> {
    let s = retry_tests::setup_retry_scenario().await;

    // Error code 11001 = TokenAlreadySpent (not a keyset error)
    let net = SelectiveRetryTestNetworking::new(11001, "Token already spent");

    let payment_json = serde_json::json!({
        "channel_id": s.channel_id,
        "balance": s.balance,
        "signature": s.close_signature,
    })
    .to_string();

    let err = s
        .bridge
        .execute_cooperative_close(&payment_json, &net)
        .expect_err("close should fail immediately without retry");

    // Should only call swap once (no retry)
    assert_eq!(
        net.swap_call_count.get(),
        1,
        "Should only attempt swap once for non-keyset error"
    );
    // Should not refresh keysets
    assert_eq!(
        net.refresh_count.get(),
        0,
        "Should not refresh keysets for non-keyset error"
    );

    // Should return MintRejected (not MintRejectedAfterRetry)
    match err {
        CloseError::MintRejected { mint_error, status } => {
            assert_eq!(status, 502);
            assert_eq!(mint_error["code"], serde_json::json!(11001));
            assert_eq!(
                mint_error["detail"],
                serde_json::json!("Token already spent")
            );
        }
        other => panic!("expected MintRejected, got {other:?}"),
    }

    Ok(())
}

/// Test that keyset errors (12001, 12002) trigger retry after refreshing keysets.
#[tokio::test(flavor = "multi_thread")]
async fn test_close_retry_on_keyset_error() -> anyhow::Result<()> {
    let s = retry_tests::setup_retry_scenario().await;

    // Error code 12001 = KeysetNotFound (keyset error, should retry)
    let net = SelectiveRetryTestNetworking::new(12001, "Keyset not found");

    let payment_json = serde_json::json!({
        "channel_id": s.channel_id,
        "balance": s.balance,
        "signature": s.close_signature,
    })
    .to_string();

    let err = s
        .bridge
        .execute_cooperative_close(&payment_json, &net)
        .expect_err("close should fail after retry");

    // Should call swap twice (initial + retry)
    assert_eq!(
        net.swap_call_count.get(),
        2,
        "Should attempt swap twice for keyset error"
    );
    // Should refresh keysets once
    assert_eq!(
        net.refresh_count.get(),
        1,
        "Should refresh keysets once for keyset error"
    );

    // Should return MintRejectedAfterRetry
    match err {
        CloseError::MintRejectedAfterRetry {
            original_error,
            retry_error,
            status,
        } => {
            assert_eq!(status, 502);
            assert_eq!(original_error["code"], serde_json::json!(12001));
            assert_eq!(retry_error["code"], serde_json::json!(12001));
        }
        other => panic!("expected MintRejectedAfterRetry, got {other:?}"),
    }

    Ok(())
}

/// Test that unparseable error responses fail immediately without retry.
#[tokio::test(flavor = "multi_thread")]
async fn test_close_no_retry_on_unparseable_error() -> anyhow::Result<()> {
    let s = retry_tests::setup_retry_scenario().await;

    // A networking mock that returns unparseable errors
    struct UnparseableErrorNetworking {
        swap_call_count: std::cell::Cell<u32>,
        refresh_count: std::cell::Cell<u32>,
    }

    impl SpilmanNetworking for UnparseableErrorNetworking {
        fn call_mint_swap(&self, _: &str, _: &str) -> Result<String, String> {
            self.swap_call_count.set(self.swap_call_count.get() + 1);
            // Return a plain string error without JSON structure
            Err("Internal server error".to_string())
        }

        fn refresh_all_keysets(&self, _: &str) -> Result<(), String> {
            self.refresh_count.set(self.refresh_count.get() + 1);
            Ok(())
        }
    }

    let net = UnparseableErrorNetworking {
        swap_call_count: std::cell::Cell::new(0),
        refresh_count: std::cell::Cell::new(0),
    };

    let payment_json = serde_json::json!({
        "channel_id": s.channel_id,
        "balance": s.balance,
        "signature": s.close_signature,
    })
    .to_string();

    let err = s
        .bridge
        .execute_cooperative_close(&payment_json, &net)
        .expect_err("close should fail immediately without retry");

    // Should only call swap once (no retry for unparseable errors)
    assert_eq!(
        net.swap_call_count.get(),
        1,
        "Should only attempt swap once for unparseable error"
    );
    // Should not refresh keysets
    assert_eq!(
        net.refresh_count.get(),
        0,
        "Should not refresh keysets for unparseable error"
    );

    // Should return MintRejected with the error as a string value
    match err {
        CloseError::MintRejected { mint_error, status } => {
            assert_eq!(status, 502);
            // The unparseable error should be wrapped as a JSON string
            assert_eq!(mint_error, serde_json::json!("Internal server error"));
        }
        other => panic!("expected MintRejected, got {other:?}"),
    }

    Ok(())
}

/// Test that verification errors (10001) fail immediately without retry.
#[tokio::test(flavor = "multi_thread")]
async fn test_close_no_retry_on_verification_error() -> anyhow::Result<()> {
    let s = retry_tests::setup_retry_scenario().await;

    // Error code 10001 = TokenNotVerified
    let net = SelectiveRetryTestNetworking::new(10001, "Token verification failed");

    let payment_json = serde_json::json!({
        "channel_id": s.channel_id,
        "balance": s.balance,
        "signature": s.close_signature,
    })
    .to_string();

    let err = s
        .bridge
        .execute_cooperative_close(&payment_json, &net)
        .expect_err("close should fail immediately without retry");

    assert_eq!(
        net.swap_call_count.get(),
        1,
        "Should only attempt swap once for verification error"
    );
    assert_eq!(
        net.refresh_count.get(),
        0,
        "Should not refresh keysets for verification error"
    );

    match err {
        CloseError::MintRejected { mint_error, status } => {
            assert_eq!(status, 502);
            assert_eq!(mint_error["code"], serde_json::json!(10001));
        }
        other => panic!("expected MintRejected, got {other:?}"),
    }

    Ok(())
}

// ============================================================================
// Integration Test: Selective Retry Against Real Mint (Double-Spend)
// ============================================================================

/// Test that the selective retry logic correctly fails immediately (no retry)
/// when a mint returns error 11001 (TokenAlreadySpent).
///
/// This test:
/// 1. Funds a channel with real proofs from a real in-memory mint
/// 2. Successfully closes the channel (spends the proofs)
/// 3. Resets channel state and attempts to close again with the same (now spent) proofs
/// 4. Verifies the second close fails immediately without retry
///
/// This test uses the in-memory test mint (same as other retry tests), so no
/// external mint is required. It's NOT marked `#[ignore]`.
///
/// The key assertion is that when proofs are already spent (11001), the bridge
/// should fail immediately without attempting a keyset refresh + retry, because
/// 11001 is not a keyset error.
#[tokio::test(flavor = "multi_thread")]
async fn test_selective_retry_no_retry_on_double_spend() -> anyhow::Result<()> {
    // Set up a real channel scenario using the existing retry test infrastructure.
    // This creates a funded channel with real proofs from an in-memory mint.
    let s = retry_tests::setup_retry_scenario().await;
    eprintln!(
        "[selective-retry] Channel {} funded with balance {}",
        s.channel_id, s.balance
    );

    let payment_json = serde_json::json!({
        "channel_id": s.channel_id,
        "balance": s.balance,
        "signature": s.close_signature,
    })
    .to_string();

    // Record initial swap count
    let initial_swap_count = s.bridge.host().swap_call_count.get();
    eprintln!(
        "[selective-retry] Initial swap count: {}",
        initial_swap_count
    );

    // First close: should succeed (with retry due to keyset rotation in setup).
    // The RetryTestHost starts with keyset A active, but keyset A has been rotated
    // to inactive, so the first swap fails with 12002 (inactive keyset), then
    // refresh_all_keysets switches to keyset B, and the retry succeeds.
    eprintln!("[selective-retry] Attempting first close (should succeed with retry)...");
    let result1 = s
        .bridge
        .execute_cooperative_close(&payment_json, s.bridge.host());

    let after_first_close_swap_count = s.bridge.host().swap_call_count.get();
    let after_first_close_refresh_count = s.bridge.host().refresh_count.get();
    eprintln!(
        "[selective-retry] After first close: swap_count={}, refresh_count={}",
        after_first_close_swap_count, after_first_close_refresh_count
    );

    match &result1 {
        Ok(success) => {
            eprintln!(
                "[selective-retry] First close succeeded: total_value={}",
                success.total_value
            );
        }
        Err(e) => {
            panic!("[selective-retry] First close should succeed, got error: {e:?}");
        }
    }

    // First close should have used 2 swaps (initial fail + retry) and 1 refresh
    assert_eq!(
        after_first_close_swap_count - initial_swap_count,
        2,
        "First close should use 2 swap calls (initial + retry)"
    );
    assert_eq!(
        after_first_close_refresh_count, 1,
        "First close should use 1 refresh call"
    );

    // Reset the channel state to allow another close attempt.
    // This simulates a buggy client trying to double-spend.
    *s.bridge.host().channel_state.borrow_mut() = ChannelState::Open;
    *s.bridge.host().closing_data.borrow_mut() = None;
    // Also reset the active keyset back to the original (now inactive) one
    // to ensure the second close doesn't fail due to keyset issues first.
    // Actually, let's keep the fresh keyset so the keyset is valid,
    // and the only error should be "proofs already spent".
    eprintln!("[selective-retry] Reset channel state for second close attempt");

    // Second close: should fail immediately with 11001 (TokenAlreadySpent).
    // The proofs have already been spent by the first close.
    eprintln!("[selective-retry] Attempting second close (should fail with 11001, no retry)...");

    let result2 = s
        .bridge
        .execute_cooperative_close(&payment_json, s.bridge.host());

    let after_second_close_swap_count = s.bridge.host().swap_call_count.get();
    let after_second_close_refresh_count = s.bridge.host().refresh_count.get();
    eprintln!(
        "[selective-retry] After second close: swap_count={}, refresh_count={}",
        after_second_close_swap_count, after_second_close_refresh_count
    );

    // The second close should fail
    let err = result2.expect_err("Second close should fail (proofs already spent)");
    eprintln!("[selective-retry] Second close error: {err:?}");

    // KEY ASSERTION: Second close should use only 1 swap (no retry for 11001)
    let second_close_swaps = after_second_close_swap_count - after_first_close_swap_count;
    assert_eq!(
        second_close_swaps, 1,
        "Second close should use only 1 swap call (no retry for token-spent error), got {}",
        second_close_swaps
    );
    eprintln!("[selective-retry] ✓ Second close used only 1 swap (no retry)");

    // KEY ASSERTION: Second close should NOT trigger a keyset refresh
    let second_close_refreshes = after_second_close_refresh_count - after_first_close_refresh_count;
    assert_eq!(
        second_close_refreshes, 0,
        "Second close should not refresh keysets for token-spent error, got {} refreshes",
        second_close_refreshes
    );
    eprintln!("[selective-retry] ✓ Second close did not refresh keysets");

    // Check the error type and code
    match &err {
        CloseError::MintRejected { mint_error, status } => {
            eprintln!(
                "[selective-retry] Got MintRejected: status={}, error={}",
                status, mint_error
            );
            let code = mint_error.get("code").and_then(|v| v.as_u64()).unwrap_or(0);
            eprintln!("[selective-retry] NUT-00 error code: {code}");

            // 11001 = TokenAlreadySpent
            assert_eq!(
                code, 11001,
                "Expected NUT-00 code 11001 (TokenAlreadySpent), got {code}"
            );
            eprintln!("[selective-retry] ✓ Got expected error code 11001 (TokenAlreadySpent)");
        }
        CloseError::MintRejectedAfterRetry { .. } => {
            panic!(
                "Got MintRejectedAfterRetry, but should have failed immediately without retry! \
                 The selective retry logic should not retry on 11001 (TokenAlreadySpent)."
            );
        }
        other => {
            panic!(
                "[selective-retry] Got unexpected error type: {other:?}. \
                 Expected MintRejected with code 11001."
            );
        }
    }

    eprintln!("[selective-retry] PASSED: Selective retry correctly skipped retry for 11001 error");
    Ok(())
}
