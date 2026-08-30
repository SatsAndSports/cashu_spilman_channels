//! Established Spilman Channel
//!
//! Contains the complete channel state after funding

use bitcoin::hashes::{sha256, Hash};
use cashu::nuts::{
    BlindSignature, BlindedMessage, Proof, RestoreRequest, SecretKey, State, SwapRequest, Witness,
};
use cashu::secret::Secret;
use cashu::util::hex;
use cashu::Amount;
use serde::{Deserialize, Serialize};

use super::client_storage::ClientChannelFunding;
use super::deterministic::MintConnection;
use super::keysets_and_amounts::OrderedListOfAmounts;
use super::params::{hash_to_secp_scalar, ChannelParameters};
use super::sender_and_receiver::SpilmanChannelSender;
use crate::bindings::parse_keyset_info_from_json;

const SENDER_REFUND_LOOSE_CONTEXT: &str = "sender_refund_loose";

/// One prepared output for a post-expiry sender refund.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedSenderRefundOutput {
    /// Output amount in raw mint units.
    pub amount: u64,
    /// Per-amount output index.
    pub index: usize,
    /// Output secret that will become the loose proof secret.
    pub secret: Secret,
    /// Output blinding factor.
    pub blinding_factor: SecretKey,
    /// Blinded message submitted/restored at the mint.
    pub blinded_message: BlindedMessage,
}

/// A durable, replayable post-expiry refund attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedSenderRefund {
    /// Channel id being refunded.
    pub channel_id: String,
    /// Total value expected from the refund outputs after input fees.
    pub output_amount_raw: u64,
    /// Prepared refund outputs. Persist these before submitting the swap.
    pub outputs: Vec<PreparedSenderRefundOutput>,
    /// Signed atomic swap spending all funding proofs into `outputs`.
    pub swap_request: SwapRequest,
}

/// Protocol-level classification of how a funding proof was spent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FundingSpendKind {
    /// The client spent the funding proof via the one-signature post-expiry refund path.
    PostExpiryRefund,
    /// The relay close spent the funding proof with the sender + receiver stage-1 signatures.
    RelayClose,
    /// No supported NUT-07 witness classification was available.
    Unknown,
}

/// An established Spilman payment channel
/// Contains all channel components after funding transaction is complete
#[derive(Debug, Clone)]
pub struct EstablishedChannel {
    /// Channel parameters (includes shared_secret)
    pub params: ChannelParameters,
    /// Locked proofs (2-of-2 multisig with expiry-based refund)
    pub funding_proofs: Vec<Proof>,
}

impl EstablishedChannel {
    /// Create new established channel
    pub fn new(
        params: ChannelParameters,
        funding_proofs: Vec<Proof>,
    ) -> Result<Self, anyhow::Error> {
        // Note: This performs basic structural validation only.
        // DLEQ proof verification (which ensures the mint actually signed these proofs)
        // is done separately via `verify_valid_channel()` and should be called by the
        // receiver (Charlie) when first receiving funding. The SpilmanBridge does this
        // automatically in its `resolve_funding` step.

        // Assert all proofs have the expected keyset_id from params
        let expected_keyset_id = params.keyset_info.keyset_id;
        for proof in &funding_proofs {
            if proof.keyset_id != expected_keyset_id {
                anyhow::bail!(
                    "Funding proof has keyset_id {} but expected {} from params",
                    proof.keyset_id,
                    expected_keyset_id
                );
            }
        }

        // Assert the total value of funding proofs matches the expected funding token amount
        let actual_funding_value: u64 = funding_proofs
            .iter()
            .map(|proof| u64::from(proof.amount))
            .sum();
        let expected_funding_value = params.get_total_funding_token_amount()?;

        if actual_funding_value != expected_funding_value {
            anyhow::bail!(
                "Funding proofs total value {} does not match expected funding token amount {}",
                actual_funding_value,
                expected_funding_value
            );
        }

        Ok(Self {
            params,
            funding_proofs,
        })
    }

    /// Reconstruct an established channel from client-side persisted funding data.
    pub fn from_client_channel_funding(
        funding: &ClientChannelFunding,
    ) -> Result<Self, anyhow::Error> {
        let keyset_info = parse_keyset_info_from_json(&funding.keyset_info_json)
            .map_err(|e| anyhow::anyhow!(e))?;
        let channel_secret: [u8; 32] = hex::decode(&funding.channel_secret_hex)
            .map_err(|e| anyhow::anyhow!("invalid channel secret hex: {e}"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("channel secret is not 32 bytes"))?;
        let params = ChannelParameters::from_json_with_channel_secret(
            &funding.params_json,
            keyset_info,
            channel_secret,
        )
        .map_err(|e| anyhow::anyhow!(e))?;
        let funding_proofs: Vec<Proof> = serde_json::from_str(&funding.funding_proofs_json)
            .map_err(|e| anyhow::anyhow!("invalid funding proofs JSON: {e}"))?;

        Self::new(params, funding_proofs)
    }

    /// Restore the sender's deterministic output proofs after the receiver has
    /// spent the funding token, using client-side persisted funding data.
    pub async fn restore_sender_proofs_from_client_funding<M>(
        funding: &ClientChannelFunding,
        sender_secret: SecretKey,
        mint_connection: &M,
    ) -> Result<Vec<Proof>, anyhow::Error>
    where
        M: MintConnection + ?Sized,
    {
        let channel = Self::from_client_channel_funding(funding)?;
        SpilmanChannelSender::new(sender_secret, channel)
            .restore_sender_proofs(mint_connection)
            .await
    }

    /// Prepare a signed, atomic post-expiry sender refund swap.
    ///
    /// The returned output metadata is sufficient to restore/import the refund
    /// outputs if the mint accepts the swap but the response is lost. Callers
    /// should persist it before submitting `swap_request`.
    pub fn prepare_sender_refund_after_expiry(
        &self,
        sender_secret: SecretKey,
        now_seconds: u64,
    ) -> Result<PreparedSenderRefund, anyhow::Error> {
        if now_seconds < self.params.expiry_timestamp {
            anyhow::bail!(
                "channel has not expired: now={} expiry={}",
                now_seconds,
                self.params.expiry_timestamp
            );
        }

        let funding_total = self.funding_total_raw()?;
        let input_fee = (self.params.keyset_info.input_fee_ppk * self.funding_proofs.len() as u64)
            .div_ceil(1000);
        let output_amount_raw = funding_total
            .checked_sub(input_fee)
            .ok_or_else(|| anyhow::anyhow!("funding input fee exceeds funding total"))?;
        let output_amounts = OrderedListOfAmounts::from_target(
            output_amount_raw,
            self.params.maximum_amount_for_one_output,
            &self.params.keyset_info,
        )?;

        let outputs = self.prepare_loose_refund_outputs(output_amounts.amounts())?;
        let blinded_messages = outputs
            .iter()
            .map(|output| output.blinded_message.clone())
            .collect::<Vec<_>>();
        let mut swap_request = SwapRequest::new(self.funding_proofs.clone(), blinded_messages);
        let refund_secret = self
            .params
            .get_sender_blinded_secret_key_for_stage1_refund(&sender_secret)?;
        swap_request.sign_sig_all(refund_secret)?;

        Ok(PreparedSenderRefund {
            channel_id: self.params.get_channel_id(),
            output_amount_raw,
            outputs,
            swap_request,
        })
    }

    /// Submit a prepared sender refund and unblind the returned proofs.
    pub async fn submit_prepared_sender_refund<M>(
        prepared: &PreparedSenderRefund,
        mint_connection: &M,
        active_keys: &cashu::nuts::Keys,
    ) -> Result<Vec<Proof>, anyhow::Error>
    where
        M: MintConnection + ?Sized,
    {
        let response = mint_connection
            .process_swap(prepared.swap_request.clone())
            .await?;
        Self::complete_prepared_sender_refund(prepared, response.signatures, active_keys)
    }

    /// Restore prepared sender refund outputs after an ambiguous submit.
    pub async fn restore_prepared_sender_refund_outputs<M>(
        prepared: &PreparedSenderRefund,
        mint_connection: &M,
        active_keys: &cashu::nuts::Keys,
    ) -> Result<Vec<Proof>, anyhow::Error>
    where
        M: MintConnection + ?Sized,
    {
        let response = mint_connection
            .post_restore(RestoreRequest {
                outputs: prepared
                    .outputs
                    .iter()
                    .map(|output| output.blinded_message.clone())
                    .collect(),
            })
            .await?;
        Self::complete_prepared_sender_refund(prepared, response.signatures, active_keys)
    }

    fn complete_prepared_sender_refund(
        prepared: &PreparedSenderRefund,
        blind_signatures: Vec<BlindSignature>,
        active_keys: &cashu::nuts::Keys,
    ) -> Result<Vec<Proof>, anyhow::Error> {
        if blind_signatures.len() != prepared.outputs.len() {
            anyhow::bail!(
                "expected {} refund signatures but got {}",
                prepared.outputs.len(),
                blind_signatures.len()
            );
        }
        let blinding_factors = prepared
            .outputs
            .iter()
            .map(|output| output.blinding_factor.clone())
            .collect::<Vec<_>>();
        let secrets = prepared
            .outputs
            .iter()
            .map(|output| output.secret.clone())
            .collect::<Vec<_>>();
        cashu::dhke::construct_proofs(blind_signatures, blinding_factors, secrets, active_keys)
            .map_err(Into::into)
    }

    fn funding_total_raw(&self) -> Result<u64, anyhow::Error> {
        self.funding_proofs.iter().try_fold(0u64, |total, proof| {
            total
                .checked_add(u64::from(proof.amount))
                .ok_or_else(|| anyhow::anyhow!("funding proof total overflow"))
        })
    }

    fn prepare_loose_refund_outputs(
        &self,
        amounts: &[u64],
    ) -> Result<Vec<PreparedSenderRefundOutput>, anyhow::Error> {
        let mut per_amount_index = std::collections::BTreeMap::<u64, usize>::new();
        amounts
            .iter()
            .map(|&amount| {
                let index = per_amount_index.entry(amount).or_insert(0);
                let output = self.prepare_loose_refund_output(amount, *index)?;
                *index += 1;
                Ok(output)
            })
            .collect()
    }

    fn prepare_loose_refund_output(
        &self,
        amount: u64,
        index: usize,
    ) -> Result<PreparedSenderRefundOutput, anyhow::Error> {
        let channel_id = self.params.get_channel_id();
        let mut secret_preimage = Vec::new();
        secret_preimage.extend_from_slice(&self.params.channel_secret);
        secret_preimage.extend_from_slice(
            format!(
                "{}|{}|{}|{}|secret",
                channel_id, SENDER_REFUND_LOOSE_CONTEXT, amount, index
            )
            .as_bytes(),
        );
        let secret_hash = sha256::Hash::hash(&secret_preimage);
        let secret = Secret::new(format!(
            "{}:{}:{}:{}",
            SENDER_REFUND_LOOSE_CONTEXT,
            channel_id,
            amount,
            hex::encode(secret_hash.to_byte_array())
        ));

        let mut blinding_preimage = Vec::new();
        blinding_preimage.extend_from_slice(&self.params.channel_secret);
        blinding_preimage.extend_from_slice(
            format!(
                "{}|{}|{}|{}|blinding",
                channel_id, SENDER_REFUND_LOOSE_CONTEXT, amount, index
            )
            .as_bytes(),
        );
        let blinding_scalar = hash_to_secp_scalar(&blinding_preimage, |input| {
            sha256::Hash::hash(input).to_byte_array()
        })?;
        let blinding_factor = SecretKey::from_slice(&blinding_scalar.to_be_bytes())?;
        let (blinded_point, _) =
            cashu::dhke::blind_message(&secret.to_bytes(), Some(blinding_factor.clone()))?;
        let blinded_message = BlindedMessage::new(
            Amount::from(amount),
            self.params.keyset_info.keyset_id,
            blinded_point,
        );

        Ok(PreparedSenderRefundOutput {
            amount,
            index,
            secret,
            blinding_factor,
            blinded_message,
        })
    }

    /// Get the Y value for checking the funding token state
    ///
    /// Since all funding proofs are spent together (they're all inputs to the commitment transaction),
    /// checking any one of them is sufficient to determine if the funding token has been spent.
    /// This returns the Y value of the first funding proof for use with NUT-07 state checks.
    fn get_one_funding_token_y_for_state_check(
        &self,
    ) -> Result<cashu::nuts::PublicKey, anyhow::Error> {
        let proof = self
            .funding_proofs
            .first()
            .ok_or_else(|| anyhow::anyhow!("No funding proofs available"))?;
        Ok(proof.y()?)
    }

    /// Check the state of the funding token using NUT-07
    ///
    /// Since all funding proofs are spent together (they're all inputs to the commitment transaction),
    /// checking any one of them is sufficient to determine if the funding token has been spent.
    /// This method checks the first funding proof and returns its state.
    ///
    /// Returns the state (UNSPENT, PENDING, or SPENT) of the funding token.
    pub async fn check_funding_token_state<M>(
        &self,
        mint_connection: &M,
    ) -> Result<cashu::nuts::ProofState, anyhow::Error>
    where
        M: MintConnection + ?Sized,
    {
        let y = self.get_one_funding_token_y_for_state_check()?;
        let response = mint_connection.check_state(vec![y]).await?;
        response
            .states
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No state returned for funding token"))
    }

    /// Classify a spent funding proof from its NUT-07 witness signature shape.
    ///
    /// This classifier is specific to MONAD's Spilman funding proof protocol:
    /// the post-expiry refund path is signed by the sender refund key only,
    /// while relay close carries the sender and receiver stage-1 signatures.
    pub fn classify_funding_spend_witness(
        proof_state: &cashu::nuts::ProofState,
    ) -> FundingSpendKind {
        if proof_state.state != State::Spent {
            return FundingSpendKind::Unknown;
        }

        match &proof_state.witness {
            Some(Witness::P2PKWitness(witness)) => match witness.signatures.len() {
                1 => FundingSpendKind::PostExpiryRefund,
                2 => FundingSpendKind::RelayClose,
                _ => FundingSpendKind::Unknown,
            },
            _ => FundingSpendKind::Unknown,
        }
    }
}

impl PreparedSenderRefund {
    /// Serialize a prepared refund attempt for durable storage before submit.
    pub fn to_json(&self) -> Result<String, anyhow::Error> {
        serde_json::to_string(self).map_err(Into::into)
    }

    /// Restore a prepared refund attempt from durable storage.
    pub fn from_json(json: &str) -> Result<Self, anyhow::Error> {
        serde_json::from_str(json).map_err(Into::into)
    }
}
