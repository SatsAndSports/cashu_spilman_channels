//! Established Spilman Channel
//!
//! Contains the complete channel state after funding

use bitcoin::hashes::{sha256, Hash};
use cashu::nuts::nut10::SpendingConditionVerification;
use cashu::nuts::{
    BlindSignature, BlindedMessage, Proof, RestoreRequest, RestoreResponse, SecretKey, SwapRequest,
    Witness,
};
use cashu::secret::Secret;
use cashu::util::hex;
use cashu::Amount;
use serde::{Deserialize, Serialize};

use super::client_storage::ClientChannelFunding;
use super::deterministic::MintConnection;
use super::keysets_and_amounts::{KeysetInfo, OrderedListOfAmounts};
use super::params::{hash_to_secp_scalar, ChannelParameters};
use super::sender_and_receiver::SpilmanChannelSender;
use crate::bindings::{
    complete_exact_signatures, match_restore_response, parse_keyset_info_from_json, PreparedOutput,
};

const SENDER_REFUND_LOOSE_CONTEXT: &str = "sender_refund_loose";

/// Local refund eligibility failures, downcastable from the returned anyhow error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SenderRefundError {
    /// The refund branch requires strictly later than the channel expiry.
    #[error("channel has not expired: now={now} expiry={expiry}")]
    NotExpired {
        /// Caller-supplied current Unix time.
        now: u64,
        /// Channel locktime.
        expiry: u64,
    },
    /// No positive-value outputs remain after funding input fees.
    #[error("refund has zero net value")]
    ZeroNetValue,
}

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
///
/// Contains confidential output secrets and blindings: protect serialized records
/// and do not log this value. The sender private key is used for derivation but
/// is not stored in the record; never log the derivation preimages either.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedSenderRefund {
    /// Channel id being refunded.
    pub channel_id: String,
    /// Mint to which this immutable request must be sent.
    pub mint: String,
    /// Output unit, identical to the funding unit.
    pub unit: cashu::nuts::CurrencyUnit,
    /// Historical output keys and metadata, independent of the funding keyset.
    pub output_keyset: KeysetInfo,
    /// Immutable original output metadata used to derive secrets and denominations.
    /// Required on disk; keyset-only successors retain it unchanged.
    pub derivation_keyset: KeysetInfo,
    /// Output derivation format. Currently 1; unknown versions are rejected.
    pub derivation_version: u32,
    /// Caller-chosen context for the original preparation; retained by successors.
    pub derivation_context: [u8; 32],
    /// Total value expected from the refund outputs after input fees.
    pub output_amount_raw: u64,
    /// Prepared refund outputs. Persist these before submitting the swap.
    pub outputs: Vec<PreparedSenderRefundOutput>,
    /// Signed atomic swap spending all funding proofs into `outputs`.
    pub swap_request: SwapRequest,
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
        let actual_funding_value = funding_proofs.iter().try_fold(0u64, |total, proof| {
            total
                .checked_add(u64::from(proof.amount))
                .ok_or_else(|| anyhow::anyhow!("funding proof total overflow"))
        })?;
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
        output_keyset: KeysetInfo,
        derivation_context: [u8; 32],
    ) -> Result<PreparedSenderRefund, anyhow::Error> {
        if now_seconds <= self.params.expiry_timestamp {
            return Err(SenderRefundError::NotExpired {
                now: now_seconds,
                expiry: self.params.expiry_timestamp,
            }
            .into());
        }
        anyhow::ensure!(
            sender_secret.public_key() == self.params.sender_pubkey,
            "incorrect sender secret"
        );
        let mut prepared =
            self.prepare_unsigned_sender_refund(&sender_secret, output_keyset, derivation_context)?;
        let refund_secret = self
            .params
            .get_sender_blinded_secret_key_for_stage1_refund(&sender_secret)?;
        prepared.swap_request.sign_sig_all(refund_secret)?;
        Ok(prepared)
    }

    fn prepare_unsigned_sender_refund(
        &self,
        sender_secret: &SecretKey,
        output_keyset: KeysetInfo,
        derivation_context: [u8; 32],
    ) -> anyhow::Result<PreparedSenderRefund> {
        anyhow::ensure!(
            output_keyset.unit == self.params.unit,
            "refund output unit mismatch"
        );
        let expected_id = match output_keyset.keyset_id.get_version() {
            cashu::nuts::nut02::KeySetVersion::Version00 => {
                cashu::nuts::Id::v1_from_keys(&output_keyset.active_keys)
            }
            cashu::nuts::nut02::KeySetVersion::Version01 => cashu::nuts::Id::v2_from_data(
                &output_keyset.active_keys,
                &output_keyset.unit,
                output_keyset.input_fee_ppk,
                output_keyset.final_expiry,
            ),
        };
        anyhow::ensure!(
            expected_id == output_keyset.keyset_id,
            "refund output keyset identity mismatch"
        );
        let canonical = KeysetInfo::new(
            output_keyset.keyset_id,
            output_keyset.unit.clone(),
            output_keyset.active_keys.clone(),
            output_keyset.input_fee_ppk,
            output_keyset.final_expiry,
        );
        anyhow::ensure!(
            !canonical.amounts_largest_first.contains(&0)
                && canonical.amounts_largest_first == output_keyset.amounts_largest_first,
            "invalid refund output denominations"
        );

        let funding_total = self.funding_total_raw()?;
        let input_fee = self
            .params
            .keyset_info
            .input_fee_ppk
            .checked_mul(u64::try_from(self.funding_proofs.len())?)
            .ok_or_else(|| anyhow::anyhow!("funding input fee overflow"))?
            .div_ceil(1000);
        let output_amount_raw = funding_total
            .checked_sub(input_fee)
            .ok_or_else(|| anyhow::anyhow!("funding input fee exceeds funding total"))?;
        if output_amount_raw == 0 {
            return Err(SenderRefundError::ZeroNetValue.into());
        }
        let output_amounts = OrderedListOfAmounts::from_target(
            output_amount_raw,
            self.params.maximum_amount_for_one_output,
            &output_keyset,
        )?;

        let outputs = self.prepare_loose_refund_outputs(
            sender_secret,
            output_amounts.amounts(),
            &output_keyset,
            derivation_context,
        )?;
        let blinded_messages = outputs
            .iter()
            .map(|output| output.blinded_message.clone())
            .collect::<Vec<_>>();
        let mut inputs = self.funding_proofs.clone();
        for input in &mut inputs {
            input.witness = None;
        }
        let swap_request = SwapRequest::new(inputs, blinded_messages);

        Ok(PreparedSenderRefund {
            channel_id: self.params.get_channel_id(),
            mint: self.params.mint.clone(),
            unit: self.params.unit.clone(),
            derivation_keyset: output_keyset.clone(),
            output_keyset,
            derivation_version: 1,
            derivation_context,
            output_amount_raw,
            outputs,
            swap_request,
        })
    }

    /// Submit a prepared sender refund and unblind the returned proofs.
    pub async fn submit_prepared_sender_refund<M>(
        &self,
        prepared: &PreparedSenderRefund,
        sender_secret: &SecretKey,
        now_seconds: u64,
        mint_connection: &M,
    ) -> Result<Vec<Proof>, anyhow::Error>
    where
        M: MintConnection + ?Sized,
    {
        if now_seconds <= self.params.expiry_timestamp {
            return Err(SenderRefundError::NotExpired {
                now: now_seconds,
                expiry: self.params.expiry_timestamp,
            }
            .into());
        }
        prepared.verify(self, sender_secret)?;
        let response = mint_connection
            .process_swap(prepared.swap_request.clone())
            .await?;
        self.complete_prepared_sender_refund(prepared, sender_secret, response.signatures)
    }

    /// Restore prepared sender refund outputs after an ambiguous submit.
    /// This low-level exact-restore primitive does not inspect funding. Use
    /// [`SpilmanChannelSender::recover_funds`] to reconcile NUT-07 first and fall
    /// back to receiver-close discovery when valid refund restores are empty.
    pub async fn restore_prepared_sender_refund_outputs<M>(
        &self,
        prepared: &PreparedSenderRefund,
        sender_secret: &SecretKey,
        mint_connection: &M,
    ) -> Result<Option<Vec<Proof>>, anyhow::Error>
    where
        M: MintConnection + ?Sized,
    {
        prepared.verify(self, sender_secret)?;
        let response = mint_connection
            .post_restore(RestoreRequest {
                outputs: prepared
                    .outputs
                    .iter()
                    .map(|output| output.blinded_message.clone())
                    .collect(),
            })
            .await?;
        self.complete_prepared_sender_refund_restore(prepared, sender_secret, response)
    }

    /// Pure checked completion using only the persisted output keys.
    pub fn complete_prepared_sender_refund(
        &self,
        prepared: &PreparedSenderRefund,
        sender_secret: &SecretKey,
        blind_signatures: Vec<BlindSignature>,
    ) -> Result<Vec<Proof>, anyhow::Error> {
        prepared.verify(self, sender_secret)?;
        complete_exact_signatures(
            blind_signatures,
            prepared
                .outputs
                .iter()
                .map(|output| PreparedOutput {
                    blinded_message: output.blinded_message.clone(),
                    secret: output.secret.clone(),
                    blinding_factor: output.blinding_factor.clone(),
                })
                .collect(),
            &prepared.output_keyset,
            None,
        )
        .map_err(anyhow::Error::msg)
    }

    /// Pure checked NUT-09 completion. Only two empty arrays mean absent; partial
    /// or invalid responses are errors. Proofs are returned in prepared order.
    pub fn complete_prepared_sender_refund_restore(
        &self,
        prepared: &PreparedSenderRefund,
        sender_secret: &SecretKey,
        response: RestoreResponse,
    ) -> Result<Option<Vec<Proof>>, anyhow::Error> {
        prepared.verify(self, sender_secret)?;
        if response.outputs.is_empty() && response.signatures.is_empty() {
            return Ok(None);
        }
        let outputs = prepared
            .outputs
            .iter()
            .map(|output| output.blinded_message.clone())
            .collect::<Vec<_>>();
        let signatures =
            match_restore_response(response, &outputs, "refund").map_err(anyhow::Error::msg)?;
        self.complete_prepared_sender_refund(prepared, sender_secret, signatures)
            .map(Some)
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
        sender_secret: &SecretKey,
        amounts: &[u64],
        output_keyset: &KeysetInfo,
        derivation_context: [u8; 32],
    ) -> Result<Vec<PreparedSenderRefundOutput>, anyhow::Error> {
        let mut per_amount_index = std::collections::BTreeMap::<u64, usize>::new();
        amounts
            .iter()
            .map(|&amount| {
                let index = per_amount_index.entry(amount).or_insert(0);
                let output = self.prepare_loose_refund_output(
                    sender_secret,
                    amount,
                    *index,
                    output_keyset,
                    derivation_context,
                )?;
                *index += 1;
                Ok(output)
            })
            .collect()
    }

    fn prepare_loose_refund_output(
        &self,
        sender_secret: &SecretKey,
        amount: u64,
        index: usize,
        output_keyset: &KeysetInfo,
        derivation_context: [u8; 32],
    ) -> Result<PreparedSenderRefundOutput, anyhow::Error> {
        let channel_id = self.params.get_channel_id();
        let mut secret_preimage = Vec::new();
        secret_preimage.extend_from_slice(&self.params.channel_secret);
        // The receiver also knows channel_secret; loose refunds must be sender-only.
        secret_preimage.extend_from_slice(sender_secret.as_secret_bytes());
        secret_preimage.extend_from_slice(&derivation_context);
        secret_preimage.extend_from_slice(&serde_json::to_vec(output_keyset)?);
        secret_preimage.extend_from_slice(&1u32.to_be_bytes());
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
        blinding_preimage.extend_from_slice(sender_secret.as_secret_bytes());
        blinding_preimage.extend_from_slice(&derivation_context);
        blinding_preimage.extend_from_slice(&serde_json::to_vec(output_keyset)?);
        blinding_preimage.extend_from_slice(&1u32.to_be_bytes());
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
        let blinded_message =
            BlindedMessage::new(Amount::from(amount), output_keyset.keyset_id, blinded_point);

        Ok(PreparedSenderRefundOutput {
            amount,
            index,
            secret,
            blinding_factor,
            blinded_message,
        })
    }
}

impl PreparedSenderRefund {
    /// Construct a keyset-only candidate without signing or submitting. The host
    /// owns refresh, active-key selection, successor authority and retry budgets.
    /// Every output amount must be supported by the replacement keyset.
    pub fn with_output_keyset(
        &self,
        channel: &EstablishedChannel,
        sender_secret: &SecretKey,
        output_keyset: KeysetInfo,
    ) -> anyhow::Result<Self> {
        self.verify(channel, sender_secret)?;
        anyhow::ensure!(
            self.output_keyset.keyset_id != output_keyset.keyset_id,
            "refund successor requires a different output keyset"
        );
        let mut successor = self.clone();
        successor.replace_output_keyset(output_keyset)?;
        anyhow::ensure!(
            self.swap_request.sig_all_msg_to_sign() == successor.swap_request.sig_all_msg_to_sign(),
            "refund successor changed SIG_ALL"
        );
        successor.verify(channel, sender_secret)?;
        Ok(successor)
    }

    fn replace_output_keyset(&mut self, keyset: KeysetInfo) -> anyhow::Result<()> {
        anyhow::ensure!(keyset.unit == self.unit, "refund output unit mismatch");
        let expected_id = match keyset.keyset_id.get_version() {
            cashu::nuts::nut02::KeySetVersion::Version00 => {
                cashu::nuts::Id::v1_from_keys(&keyset.active_keys)
            }
            cashu::nuts::nut02::KeySetVersion::Version01 => cashu::nuts::Id::v2_from_data(
                &keyset.active_keys,
                &keyset.unit,
                keyset.input_fee_ppk,
                keyset.final_expiry,
            ),
        };
        let canonical = KeysetInfo::new(
            keyset.keyset_id,
            keyset.unit.clone(),
            keyset.active_keys.clone(),
            keyset.input_fee_ppk,
            keyset.final_expiry,
        );
        anyhow::ensure!(
            expected_id == keyset.keyset_id
                && canonical.amounts_largest_first == keyset.amounts_largest_first
                && !canonical.amounts_largest_first.contains(&0),
            "invalid refund output keyset"
        );
        for output in &mut self.outputs {
            anyhow::ensure!(
                keyset
                    .active_keys
                    .amount_key(output.amount.into())
                    .is_some(),
                "replacement keyset lacks refund denomination"
            );
            output.blinded_message.keyset_id = keyset.keyset_id;
        }
        // Preserve the complete signed inputs and all other request fields.
        let mut request = serde_json::to_value(&self.swap_request)?;
        let outputs = request["outputs"]
            .as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("missing refund outputs"))?;
        for output in outputs {
            output["id"] = serde_json::to_value(keyset.keyset_id)?;
        }
        self.swap_request = serde_json::from_value(request)?;
        self.output_keyset = keyset;
        Ok(())
    }

    /// Pure validation of persisted metadata, deterministic outputs, exact inputs
    /// and the sender's SIG_ALL authorization. Does not consult time or the mint.
    pub fn verify(
        &self,
        channel: &EstablishedChannel,
        sender_secret: &SecretKey,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            channel.params.expiry_timestamp < u64::MAX,
            "channel expiry cannot be exceeded"
        );
        anyhow::ensure!(
            sender_secret.public_key() == channel.params.sender_pubkey,
            "incorrect sender secret"
        );
        let mut expected = channel.prepare_unsigned_sender_refund(
            sender_secret,
            self.derivation_keyset.clone(),
            self.derivation_context,
        )?;
        expected.replace_output_keyset(self.output_keyset.clone())?;
        let mut actual = self.clone();
        let msg = actual.swap_request.sig_all_msg_to_sign();
        let input = actual
            .swap_request
            .inputs_mut()
            .first_mut()
            .ok_or_else(|| anyhow::anyhow!("missing refund input"))?;
        let Some(Witness::P2PKWitness(witness)) = input.witness.take() else {
            anyhow::bail!("missing refund authorization");
        };
        anyhow::ensure!(
            witness.signatures.len() == 1,
            "expected one refund signature"
        );
        channel
            .params
            .get_sender_blinded_pubkey_for_stage1_refund()?
            .verify(msg.as_bytes(), &witness.signatures[0].parse()?)?;
        anyhow::ensure!(
            serde_json::to_value(actual)? == serde_json::to_value(expected)?,
            "prepared refund does not match channel, metadata or deterministic request"
        );
        Ok(())
    }

    /// Serialize a prepared refund attempt for durable storage before submit.
    pub fn to_json(&self) -> Result<String, anyhow::Error> {
        serde_json::to_string(self).map_err(Into::into)
    }

    /// Restore a prepared refund attempt from durable storage.
    pub fn from_json(json: &str) -> Result<Self, anyhow::Error> {
        serde_json::from_str(json).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeterministicOutputsForOneContext;
    use cashu::nuts::{CheckStateResponse, CurrencyUnit, Id, Keys, SwapResponse};

    fn keyset(secret: &SecretKey) -> KeysetInfo {
        let keys = Keys::new(
            [1u64, 2, 4, 8]
                .into_iter()
                .map(|amount| (Amount::from(amount), secret.public_key()))
                .collect(),
        );
        KeysetInfo::new(Id::v1_from_keys(&keys), CurrencyUnit::Sat, keys, 0, None)
    }

    fn fixture() -> (EstablishedChannel, SecretKey, KeysetInfo, SecretKey) {
        let sender = SecretKey::generate();
        let funding_secret = SecretKey::generate();
        let params = ChannelParameters::new_with_secret_key(
            sender.public_key(),
            SecretKey::generate().public_key(),
            "https://mint.example".to_string(),
            CurrencyUnit::Sat,
            8,
            14,
            100,
            1,
            keyset(&funding_secret),
            4,
            &sender,
        )
        .unwrap();
        let funding =
            DeterministicOutputsForOneContext::new("funding".to_string(), 14, params.clone())
                .unwrap();
        let funding_proofs = funding
            .get_secrets_with_blinding()
            .unwrap()
            .into_iter()
            .map(|output| Proof {
                amount: Amount::from(output.amount),
                keyset_id: params.keyset_info.keyset_id,
                secret: output.secret,
                c: funding_secret.public_key(),
                witness: None,
                dleq: None,
                p2pk_e: None,
            })
            .collect();
        let mint_secret = SecretKey::generate();
        (
            EstablishedChannel::new(params, funding_proofs).unwrap(),
            sender,
            keyset(&mint_secret),
            mint_secret,
        )
    }

    fn signatures(prepared: &PreparedSenderRefund, mint_secret: &SecretKey) -> Vec<BlindSignature> {
        prepared
            .outputs
            .iter()
            .map(|output| {
                let message = &output.blinded_message;
                let c = cashu::dhke::sign_message(mint_secret, &message.blinded_secret).unwrap();
                BlindSignature::new(
                    message.amount,
                    c,
                    message.keyset_id,
                    &message.blinded_secret,
                    mint_secret,
                )
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn loose_refund_derivation_requires_sender_private_material() {
        let (channel, sender, output_keyset, _) = fixture();
        let derive = |key: &SecretKey| {
            channel
                .prepare_loose_refund_output(key, 4, 0, &output_keyset, [0; 32])
                .unwrap()
        };
        let output = derive(&sender);
        let repeated = derive(&sender);
        assert_eq!(output.secret, repeated.secret);
        assert_eq!(output.blinding_factor, repeated.blinding_factor);
        assert_eq!(output.blinded_message, repeated.blinded_message);
        let receiver_output = derive(&SecretKey::from_slice(&[2; 32]).unwrap());
        assert_ne!(output.secret, receiver_output.secret);
        assert_ne!(output.blinding_factor, receiver_output.blinding_factor);
        assert_ne!(output.blinded_message, receiver_output.blinded_message);

        // Reproduce the vulnerable derivation using only receiver-known material.
        let channel_id = channel.params.get_channel_id();
        let legacy_preimage = |suffix| {
            let mut bytes = channel.params.channel_secret.to_vec();
            bytes.extend_from_slice(
                format!("{channel_id}|{SENDER_REFUND_LOOSE_CONTEXT}|4|0|{suffix}").as_bytes(),
            );
            bytes
        };
        let legacy_secret = Secret::new(format!(
            "{SENDER_REFUND_LOOSE_CONTEXT}:{channel_id}:4:{}",
            hex::encode(sha256::Hash::hash(&legacy_preimage("secret")).to_byte_array())
        ));
        let scalar = hash_to_secp_scalar(&legacy_preimage("blinding"), |input| {
            sha256::Hash::hash(input).to_byte_array()
        })
        .unwrap();
        let legacy_blinding = SecretKey::from_slice(&scalar.to_be_bytes()).unwrap();
        let (legacy_point, _) =
            cashu::dhke::blind_message(&legacy_secret.to_bytes(), Some(legacy_blinding.clone()))
                .unwrap();
        assert_ne!(output.secret, legacy_secret);
        assert_ne!(output.blinding_factor, legacy_blinding);
        assert_ne!(output.blinded_message.blinded_secret, legacy_point);
    }

    #[test]
    fn refund_independent_keys_roundtrip_and_successor_context() {
        let (channel, sender, output_keyset, mint_secret) = fixture();
        assert_ne!(
            channel.params.keyset_info.keyset_id,
            output_keyset.keyset_id
        );
        let prepared = channel
            .prepare_sender_refund_after_expiry(sender.clone(), 101, output_keyset.clone(), [1; 32])
            .unwrap();
        let restored = PreparedSenderRefund::from_json(&prepared.to_json().unwrap()).unwrap();
        restored.verify(&channel, &sender).unwrap();
        let receiver_attempt = channel
            .prepare_loose_refund_output(
                &SecretKey::generate(),
                prepared.outputs[0].amount,
                prepared.outputs[0].index,
                &output_keyset,
                prepared.derivation_context,
            )
            .unwrap();
        assert_ne!(receiver_attempt.secret, prepared.outputs[0].secret);
        assert_ne!(
            receiver_attempt.blinding_factor,
            prepared.outputs[0].blinding_factor
        );
        let proofs = channel
            .complete_prepared_sender_refund(
                &restored,
                &sender,
                signatures(&prepared, &mint_secret),
            )
            .unwrap();
        assert_eq!(proofs.iter().map(|p| u64::from(p.amount)).sum::<u64>(), 14);
        assert!(proofs
            .iter()
            .all(|p| p.keyset_id == output_keyset.keyset_id && p.p2pk_e.is_none()));
        for proof in proofs {
            proof.verify_dleq(mint_secret.public_key()).unwrap();
        }
        let successor = channel
            .prepare_sender_refund_after_expiry(sender.clone(), 101, output_keyset, [2; 32])
            .unwrap();
        assert!(prepared
            .outputs
            .iter()
            .zip(&successor.outputs)
            .all(|(a, b)| a.secret != b.secret
                && a.blinded_message.blinded_secret != b.blinded_message.blinded_secret));
        let rotated = channel
            .prepare_sender_refund_after_expiry(
                sender,
                101,
                keyset(&SecretKey::generate()),
                [1; 32],
            )
            .unwrap();
        assert_ne!(prepared.outputs[0].secret, rotated.outputs[0].secret);
    }

    #[test]
    fn refund_expiry_and_checked_fees() {
        let (mut channel, sender, output, _) = fixture();
        for now in [99, 100] {
            let error = channel
                .prepare_sender_refund_after_expiry(sender.clone(), now, output.clone(), [0; 32])
                .unwrap_err();
            assert!(matches!(
                error.downcast_ref::<SenderRefundError>(),
                Some(SenderRefundError::NotExpired { .. })
            ));
        }
        channel.params.expiry_timestamp = u64::MAX;
        assert!(channel
            .prepare_sender_refund_after_expiry(sender.clone(), u64::MAX, output.clone(), [0; 32])
            .is_err());
        channel.params.expiry_timestamp = 100;
        channel.params.keyset_info.input_fee_ppk = u64::MAX;
        assert!(channel
            .prepare_sender_refund_after_expiry(sender.clone(), 101, output.clone(), [0; 32])
            .unwrap_err()
            .to_string()
            .contains("overflow"));
        // Four funding proofs: ceil(3500 * 4 / 1000) consumes the entire value.
        assert_eq!(channel.funding_proofs.len(), 4);
        channel.params.keyset_info.input_fee_ppk = 3500;
        let error = channel
            .prepare_sender_refund_after_expiry(sender.clone(), 101, output.clone(), [0; 32])
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<SenderRefundError>(),
            Some(&SenderRefundError::ZeroNetValue)
        );
        channel.params.keyset_info.input_fee_ppk = 4000;
        assert!(channel
            .prepare_sender_refund_after_expiry(sender, 101, output, [0; 32])
            .unwrap_err()
            .to_string()
            .contains("exceeds"));
    }

    #[test]
    fn refund_output_denominations_and_funding_fee_rounding_are_independent() {
        let (mut channel, sender, mut output, mint_secret) = fixture();
        channel.params.keyset_info.input_fee_ppk = 100;
        // ceil(4 * 100 / 1000) = 1; output fees do not reduce this refund.
        output = KeysetInfo::new(
            output.keyset_id,
            output.unit,
            Keys::new(
                [(Amount::from(1), mint_secret.public_key())]
                    .into_iter()
                    .collect(),
            ),
            9999,
            None,
        );
        output.keyset_id = Id::v1_from_keys(&output.active_keys);
        let prepared = channel
            .prepare_sender_refund_after_expiry(sender.clone(), 101, output.clone(), [0; 32])
            .unwrap();
        assert_eq!(prepared.output_amount_raw, 13);
        assert_eq!(prepared.outputs.len(), 13);
        output.unit = CurrencyUnit::Msat;
        assert!(channel
            .prepare_sender_refund_after_expiry(sender.clone(), 101, output.clone(), [0; 32])
            .is_err());
        output.unit = CurrencyUnit::Sat;
        output.active_keys = Keys::new(
            [(Amount::from(3), mint_secret.public_key())]
                .into_iter()
                .collect(),
        );
        output = KeysetInfo::new(
            Id::v1_from_keys(&output.active_keys),
            output.unit,
            output.active_keys,
            0,
            None,
        );
        assert!(channel
            .prepare_sender_refund_after_expiry(sender.clone(), 101, output.clone(), [0; 32])
            .unwrap_err()
            .to_string()
            .contains("Cannot represent"));
        channel.funding_proofs[0].amount = Amount::from(u64::MAX);
        assert!(channel
            .prepare_sender_refund_after_expiry(sender, 101, output, [0; 32])
            .unwrap_err()
            .to_string()
            .contains("overflow"));
    }

    #[test]
    fn refund_prepared_tampering_rejected() {
        let (channel, sender, output, _) = fixture();
        let prepared = channel
            .prepare_sender_refund_after_expiry(sender.clone(), 101, output, [0; 32])
            .unwrap();
        assert!(prepared.verify(&channel, &SecretKey::generate()).is_err());
        let mutations: Vec<fn(&mut PreparedSenderRefund)> = vec![
            |p| p.channel_id.push('x'),
            |p| p.mint.push('x'),
            |p| p.unit = CurrencyUnit::Msat,
            |p| p.derivation_version += 1,
            |p| p.derivation_context[0] ^= 1,
            |p| p.output_amount_raw += 1,
            |p| p.derivation_keyset.input_fee_ppk += 1,
            |p| p.output_keyset.amounts_largest_first.push(0),
            |p| p.output_keyset.active_keys = keyset(&SecretKey::generate()).active_keys,
            |p| p.outputs[0].amount += 1,
            |p| p.outputs[0].index += 1,
            |p| p.outputs[0].secret = Secret::new("tampered".to_string()),
            |p| p.outputs[0].blinding_factor = SecretKey::generate(),
            |p| p.outputs[0].blinded_message.amount = Amount::from(1),
            |p| p.swap_request.inputs_mut()[0].witness = None,
            |p| p.swap_request.inputs_mut()[0].amount = Amount::from(1),
            |p| p.swap_request.inputs_mut()[1].witness = p.swap_request.inputs()[0].witness.clone(),
        ];
        for (index, mutate) in mutations.into_iter().enumerate() {
            let mut bad = prepared.clone();
            mutate(&mut bad);
            assert!(bad.verify(&channel, &sender).is_err(), "mutation {index}");
        }
    }

    #[test]
    fn refund_keyset_successor_preserves_authorization_and_rejects_missing_denominations() {
        let (channel, sender, output, _) = fixture();
        let a = channel
            .prepare_sender_refund_after_expiry(sender.clone(), 101, output, [9; 32])
            .unwrap();
        let b = a
            .with_output_keyset(&channel, &sender, keyset(&SecretKey::generate()))
            .unwrap();
        assert!(a.swap_request.inputs() == b.swap_request.inputs());
        assert!(a.swap_request.sig_all_msg_to_sign() == b.swap_request.sig_all_msg_to_sign());
        for (a, b) in a.outputs.iter().zip(&b.outputs) {
            assert!(a.secret == b.secret && a.blinding_factor == b.blinding_factor);
            assert_eq!(
                a.blinded_message.blinded_secret,
                b.blinded_message.blinded_secret
            );
        }
        b.verify(&channel, &sender).unwrap();
        let mut json = serde_json::to_value(&a).unwrap();
        json.as_object_mut().unwrap().remove("derivation_keyset");
        assert!(PreparedSenderRefund::from_json(&json.to_string()).is_err());
        let keys = Keys::new(
            [(Amount::from(1024), SecretKey::generate().public_key())]
                .into_iter()
                .collect(),
        );
        let unsupported =
            KeysetInfo::new(Id::v1_from_keys(&keys), CurrencyUnit::Sat, keys, 0, None);
        assert!(a
            .with_output_keyset(&channel, &sender, unsupported)
            .is_err());
    }

    #[test]
    fn refund_exact_crypto_and_restore_validation() {
        let (channel, sender, output, mint_secret) = fixture();
        let prepared = channel
            .prepare_sender_refund_after_expiry(sender.clone(), 101, output, [0; 32])
            .unwrap();
        let valid = signatures(&prepared, &mint_secret);
        let complete = |s| channel.complete_prepared_sender_refund(&prepared, &sender, s);
        assert!(complete(vec![]).is_err());
        assert!(complete(valid[..1].to_vec()).is_err());
        let mut bad = valid.clone();
        bad.push(valid[0].clone());
        assert!(complete(bad).is_err());
        let mut bad = valid.clone();
        bad[0].amount = Amount::from(1);
        assert!(complete(bad).is_err());
        let mut bad = valid.clone();
        bad[0].keyset_id = channel.params.keyset_info.keyset_id;
        assert!(complete(bad).is_err());
        let mut bad = valid.clone();
        bad[0].dleq = None;
        assert!(complete(bad).is_err());
        let mut bad = valid.clone();
        bad[0].c = SecretKey::generate().public_key();
        assert!(complete(bad).is_err());
        let mut bad = valid.clone();
        bad.swap(0, 1);
        assert!(complete(bad).is_err());
        let outputs = prepared
            .outputs
            .iter()
            .map(|p| p.blinded_message.clone())
            .collect::<Vec<_>>();
        let restore = |outputs, signatures| {
            channel.complete_prepared_sender_refund_restore(
                &prepared,
                &sender,
                RestoreResponse {
                    outputs,
                    signatures,
                },
            )
        };
        assert!(restore(vec![], vec![]).unwrap().is_none());
        assert!(restore(outputs.clone(), vec![]).is_err());
        assert!(restore(vec![], valid.clone()).is_err());
        assert!(restore(outputs[..1].to_vec(), valid[..1].to_vec()).is_err());
        let mut duplicate = outputs.clone();
        duplicate[1] = duplicate[0].clone();
        assert!(restore(duplicate, valid.clone()).is_err());
        let mut unknown = outputs.clone();
        unknown[0].blinded_secret = SecretKey::generate().public_key();
        assert!(restore(unknown, valid.clone()).is_err());
        let mut reversed_outputs = outputs.clone();
        reversed_outputs.reverse();
        let mut reversed_signatures = valid.clone();
        reversed_signatures.reverse();
        let canonical = restore(reversed_outputs, reversed_signatures)
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::to_value(canonical).unwrap(),
            serde_json::to_value(complete(valid).unwrap()).unwrap()
        );
    }

    #[derive(Debug, thiserror::Error)]
    #[error("structured mint rejection 12002")]
    struct MintRejection;

    struct RejectingMint;
    #[async_trait::async_trait]
    impl MintConnection for RejectingMint {
        async fn process_swap(&self, _: SwapRequest) -> anyhow::Result<SwapResponse> {
            Err(MintRejection.into())
        }
        async fn post_restore(&self, _: RestoreRequest) -> anyhow::Result<RestoreResponse> {
            Err(MintRejection.into())
        }
        async fn check_state(
            &self,
            _: Vec<cashu::nuts::PublicKey>,
        ) -> anyhow::Result<CheckStateResponse> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn refund_preserves_mint_errors() {
        let (channel, sender, output, _) = fixture();
        let prepared = channel
            .prepare_sender_refund_after_expiry(sender.clone(), 101, output, [0; 32])
            .unwrap();
        let error = channel
            .submit_prepared_sender_refund(&prepared, &sender, 100, &RejectingMint)
            .await
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<SenderRefundError>(),
            Some(SenderRefundError::NotExpired { .. })
        ));
        let error = channel
            .submit_prepared_sender_refund(&prepared, &sender, 101, &RejectingMint)
            .await
            .unwrap_err();
        assert!(error.downcast_ref::<MintRejection>().is_some());
        let error = channel
            .restore_prepared_sender_refund_outputs(&prepared, &sender, &RejectingMint)
            .await
            .unwrap_err();
        assert!(error.downcast_ref::<MintRejection>().is_some());
    }
}
