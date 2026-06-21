//! Established Spilman Channel
//!
//! Contains the complete channel state after funding

use cashu::nuts::{Proof, SecretKey};
use cashu::util::hex;

use super::client_storage::ClientChannelFunding;
use super::deterministic::MintConnection;
use super::params::ChannelParameters;
use super::sender_and_receiver::SpilmanChannelSender;
use crate::bindings::parse_keyset_info_from_json;

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
}
