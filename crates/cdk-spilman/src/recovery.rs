//! State-first reconciliation of ordinary channel funding spends.
//!
//! These operations only inspect and recover. Hosts retain immutable attempts,
//! own durable finalization, and decide when to submit, replay, or stop collecting.

use anyhow::{ensure, Context, Result};
use cashu::nuts::{CheckStateResponse, Proof, RestoreRequest, State, SwapRequest};

use crate::{
    parse_keyset_info_from_json, verify_valid_channel, ChannelParameters, ChannelState,
    CompletedClose, EstablishedChannel, KeysetInfo, MintConnection, PaymentProof, PreparedClose,
    PreparedSenderRefund, SpilmanBridge, SpilmanChannelSender, SpilmanHost,
};

/// Aggregate state of exactly the channel's funding proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FundingState {
    /// All funding is unspent at the time of the query; not a reservation.
    Unspent,
    /// All funding is pending; the operation must remain unresolved.
    Pending,
    /// All funding has been spent, without identifying the spending transaction.
    Spent,
    /// Different input states, including a possible partial post-expiry refund.
    Mixed,
}

/// Identity-checked NUT-07 evidence. No witness-based spend classification is made.
#[derive(Clone)]
pub struct FundingInspection {
    state: FundingState,
    response: CheckStateResponse,
}

impl FundingInspection {
    /// Aggregate state. Mixed/pending evidence does not authorize recovery or replay.
    pub fn state(&self) -> FundingState {
        self.state
    }

    /// Complete mint evidence, including witnesses and any issuance metadata.
    pub fn response(&self) -> &CheckStateResponse {
        &self.response
    }
}

impl core::fmt::Debug for FundingInspection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FundingInspection")
            .field("state", &self.state)
            .field("proof_count", &self.response.states.len())
            .finish_non_exhaustive()
    }
}

/// Result of inspecting funding and, only if spent, restoring known payouts.
/// Errors are returned separately, never represented as an empty restore.
#[derive(Debug)]
pub enum ChannelRecovery<T> {
    /// No committed spend observed. Preserve uncertain attempts and replay rules.
    Unspent(FundingInspection),
    /// Wait; do not submit a replacement transaction.
    Pending(FundingInspection),
    /// Inconsistent input states or a partial spend; leave policy to the host.
    Mixed(FundingInspection),
    /// Verified payout, ready for the host's durable finalization/import.
    Recovered {
        /// Funding evidence observed before restoration.
        funding: FundingInspection,
        /// Verified recovered value.
        payout: T,
    },
    /// Funding is spent but valid empty restores found no known payout.
    /// This is not proof of a refund, a zero payout, or successful settlement.
    SpentNoKnownPayout(FundingInspection),
}

impl<T> ChannelRecovery<T> {
    fn without_payout(funding: FundingInspection) -> Self {
        match funding.state {
            FundingState::Unspent => Self::Unspent(funding),
            FundingState::Pending => Self::Pending(funding),
            FundingState::Mixed => Self::Mixed(funding),
            FundingState::Spent => Self::SpentNoKnownPayout(funding),
        }
    }
}

/// Positively established source of Alice's recovered proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenderRecoverySource {
    /// Index into the caller's retained refund attempts.
    Refund {
        /// Position of the authenticated refund in the supplied attempt list.
        attempt_index: usize,
    },
    /// Verified deterministic sender outputs from a receiver close.
    ReceiverClose,
}

/// Alice's verified proofs. Receiver-close outputs still require the ordinary
/// second-stage swap; refund outputs are already loose proofs.
pub struct RecoveredSenderFunds {
    /// How the proofs were recovered, not a signature-count inference.
    pub source: SenderRecoverySource,
    /// Verified proofs to persist before import or further spending.
    pub proofs: Vec<Proof>,
}

impl core::fmt::Debug for RecoveredSenderFunds {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoveredSenderFunds")
            .field("source", &self.source)
            .field("proof_count", &self.proofs.len())
            .finish_non_exhaustive()
    }
}

impl EstablishedChannel {
    /// Query all funding proofs once and validate exact, duplicate-free identity
    /// coverage. Response ordering is immaterial. No state or witness metadata is
    /// discarded. This does not classify the spending transaction or change state.
    pub async fn inspect_funding<M>(&self, mint: &M) -> Result<FundingInspection>
    where
        M: MintConnection + ?Sized,
    {
        ensure!(
            verify_valid_channel(&self.funding_proofs, &self.params).valid,
            "invalid channel funding model"
        );
        let ys = self
            .funding_proofs
            .iter()
            .map(Proof::y)
            .collect::<Result<Vec<_>, _>>()?;
        ensure!(
            !ys.is_empty() && ys.iter().collect::<std::collections::HashSet<_>>().len() == ys.len(),
            "invalid funding identities"
        );
        let response = mint
            .check_state(ys.clone())
            .await
            .context("funding inspection failed")?;
        ensure!(
            response.states.len() == ys.len()
                && ys
                    .iter()
                    .all(|y| response.states.iter().filter(|s| s.y == *y).count() == 1),
            "funding inspection requires exact identity coverage"
        );
        ensure!(
            response
                .states
                .iter()
                .all(|s| matches!(s.state, State::Unspent | State::Pending | State::Spent)),
            "unsupported funding state"
        );
        let first = response.states[0].state;
        let state = if response.states.iter().any(|s| s.state != first) {
            FundingState::Mixed
        } else {
            match first {
                State::Unspent => FundingState::Unspent,
                State::Pending => FundingState::Pending,
                State::Spent => FundingState::Spent,
                State::Reserved | State::PendingSpent => anyhow::bail!("unsupported funding state"),
            }
        };
        Ok(FundingInspection { state, response })
    }
}

impl SpilmanChannelSender {
    /// Reconcile Alice's ordinary channel without submitting anything. Inspect
    /// NUT-07 first; if spent, try every maybe-submitted refund before discovering
    /// her share of a receiver close. Refund attempts are authenticated against
    /// this channel and sender before mint I/O. Historical close output keys must
    /// be supplied by the caller; no key refresh or selection is performed here.
    ///
    /// Only valid empty refund restores permit close discovery. Invalid/failed
    /// restores remain errors unless another retained refund can be recovered.
    pub async fn recover_funds<M>(
        &self,
        mint: &M,
        refund_attempts: &[PreparedSenderRefund],
        close_output_keysets: &[KeysetInfo],
    ) -> Result<ChannelRecovery<RecoveredSenderFunds>>
    where
        M: MintConnection + ?Sized,
    {
        ensure!(
            self.alice_secret.public_key() == self.channel.params.sender_pubkey,
            "incorrect sender key"
        );
        for attempt in refund_attempts {
            attempt.verify(&self.channel, &self.alice_secret)?;
        }
        let funding = self.channel.inspect_funding(mint).await?;
        if funding.state != FundingState::Spent {
            return Ok(ChannelRecovery::without_payout(funding));
        }
        let mut invalid_restore = None;
        for attempt in refund_attempts {
            let response = mint
                .post_restore(RestoreRequest {
                    outputs: attempt
                        .outputs
                        .iter()
                        .map(|o| o.blinded_message.clone())
                        .collect(),
                })
                .await;
            let mut response = match response {
                Ok(response) => response,
                Err(error) => {
                    invalid_restore.get_or_insert(error);
                    continue;
                }
            };
            if response.outputs.len() != response.signatures.len() {
                invalid_restore
                    .get_or_insert_with(|| anyhow::anyhow!("invalid refund restore coverage"));
                continue;
            }
            // NUT-09 can echo the queried ID while returning a different retained
            // candidate's issuance for the same blinded points. Signature IDs
            // route candidates; exact completion verifies the entire payout.
            for (output, signature) in response.outputs.iter_mut().zip(&response.signatures) {
                output.keyset_id = signature.keyset_id;
            }
            let mut candidate_error = None;
            let mut empty = false;
            for (attempt_index, candidate) in refund_attempts.iter().enumerate() {
                match self.channel.complete_prepared_sender_refund_restore(
                    candidate,
                    &self.alice_secret,
                    response.clone(),
                ) {
                    Ok(Some(proofs)) => {
                        return Ok(ChannelRecovery::Recovered {
                            funding,
                            payout: RecoveredSenderFunds {
                                source: SenderRecoverySource::Refund { attempt_index },
                                proofs,
                            },
                        })
                    }
                    Ok(None) => {
                        empty = true;
                    }
                    Err(error) => {
                        candidate_error.get_or_insert(error);
                    }
                }
            }
            if !empty {
                if let Some(error) = candidate_error {
                    invalid_restore.get_or_insert(error);
                }
            }
        }
        if let Some(error) = invalid_restore {
            return Err(error.context("refund recovery unresolved"));
        }
        let proofs = self
            .restore_sender_proofs_with_keysets(mint, close_output_keysets)
            .await?;
        if proofs.is_empty() {
            Ok(ChannelRecovery::SpentNoKnownPayout(funding))
        } else {
            Ok(ChannelRecovery::Recovered {
                funding,
                payout: RecoveredSenderFunds {
                    source: SenderRecoverySource::ReceiverClose,
                    proofs,
                },
            })
        }
    }
}

impl<H: SpilmanHost<C>, C> SpilmanBridge<H, C> {
    /// Reconcile Charlie's retained ordinary close attempts for a channel in
    /// `Closing`. Authenticates each request against stored funding and the fixed
    /// closing payment, then inspects NUT-07 before any NUT-09 requests. Does not
    /// submit, replay, select keys, classify witnesses, or mutate host storage.
    /// A recovered close must be durably finalized by the caller. Existing verified
    /// completions can still be finalized offline without calling this method.
    pub async fn recover_close<M>(
        &self,
        channel_id: &str,
        attempts: &[PreparedClose],
        mint: &M,
    ) -> Result<ChannelRecovery<CompletedClose>>
    where
        M: MintConnection + ?Sized,
    {
        ensure!(
            self.host()
                .get_channel_state(channel_id)
                .map_err(anyhow::Error::msg)?
                == Some(ChannelState::Closing),
            "channel is not closing"
        );
        let stored = self
            .host()
            .get_funding(channel_id)
            .context("missing channel funding")?;
        let closing = self
            .host()
            .get_closing_data(channel_id)
            .context("missing closing payment")?;
        let payment = PaymentProof {
            balance: closing.balance,
            signature: closing.signature,
        };
        let secret = cashu::util::hex::decode(&stored.channel_secret_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid channel secret length"))?;
        let params = ChannelParameters::from_json_with_channel_secret(
            &stored.params_json,
            parse_keyset_info_from_json(&stored.keyset_info_json).map_err(anyhow::Error::msg)?,
            secret,
        )?;
        ensure!(
            params.get_channel_id() == channel_id
                && self
                    .host()
                    .receiver_key_is_acceptable(&params.receiver_pubkey),
            "incorrect receiver channel binding"
        );
        for attempt in attempts {
            self.verify_prepared_close(attempt, &stored, &payment, &params.receiver_pubkey)?;
        }
        let channel =
            EstablishedChannel::new(params, serde_json::from_str(&stored.funding_proofs_json)?)?;
        let funding = channel.inspect_funding(mint).await?;
        if funding.state != FundingState::Spent {
            return Ok(ChannelRecovery::without_payout(funding));
        }
        let mut invalid_restore = None;
        for attempt in attempts {
            let request: SwapRequest = serde_json::from_value(attempt.swap_request.clone())?;
            let result = async {
                let response = mint
                    .post_restore(RestoreRequest {
                        outputs: request.outputs().clone(),
                    })
                    .await?;
                self.complete_prepared_close_restore(&serde_json::to_string(&response)?, attempt)
                    .map_err(anyhow::Error::from)
            }
            .await;
            match result {
                Ok(Some(payout)) => return Ok(ChannelRecovery::Recovered { funding, payout }),
                Ok(None) => {}
                Err(error) => {
                    invalid_restore.get_or_insert(error);
                }
            }
        }
        if let Some(error) = invalid_restore {
            return Err(error.context("receiver close recovery unresolved"));
        }
        Ok(ChannelRecovery::SpentNoKnownPayout(funding))
    }
}
