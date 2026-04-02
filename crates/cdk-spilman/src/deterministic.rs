#![allow(missing_docs)]
//! Deterministic P2PK Output Generation
//!
//! Types for creating deterministic P2PK outputs for Spilman payment channels.
//! Contains a hierarchy of output types:
//! - `DeterministicSecretWithBlinding` - single output (secret + blinding + amount)
//! - `DeterministicOutputsForOneContext` - all outputs for one party
//! - `CommitmentOutputs` - outputs for both parties (receiver + sender)

use async_trait::async_trait;

use cashu::dhke::blind_message;
use cashu::nuts::nut10::Conditions;
use cashu::nuts::nut11::SigFlag;
use cashu::nuts::{BlindSignature, BlindedMessage, Id, RestoreRequest, SecretKey};
use cashu::secret::Secret;
use cashu::Amount;

use super::keysets_and_amounts::OrderedListOfAmounts;
use super::params::{ChannelParameters, Stage2Role};

/// Trait for mint connection operations needed by Spilman channels
#[async_trait]
pub trait MintConnection: Send + Sync {
    /// Process a swap request
    async fn process_swap(
        &self,
        request: cashu::nuts::SwapRequest,
    ) -> anyhow::Result<cashu::nuts::SwapResponse>;
    /// Post a restore request
    async fn post_restore(
        &self,
        request: RestoreRequest,
    ) -> anyhow::Result<cashu::nuts::RestoreResponse>;
    /// Check proof state
    async fn check_state(
        &self,
        ys: Vec<cashu::nuts::PublicKey>,
    ) -> anyhow::Result<cashu::nuts::CheckStateResponse>;
}

/// Deterministic secret with blinding factor
/// Can hold any type of secret (simple P2PK, P2PK with conditions, HTLC, etc.)
#[derive(Debug, Clone)]
pub struct DeterministicSecretWithBlinding {
    /// The secret (can be any NUT-10 secret with specified nonce)
    pub secret: Secret,
    /// The blinding factor
    pub blinding_factor: SecretKey,
    /// The amount for this output
    pub amount: u64,
    /// The index within outputs of the same amount (for per-proof blinding)
    pub index: usize,
}

impl DeterministicSecretWithBlinding {
    /// Create a simple P2PK output (1-of-1 signature)
    /// Used for commitment outputs (sender or receiver)
    pub fn new_p2pk(
        pubkey: &cashu::nuts::PublicKey,
        nonce: String,
        blinding_factor: SecretKey,
        amount: u64,
        index: usize,
    ) -> Result<Self, anyhow::Error> {
        // Manually construct the NUT-10 P2PK secret JSON
        // Format: ["P2PK", {"nonce": "...", "data": "pubkey_hex", "tags": null}]
        let secret_json = serde_json::json!([
            "P2PK",
            {
                "nonce": nonce,
                "data": pubkey.to_hex(),
                "tags": null
            }
        ]);

        // Create a Secret from the JSON string
        let secret = Secret::new(secret_json.to_string());

        Ok(Self {
            secret,
            blinding_factor,
            amount,
            index,
        })
    }

    /// Create a funding output with 2-of-2 multisig + expiry conditions
    /// Used for the funding token that both parties must sign to spend,
    /// or Alice alone can reclaim after expiry.
    ///
    /// Uses BLINDED pubkeys for privacy - the mint cannot correlate
    /// the funding token to Alice and Charlie's real identities.
    ///
    /// Note: Funding outputs use SHARED blinding (same pubkey for all proofs)
    /// because SIG_ALL requires identical keys in every proof. The index
    /// is stored but not used for blinding derivation in the funding context.
    pub fn new_funding(
        params: &ChannelParameters,
        nonce: String,
        blinding_factor: SecretKey,
        amount: u64,
        index: usize,
    ) -> Result<Self, anyhow::Error> {
        // Get blinded pubkeys for privacy
        // The 2-of-2 path uses one set of blinded keys
        let blinded_sender_pubkey = params.get_sender_blinded_pubkey_for_stage1()?;
        let blinded_receiver_pubkey = params.get_receiver_blinded_pubkey_for_stage1()?;
        // The refund path uses a DIFFERENT blinded key for Alice (unlinkable to 2-of-2)
        let blinded_sender_pubkey_refund = params.get_sender_blinded_pubkey_for_stage1_refund()?;

        // Create the spending conditions: 2-of-2 multisig (Alice + Charlie) before expiry
        // After expiry, Alice can refund with just her signature
        // All pubkeys are BLINDED for privacy, with refund using a separate tweak
        let conditions = Conditions::new(
            Some(params.expiry_timestamp), // Expiry timestamp for Alice's refund
            Some(vec![blinded_receiver_pubkey]), // Charlie's blinded key for 2-of-2
            Some(vec![blinded_sender_pubkey_refund]), // Alice's REFUND blinded key (different tweak)
            Some(2),                                  // Require 2 signatures before expiry
            Some(SigFlag::SigAll),                    // SigAll: signatures commit to outputs
            Some(1),                                  // Only 1 signature needed for refund (Alice)
        )?;

        // Convert conditions to proper NUT-10/11 tag array format
        let tags: Vec<Vec<String>> = conditions.into();
        let tags_json = serde_json::to_value(tags)
            .map_err(|e| anyhow::anyhow!("Failed to serialize spending conditions: {}", e))?;

        // Manually construct the NUT-10 P2PK secret JSON with spending conditions
        // Format: ["P2PK", {"nonce": "...", "data": "pubkey_hex", "tags": [...conditions...]}]
        // The "data" field contains Alice's BLINDED pubkey
        let secret_json = serde_json::json!([
            "P2PK",
            {
                "nonce": nonce,
                "data": blinded_sender_pubkey.to_hex(),
                "tags": tags_json
            }
        ]);

        // Create a Secret from the JSON string
        let secret = Secret::new(secret_json.to_string());

        Ok(Self {
            secret,
            blinding_factor,
            amount,
            index,
        })
    }

    /// Create a BlindedMessage from this deterministic output
    pub fn to_blinded_message(
        &self,
        amount: Amount,
        keyset_id: Id,
    ) -> Result<BlindedMessage, anyhow::Error> {
        // Blind the secret using the deterministic blinding factor
        let (blinded_point, _) =
            blind_message(&self.secret.to_bytes(), Some(self.blinding_factor.clone()))?;

        Ok(BlindedMessage::new(amount, keyset_id, blinded_point))
    }
}

/// A set of deterministic outputs for a specific pubkey and amount
/// This represents all the deterministic blinded messages, secrets, and blinding factors
/// for splitting a given amount into ecash outputs
#[derive(Debug, Clone)]
pub struct DeterministicOutputsForOneContext {
    /// The context for these outputs: "sender", "receiver", or "funding"
    pub context: String,
    /// The total amount to allocate
    pub amount: u64,
    /// The breakdown of amounts (largest-first)
    pub ordered_amounts: OrderedListOfAmounts,
    /// Channel parameters (includes shared_secret)
    pub params: ChannelParameters,
}

impl DeterministicOutputsForOneContext {
    /// Create a new set of deterministic outputs
    pub fn new(context: String, amount: u64, params: ChannelParameters) -> anyhow::Result<Self> {
        // Get the ordered list of amounts for this target
        let ordered_amounts = OrderedListOfAmounts::from_target(
            amount,
            params.maximum_amount_for_one_output,
            &params.keyset_info,
        )?;

        Ok(Self {
            context,
            amount,
            ordered_amounts,
            params,
        })
    }

    /// Calculate the value after stage 2 fees
    pub fn value_after_fees(&self) -> u64 {
        self.ordered_amounts.value_after_fees()
    }

    /// Get the secrets with blinding for these outputs
    /// Works for all contexts: "sender", "receiver", and "funding"
    /// Returns full DeterministicSecretWithBlinding objects (secret + blinding factor)
    /// Outputs are ordered smallest-first per Cashu protocol recommendation
    pub fn get_secrets_with_blinding(
        &self,
    ) -> Result<Vec<DeterministicSecretWithBlinding>, anyhow::Error> {
        if self.amount == 0 {
            return Ok(vec![]);
        }

        let mut outputs = Vec::new();

        // Use iter_smallest_first to track index per amount (Cashu protocol recommendation)
        for (&single_amount, &count) in self.ordered_amounts.iter_smallest_first() {
            for index in 0..count {
                let det_output = self.params.create_deterministic_output_with_blinding(
                    &self.context,
                    single_amount,
                    index,
                )?;
                outputs.push(det_output);
            }
        }

        Ok(outputs)
    }

    /// Get the blinded messages for these outputs
    /// Works for all contexts: "sender", "receiver", and "funding"
    /// Outputs are ordered smallest-first per Cashu protocol recommendation
    pub fn get_blinded_messages(
        &self,
        override_keyset_id: Option<Id>,
    ) -> Result<Vec<BlindedMessage>, anyhow::Error> {
        // Get the secrets with blinding factors (already in smallest-first order)
        let secrets = self.get_secrets_with_blinding()?;

        // Build parallel vector of amounts in the same order as the secrets (smallest-first)
        let amounts: Vec<u64> = self
            .ordered_amounts
            .iter_smallest_first()
            .flat_map(|(&amount, &count)| std::iter::repeat_n(amount, count))
            .collect();

        // Use override keyset if provided, otherwise use the one from params
        let keyset_id = override_keyset_id.unwrap_or(self.params.keyset_info.keyset_id);

        // Convert each secret to a blinded message
        secrets
            .iter()
            .zip(amounts.iter())
            .map(|(secret, &amount)| secret.to_blinded_message(Amount::from(amount), keyset_id))
            .collect()
    }
}

/// Commitment outputs for a specific balance distribution
/// Contains the deterministic outputs for both sender (Alice) and receiver (Charlie)
/// at a specific balance point in the channel
#[derive(Debug, Clone)]
pub struct CommitmentOutputs {
    /// Receiver's (Charlie's) deterministic outputs
    pub receiver_outputs: DeterministicOutputsForOneContext,
    /// Sender's (Alice's) deterministic outputs
    pub sender_outputs: DeterministicOutputsForOneContext,
}

/// A proof with its associated metadata from the channel
///
/// Used when unblinding proofs to track which party owns each proof
/// and the (amount, index) needed for per-proof blinded key derivation.
#[derive(Debug, Clone)]
pub struct ProofWithMetadata {
    /// The unblinded proof
    pub proof: cashu::nuts::Proof,
    /// The nominal amount of this proof
    pub amount: u64,
    /// The index within proofs of the same amount (for per-proof blinding)
    pub index: usize,
    /// Whether this proof belongs to the receiver (Charlie) or sender (Alice)
    pub is_receiver: bool,
}

impl CommitmentOutputs {
    /// Create new commitment outputs
    pub fn new(
        receiver_outputs: DeterministicOutputsForOneContext,
        sender_outputs: DeterministicOutputsForOneContext,
    ) -> Self {
        Self {
            receiver_outputs,
            sender_outputs,
        }
    }

    /// Create commitment outputs for a given receiver balance
    ///
    /// Given the receiver's (Charlie's) desired final balance, this creates:
    /// - One DeterministicOutputsForOneContext for the receiver (Charlie)
    /// - One DeterministicOutputsForOneContext for the sender (Alice) with the remainder
    ///
    /// The process:
    /// 1. Use inverse function to find nominal value for receiver's deterministic outputs
    /// 2. Calculate sender's nominal value as: amount_after_stage1 - receiver_nominal
    /// 3. Create both sets of outputs wrapped in CommitmentOutputs
    ///
    /// Parameters:
    /// - receiver_balance: The desired final balance for the receiver (after stage 2 fees)
    /// - params: Channel parameters
    ///
    /// Returns CommitmentOutputs containing both receiver and sender outputs
    pub fn for_balance(receiver_balance: u64, params: &ChannelParameters) -> anyhow::Result<Self> {
        // Validate that receiver balance doesn't exceed channel capacity
        if receiver_balance > params.capacity {
            anyhow::bail!(
                "Receiver balance {} exceeds channel capacity {}",
                receiver_balance,
                params.capacity
            );
        }

        let max_amount = params.maximum_amount_for_one_output;

        // Get the amount available after stage 1 fees
        let amount_after_stage1 = params.get_value_after_stage1()?;

        // Find the nominal value needed for Charlie's deterministic outputs
        let inverse_result = params
            .keyset_info
            .inverse_deterministic_value_after_fees(receiver_balance, max_amount)?;
        let charlie_nominal = inverse_result.nominal_value;

        // Check if there's enough left for Alice (alice_nominal would be negative otherwise)
        if charlie_nominal > amount_after_stage1 {
            anyhow::bail!(
                "Receiver balance {} requires nominal value {} which exceeds available amount {} after stage 1 fees",
                receiver_balance,
                charlie_nominal,
                amount_after_stage1
            );
        }

        let alice_nominal = amount_after_stage1 - charlie_nominal;

        // Create outputs for Charlie (receiver)
        let charlie_outputs = DeterministicOutputsForOneContext::new(
            "receiver".to_string(),
            charlie_nominal,
            params.clone(),
        )?;

        // Create outputs for Alice (sender)
        let alice_outputs = DeterministicOutputsForOneContext::new(
            "sender".to_string(),
            alice_nominal,
            params.clone(),
        )?;

        Ok(Self::new(charlie_outputs, alice_outputs))
    }

    /// Create an unsigned swap request from this commitment
    ///
    /// Takes the funding proofs and creates a SwapRequest with:
    /// - Inputs: all funding proofs
    /// - Outputs: all outputs sorted by amount (stable) for privacy
    ///
    /// The swap request is unsigned and needs to be signed by the sender (Alice) before sending
    pub fn create_swap_request(
        &self,
        funding_proofs: Vec<cashu::nuts::Proof>,
        override_keyset_id: Option<Id>,
    ) -> Result<cashu::nuts::SwapRequest, anyhow::Error> {
        // Get blinded messages for receiver (Charlie)
        let mut outputs = self
            .receiver_outputs
            .get_blinded_messages(override_keyset_id)?;

        // Get blinded messages for sender (Alice)
        let sender_outputs = self
            .sender_outputs
            .get_blinded_messages(override_keyset_id)?;

        // Concatenate (receiver first, then sender)
        outputs.extend(sender_outputs);

        // Sort by amount (stable) for privacy - mixes receiver and sender outputs
        outputs.sort_by_key(|bm| u64::from(bm.amount));

        // Create swap request with all funding proofs as inputs
        Ok(cashu::nuts::SwapRequest::new(funding_proofs, outputs))
    }

    /// Unblind all outputs from a swap response
    ///
    /// Takes the blind signatures from the swap response and returns
    /// a vector of `ProofWithMetadata` containing each proof along with
    /// its amount, index, and ownership flag.
    ///
    /// The caller can filter by `is_receiver` to separate receiver/sender proofs.
    pub fn unblind_all(
        &self,
        blind_signatures: Vec<BlindSignature>,
        active_keys: &cashu::nuts::Keys,
    ) -> Result<Vec<ProofWithMetadata>, anyhow::Error> {
        // Assert the number of signatures matches the expected number of outputs
        let expected_count =
            self.receiver_outputs.ordered_amounts.len() + self.sender_outputs.ordered_amounts.len();
        if blind_signatures.len() != expected_count {
            anyhow::bail!(
                "Expected {} blind signatures but received {}",
                expected_count,
                blind_signatures.len()
            );
        }

        // Get outputs for receiver and sender
        let receiver_outputs = self.receiver_outputs.get_secrets_with_blinding()?;
        let sender_outputs = self.sender_outputs.get_secrets_with_blinding()?;

        // Create vector with all outputs paired with ownership flag
        // Format: (DeterministicSecretWithBlinding, is_receiver)
        let mut all_outputs: Vec<(DeterministicSecretWithBlinding, bool)> =
            receiver_outputs.into_iter().map(|o| (o, true)).collect();

        // Extend with sender outputs with flag = false
        all_outputs.extend(sender_outputs.into_iter().map(|o| (o, false)));

        // Sort by amount (stable) to match create_swap_request ordering, i.e.
        // smallest amounts first, tie-breaking by the partner (Charlie first,
        // then Alice). For a given amount and partner, they are ordered by 'index'
        all_outputs.sort_by_key(|(output, _)| output.amount);

        if all_outputs.len() != blind_signatures.len() {
            anyhow::bail!(
                "Internal mismatch: derived {} outputs for {} blind signatures",
                all_outputs.len(),
                blind_signatures.len()
            );
        }

        // Extract secrets and blinding factors in sorted order
        let sorted_secrets: Vec<_> = all_outputs.iter().map(|(o, _)| o.secret.clone()).collect();
        let sorted_blinding: Vec<_> = all_outputs
            .iter()
            .map(|(o, _)| o.blinding_factor.clone())
            .collect();

        if sorted_secrets.len() != blind_signatures.len() {
            anyhow::bail!(
                "Internal mismatch: derived {} secrets for {} blind signatures",
                sorted_secrets.len(),
                blind_signatures.len()
            );
        }
        if sorted_blinding.len() != blind_signatures.len() {
            anyhow::bail!(
                "Internal mismatch: derived {} blinding factors for {} blind signatures",
                sorted_blinding.len(),
                blind_signatures.len()
            );
        }

        // Unblind all proofs in sorted order
        let all_proofs = cashu::dhke::construct_proofs(
            blind_signatures,
            sorted_blinding,
            sorted_secrets,
            active_keys,
        )?;

        if all_proofs.len() != all_outputs.len() {
            anyhow::bail!(
                "Internal mismatch: unblinded {} proofs for {} outputs",
                all_proofs.len(),
                all_outputs.len()
            );
        }

        // Build result with metadata for each proof
        all_proofs
            .into_iter()
            .zip(all_outputs.iter())
            .map(|(mut proof, (output, is_receiver))| {
                let role = if *is_receiver {
                    Stage2Role::Receiver
                } else {
                    Stage2Role::Sender
                };
                self.receiver_outputs.params.attach_stage2_p2pk_e(
                    &mut proof,
                    role,
                    output.amount,
                    output.index,
                )?;

                Ok(ProofWithMetadata {
                    proof,
                    amount: output.amount,
                    index: output.index,
                    is_receiver: *is_receiver,
                })
            })
            .collect()
    }

    /// Restore blind signatures from the mint using NUT-09
    ///
    /// This allows recovering the blind signatures for a commitment transaction
    /// without needing to have received them from the original swap.
    /// Since outputs are deterministic, we can recreate the blinded messages
    /// and ask the mint to restore the corresponding blind signatures.
    ///
    /// Returns the blind signatures in the same order as create_swap_request:
    /// sorted by amount (stable) for privacy
    pub async fn restore_all_blind_signatures<M>(
        &self,
        mint_connection: &M,
    ) -> Result<Vec<BlindSignature>, anyhow::Error>
    where
        M: MintConnection + ?Sized,
    {
        // Get all blinded messages in the same order as create_swap_request
        // (receiver first, then sender)
        let mut all_outputs = self.receiver_outputs.get_blinded_messages(None)?;
        let sender_outputs = self.sender_outputs.get_blinded_messages(None)?;
        all_outputs.extend(sender_outputs);

        // Sort by amount (stable) for privacy - matches create_swap_request ordering
        all_outputs.sort_by_key(|bm| u64::from(bm.amount));

        // Create restore request
        let restore_request = RestoreRequest {
            outputs: all_outputs,
        };

        // Call mint restore endpoint
        let restore_response = mint_connection
            .post_restore(restore_request)
            .await
            .map_err(|e| anyhow::anyhow!("Restore failed: {}", e))?;

        // Extract blind signatures from the response
        let blind_signatures: Vec<BlindSignature> = restore_response.signatures;

        // Verify we got the expected number of signatures
        let expected_count =
            self.receiver_outputs.ordered_amounts.len() + self.sender_outputs.ordered_amounts.len();
        if blind_signatures.len() != expected_count {
            anyhow::bail!(
                "Restore returned {} blind signatures but expected {}",
                blind_signatures.len(),
                expected_count
            );
        }

        Ok(blind_signatures)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::super::keysets_and_amounts::KeysetInfo;
    use super::*;
    use cashu::nuts::{CurrencyUnit, Id, Keys};

    fn create_test_params(input_fee_ppk: u64, power: u64) -> ChannelParameters {
        // Create a simple keyset with powers of the given base for testing
        // power=2 gives powers-of-2: 1, 2, 4, 8, 16, ...
        // power=10 gives powers-of-10: 1, 10, 100, 1000, ...
        use std::collections::BTreeMap;

        let alice_secret = SecretKey::generate();
        let sender_pubkey = alice_secret.public_key();

        let charlie_secret = SecretKey::generate();
        let receiver_pubkey = charlie_secret.public_key();

        let mint_secret = SecretKey::generate();
        let mint_pubkey = mint_secret.public_key();

        let mut keys_map = BTreeMap::new();
        for i in 0..10 {
            let amount = Amount::from(power.pow(i as u32));
            keys_map.insert(amount, mint_pubkey);
        }
        let keys = Keys::new(keys_map);

        // Create keyset info
        let keyset_id = Id::from_bytes(&[0; 8]).unwrap();
        let keyset_info = KeysetInfo::new(keyset_id, CurrencyUnit::Sat, keys, input_fee_ppk, None);

        let capacity = 1000;
        let maximum_amount = 100_000;
        let funding_token_amount = ChannelParameters::get_minimum_funding_token_amount(
            capacity,
            &keyset_info,
            maximum_amount,
        )
        .unwrap();

        ChannelParameters::new_with_secret_key(
            sender_pubkey,
            receiver_pubkey,
            "local".to_string(),
            CurrencyUnit::Sat,
            capacity,
            funding_token_amount,
            0, // expiry_timestamp
            0, // setup_timestamp
            keyset_info,
            maximum_amount,
            &alice_secret,
        )
        .unwrap()
    }

    #[test]
    fn test_count_by_amount() {
        let params = create_test_params(0, 2); // Powers of 2, no fees
        let max_amount = params.maximum_amount_for_one_output;
        let keyset_info = &params.keyset_info;

        // Test a specific example: 42 = 32 + 8 + 2
        let amounts = OrderedListOfAmounts::from_target(42, max_amount, keyset_info).unwrap();
        let count_map = &amounts.count_by_amount;

        // Should have 1×32, 1×8, 1×2
        assert_eq!(count_map.get(&32), Some(&1));
        assert_eq!(count_map.get(&8), Some(&1));
        assert_eq!(count_map.get(&2), Some(&1));
        assert_eq!(count_map.len(), 3);

        // Verify forward iteration gives us smallest-to-largest (BTreeMap natural order)
        let forward: Vec<(u64, usize)> = count_map.iter().map(|(&k, &v)| (k, v)).collect();
        assert_eq!(forward, vec![(2, 1), (8, 1), (32, 1)]);

        // Test another: 15 = 8 + 4 + 2 + 1
        let amounts = OrderedListOfAmounts::from_target(15, max_amount, keyset_info).unwrap();
        let count_map = &amounts.count_by_amount;
        assert_eq!(count_map.get(&8), Some(&1));
        assert_eq!(count_map.get(&4), Some(&1));
        assert_eq!(count_map.get(&2), Some(&1));
        assert_eq!(count_map.get(&1), Some(&1));
        assert_eq!(count_map.len(), 4);

        // Verify forward iteration (smallest-first)
        let forward: Vec<(u64, usize)> = count_map.iter().map(|(&k, &v)| (k, v)).collect();
        assert_eq!(forward, vec![(1, 1), (2, 1), (4, 1), (8, 1)]);

        // Test with multiple of same amount: 7 = 4 + 2 + 1
        let amounts = OrderedListOfAmounts::from_target(7, max_amount, keyset_info).unwrap();
        let count_map = &amounts.count_by_amount;
        assert_eq!(count_map.get(&4), Some(&1));
        assert_eq!(count_map.get(&2), Some(&1));
        assert_eq!(count_map.get(&1), Some(&1));

        let forward: Vec<(u64, usize)> = count_map.iter().map(|(&k, &v)| (k, v)).collect();
        assert_eq!(forward, vec![(1, 1), (2, 1), (4, 1)]);
    }

    /// Create test params with a specific expiry_timestamp (for funding token tests)
    fn create_test_params_with_expiry(
        input_fee_ppk: u64,
        power: u64,
        expiry_timestamp: u64,
    ) -> ChannelParameters {
        use std::collections::BTreeMap;

        let alice_secret = SecretKey::generate();
        let sender_pubkey = alice_secret.public_key();

        let charlie_secret = SecretKey::generate();
        let receiver_pubkey = charlie_secret.public_key();

        let mint_secret = SecretKey::generate();
        let mint_pubkey = mint_secret.public_key();

        let mut keys_map = BTreeMap::new();
        for i in 0..10 {
            let amount = Amount::from(power.pow(i as u32));
            keys_map.insert(amount, mint_pubkey);
        }
        let keys = Keys::new(keys_map);

        let keyset_id = Id::from_bytes(&[0; 8]).unwrap();
        let keyset_info = KeysetInfo::new(keyset_id, CurrencyUnit::Sat, keys, input_fee_ppk, None);

        let capacity = 1000;
        let maximum_amount = 100_000;
        let funding_token_amount = ChannelParameters::get_minimum_funding_token_amount(
            capacity,
            &keyset_info,
            maximum_amount,
        )
        .unwrap();

        ChannelParameters::new_with_secret_key(
            sender_pubkey,
            receiver_pubkey,
            "local".to_string(),
            CurrencyUnit::Sat,
            capacity,
            funding_token_amount,
            expiry_timestamp, // expiry_timestamp (configurable)
            0,                // setup_timestamp
            keyset_info,
            maximum_amount,
            &alice_secret,
        )
        .unwrap()
    }

    #[test]
    fn test_funding_token_uses_correct_blinded_pubkeys() {
        // Test that funding token P2PK secret contains the correct blinded pubkeys:
        // - "data" field: Alice's blinded pubkey (sender_stage1)
        // - "pubkeys" tag: Charlie's blinded pubkey (receiver_stage1) for 2-of-2
        // - refund "pubkeys" tag: Alice's REFUND blinded pubkey (sender_stage1_refund)

        // Use a future expiry_timestamp to pass Conditions::new() validation
        let future_expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600; // 1 hour in the future

        let params = create_test_params_with_expiry(0, 2, future_expiry);

        // Get the expected blinded pubkeys
        let expected_alice_blinded = params
            .get_sender_blinded_pubkey_for_stage1()
            .expect("Failed to get sender blinded pubkey");
        let expected_charlie_blinded = params
            .get_receiver_blinded_pubkey_for_stage1()
            .expect("Failed to get receiver blinded pubkey");
        let expected_alice_refund = params
            .get_sender_blinded_pubkey_for_stage1_refund()
            .expect("Failed to get refund blinded pubkey");

        println!(
            "Expected Alice blinded (data):   {}",
            expected_alice_blinded.to_hex()
        );
        println!(
            "Expected Charlie blinded (2of2): {}",
            expected_charlie_blinded.to_hex()
        );
        println!(
            "Expected Alice refund:           {}",
            expected_alice_refund.to_hex()
        );

        // Verify all three are distinct
        assert_ne!(
            expected_alice_blinded.to_hex(),
            expected_charlie_blinded.to_hex(),
            "Alice and Charlie blinded pubkeys should differ"
        );
        assert_ne!(
            expected_alice_blinded.to_hex(),
            expected_alice_refund.to_hex(),
            "Alice blinded and refund pubkeys should differ"
        );
        assert_ne!(
            expected_charlie_blinded.to_hex(),
            expected_alice_refund.to_hex(),
            "Charlie blinded and Alice refund pubkeys should differ"
        );

        // Create a funding output
        let funding_output = params
            .create_deterministic_output_with_blinding("funding", 64, 0)
            .expect("Failed to create funding output");

        // Parse the secret as JSON to inspect the P2PK structure
        let secret_str = funding_output.secret.to_string();
        println!("Funding secret: {}", secret_str);

        let secret_json: serde_json::Value =
            serde_json::from_str(&secret_str).expect("Failed to parse secret as JSON");

        // Structure is: ["P2PK", {"nonce": "...", "data": "pubkey_hex", "tags": [...]}]
        let inner = secret_json
            .as_array()
            .expect("Secret should be an array")
            .get(1)
            .expect("Secret should have inner object");

        // Check "data" field contains Alice's blinded pubkey
        let data_pubkey = inner["data"]
            .as_str()
            .expect("data field should be a string");
        assert_eq!(
            data_pubkey,
            expected_alice_blinded.to_hex(),
            "data field should contain Alice's blinded pubkey"
        );
        println!("✓ data field contains Alice's blinded pubkey");

        // Parse tags to find pubkeys and refund keys
        let tags = inner["tags"].as_array().expect("tags should be an array");

        // Find the "pubkeys" tag (Charlie's key for 2-of-2)
        let pubkeys_tag = tags
            .iter()
            .find(|tag| {
                tag.as_array()
                    .and_then(|arr| arr.first())
                    .and_then(|v| v.as_str())
                    == Some("pubkeys")
            })
            .expect("Should have pubkeys tag");

        let receiver_pubkey_in_tag = pubkeys_tag
            .as_array()
            .and_then(|arr| arr.get(1))
            .and_then(|v| v.as_str())
            .expect("pubkeys tag should have a pubkey value");

        assert_eq!(
            receiver_pubkey_in_tag,
            expected_charlie_blinded.to_hex(),
            "pubkeys tag should contain Charlie's blinded pubkey"
        );
        println!("✓ pubkeys tag contains Charlie's blinded pubkey");

        // Find the "refund" tag (Alice's refund key)
        let refund_tag = tags
            .iter()
            .find(|tag| {
                tag.as_array()
                    .and_then(|arr| arr.first())
                    .and_then(|v| v.as_str())
                    == Some("refund")
            })
            .expect("Should have refund tag");

        let alice_refund_in_tag = refund_tag
            .as_array()
            .and_then(|arr| arr.get(1))
            .and_then(|v| v.as_str())
            .expect("refund tag should have a pubkey value");

        assert_eq!(
            alice_refund_in_tag,
            expected_alice_refund.to_hex(),
            "refund tag should contain Alice's REFUND blinded pubkey (different tweak)"
        );
        println!("✓ refund tag contains Alice's refund blinded pubkey");

        // Verify it's NOT the same as the data field (different tweak)
        assert_ne!(
            data_pubkey, alice_refund_in_tag,
            "data and refund pubkeys should use different tweaks"
        );
        println!("✓ data and refund pubkeys are distinct (different tweaks)");
    }

    #[test]
    fn test_funding_outputs_are_ascending_by_amount() {
        // Funding outputs should be in ascending order of amount per NUT-03 recommendation.
        // Use powers-of-2 keyset so e.g. 1000 = 512 + 256 + 128 + 64 + 32 + 8
        let future_expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let params = create_test_params_with_expiry(0, 2, future_expiry);
        let funding_outputs = DeterministicOutputsForOneContext::new(
            "funding".to_string(),
            params.funding_token_amount,
            params.clone(),
        )
        .expect("funding outputs");

        let blinded_messages = funding_outputs
            .get_blinded_messages(None)
            .expect("get_blinded_messages");

        assert!(
            blinded_messages.len() > 1,
            "need multiple outputs to test ordering"
        );

        let amounts: Vec<u64> = blinded_messages
            .iter()
            .map(|bm| u64::from(bm.amount))
            .collect();

        for i in 1..amounts.len() {
            assert!(
                amounts[i] >= amounts[i - 1],
                "funding outputs not in ascending order: {:?}",
                amounts
            );
        }
        println!("✓ funding outputs are ascending: {:?}", amounts);
    }

    #[test]
    fn test_commitment_outputs_are_ascending_receiver_before_sender() {
        // Commitment swap outputs should be ascending by amount,
        // with receiver (Charlie) before sender (Alice) for same amounts.
        // Use powers-of-10 keyset to get repeated amounts (e.g. five 100-sat outputs).
        let params = create_test_params(0, 10);
        let balance = params.capacity / 2; // split roughly evenly

        let commitment =
            CommitmentOutputs::for_balance(balance, &params).expect("commitment outputs");

        // We need dummy funding proofs to call create_swap_request.
        // Build them from the funding outputs structure.
        let funding = DeterministicOutputsForOneContext::new(
            "funding".to_string(),
            params.funding_token_amount,
            params.clone(),
        )
        .expect("funding outputs");

        // Create minimal dummy proofs with correct amounts
        let dummy_proofs: Vec<cashu::nuts::Proof> = funding
            .ordered_amounts
            .iter_smallest_first()
            .flat_map(|(&amount, &count)| {
                (0..count).map(move |_| cashu::nuts::Proof {
                    amount: Amount::from(amount),
                    keyset_id: params.keyset_info.keyset_id,
                    secret: Secret::new("dummy".to_string()),
                    c: cashu::nuts::PublicKey::from_str(
                        "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
                    )
                    .unwrap(),
                    witness: None,
                    dleq: None,
                    p2pk_e: None,
                })
            })
            .collect();

        let swap_request = commitment
            .create_swap_request(dummy_proofs, None)
            .expect("create_swap_request");

        let outputs = swap_request.outputs();
        let output_amounts: Vec<u64> = outputs.iter().map(|bm| u64::from(bm.amount)).collect();

        // 1. Verify ascending order
        for i in 1..output_amounts.len() {
            assert!(
                output_amounts[i] >= output_amounts[i - 1],
                "commitment outputs not in ascending order: {:?}",
                output_amounts
            );
        }
        println!("✓ commitment outputs are ascending: {:?}", output_amounts);

        // 2. Verify receiver comes before sender for same amounts.
        // We can check this by getting each party's blinded messages separately
        // and confirming the interleaved order matches: for each amount group,
        // receiver outputs appear first.
        let receiver_msgs = commitment
            .receiver_outputs
            .get_blinded_messages(None)
            .expect("receiver msgs");
        let sender_msgs = commitment
            .sender_outputs
            .get_blinded_messages(None)
            .expect("sender msgs");

        // Build a set of B_ values (blinded points) for each party
        let receiver_b_set: std::collections::HashSet<String> = receiver_msgs
            .iter()
            .map(|bm| format!("{:?}", bm.blinded_secret))
            .collect();
        let sender_b_set: std::collections::HashSet<String> = sender_msgs
            .iter()
            .map(|bm| format!("{:?}", bm.blinded_secret))
            .collect();

        // Walk through the combined outputs grouped by amount.
        // Within each amount group, all receiver outputs should precede all sender outputs.
        let mut i = 0;
        while i < outputs.len() {
            let current_amount = u64::from(outputs[i].amount);
            let group_start = i;

            // Collect the group of outputs with this amount
            while i < outputs.len() && u64::from(outputs[i].amount) == current_amount {
                i += 1;
            }

            // Within this group, check that all receiver outputs come before sender outputs
            let mut seen_sender = false;
            for j in group_start..i {
                let b_key = format!("{:?}", outputs[j].blinded_secret);
                let is_receiver = receiver_b_set.contains(&b_key);
                let is_sender = sender_b_set.contains(&b_key);

                if is_receiver {
                    assert!(
                        !seen_sender,
                        "receiver output at position {} follows a sender output for amount {}",
                        j, current_amount
                    );
                }
                if is_sender {
                    seen_sender = true;
                }

                // At least one should match (unless the amount only belongs to one party)
                assert!(
                    is_receiver || is_sender,
                    "output at position {} doesn't match receiver or sender for amount {}",
                    j,
                    current_amount
                );
            }
        }
        println!("✓ receiver outputs precede sender outputs within each amount group");
    }
}
