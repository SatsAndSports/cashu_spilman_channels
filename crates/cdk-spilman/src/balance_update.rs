//! Balance Update Message
//!
//! Represents signed and unsigned balance updates in a Spilman payment channel.
//!
//! The typical flow is:
//! 1. Create an `UnsignedBalanceUpdate` from channel funding data
//! 2. Sign it using a host/signer (using `message_hex` and `tweak_scalar_hex`)
//! 3. Call `sign()` to produce a `BalanceUpdateMessage`

use bitcoin::secp256k1::schnorr::Signature;
use cashu::nuts::nut10::SpendingConditionVerification;
use cashu::nuts::{P2PKWitness, SwapRequest, Witness};
use std::str::FromStr;

use super::client_storage::ClientChannelFunding;
use super::deterministic::CommitmentOutputs;
use super::established_channel::EstablishedChannel;

/// Extract signatures from a swap request's first proof witness
pub fn get_signatures_from_swap_request(
    swap_request: &SwapRequest,
) -> Result<Vec<Signature>, anyhow::Error> {
    let first_proof = swap_request
        .inputs()
        .first()
        .ok_or_else(|| anyhow::anyhow!("No inputs in swap request"))?;

    let signatures =
        if let Some(cashu::nuts::Witness::P2PKWitness(p2pk_witness)) = &first_proof.witness {
            // Parse all signature strings into Signature objects
            p2pk_witness
                .signatures
                .iter()
                .filter_map(|sig_str| sig_str.parse::<Signature>().ok())
                .collect()
        } else {
            vec![]
        };

    Ok(signatures)
}

pub(crate) fn sig_all_message_hash_hex<T>(value: &T) -> String
where
    T: SpendingConditionVerification,
{
    use bitcoin::hashes::{sha256, Hash};

    let msg = value.sig_all_msg_to_sign();
    let hash = sha256::Hash::hash(msg.as_bytes());

    cashu::util::hex::encode(hash.to_byte_array())
}

pub(crate) fn attach_signature_to_first_input(
    swap_request: &mut SwapRequest,
    sig_hex: &str,
) -> Result<(), anyhow::Error> {
    let first_input = swap_request
        .inputs_mut()
        .first_mut()
        .ok_or_else(|| anyhow::anyhow!("Swap request has no inputs"))?;

    match first_input.witness.as_mut() {
        Some(witness) => witness.add_signatures(vec![sig_hex.to_string()]),
        None => {
            let mut p2pk_witness = Witness::P2PKWitness(P2PKWitness::default());
            p2pk_witness.add_signatures(vec![sig_hex.to_string()]);
            first_input.witness = Some(p2pk_witness);
        }
    }

    Ok(())
}

/// A balance update message from Alice to Charlie
///
/// This represents a signed commitment to a new channel balance.
/// Alice signs a swap request that distributes the channel funds according to the new balance.
#[derive(Debug, Clone)]
pub struct BalanceUpdateMessage {
    /// Channel ID to identify which channel this update is for
    pub channel_id: String,
    /// New balance for the receiver (Charlie)
    pub amount: u64,
    /// Alice's signature over the swap request
    pub signature: Signature,
}

impl BalanceUpdateMessage {
    /// Used by Alice to create a balance update message from a swap request
    /// which is signed by her. She then sends the resulting message to Charlie.
    pub fn from_signed_swap_request(
        channel_id: String,
        amount: u64,
        swap_request: &SwapRequest,
    ) -> Result<Self, anyhow::Error> {
        // Extract Alice's signature from the swap request
        let signatures = get_signatures_from_swap_request(swap_request)?;

        // Ensure there is exactly one signature (Alice's only)
        if signatures.len() != 1 {
            anyhow::bail!(
                "Expected exactly 1 signature (Alice's), but found {}",
                signatures.len()
            );
        }

        let signature = signatures[0];

        Ok(Self {
            channel_id,
            amount,
            signature,
        })
    }

    /// Verify the signature using the established channel
    /// Charlie reconstructs the swap request from the amount to verify the signature
    /// Throws an error if the signature is invalid
    pub fn verify_sender_signature(
        &self,
        channel: &EstablishedChannel,
    ) -> Result<(), anyhow::Error> {
        // Reconstruct the commitment outputs for this balance
        let commitment_outputs = CommitmentOutputs::for_balance(self.amount, &channel.params)?;

        // Reconstruct the unsigned swap request
        let swap_request =
            commitment_outputs.create_swap_request(channel.funding_proofs.clone(), None)?;

        // Extract the SIG_ALL message from the swap request
        let msg_to_sign = swap_request.sig_all_msg_to_sign();

        // Verify the signature using Alice's BLINDED pubkey
        // Alice signs with her blinded secret key (the funding token uses blinded pubkeys for privacy)
        let blinded_sender_pubkey = channel.params.get_sender_blinded_pubkey_for_stage1()?;
        blinded_sender_pubkey
            .verify(msg_to_sign.as_bytes(), &self.signature)
            .map_err(|_| {
                anyhow::anyhow!("Invalid signature: Alice did not authorize this balance update")
            })?;

        Ok(())
    }
}

// ============================================================================
// UnsignedBalanceUpdate
// ============================================================================

/// An unsigned balance update, ready for signing.
///
/// Contains the precomputed message hash and tweak scalar needed for signing.
/// Once signed, use `sign()` to produce a `BalanceUpdateMessage`.
///
/// # Example
/// ```ignore
/// let unsigned = UnsignedBalanceUpdate::new(channel_id, balance, &funding)?;
/// let signature = host.sign_with_tweaked_key(
///     &funding.sender_pubkey_hex,
///     &unsigned.message_hex,
///     &unsigned.tweak_scalar_hex,
/// )?;
/// let balance_update = unsigned.sign(&signature)?;
/// ```
#[derive(Debug, Clone)]
pub struct UnsignedBalanceUpdate {
    /// Channel ID
    pub channel_id: String,
    /// Balance (cumulative amount receiver can claim)
    pub balance: u64,
    /// SHA-256 hash of the SIG_ALL message (32 bytes, hex-encoded)
    pub message_hex: String,
    /// P2BK blinding scalar for the sender (32 bytes, hex-encoded)
    pub tweak_scalar_hex: String,
}

impl UnsignedBalanceUpdate {
    /// Create an unsigned balance update from channel funding data.
    ///
    /// Computes the message hash and tweak scalar needed for signing.
    pub fn new(
        channel_id: &str,
        balance: u64,
        funding: &ClientChannelFunding,
    ) -> Result<Self, String> {
        // Use the existing bindings function (Option B: pragmatic approach)
        let unsigned_json = super::bindings::create_unsigned_balance_update(
            &funding.params_json,
            &funding.keyset_info_json,
            &funding.channel_secret_hex,
            &funding.funding_proofs_json,
            balance,
        )?;

        let unsigned: serde_json::Value = serde_json::from_str(&unsigned_json)
            .map_err(|e| format!("Failed to parse unsigned update: {}", e))?;

        let message_hex = unsigned["message_hex"]
            .as_str()
            .ok_or("Missing 'message_hex'")?
            .to_string();

        let tweak_scalar_hex = unsigned["tweak_scalar_hex"]
            .as_str()
            .ok_or("Missing 'tweak_scalar_hex'")?
            .to_string();

        Ok(Self {
            channel_id: channel_id.to_string(),
            balance,
            message_hex,
            tweak_scalar_hex,
        })
    }

    /// Attach a signature and produce a `BalanceUpdateMessage`.
    ///
    /// The signature should be a BIP-340 Schnorr signature (64 bytes, hex-encoded)
    /// produced by signing `message_hex` with the tweaked key.
    pub fn sign(self, signature_hex: &str) -> Result<BalanceUpdateMessage, String> {
        let signature =
            Signature::from_str(signature_hex).map_err(|e| format!("Invalid signature: {}", e))?;

        Ok(BalanceUpdateMessage {
            channel_id: self.channel_id,
            amount: self.balance,
            signature,
        })
    }
}
