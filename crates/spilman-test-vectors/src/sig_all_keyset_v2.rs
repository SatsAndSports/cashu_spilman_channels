//! V2-keyset test vector for the NUT-11 SIG_ALL commitment-swap message.

use crate::commitment_outputs_keyset_v2::spilman_test_vector_commitment_outputs_keysetv2;
use crate::funding_outputs_keyset_v2::spilman_test_vector_funding_outputs_keysetv2;

/// Canonical name of the NUT-11 SIG_ALL compatibility fixture.
pub const SPILMAN_TEST_VECTOR_SIG_ALL_KEYSETV2_NAME: &str = "spilman-test-vector-sig-all-keysetv2";

/// Fixed NUT-11 SIG_ALL commitment-swap fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigAllTestVector {
    /// Receiver balance used to construct the commitment outputs.
    pub receiver_balance: u64,
    /// Unblinded `C` values from the funding proofs in transaction order.
    pub funding_proof_cs: [&'static str; 3],
    /// SHA-256 of the exact NUT-11 SIG_ALL message.
    pub message_sha256: [u8; 32],
}

/// Return the funding input secret bytes in their transaction order.
pub fn funding_input_secrets() -> [&'static str; 3] {
    let outputs = spilman_test_vector_funding_outputs_keysetv2();
    [outputs[0].secret, outputs[1].secret, outputs[2].secret]
}

/// Return the funding proof `C` values in transaction order.
pub fn funding_input_cs() -> [&'static str; 3] {
    spilman_test_vector_sig_all_keysetv2().funding_proof_cs
}

/// Return commitment output `B_` values in their stable transaction order.
pub fn commitment_output_blinded_messages() -> [&'static str; 6] {
    let outputs = spilman_test_vector_commitment_outputs_keysetv2();
    [
        outputs[0].blinded_message,
        outputs[3].blinded_message,
        outputs[1].blinded_message,
        outputs[4].blinded_message,
        outputs[2].blinded_message,
        outputs[5].blinded_message,
    ]
}

/// Independently construct the exact NUT-11 SIG_ALL message bytes.
pub fn derive_sig_all_message_reference() -> Vec<u8> {
    let mut message = Vec::new();
    for (secret, c) in funding_input_secrets().into_iter().zip(funding_input_cs()) {
        message.extend_from_slice(secret.as_bytes());
        message.extend_from_slice(c.as_bytes());
    }
    for (amount, blinded_message) in [2, 2, 16, 16, 32, 32]
        .into_iter()
        .zip(commitment_output_blinded_messages())
    {
        message.extend_from_slice(amount.to_string().as_bytes());
        message.extend_from_slice(blinded_message.as_bytes());
    }
    message
}

/// Return the fixed NUT-11 SIG_ALL test vector.
pub fn spilman_test_vector_sig_all_keysetv2() -> SigAllTestVector {
    SigAllTestVector {
        receiver_balance: 50,
        funding_proof_cs: [
            "028d2b7d1215b72c2b23d51563fb0d61e3652b87a77ceb3b237df1b9f46b0d044f",
            "02de5cb101e677403e4658d615e1a665db787558cccd09ff93a65983fa48fcecfd",
            "03bb199086ab2d33ce69cc80a007b48350fb13ce669af96be24f44613e9d0013b7",
        ],
        message_sha256: [
            0x93, 0xdd, 0xe7, 0x28, 0x50, 0xcf, 0x5d, 0xea, 0x63, 0x9d, 0x67, 0x5d, 0xc1, 0x9f,
            0x82, 0x9b, 0xf8, 0x53, 0x69, 0xbe, 0xbd, 0xb8, 0x51, 0x34, 0x22, 0x98, 0x2a, 0x1a,
            0x07, 0x93, 0x41, 0x5f,
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::{
        derive_sig_all_message_reference, funding_input_cs,
        SPILMAN_TEST_VECTOR_SIG_ALL_KEYSETV2_NAME,
    };

    #[test]
    fn spilman_test_vector_sig_all_keysetv2() {
        use sha2::{Digest, Sha256};

        let vector = super::spilman_test_vector_sig_all_keysetv2();
        assert_eq!(
            Sha256::digest(derive_sig_all_message_reference()).as_slice(),
            vector.message_sha256
        );
        assert_eq!(
            SPILMAN_TEST_VECTOR_SIG_ALL_KEYSETV2_NAME,
            "spilman-test-vector-sig-all-keysetv2"
        );
    }

    #[tokio::test]
    async fn funding_proof_signatures_match_deterministic_test_mint() {
        use std::collections::BTreeMap;
        use std::str::FromStr;

        use cashu::dhke::construct_proofs;
        use cashu::nuts::{BlindedMessage, Id, Keys, PublicKey, SecretKey};
        use cashu::secret::Secret;
        use cashu::Amount;

        use crate::channel_id::spilman_test_vector_channel_id_keysetv2;
        use crate::funding_outputs_keyset_v2::spilman_test_vector_funding_outputs_keysetv2;
        use crate::real_mint_keyset_v2::build_real_test_mint_v2;

        let channel = spilman_test_vector_channel_id_keysetv2();
        let keyset_id = Id::from_str(channel.keyset_id).expect("valid keyset ID");
        let keys = Keys::new(
            channel
                .public_keys
                .iter()
                .map(|(amount, key)| {
                    (
                        Amount::from(*amount),
                        PublicKey::from_str(key).expect("valid mint key"),
                    )
                })
                .collect::<BTreeMap<_, _>>(),
        );
        let outputs = spilman_test_vector_funding_outputs_keysetv2();
        let blinded_messages = outputs
            .iter()
            .map(|output| {
                BlindedMessage::new(
                    Amount::from(output.amount),
                    keyset_id,
                    PublicKey::from_str(output.blinded_message).expect("valid blinded message"),
                )
            })
            .collect();
        let signatures = build_real_test_mint_v2()
            .await
            .expect("deterministic mint")
            .blind_sign(blinded_messages)
            .await
            .expect("mint signs fixed outputs");
        let proofs = construct_proofs(
            signatures,
            outputs
                .iter()
                .map(|output| SecretKey::from_hex(output.blinding_factor).expect("valid blinding"))
                .collect(),
            outputs
                .iter()
                .map(|output| Secret::new(output.secret.to_owned()))
                .collect(),
            &keys,
        )
        .expect("unblind fixed funding proofs");
        for (proof, expected_c) in proofs.into_iter().zip(funding_input_cs()) {
            assert_eq!(proof.c.to_hex(), expected_c);
        }
    }
}
