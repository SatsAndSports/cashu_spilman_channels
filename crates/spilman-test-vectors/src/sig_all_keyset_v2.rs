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
            "03324f2f0c4961e71397999bb072623d53e05276faf6e377aff1e04c8fc89757f0",
            "0396b23d7ddc18f2f2f0a47c464d0316bd65011d1e96605c2d653272cd5955f04b",
            "03ce7ca88ba5cdc6999008b6395feaf372a628587203a974ca1a284f3d019e6484",
        ],
        message_sha256: [
            0x91, 0x73, 0x19, 0xd4, 0x09, 0xc8, 0x4d, 0xcc, 0xb0, 0xd2, 0x1f, 0xe3, 0x1a, 0x61,
            0x29, 0xbb, 0xd3, 0x4c, 0x5d, 0xb7, 0x2c, 0x97, 0x57, 0xd3, 0xa2, 0x52, 0x2e, 0xad,
            0xca, 0x03, 0x01, 0x89,
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
        let actual: Vec<_> = proofs.into_iter().map(|proof| proof.c.to_hex()).collect();
        assert_eq!(actual, funding_input_cs());
    }
}
