//! V2-keyset reference derivations for stage-2 P2BK key material.

use k256::{
    elliptic_curve::sec1::ToEncodedPoint, AffinePoint, ProjectivePoint, PublicKey, SecretKey,
};
use sha2::{Digest, Sha256};

use crate::channel_id::spilman_test_vector_channel_id_keysetv2;

const EPHEMERAL_PREFIX: &[u8] = b"Cashu_Spilman_P2BK_ephemeral_v1";
const P2BK_PREFIX: &[u8] = b"Cashu_P2BK_v1";

/// Canonical name of the stage-2 P2BK compatibility fixture.
pub const SPILMAN_TEST_VECTOR_STAGE2_P2BK_KEYSETV2_NAME: &str =
    "spilman-test-vector-stage2-p2bk-keysetv2";

/// One fixed stage-2 P2BK compatibility fixture entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stage2P2bkTestVector {
    /// NUT-XX stage-2 context.
    pub context: &'static str,
    /// Recipient's untweaked compressed SEC1 public key.
    pub recipient_pubkey: &'static str,
    /// Output amount.
    pub amount: u64,
    /// Per-denomination output index.
    pub index: usize,
    /// Deterministic ephemeral scalar retry counter.
    pub retry_counter: u8,
    /// Deterministic ephemeral secret scalar.
    pub ephemeral_secret: &'static str,
    /// Compressed SEC1 ephemeral public key, used as `p2pk_e`.
    pub ephemeral_pubkey: &'static str,
    /// NUT-28 ECDH shared-secret x-coordinate.
    pub shared_secret_x: &'static str,
    /// NUT-28 P2BK scalar retry counter.
    pub p2bk_retry_counter: u8,
    /// P2BK scalar applied to the recipient public key.
    pub p2bk_scalar: &'static str,
    /// Resulting compressed SEC1 blinded recipient public key.
    pub blinded_pubkey: &'static str,
}

/// Return fixed stage-2 P2BK entries for amount 32, index 0.
pub fn spilman_test_vector_stage2_p2bk_keysetv2() -> [Stage2P2bkTestVector; 2] {
    [
        Stage2P2bkTestVector {
            context: "receiver_stage2",
            recipient_pubkey: "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            amount: 32,
            index: 0,
            retry_counter: 0,
            ephemeral_secret: "dc2029be89e39a26f5a49653a7de750807002f9549f4774ed8c6376d1cf4bc7b",
            ephemeral_pubkey: "02224366f001c35581b8316a62160d4e5733f102757a1a824d8e41a9ad795d5a90",
            shared_secret_x: "e5198d9a589490993b1edd9c5bf76e31bf9610bdca088654fb2d654b62a0085d",
            p2bk_retry_counter: 0,
            p2bk_scalar: "51db52022fe771a7e084346852a2115fbefd204efe4fb6c5e94cd3844c718e75",
            blinded_pubkey: "0397dfedc39293131c2d4c5f76169001e2b11057284dc9345e8178f3ce035660df",
        },
        Stage2P2bkTestVector {
            context: "sender_stage2",
            recipient_pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            amount: 32,
            index: 0,
            retry_counter: 0,
            ephemeral_secret: "b0a12b2dc14d71c23a27c02d35ebde1eccdc50984fac5b4597099cc653a6d69b",
            ephemeral_pubkey: "02a1be7b930f67d26fd168214a18f5c208cb21cda5f6f08bbf61930cae109d5a39",
            shared_secret_x: "a1be7b930f67d26fd168214a18f5c208cb21cda5f6f08bbf61930cae109d5a39",
            p2bk_retry_counter: 0,
            p2bk_scalar: "891005d4ef10bee9b46144fec3d81f051e8d5db42c6078f60a0fd1ad0c4798db",
            blinded_pubkey: "023725a2912497df0d49de8269b778e664b917e6c919e122fd099e2e99be03f1af",
        },
    ]
}

/// Independently derived stage-2 P2BK material for one output role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage2P2bkReference {
    /// NUT-XX stage-2 context.
    pub context: &'static str,
    /// Recipient's untweaked compressed SEC1 public key.
    pub recipient_pubkey: &'static str,
    /// Deterministic ephemeral scalar retry counter.
    pub retry_counter: u8,
    /// Exact preimage hashed to derive the ephemeral scalar.
    pub ephemeral_message: Vec<u8>,
    /// Deterministic ephemeral secret scalar.
    pub ephemeral_secret: [u8; 32],
    /// Compressed SEC1 ephemeral public key, used as `p2pk_e`.
    pub ephemeral_pubkey: String,
    /// NUT-28 ECDH shared-secret x-coordinate.
    pub shared_secret_x: [u8; 32],
    /// NUT-28 P2BK scalar retry counter.
    pub p2bk_retry_counter: u8,
    /// P2BK scalar applied to the recipient public key.
    pub p2bk_scalar: [u8; 32],
    /// Resulting compressed SEC1 blinded recipient public key.
    pub blinded_pubkey: String,
}

fn encoded(point: ProjectivePoint) -> String {
    hex::encode(AffinePoint::from(point).to_encoded_point(true).as_bytes())
}

fn derive_one(
    context: &'static str,
    recipient_pubkey: &'static str,
    amount: u64,
    index: usize,
) -> Stage2P2bkReference {
    let channel = spilman_test_vector_channel_id_keysetv2();
    let channel_id = hex::encode(channel.channel_id);
    let (retry_counter, ephemeral_message, ephemeral_secret) = (0u8..=255)
        .find_map(|retry| {
            let suffix = format!("{channel_id}|{context}|{amount}|{index}|{retry}");
            let mut message = EPHEMERAL_PREFIX.to_vec();
            message.extend_from_slice(&channel.channel_secret);
            message.extend_from_slice(suffix.as_bytes());
            let secret: [u8; 32] = Sha256::digest(&message).into();
            SecretKey::from_slice(&secret)
                .ok()
                .map(|_| (retry, message, secret))
        })
        .expect("valid fixed ephemeral scalar");
    let ephemeral = SecretKey::from_slice(&ephemeral_secret).expect("valid ephemeral scalar");
    let recipient = PublicKey::from_sec1_bytes(
        &hex::decode(recipient_pubkey).expect("valid recipient public key"),
    )
    .expect("valid recipient public key");
    let shared =
        ProjectivePoint::from(*recipient.as_affine()) * ephemeral.to_nonzero_scalar().as_ref();
    let shared_secret_x: [u8; 32] = AffinePoint::from(shared).to_encoded_point(true).as_bytes()
        [1..]
        .try_into()
        .expect("compressed point x-coordinate");
    let (p2bk_retry_counter, p2bk_scalar) = [None, Some(0xff)]
        .into_iter()
        .enumerate()
        .find_map(|(retry, suffix)| {
            let mut message = P2BK_PREFIX.to_vec();
            message.extend_from_slice(&shared_secret_x);
            message.push(0x00);
            if let Some(suffix) = suffix {
                message.push(suffix);
            }
            let scalar: [u8; 32] = Sha256::digest(message).into();
            SecretKey::from_slice(&scalar)
                .ok()
                .map(|_| (retry as u8, scalar))
        })
        .expect("valid fixed P2BK scalar");
    let recipient_affine = *recipient.as_affine();
    let effective_recipient = if recipient_affine.to_encoded_point(true).as_bytes()[0] == 3 {
        -ProjectivePoint::from(recipient_affine)
    } else {
        ProjectivePoint::from(recipient_affine)
    };
    let tweak = SecretKey::from_slice(&p2bk_scalar).expect("valid P2BK scalar");

    Stage2P2bkReference {
        context,
        recipient_pubkey,
        retry_counter,
        ephemeral_message,
        ephemeral_secret,
        ephemeral_pubkey: hex::encode(ephemeral.public_key().to_encoded_point(true).as_bytes()),
        shared_secret_x,
        p2bk_retry_counter,
        p2bk_scalar,
        blinded_pubkey: encoded(
            effective_recipient + ProjectivePoint::GENERATOR * tweak.to_nonzero_scalar().as_ref(),
        ),
    }
}

pub(crate) fn derive_stage2_p2bk_reference_for(
    context: &'static str,
    recipient_pubkey: &'static str,
    amount: u64,
    index: usize,
) -> Stage2P2bkReference {
    derive_one(context, recipient_pubkey, amount, index)
}

/// Independently derive both fixed stage-2 role vectors for amount 32, index 0.
pub fn derive_stage2_p2bk_reference() -> [Stage2P2bkReference; 2] {
    [
        derive_stage2_p2bk_reference_for(
            "receiver_stage2",
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            32,
            0,
        ),
        derive_stage2_p2bk_reference_for(
            "sender_stage2",
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            32,
            0,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::{
        derive_stage2_p2bk_reference,
        spilman_test_vector_stage2_p2bk_keysetv2 as get_test_vector_details,
        SPILMAN_TEST_VECTOR_STAGE2_P2BK_KEYSETV2_NAME,
    };

    #[test]
    fn spilman_test_vector_stage2_p2bk_keysetv2() {
        for (vector, reference) in get_test_vector_details()
            .into_iter()
            .zip(derive_stage2_p2bk_reference())
        {
            assert_eq!(vector.context, reference.context);
            assert_eq!(vector.recipient_pubkey, reference.recipient_pubkey);
            assert_eq!(vector.retry_counter, reference.retry_counter);
            assert_eq!(
                vector.ephemeral_secret,
                hex::encode(reference.ephemeral_secret)
            );
            assert_eq!(vector.ephemeral_pubkey, reference.ephemeral_pubkey);
            assert_eq!(
                vector.shared_secret_x,
                hex::encode(reference.shared_secret_x)
            );
            assert_eq!(vector.p2bk_retry_counter, reference.p2bk_retry_counter);
            assert_eq!(vector.p2bk_scalar, hex::encode(reference.p2bk_scalar));
            assert_eq!(vector.blinded_pubkey, reference.blinded_pubkey);
        }
        assert_eq!(
            SPILMAN_TEST_VECTOR_STAGE2_P2BK_KEYSETV2_NAME,
            "spilman-test-vector-stage2-p2bk-keysetv2"
        );
    }
}
