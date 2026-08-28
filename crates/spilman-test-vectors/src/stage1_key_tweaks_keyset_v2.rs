//! V2-keyset test vector for stage-1 P2PK key tweaks.

use hmac::{Hmac, Mac};
use k256::{
    elliptic_curve::sec1::ToEncodedPoint, AffinePoint, ProjectivePoint, PublicKey, SecretKey,
};
use sha2::Sha256;

use crate::channel_id::spilman_test_vector_channel_id_keysetv2;

/// Canonical name of the stage-1 key-tweak compatibility fixture.
pub const SPILMAN_TEST_VECTOR_STAGE1_KEY_TWEAKS_KEYSETV2_NAME: &str =
    "spilman-test-vector-stage1-key-tweaks-keysetv2";

const PREFIX: &[u8] = b"Cashu_Spilman_stage1_key_tweak_v1";
const SENDER_PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const RECEIVER_PUBKEY: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

/// One stage-1 key-tweak fixture entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stage1KeyTweakTestVector {
    /// Stage-1 role context.
    pub context: &'static str,
    /// Untweaked compressed SEC1 public key.
    pub original_pubkey: &'static str,
    /// Accepted scalar retry counter.
    pub retry_counter: u8,
    /// Exact HMAC input.
    pub message: &'static str,
    /// Expected tweak scalar.
    pub scalar: [u8; 32],
    /// Expected compressed SEC1 blinded public key.
    pub blinded_pubkey: &'static str,
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Return fixed stage-1 key-tweak entries.
///
/// # Panics
///
/// Panics only if a hard-coded fixture scalar is malformed.
pub fn spilman_test_vector_stage1_key_tweaks_keysetv2() -> [Stage1KeyTweakTestVector; 3] {
    [
        Stage1KeyTweakTestVector { context: "sender_stage1", original_pubkey: SENDER_PUBKEY, retry_counter: 0, message: "Cashu_Spilman_stage1_key_tweak_v17af675f4f1b9843200d23060ebeb5bf5abea67fa511af79aefa4ba6a19b88c2e|sender_stage1|0", scalar: hex::decode("2c30d26a35b0d093bab0d1d58f6c70572c0c7cd82cb0ecc34d7e26a54a0eae49").expect("valid vector scalar").try_into().expect("32-byte scalar"), blinded_pubkey: "03da88bac82ac2731d6f4463e2d981824ea2d0e4862215bf8a422b1afe4eea6a8d" },
        Stage1KeyTweakTestVector { context: "receiver_stage1", original_pubkey: RECEIVER_PUBKEY, retry_counter: 0, message: "Cashu_Spilman_stage1_key_tweak_v17af675f4f1b9843200d23060ebeb5bf5abea67fa511af79aefa4ba6a19b88c2e|receiver_stage1|0", scalar: hex::decode("ea4bf4110a5c73c232ea288adf577be653d334521a82f71a767fdbe66fb49614").expect("valid vector scalar").try_into().expect("32-byte scalar"), blinded_pubkey: "03c988d50c11fa634afdd519e2a9ce751adf29f0b17ad6251b7c199fdf9c1f7455" },
        Stage1KeyTweakTestVector { context: "sender_stage1_refund", original_pubkey: SENDER_PUBKEY, retry_counter: 0, message: "Cashu_Spilman_stage1_key_tweak_v17af675f4f1b9843200d23060ebeb5bf5abea67fa511af79aefa4ba6a19b88c2e|sender_stage1_refund|0", scalar: hex::decode("45ad552923c0cd0e988c5a929766c7da81e1b6eced096ff745a3f95b30abbc2b").expect("valid vector scalar").try_into().expect("32-byte scalar"), blinded_pubkey: "02d9194f39e5689e97a4f20614b09e5ec751edc41f63d0bde6fc39d7dfeba74760" },
    ]
}

/// Values independently derived for one stage-1 key-tweak entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage1KeyTweakReference {
    /// Accepted scalar retry counter.
    pub retry_counter: u8,
    /// Exact HMAC input.
    pub message: String,
    /// Derived tweak scalar.
    pub scalar: [u8; 32],
    /// Derived compressed SEC1 blinded public key.
    pub blinded_pubkey: String,
}

/// Independently derive stage-1 tweak entries with RustCrypto secp256k1.
///
/// # Panics
///
/// Panics only if fixed fixture inputs are malformed or no valid scalar exists.
pub fn derive_stage1_key_tweaks_reference() -> Vec<Stage1KeyTweakReference> {
    let channel = spilman_test_vector_channel_id_keysetv2();
    let channel_id = hex::encode(channel.channel_id);
    spilman_test_vector_stage1_key_tweaks_keysetv2()
        .into_iter()
        .map(|entry| {
            let (retry_counter, scalar) = (0u8..=255)
                .find_map(|retry_counter| {
                    let suffix = format!("{channel_id}|{}|{retry_counter}", entry.context);
                    let mut message = PREFIX.to_vec();
                    message.extend_from_slice(suffix.as_bytes());
                    let scalar = hmac_sha256(&channel.channel_secret, &message);
                    SecretKey::from_slice(&scalar)
                        .ok()
                        .map(|_| (retry_counter, scalar))
                })
                .expect("valid stage-1 test scalar");
            let public_key = PublicKey::from_sec1_bytes(
                &hex::decode(entry.original_pubkey).expect("valid public key"),
            )
            .expect("valid secp256k1 public key");
            let affine = *public_key.as_affine();
            let encoded = affine.to_encoded_point(true);
            let effective = if encoded.as_bytes()[0] == 3 {
                -ProjectivePoint::from(affine)
            } else {
                ProjectivePoint::from(affine)
            };
            let tweak = SecretKey::from_slice(&scalar).expect("valid scalar");
            let blinded = AffinePoint::from(
                effective + ProjectivePoint::GENERATOR * tweak.to_nonzero_scalar().as_ref(),
            )
            .to_encoded_point(true);
            Stage1KeyTweakReference {
                retry_counter,
                message: String::from_utf8(
                    [
                        PREFIX,
                        format!("{channel_id}|{}|{retry_counter}", entry.context).as_bytes(),
                    ]
                    .concat(),
                )
                .expect("ASCII message"),
                scalar,
                blinded_pubkey: hex::encode(blinded.as_bytes()),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        derive_stage1_key_tweaks_reference,
        spilman_test_vector_stage1_key_tweaks_keysetv2 as get_test_vector_details,
        SPILMAN_TEST_VECTOR_STAGE1_KEY_TWEAKS_KEYSETV2_NAME,
    };

    #[test]
    fn spilman_test_vector_stage1_key_tweaks_keysetv2() {
        for (vector, reference) in get_test_vector_details()
            .into_iter()
            .zip(derive_stage1_key_tweaks_reference())
        {
            assert_eq!(
                reference.retry_counter, vector.retry_counter,
                "{SPILMAN_TEST_VECTOR_STAGE1_KEY_TWEAKS_KEYSETV2_NAME}: {} retry counter",
                vector.context
            );
            assert_eq!(
                reference.message, vector.message,
                "{SPILMAN_TEST_VECTOR_STAGE1_KEY_TWEAKS_KEYSETV2_NAME}: {} HMAC message",
                vector.context
            );
            assert_eq!(
                reference.scalar, vector.scalar,
                "{SPILMAN_TEST_VECTOR_STAGE1_KEY_TWEAKS_KEYSETV2_NAME}: {} tweak scalar",
                vector.context
            );
            assert_eq!(
                reference.blinded_pubkey, vector.blinded_pubkey,
                "{SPILMAN_TEST_VECTOR_STAGE1_KEY_TWEAKS_KEYSETV2_NAME}: {} blinded pubkey",
                vector.context
            );
        }
    }
}
