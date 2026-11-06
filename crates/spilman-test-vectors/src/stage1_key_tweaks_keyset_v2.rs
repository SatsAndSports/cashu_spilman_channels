//! V2-keyset test vector for stage-1 P2PK key tweaks.

use hmac::{Hmac, KeyInit, Mac};
use k256::{elliptic_curve::sec1::ToSec1Point, AffinePoint, ProjectivePoint, PublicKey, SecretKey};
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
        Stage1KeyTweakTestVector { context: "sender_stage1", original_pubkey: SENDER_PUBKEY, message: "Cashu_Spilman_stage1_key_tweak_v122d8063ac8592223c0cb20d9da883787382db861569c0aa84f664ae75c641781|sender_stage1", scalar: hex::decode("c91d056874abe1711778d9674158b43b42ac6754e58072431627ef8dce944218").expect("valid vector scalar").try_into().expect("32-byte scalar"), blinded_pubkey: "025032d5e99037ddabf57564ebd03e79994bd86d77f47302ca81eca7e8555dd80b" },
        Stage1KeyTweakTestVector { context: "receiver_stage1", original_pubkey: RECEIVER_PUBKEY, message: "Cashu_Spilman_stage1_key_tweak_v122d8063ac8592223c0cb20d9da883787382db861569c0aa84f664ae75c641781|receiver_stage1", scalar: hex::decode("983b646d09e66356f4a1fd6d5f8189c0a59a4412db772e5a13dca08804d01ff6").expect("valid vector scalar").try_into().expect("32-byte scalar"), blinded_pubkey: "035ab3f5c8bfd229dfddf3d6bd0f4c6a7470c43f3c864f8e4121d6ac86a16e43e4" },
        Stage1KeyTweakTestVector { context: "sender_stage1_refund", original_pubkey: SENDER_PUBKEY, message: "Cashu_Spilman_stage1_key_tweak_v122d8063ac8592223c0cb20d9da883787382db861569c0aa84f664ae75c641781|sender_stage1_refund", scalar: hex::decode("67def3cde1286293b89db06d5797741c4cbb89a7dd5deb43aca30dfb2c1f6f11").expect("valid vector scalar").try_into().expect("32-byte scalar"), blinded_pubkey: "0262059f95d1ac59f34a29f9e9d5c26b414e1921b0b76d5f162b54d67d0540a72d" },
    ]
}

/// Values independently derived for one stage-1 key-tweak entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage1KeyTweakReference {
    /// Stage-1 role context.
    pub context: &'static str,
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
    derive_stage1_for_channel(spilman_test_vector_channel_id_keysetv2())
}

pub(crate) fn derive_stage1_for_channel(
    channel: crate::channel_id::ChannelIdTestVector,
) -> Vec<Stage1KeyTweakReference> {
    let channel_id = hex::encode(channel.channel_id);
    spilman_test_vector_stage1_key_tweaks_keysetv2()
        .into_iter()
        .map(|entry| {
            let suffix = format!("{channel_id}|{}", entry.context);
            let mut message = PREFIX.to_vec();
            message.extend_from_slice(suffix.as_bytes());
            let mut scalar = hmac_sha256(&channel.channel_secret, &message);
            if SecretKey::from_slice(&scalar).is_err() {
                message.push(0xff);
                scalar = hmac_sha256(&channel.channel_secret, &message);
            }
            assert!(
                SecretKey::from_slice(&scalar).is_ok(),
                "valid stage-1 test scalar"
            );
            let public_key = PublicKey::from_sec1_bytes(
                &hex::decode(entry.original_pubkey).expect("valid public key"),
            )
            .expect("valid secp256k1 public key");
            let affine = *public_key.as_affine();
            let encoded = affine.to_sec1_point(true);
            let effective = if encoded.as_bytes()[0] == 3 {
                -ProjectivePoint::from(affine)
            } else {
                ProjectivePoint::from(affine)
            };
            let tweak = SecretKey::from_slice(&scalar).expect("valid scalar");
            let blinded = AffinePoint::from(
                effective + ProjectivePoint::GENERATOR * tweak.to_nonzero_scalar().as_ref(),
            )
            .to_sec1_point(true);
            Stage1KeyTweakReference {
                context: entry.context,
                message: String::from_utf8(message).expect("ASCII message"),
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
