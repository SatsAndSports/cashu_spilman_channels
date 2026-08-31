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
        Stage1KeyTweakTestVector { context: "sender_stage1", original_pubkey: SENDER_PUBKEY, message: "Cashu_Spilman_stage1_key_tweak_v17af675f4f1b9843200d23060ebeb5bf5abea67fa511af79aefa4ba6a19b88c2e|sender_stage1", scalar: hex::decode("08bcce7d4847ab4ed33c737431cfe6f6aeba419edd418cae80e12178221296e9").expect("valid vector scalar").try_into().expect("32-byte scalar"), blinded_pubkey: "02516479c6dee216722f477dcc5ecddb6a793fa7aaf7d8d2b887f45dc6ff96faee" },
        Stage1KeyTweakTestVector { context: "receiver_stage1", original_pubkey: RECEIVER_PUBKEY, message: "Cashu_Spilman_stage1_key_tweak_v17af675f4f1b9843200d23060ebeb5bf5abea67fa511af79aefa4ba6a19b88c2e|receiver_stage1", scalar: hex::decode("0f1bf68bab1e80af962b49eec1f2dc479c3bff3d093e8d2ad9c4c475713cada9").expect("valid vector scalar").try_into().expect("32-byte scalar"), blinded_pubkey: "02b37243d00583b225e1f5dc23a48a7568b09eec889bfa45c20fc865de7309b2a9" },
        Stage1KeyTweakTestVector { context: "sender_stage1_refund", original_pubkey: SENDER_PUBKEY, message: "Cashu_Spilman_stage1_key_tweak_v17af675f4f1b9843200d23060ebeb5bf5abea67fa511af79aefa4ba6a19b88c2e|sender_stage1_refund", scalar: hex::decode("956ac1d4ed35bf4abf97b2177053c50ca66e9e1d614dd3934b2374fa1bda5f2e").expect("valid vector scalar").try_into().expect("32-byte scalar"), blinded_pubkey: "022055ae1c0cba2f9cb756b4779276c8e061fe9ccd286c43a91b4164d265fcfbe8" },
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
    let channel = spilman_test_vector_channel_id_keysetv2();
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
