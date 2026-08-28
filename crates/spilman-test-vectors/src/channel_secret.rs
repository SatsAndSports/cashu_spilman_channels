//! Test vectors for the channel-secret derivation.

use hmac::{Hmac, Mac};
use k256::{
    elliptic_curve::sec1::ToEncodedPoint, AffinePoint, ProjectivePoint, PublicKey, SecretKey,
};
use sha2::{Digest, Sha256};

/// Canonical name of the first channel-secret compatibility fixture.
pub const SPILMAN_TEST_VECTOR_CHANNEL_SECRET_HKDF_V1_001_NAME: &str =
    "spilman-test-vector-channel-secret-hkdf-v1-001";

const ALICE_SECRET_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000001";
const CHARLIE_SECRET_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000002";
const ALICE_PUBLIC_KEY_HEX: &str =
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const CHARLIE_PUBLIC_KEY_HEX: &str =
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const SHARED_POINT_HEX: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const DH_HEX: &str = "b1c9938f01121e159887ac2c8d393a22e4476ff8212de13fe1939de2a236f0a7";
const CHANNEL_SECRET_HEX: &str = "acfc96a584e645524b017b75cfe0770c3b8dc2ba4f9cef6d99f2cb7bcee691cf";
const CHANNEL_SECRET_INFO: &[u8] = b"Cashu_Spilman_channel_secret_v1";

/// Fixed inputs and expected output for a channel-secret compatibility vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelSecretTestVector {
    /// Alice's 32-byte secp256k1 private key.
    pub alice_secret_key: [u8; 32],
    /// Charlie's 32-byte secp256k1 private key.
    pub charlie_secret_key: [u8; 32],
    /// Alice's 33-byte compressed SEC1 public key.
    pub alice_public_key: [u8; 33],
    /// Charlie's 33-byte compressed SEC1 public key.
    pub charlie_public_key: [u8; 33],
    /// The 33-byte compressed ECDH shared point.
    pub shared_point: [u8; 33],
    /// SHA-256 of the compressed shared point.
    pub dh: [u8; 32],
    /// The 32-byte HKDF-SHA256 channel secret.
    pub channel_secret: [u8; 32],
}

/// Values derived independently from the fixed channel-secret vector inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelSecretReference {
    /// Alice's 33-byte compressed SEC1 public key.
    pub alice_public_key: [u8; 33],
    /// Charlie's 33-byte compressed SEC1 public key.
    pub charlie_public_key: [u8; 33],
    /// The 33-byte compressed ECDH shared point.
    pub shared_point: [u8; 33],
    /// SHA-256 of the compressed shared point.
    pub dh: [u8; 32],
    /// The 32-byte HKDF-SHA256 channel secret.
    pub channel_secret: [u8; 32],
}

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value)
        .expect("test-vector hex must be valid")
        .try_into()
        .expect("test-vector hex must have the expected length")
}

/// Return the fixed values for
/// `spilman-test-vector-channel-secret-hkdf-v1-001`.
pub fn spilman_test_vector_channel_secret_hkdf_v1_001() -> ChannelSecretTestVector {
    ChannelSecretTestVector {
        alice_secret_key: decode_hex(ALICE_SECRET_KEY_HEX),
        charlie_secret_key: decode_hex(CHARLIE_SECRET_KEY_HEX),
        alice_public_key: decode_hex(ALICE_PUBLIC_KEY_HEX),
        charlie_public_key: decode_hex(CHARLIE_PUBLIC_KEY_HEX),
        shared_point: decode_hex(SHARED_POINT_HEX),
        dh: decode_hex(DH_HEX),
        channel_secret: decode_hex(CHANNEL_SECRET_HEX),
    }
}

fn compressed_public_key(secret_key: &SecretKey) -> [u8; 33] {
    let point = ProjectivePoint::GENERATOR * secret_key.to_nonzero_scalar().as_ref();
    AffinePoint::from(point)
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed secp256k1 public keys are 33 bytes")
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

fn hkdf_sha256_empty_salt(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = hmac_sha256(&[], ikm);
    let mut expand_message = Vec::with_capacity(info.len() + 1);
    expand_message.extend_from_slice(info);
    expand_message.push(1);
    hmac_sha256(&prk, &expand_message)
}

/// Derive the channel-secret fixture with RustCrypto `k256` and a manual
/// one-block RFC 5869 HKDF-SHA256 expansion.
///
/// # Panics
///
/// Panics only if the fixed test-vector keys or their point encodings are
/// invalid, which would indicate corruption of the fixture itself.
pub fn derive_spilman_test_vector_channel_secret_hkdf_v1_001_reference() -> ChannelSecretReference {
    let vector = spilman_test_vector_channel_secret_hkdf_v1_001();
    let alice_secret =
        SecretKey::from_slice(&vector.alice_secret_key).expect("valid Alice test key");
    let charlie_secret =
        SecretKey::from_slice(&vector.charlie_secret_key).expect("valid Charlie test key");
    let alice_public_key = compressed_public_key(&alice_secret);
    let charlie_public_key = compressed_public_key(&charlie_secret);
    let charlie_public =
        PublicKey::from_sec1_bytes(&charlie_public_key).expect("valid Charlie public key");
    let shared_point = AffinePoint::from(
        ProjectivePoint::from(*charlie_public.as_affine())
            * alice_secret.to_nonzero_scalar().as_ref(),
    )
    .to_encoded_point(true)
    .as_bytes()
    .try_into()
    .expect("compressed shared points are 33 bytes");
    let dh: [u8; 32] = Sha256::digest(shared_point).into();

    ChannelSecretReference {
        alice_public_key,
        charlie_public_key,
        shared_point,
        dh,
        channel_secret: hkdf_sha256_empty_salt(&dh, CHANNEL_SECRET_INFO),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        derive_spilman_test_vector_channel_secret_hkdf_v1_001_reference,
        spilman_test_vector_channel_secret_hkdf_v1_001 as get_test_vector_details,
        SPILMAN_TEST_VECTOR_CHANNEL_SECRET_HKDF_V1_001_NAME,
    };

    #[test]
    fn spilman_test_vector_channel_secret_hkdf_v1_001() {
        let vector = get_test_vector_details();
        let reference = derive_spilman_test_vector_channel_secret_hkdf_v1_001_reference();

        assert_eq!(
            hex::encode(reference.alice_public_key),
            hex::encode(vector.alice_public_key),
            "{SPILMAN_TEST_VECTOR_CHANNEL_SECRET_HKDF_V1_001_NAME}: independent Alice public-key derivation"
        );
        assert_eq!(
            hex::encode(reference.charlie_public_key),
            hex::encode(vector.charlie_public_key),
            "{SPILMAN_TEST_VECTOR_CHANNEL_SECRET_HKDF_V1_001_NAME}: independent Charlie public-key derivation"
        );
        assert_eq!(
            hex::encode(reference.shared_point),
            hex::encode(vector.shared_point),
            "{SPILMAN_TEST_VECTOR_CHANNEL_SECRET_HKDF_V1_001_NAME}: independent compressed shared-point derivation"
        );
        assert_eq!(
            hex::encode(reference.dh),
            hex::encode(vector.dh),
            "{SPILMAN_TEST_VECTOR_CHANNEL_SECRET_HKDF_V1_001_NAME}: independent hashed ECDH derivation"
        );
        assert_eq!(
            hex::encode(reference.channel_secret),
            hex::encode(vector.channel_secret),
            "{SPILMAN_TEST_VECTOR_CHANNEL_SECRET_HKDF_V1_001_NAME}: independent HKDF derivation"
        );
    }
}
