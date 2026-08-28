use cashu::util::hex;
use cdk_spilman::compute_channel_secret;
use hmac::{Hmac, Mac};
use k256::{
    elliptic_curve::sec1::ToEncodedPoint, AffinePoint, ProjectivePoint, PublicKey, SecretKey,
};
use sha2::{Digest, Sha256};

const VECTOR_NAME: &str = "spilman-test-vector-channel-secret-hkdf-v1-001";
const ALICE_SECRET_KEY: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];
const CHARLIE_SECRET_KEY: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
];
const CHANNEL_SECRET_INFO: &[u8] = b"Cashu_Spilman_channel_secret_v1";
const EXPECTED_ALICE_PUBLIC_KEY: &str =
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const EXPECTED_CHARLIE_PUBLIC_KEY: &str =
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const EXPECTED_SHARED_POINT: &str =
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const EXPECTED_DH: &str = "b1c9938f01121e159887ac2c8d393a22e4476ff8212de13fe1939de2a236f0a7";
const EXPECTED_CHANNEL_SECRET: &str =
    "acfc96a584e645524b017b75cfe0770c3b8dc2ba4f9cef6d99f2cb7bcee691cf";

struct ChannelSecretReference {
    alice_public_key: [u8; 33],
    charlie_public_key: [u8; 33],
    shared_point: [u8; 33],
    dh: [u8; 32],
    channel_secret: [u8; 32],
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

fn reference_channel_secret() -> ChannelSecretReference {
    let alice_secret = SecretKey::from_slice(&ALICE_SECRET_KEY).expect("valid Alice test key");
    let charlie_secret =
        SecretKey::from_slice(&CHARLIE_SECRET_KEY).expect("valid Charlie test key");
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

#[test]
fn spilman_test_vector_channel_secret_hkdf_v1_001() {
    let reference = reference_channel_secret();
    assert_eq!(
        hex::encode(reference.alice_public_key),
        EXPECTED_ALICE_PUBLIC_KEY,
        "{VECTOR_NAME}: independent Alice public-key derivation"
    );
    assert_eq!(
        hex::encode(reference.charlie_public_key),
        EXPECTED_CHARLIE_PUBLIC_KEY,
        "{VECTOR_NAME}: independent Charlie public-key derivation"
    );
    assert_eq!(
        hex::encode(reference.shared_point),
        EXPECTED_SHARED_POINT,
        "{VECTOR_NAME}: independent compressed shared-point derivation"
    );
    assert_eq!(
        hex::encode(reference.dh),
        EXPECTED_DH,
        "{VECTOR_NAME}: independent hashed ECDH derivation"
    );
    assert_eq!(
        hex::encode(reference.channel_secret),
        EXPECTED_CHANNEL_SECRET,
        "{VECTOR_NAME}: independent HKDF derivation"
    );

    let alice_secret =
        cashu::nuts::SecretKey::from_slice(&ALICE_SECRET_KEY).expect("valid Alice test key");
    let charlie_secret =
        cashu::nuts::SecretKey::from_slice(&CHARLIE_SECRET_KEY).expect("valid Charlie test key");

    assert_eq!(
        hex::encode(compute_channel_secret(
            &alice_secret,
            &charlie_secret.public_key()
        )),
        EXPECTED_CHANNEL_SECRET,
        "{VECTOR_NAME}: Alice production derivation"
    );
    assert_eq!(
        hex::encode(compute_channel_secret(
            &charlie_secret,
            &alice_secret.public_key()
        )),
        EXPECTED_CHANNEL_SECRET,
        "{VECTOR_NAME}: Charlie production derivation"
    );
}
