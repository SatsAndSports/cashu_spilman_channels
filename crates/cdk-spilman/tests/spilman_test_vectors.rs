//! Compatibility assertions for published Spilman test vectors.

use cashu::util::hex;
use cdk_spilman::compute_channel_secret;
use spilman_test_vectors::channel_secret::{
    spilman_test_vector_channel_secret_hkdf_v1_001 as get_test_vector_details,
    SPILMAN_TEST_VECTOR_CHANNEL_SECRET_HKDF_V1_001_NAME,
};

#[test]
fn spilman_test_vector_channel_secret_hkdf_v1_001() {
    let vector = get_test_vector_details();
    let alice_secret =
        cashu::nuts::SecretKey::from_slice(&vector.alice_secret_key).expect("valid Alice test key");
    let charlie_secret = cashu::nuts::SecretKey::from_slice(&vector.charlie_secret_key)
        .expect("valid Charlie test key");

    assert_eq!(
        hex::encode(compute_channel_secret(
            &alice_secret,
            &charlie_secret.public_key()
        )),
        hex::encode(vector.channel_secret),
        "{SPILMAN_TEST_VECTOR_CHANNEL_SECRET_HKDF_V1_001_NAME}: Alice production derivation"
    );
    assert_eq!(
        hex::encode(compute_channel_secret(
            &charlie_secret,
            &alice_secret.public_key()
        )),
        hex::encode(vector.channel_secret),
        "{SPILMAN_TEST_VECTOR_CHANNEL_SECRET_HKDF_V1_001_NAME}: Charlie production derivation"
    );
}
