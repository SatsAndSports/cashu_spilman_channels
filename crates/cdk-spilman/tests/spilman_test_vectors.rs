//! Compatibility assertions for published Spilman test vectors.

use std::collections::BTreeMap;
use std::str::FromStr;

use cashu::nuts::{CurrencyUnit, Id, Keys, PublicKey};
use cashu::{util::hex, Amount};
use cdk_spilman::{compute_channel_secret, ChannelParameters, KeysetInfo};
use spilman_test_vectors::channel_id::{
    spilman_test_vector_channel_id_keysetv2 as get_channel_id_test_vector_details,
    spilman_test_vector_channel_id_keysetv2_mint_trailing_slash as get_trailing_slash_test_vector_details,
    ChannelIdTestVector, SPILMAN_TEST_VECTOR_CHANNEL_ID_KEYSETV2_MINT_TRAILING_SLASH_NAME,
    SPILMAN_TEST_VECTOR_CHANNEL_ID_KEYSETV2_NAME,
};
use spilman_test_vectors::channel_secret::{
    spilman_test_vector_channel_secret_hkdf as get_test_vector_details,
    SPILMAN_TEST_VECTOR_CHANNEL_SECRET_HKDF_NAME,
};
use spilman_test_vectors::output_nonce_and_blinding_keyset_v2::{
    spilman_test_vector_output_nonce_and_blinding_keysetv2 as get_output_nonce_and_blinding_test_vector_details,
    SPILMAN_TEST_VECTOR_OUTPUT_NONCE_AND_BLINDING_KEYSETV2_NAME,
};

#[test]
fn spilman_test_vector_channel_secret_hkdf() {
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
        "{SPILMAN_TEST_VECTOR_CHANNEL_SECRET_HKDF_NAME}: Alice production derivation"
    );
    assert_eq!(
        hex::encode(compute_channel_secret(
            &charlie_secret,
            &alice_secret.public_key()
        )),
        hex::encode(vector.channel_secret),
        "{SPILMAN_TEST_VECTOR_CHANNEL_SECRET_HKDF_NAME}: Charlie production derivation"
    );
}

fn channel_parameters(vector: ChannelIdTestVector) -> ChannelParameters {
    let active_keys = Keys::new(
        vector
            .public_keys
            .iter()
            .map(|(amount, public_key)| {
                (
                    Amount::from(*amount),
                    PublicKey::from_str(public_key).expect("valid vector public key"),
                )
            })
            .collect::<BTreeMap<_, _>>(),
    );
    let keyset_info = KeysetInfo::new(
        Id::from_str(vector.keyset_id).expect("valid vector keyset ID"),
        CurrencyUnit::Sat,
        active_keys,
        vector.input_fee_ppk,
        None,
    );
    let sender_pubkey = PublicKey::from_str(vector.sender_pubkey).expect("valid vector sender");
    let receiver_pubkey =
        PublicKey::from_str(vector.receiver_pubkey).expect("valid vector receiver");
    ChannelParameters::new(
        sender_pubkey,
        receiver_pubkey,
        vector.mint.to_owned(),
        CurrencyUnit::Sat,
        vector.capacity,
        vector.funding_token_amount,
        vector.expiry_timestamp,
        vector.setup_timestamp,
        keyset_info,
        vector.maximum_amount,
        vector.channel_secret,
    )
    .expect("valid channel-ID vector parameters")
}

#[test]
fn spilman_test_vector_channel_id_keysetv2() {
    let vector = get_channel_id_test_vector_details();
    let parameters = channel_parameters(vector);

    assert_eq!(
        parameters.get_channel_id(),
        hex::encode(vector.channel_id),
        "{SPILMAN_TEST_VECTOR_CHANNEL_ID_KEYSETV2_NAME}: production channel-ID derivation"
    );
    assert_eq!(
        parameters.get_channel_id_bytes(),
        vector.channel_id,
        "{SPILMAN_TEST_VECTOR_CHANNEL_ID_KEYSETV2_NAME}: production channel-ID bytes"
    );
}

#[test]
fn spilman_test_vector_channel_id_keysetv2_mint_trailing_slash() {
    let vector = get_trailing_slash_test_vector_details();
    let parameters = channel_parameters(vector);

    assert_eq!(
        parameters.mint, "https://vector-mint.example",
        "{SPILMAN_TEST_VECTOR_CHANNEL_ID_KEYSETV2_MINT_TRAILING_SLASH_NAME}: production mint normalization"
    );
    assert_eq!(
        parameters.get_channel_id(),
        hex::encode(vector.channel_id),
        "{SPILMAN_TEST_VECTOR_CHANNEL_ID_KEYSETV2_MINT_TRAILING_SLASH_NAME}: production channel-ID derivation"
    );
}

#[test]
fn spilman_test_vector_output_nonce_and_blinding_keysetv2() {
    let vector = get_output_nonce_and_blinding_test_vector_details();
    let output = channel_parameters(get_channel_id_test_vector_details())
        .create_deterministic_output_with_blinding(vector.context, vector.amount, vector.index)
        .expect("valid deterministic funding output");
    let secret_json: serde_json::Value =
        serde_json::from_str(&output.secret.to_string()).expect("valid NUT-10 secret JSON");

    assert_eq!(
        secret_json[1]["nonce"],
        hex::encode(vector.nonce),
        "{SPILMAN_TEST_VECTOR_OUTPUT_NONCE_AND_BLINDING_KEYSETV2_NAME}: production output nonce"
    );
    assert_eq!(
        hex::encode(output.blinding_factor.secret_bytes()),
        hex::encode(vector.blinding_factor),
        "{SPILMAN_TEST_VECTOR_OUTPUT_NONCE_AND_BLINDING_KEYSETV2_NAME}: production Cashu blinding factor"
    );
}
