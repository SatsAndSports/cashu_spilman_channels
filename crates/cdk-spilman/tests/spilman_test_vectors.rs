//! Compatibility assertions for published Spilman test vectors.

use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::secp256k1::Scalar;
use cashu::nuts::nut10::SpendingConditionVerification;
use cashu::nuts::{CurrencyUnit, Id, Keys, PublicKey};
use cashu::{util::hex, Amount};
use cdk_spilman::{
    compute_channel_secret, ChannelParameters, CommitmentOutputs,
    DeterministicOutputsForOneContext, KeysetInfo, OrderedListOfAmounts,
};
use spilman_test_vectors::amount_selection_keyset_v2::{
    spilman_test_vector_amount_selection_keysetv2 as get_amount_selection_test_vector_details,
    spilman_test_vector_amount_selection_keysetv2_max32 as get_amount_selection_max32_test_vector_details,
};
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
use spilman_test_vectors::commitment_outputs_keyset_v2::spilman_test_vector_commitment_outputs_keysetv2 as get_commitment_outputs_test_vector_details;
use spilman_test_vectors::funding_outputs_keyset_v2::spilman_test_vector_funding_outputs_keysetv2 as get_funding_outputs_test_vector_details;
use spilman_test_vectors::output_nonce_and_blinding_keyset_v2::{
    spilman_test_vector_output_nonce_and_blinding_keysetv2 as get_output_nonce_and_blinding_test_vector_details,
    SPILMAN_TEST_VECTOR_OUTPUT_NONCE_AND_BLINDING_KEYSETV2_NAME,
};
use spilman_test_vectors::sig_all_keyset_v2::{
    derive_sig_all_message_reference, funding_input_cs, funding_input_secrets,
    spilman_test_vector_sig_all_keysetv2 as get_sig_all_test_vector_details,
};
use spilman_test_vectors::stage1_key_tweaks_keyset_v2::spilman_test_vector_stage1_key_tweaks_keysetv2 as get_stage1_key_tweaks_test_vector_details;

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
    let nonce: [u8; 32] = vector.nonce;
    assert!(
        Scalar::from_be_bytes(nonce).is_ok_and(|scalar| scalar != Scalar::ZERO),
        "{SPILMAN_TEST_VECTOR_OUTPUT_NONCE_AND_BLINDING_KEYSETV2_NAME}: nonce is a valid secp256k1 scalar"
    );
    assert_eq!(
        hex::encode(output.blinding_factor.secret_bytes()),
        hex::encode(vector.blinding_factor),
        "{SPILMAN_TEST_VECTOR_OUTPUT_NONCE_AND_BLINDING_KEYSETV2_NAME}: production Cashu blinding factor"
    );
}

#[test]
fn spilman_test_vector_amount_selection_keysetv2() {
    for vector in [
        get_amount_selection_test_vector_details(),
        get_amount_selection_max32_test_vector_details(),
    ] {
        let parameters = channel_parameters(get_channel_id_test_vector_details());
        let selected = OrderedListOfAmounts::from_target(
            vector.target,
            vector.maximum_amount,
            &parameters.keyset_info,
        )
        .expect("representable vector target");
        assert_eq!(selected.amounts(), vector.amounts);
    }
}

#[test]
fn spilman_test_vector_stage1_key_tweaks_keysetv2() {
    let parameters = channel_parameters(get_channel_id_test_vector_details());
    let vector = get_stage1_key_tweaks_test_vector_details();
    assert_eq!(
        parameters
            .get_sender_blinded_pubkey_for_stage1()
            .expect("sender stage-1 key")
            .to_hex(),
        vector[0].blinded_pubkey
    );
    assert_eq!(
        parameters
            .get_receiver_blinded_pubkey_for_stage1()
            .expect("receiver stage-1 key")
            .to_hex(),
        vector[1].blinded_pubkey
    );
    assert_eq!(
        parameters
            .get_sender_blinded_pubkey_for_stage1_refund()
            .expect("sender refund stage-1 key")
            .to_hex(),
        vector[2].blinded_pubkey
    );
}

#[test]
fn spilman_test_vector_funding_outputs_keysetv2() {
    let parameters = channel_parameters(get_channel_id_test_vector_details());
    let outputs = DeterministicOutputsForOneContext::new("funding".to_owned(), 100, parameters)
        .expect("valid funding outputs");
    let secrets = outputs
        .get_secrets_with_blinding()
        .expect("funding secrets");
    let messages = outputs
        .get_blinded_messages(None)
        .expect("funding messages");

    for ((secret, message), vector) in secrets
        .iter()
        .zip(messages.iter())
        .zip(get_funding_outputs_test_vector_details())
    {
        assert_eq!(secret.amount, vector.amount);
        assert_eq!(secret.index, vector.index);
        assert_eq!(secret.secret.to_bytes(), vector.secret.as_bytes());
        assert_eq!(
            hex::encode(secret.blinding_factor.secret_bytes()),
            vector.blinding_factor
        );
        assert_eq!(message.blinded_secret.to_hex(), vector.blinded_message);
    }
}

#[test]
fn spilman_test_vector_commitment_outputs_keysetv2() {
    let parameters = channel_parameters(get_channel_id_test_vector_details());
    let outputs = CommitmentOutputs::for_balance(50, &parameters).expect("valid commitment");
    let mut produced = Vec::new();
    for (context, outputs) in [
        ("receiver", &outputs.receiver_outputs),
        ("sender", &outputs.sender_outputs),
    ] {
        for (secret, message) in outputs
            .get_secrets_with_blinding()
            .expect("secrets")
            .into_iter()
            .zip(outputs.get_blinded_messages(None).expect("messages"))
        {
            produced.push((context, secret, message));
        }
    }
    for ((context, secret, message), vector) in produced
        .iter()
        .zip(get_commitment_outputs_test_vector_details())
    {
        assert_eq!(*context, vector.context);
        assert_eq!(secret.amount, vector.amount);
        assert_eq!(secret.index, vector.index);
        assert_eq!(secret.secret.to_bytes(), vector.secret.as_bytes());
        assert_eq!(
            hex::encode(secret.blinding_factor.secret_bytes()),
            vector.blinding_factor
        );
        assert_eq!(message.blinded_secret.to_hex(), vector.blinded_message);
    }

    let sorted = outputs
        .create_swap_request(Vec::new(), None)
        .expect("valid commitment output ordering");
    let expected: Vec<_> = get_commitment_outputs_test_vector_details()
        .into_iter()
        .map(|vector| vector.blinded_message)
        .collect();
    assert_eq!(
        sorted
            .outputs()
            .iter()
            .map(|output| output.blinded_secret.to_hex())
            .collect::<Vec<_>>(),
        [
            expected[0],
            expected[3],
            expected[1],
            expected[4],
            expected[2],
            expected[5]
        ],
    );
}

#[test]
fn spilman_test_vector_sig_all_keysetv2() {
    use bitcoin::hashes::{sha256, Hash};
    use cashu::nuts::{Proof, Witness};
    use cashu::secret::Secret;

    let parameters = channel_parameters(get_channel_id_test_vector_details());
    let vector = get_sig_all_test_vector_details();
    let funding_proofs = funding_input_secrets()
        .into_iter()
        .zip(funding_input_cs())
        .zip([4, 32, 64])
        .map(|((secret, c), amount)| {
            Proof::new(
                Amount::from(amount),
                parameters.keyset_info.keyset_id,
                Secret::new(secret.to_owned()),
                PublicKey::from_str(c).expect("valid fixed proof signature point"),
            )
        })
        .collect();
    let commitment = CommitmentOutputs::for_balance(vector.receiver_balance, &parameters)
        .expect("valid vector commitment");
    let mut swap = commitment
        .create_swap_request(funding_proofs, None)
        .expect("valid SIG_ALL swap");

    let expected_message = derive_sig_all_message_reference();
    assert_eq!(swap.sig_all_msg_to_sign().as_bytes(), expected_message);
    assert_eq!(
        sha256::Hash::hash(&expected_message).to_byte_array(),
        vector.message_sha256
    );

    let key_vector = get_test_vector_details();
    let alice = cashu::nuts::SecretKey::from_slice(&key_vector.alice_secret_key)
        .expect("valid Alice test key");
    let charlie = cashu::nuts::SecretKey::from_slice(&key_vector.charlie_secret_key)
        .expect("valid Charlie test key");
    let sender_key = parameters
        .get_sender_blinded_secret_key_for_stage1(&alice)
        .expect("valid Alice stage-1 key");
    let receiver_key = parameters
        .get_receiver_blinded_secret_key_for_stage1(&charlie)
        .expect("valid Charlie stage-1 key");

    swap.sign_sig_all(sender_key)
        .expect("Alice SIG_ALL signature");
    swap.sign_sig_all(receiver_key)
        .expect("Charlie SIG_ALL signature");

    let signatures = match &swap.inputs()[0].witness {
        Some(Witness::P2PKWitness(witness)) => &witness.signatures,
        _ => panic!("SIG_ALL signatures belong to the first input"),
    };
    assert_eq!(signatures.len(), 2);
    let alice_signature = signatures[0]
        .parse()
        .expect("valid Alice Schnorr signature");
    let charlie_signature = signatures[1]
        .parse()
        .expect("valid Charlie Schnorr signature");
    parameters
        .get_sender_blinded_pubkey_for_stage1()
        .expect("Alice stage-1 public key")
        .verify(&expected_message, &alice_signature)
        .expect("Alice signature authorizes the vector swap");
    parameters
        .get_receiver_blinded_pubkey_for_stage1()
        .expect("Charlie stage-1 public key")
        .verify(&expected_message, &charlie_signature)
        .expect("Charlie signature authorizes the vector swap");
    assert!(swap.inputs()[0].witness.is_some());
    assert!(swap.inputs()[1..]
        .iter()
        .all(|input| input.witness.is_none()));
}
