//! V2-keyset test vector for deterministic output nonces and Cashu blinding factors.

use hmac::{Hmac, Mac};
use k256::SecretKey;
use sha2::Sha256;

use crate::channel_id::spilman_test_vector_channel_id_keysetv2;

/// Canonical name of the V2-keyset deterministic output compatibility fixture.
pub const SPILMAN_TEST_VECTOR_OUTPUT_NONCE_AND_BLINDING_KEYSETV2_NAME: &str =
    "spilman-test-vector-output-nonce-and-blinding-keysetv2";

const CONTEXT: &str = "funding";
const AMOUNT: u64 = 64;
const INDEX: usize = 0;
const RETRY_COUNTER: u8 = 0;
const CHANNEL_ID: &str = "7af675f4f1b9843200d23060ebeb5bf5abea67fa511af79aefa4ba6a19b88c2e";
const NONCE_HEX: &str = "f934dd4311715f9e9af3d338c2b7235581a779f748839ffbfe584b0c1e21e37a";
const BLINDING_FACTOR_HEX: &str =
    "74285411dc702b0e295f143d026b95bd75cf730647a694e5c5b8147f619d1b35";

/// Fixed inputs and expected outputs for deterministic output derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputNonceAndBlindingTestVector {
    /// The lowercase hexadecimal channel ID.
    pub channel_id: &'static str,
    /// The channel-secret HMAC key.
    pub channel_secret: [u8; 32],
    /// The output role.
    pub context: &'static str,
    /// The output denomination.
    pub amount: u64,
    /// The zero-based index among outputs with this denomination.
    pub index: usize,
    /// Exact UTF-8 HMAC input for the nonce.
    pub nonce_message: &'static str,
    /// The resulting valid 32-byte secp256k1 scalar serialized as the nonce.
    pub nonce: [u8; 32],
    /// The accepted blinding-factor retry counter.
    pub retry_counter: u8,
    /// Exact UTF-8 HMAC input for the Cashu blinding factor.
    pub blinding_message: &'static str,
    /// The resulting valid secp256k1 scalar.
    pub blinding_factor: [u8; 32],
}

/// Values derived independently from the deterministic output vector inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputNonceAndBlindingReference {
    /// The valid 32-byte secp256k1 scalar serialized as the nonce.
    pub nonce: [u8; 32],
    /// The accepted retry counter.
    pub retry_counter: u8,
    /// The valid 32-byte secp256k1 blinding scalar.
    pub blinding_factor: [u8; 32],
}

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value)
        .expect("test-vector hex must be valid")
        .try_into()
        .expect("test-vector hex must have the expected length")
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Return the fixed values for
/// `spilman-test-vector-output-nonce-and-blinding-keysetv2`.
pub fn spilman_test_vector_output_nonce_and_blinding_keysetv2() -> OutputNonceAndBlindingTestVector
{
    let nonce_message = concat!(
        "7af675f4f1b9843200d23060ebeb5bf5abea67fa511af79aefa4ba6a19b88c2e",
        "|funding|64|nonce|0"
    );
    let blinding_message = concat!(
        "7af675f4f1b9843200d23060ebeb5bf5abea67fa511af79aefa4ba6a19b88c2e",
        "|funding|64|blinding|0|0"
    );
    OutputNonceAndBlindingTestVector {
        channel_id: CHANNEL_ID,
        channel_secret: spilman_test_vector_channel_id_keysetv2().channel_secret,
        context: CONTEXT,
        amount: AMOUNT,
        index: INDEX,
        nonce_message,
        nonce: decode_hex(NONCE_HEX),
        retry_counter: RETRY_COUNTER,
        blinding_message,
        blinding_factor: decode_hex(BLINDING_FACTOR_HEX),
    }
}

/// Derive the output nonce and first valid blinding scalar from the fixture.
///
/// # Panics
///
/// Panics if no valid secp256k1 scalar is found in the specified retry range.
pub fn derive_output_nonce_and_blinding_reference() -> OutputNonceAndBlindingReference {
    let vector = spilman_test_vector_output_nonce_and_blinding_keysetv2();
    let nonce = hmac_sha256(&vector.channel_secret, vector.nonce_message.as_bytes());
    assert!(
        SecretKey::from_slice(&nonce).is_ok(),
        "the fixture nonce must be a valid secp256k1 scalar"
    );
    let (retry_counter, blinding_factor) = (0u8..=255)
        .find_map(|retry_counter| {
            let message = format!(
                "{}|{}|{}|blinding|{}|{}",
                vector.channel_id, vector.context, vector.amount, vector.index, retry_counter
            );
            let candidate = hmac_sha256(&vector.channel_secret, message.as_bytes());
            SecretKey::from_slice(&candidate)
                .ok()
                .map(|_| (retry_counter, candidate))
        })
        .expect("a valid test-vector blinding scalar");
    assert_eq!(
        format!(
            "{}|{}|{}|blinding|{}|{}",
            vector.channel_id, vector.context, vector.amount, vector.index, retry_counter
        ),
        vector.blinding_message,
        "selected blinding message must match the published fixture"
    );

    OutputNonceAndBlindingReference {
        nonce,
        retry_counter,
        blinding_factor,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        derive_output_nonce_and_blinding_reference,
        spilman_test_vector_output_nonce_and_blinding_keysetv2 as get_test_vector_details,
        SPILMAN_TEST_VECTOR_OUTPUT_NONCE_AND_BLINDING_KEYSETV2_NAME,
    };

    #[test]
    fn spilman_test_vector_output_nonce_and_blinding_keysetv2() {
        let vector = get_test_vector_details();
        let reference = derive_output_nonce_and_blinding_reference();

        assert_eq!(
            vector.channel_id,
            hex::encode(crate::channel_id::spilman_test_vector_channel_id_keysetv2().channel_id),
            "{SPILMAN_TEST_VECTOR_OUTPUT_NONCE_AND_BLINDING_KEYSETV2_NAME}: channel-ID fixture input"
        );

        assert_eq!(
            hex::encode(reference.nonce),
            hex::encode(vector.nonce),
            "{SPILMAN_TEST_VECTOR_OUTPUT_NONCE_AND_BLINDING_KEYSETV2_NAME}: independent nonce HMAC derivation"
        );
        assert_eq!(
            reference.retry_counter, vector.retry_counter,
            "{SPILMAN_TEST_VECTOR_OUTPUT_NONCE_AND_BLINDING_KEYSETV2_NAME}: independent scalar retry selection"
        );
        assert_eq!(
            hex::encode(reference.blinding_factor),
            hex::encode(vector.blinding_factor),
            "{SPILMAN_TEST_VECTOR_OUTPUT_NONCE_AND_BLINDING_KEYSETV2_NAME}: independent blinding HMAC derivation"
        );
    }
}
