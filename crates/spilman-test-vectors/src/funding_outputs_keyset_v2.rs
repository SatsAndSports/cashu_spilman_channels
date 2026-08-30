//! V2-keyset test vector for complete funding-token outputs.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::channel_id::spilman_test_vector_channel_id_keysetv2;

/// Canonical name of the complete funding-output compatibility fixture.
pub const SPILMAN_TEST_VECTOR_FUNDING_OUTPUTS_KEYSETV2_NAME: &str =
    "spilman-test-vector-funding-outputs-keysetv2";

/// One complete funding-token output fixture entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FundingOutputTestVector {
    /// Cashu output amount.
    pub amount: u64,
    /// Per-denomination output index.
    pub index: usize,
    /// NUT-10 secret JSON.
    pub secret: &'static str,
    /// Cashu blinding factor.
    pub blinding_factor: &'static str,
    /// Resulting blinded message point.
    pub blinded_message: &'static str,
}

/// Return the fixed funding outputs in Cashu smallest-first order.
pub fn spilman_test_vector_funding_outputs_keysetv2() -> [FundingOutputTestVector; 3] {
    [
        FundingOutputTestVector { amount: 4, index: 0, secret: "[\"P2PK\",{\"data\":\"02516479c6dee216722f477dcc5ecddb6a793fa7aaf7d8d2b887f45dc6ff96faee\",\"nonce\":\"e9aad80a4e747e570bb68cff4f8a33f8c2d904f424e695f9e2febf92bbd4fb30\",\"tags\":[[\"pubkeys\",\"02b37243d00583b225e1f5dc23a48a7568b09eec889bfa45c20fc865de7309b2a9\"],[\"locktime\",\"1800000000\"],[\"n_sigs\",\"2\"],[\"refund\",\"022055ae1c0cba2f9cb756b4779276c8e061fe9ccd286c43a91b4164d265fcfbe8\"],[\"n_sigs_refund\",\"1\"],[\"sigflag\",\"SIG_ALL\"]]}]", blinding_factor: "d8d6d77cfe64154981bc10bfbb96987c27353f1854e3b977543e5c92ff91ffef", blinded_message: "036a453cdf46b2abdb52d72c591152199bd386f79dd00c322f2e2d776b0c9ec16a" },
        FundingOutputTestVector { amount: 32, index: 0, secret: "[\"P2PK\",{\"data\":\"02516479c6dee216722f477dcc5ecddb6a793fa7aaf7d8d2b887f45dc6ff96faee\",\"nonce\":\"879abe0662d57e86ec39d715103c1c95814780b29752c01aadb0888b92d3c081\",\"tags\":[[\"pubkeys\",\"02b37243d00583b225e1f5dc23a48a7568b09eec889bfa45c20fc865de7309b2a9\"],[\"locktime\",\"1800000000\"],[\"n_sigs\",\"2\"],[\"refund\",\"022055ae1c0cba2f9cb756b4779276c8e061fe9ccd286c43a91b4164d265fcfbe8\"],[\"n_sigs_refund\",\"1\"],[\"sigflag\",\"SIG_ALL\"]]}]", blinding_factor: "8952cedabe7d95af9d8388373e1bc2d8cb8897a4e59a5b3c0d3c7e93d2059b0f", blinded_message: "02be9df107c01a2e33640bc229b673b71dccdee427c4e417c83c39f585abfb5dc6" },
        FundingOutputTestVector { amount: 64, index: 0, secret: "[\"P2PK\",{\"data\":\"02516479c6dee216722f477dcc5ecddb6a793fa7aaf7d8d2b887f45dc6ff96faee\",\"nonce\":\"f934dd4311715f9e9af3d338c2b7235581a779f748839ffbfe584b0c1e21e37a\",\"tags\":[[\"pubkeys\",\"02b37243d00583b225e1f5dc23a48a7568b09eec889bfa45c20fc865de7309b2a9\"],[\"locktime\",\"1800000000\"],[\"n_sigs\",\"2\"],[\"refund\",\"022055ae1c0cba2f9cb756b4779276c8e061fe9ccd286c43a91b4164d265fcfbe8\"],[\"n_sigs_refund\",\"1\"],[\"sigflag\",\"SIG_ALL\"]]}]", blinding_factor: "95066df465e8e73f5d56df3bcf010ed7c8cc473b0e68ada8bb51589f31009618", blinded_message: "02529111ff074c0e7503ab7f299c6221702a77c40354ad5f3e38c7cb61a9dc2c83" },
    ]
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Independently derive the nonce and Cashu blinding scalar for one funding output.
///
/// # Panics
///
/// Panics if both scalar candidates are invalid.
pub fn derive_funding_output_scalars(amount: u64, index: usize) -> (String, String) {
    let channel = spilman_test_vector_channel_id_keysetv2();
    let id = hex::encode(channel.channel_id);
    let nonce = hex::encode(hmac_sha256(
        &channel.channel_secret,
        format!("{id}|funding|{amount}|nonce|{index}").as_bytes(),
    ));
    let input = format!("{id}|funding|{amount}|blinding|{index}");
    let mut value = hmac_sha256(&channel.channel_secret, input.as_bytes());
    if k256::SecretKey::from_slice(&value).is_err() {
        let mut retry_input = input.into_bytes();
        retry_input.push(0xff);
        value = hmac_sha256(&channel.channel_secret, &retry_input);
    }
    assert!(k256::SecretKey::from_slice(&value).is_ok(), "valid scalar");
    let scalar = hex::encode(value);
    (nonce, scalar)
}

#[cfg(test)]
mod tests {
    use super::{
        derive_funding_output_scalars,
        spilman_test_vector_funding_outputs_keysetv2 as get_test_vector_details,
    };
    use crate::stage1_key_tweaks_keyset_v2::spilman_test_vector_stage1_key_tweaks_keysetv2;

    #[test]
    fn spilman_test_vector_funding_outputs_keysetv2() {
        let tweaks = spilman_test_vector_stage1_key_tweaks_keysetv2();
        for output in get_test_vector_details() {
            let (nonce, scalar) = derive_funding_output_scalars(output.amount, output.index);
            assert!(output.secret.contains(&nonce));
            assert_eq!(scalar, output.blinding_factor);
        }
        assert!(get_test_vector_details()[0]
            .secret
            .contains(tweaks[0].blinded_pubkey));
        assert!(get_test_vector_details()[0]
            .secret
            .contains(tweaks[1].blinded_pubkey));
        assert!(get_test_vector_details()[0]
            .secret
            .contains(tweaks[2].blinded_pubkey));
    }
}
