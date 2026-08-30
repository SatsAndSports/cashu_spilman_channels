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
        FundingOutputTestVector { amount: 4, index: 0, secret: "[\"P2PK\",{\"data\":\"03da88bac82ac2731d6f4463e2d981824ea2d0e4862215bf8a422b1afe4eea6a8d\",\"nonce\":\"e9aad80a4e747e570bb68cff4f8a33f8c2d904f424e695f9e2febf92bbd4fb30\",\"tags\":[[\"pubkeys\",\"03c988d50c11fa634afdd519e2a9ce751adf29f0b17ad6251b7c199fdf9c1f7455\"],[\"locktime\",\"1800000000\"],[\"n_sigs\",\"2\"],[\"refund\",\"02d9194f39e5689e97a4f20614b09e5ec751edc41f63d0bde6fc39d7dfeba74760\"],[\"n_sigs_refund\",\"1\"],[\"sigflag\",\"SIG_ALL\"]]}]", blinding_factor: "d8d6d77cfe64154981bc10bfbb96987c27353f1854e3b977543e5c92ff91ffef", blinded_message: "03c1d74cd3ce918288b83438fb63850c4b316a82135afc6543e564c0915facadef" },
        FundingOutputTestVector { amount: 32, index: 0, secret: "[\"P2PK\",{\"data\":\"03da88bac82ac2731d6f4463e2d981824ea2d0e4862215bf8a422b1afe4eea6a8d\",\"nonce\":\"879abe0662d57e86ec39d715103c1c95814780b29752c01aadb0888b92d3c081\",\"tags\":[[\"pubkeys\",\"03c988d50c11fa634afdd519e2a9ce751adf29f0b17ad6251b7c199fdf9c1f7455\"],[\"locktime\",\"1800000000\"],[\"n_sigs\",\"2\"],[\"refund\",\"02d9194f39e5689e97a4f20614b09e5ec751edc41f63d0bde6fc39d7dfeba74760\"],[\"n_sigs_refund\",\"1\"],[\"sigflag\",\"SIG_ALL\"]]}]", blinding_factor: "8952cedabe7d95af9d8388373e1bc2d8cb8897a4e59a5b3c0d3c7e93d2059b0f", blinded_message: "02f4fa3357831a0eed7aa2ebd0164a75c804a463650c890f37815f5c70f3683265" },
        FundingOutputTestVector { amount: 64, index: 0, secret: "[\"P2PK\",{\"data\":\"03da88bac82ac2731d6f4463e2d981824ea2d0e4862215bf8a422b1afe4eea6a8d\",\"nonce\":\"f934dd4311715f9e9af3d338c2b7235581a779f748839ffbfe584b0c1e21e37a\",\"tags\":[[\"pubkeys\",\"03c988d50c11fa634afdd519e2a9ce751adf29f0b17ad6251b7c199fdf9c1f7455\"],[\"locktime\",\"1800000000\"],[\"n_sigs\",\"2\"],[\"refund\",\"02d9194f39e5689e97a4f20614b09e5ec751edc41f63d0bde6fc39d7dfeba74760\"],[\"n_sigs_refund\",\"1\"],[\"sigflag\",\"SIG_ALL\"]]}]", blinding_factor: "95066df465e8e73f5d56df3bcf010ed7c8cc473b0e68ada8bb51589f31009618", blinded_message: "0365caa01fd1599a8f3c1321022c56680bf010351c2af4c45936fde4bfd8469442" },
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
