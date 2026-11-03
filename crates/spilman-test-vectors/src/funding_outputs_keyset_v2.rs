//! V2-keyset test vector for complete funding-token outputs.

use hmac::{Hmac, KeyInit, Mac};
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
        FundingOutputTestVector { amount: 4, index: 0, secret: "[\"P2PK\",{\"data\":\"025032d5e99037ddabf57564ebd03e79994bd86d77f47302ca81eca7e8555dd80b\",\"nonce\":\"cd4bfbda7d1d630ba93d4027eb37fcde4cdcf886809b4a1d38af6b26dc5fdf67\",\"tags\":[[\"pubkeys\",\"035ab3f5c8bfd229dfddf3d6bd0f4c6a7470c43f3c864f8e4121d6ac86a16e43e4\"],[\"locktime\",\"1800000000\"],[\"n_sigs\",\"2\"],[\"refund\",\"0262059f95d1ac59f34a29f9e9d5c26b414e1921b0b76d5f162b54d67d0540a72d\"],[\"n_sigs_refund\",\"1\"],[\"sigflag\",\"SIG_ALL\"]]}]", blinding_factor: "08333c12d6cacac3bb9b53ac724d9cc53ee2bead9b8380353335916a7094f9a0", blinded_message: "03d3c8c76a78f1cdb3cdb4a392f77afe1d9a4f19e1681afcffe7cc013ac20d8873" },
        FundingOutputTestVector { amount: 32, index: 0, secret: "[\"P2PK\",{\"data\":\"025032d5e99037ddabf57564ebd03e79994bd86d77f47302ca81eca7e8555dd80b\",\"nonce\":\"7f3dd5bc167eb0a52c0a8fc3a02aacd79520ae5d825974dfb25cc913d21a0955\",\"tags\":[[\"pubkeys\",\"035ab3f5c8bfd229dfddf3d6bd0f4c6a7470c43f3c864f8e4121d6ac86a16e43e4\"],[\"locktime\",\"1800000000\"],[\"n_sigs\",\"2\"],[\"refund\",\"0262059f95d1ac59f34a29f9e9d5c26b414e1921b0b76d5f162b54d67d0540a72d\"],[\"n_sigs_refund\",\"1\"],[\"sigflag\",\"SIG_ALL\"]]}]", blinding_factor: "47f8a37dba6dd9962f324aa46071f75ee290bae336ef341fc9e10ab7b7ac4a2d", blinded_message: "02b852b64fd1fcdd6c8e8aa0bd4609ab2925d9dc588b2a883123c7ab27d1a54503" },
        FundingOutputTestVector { amount: 64, index: 0, secret: "[\"P2PK\",{\"data\":\"025032d5e99037ddabf57564ebd03e79994bd86d77f47302ca81eca7e8555dd80b\",\"nonce\":\"872b3ae7294249e7bb7a5351623b3a8a400820f5af294cf7f74888eb55a22273\",\"tags\":[[\"pubkeys\",\"035ab3f5c8bfd229dfddf3d6bd0f4c6a7470c43f3c864f8e4121d6ac86a16e43e4\"],[\"locktime\",\"1800000000\"],[\"n_sigs\",\"2\"],[\"refund\",\"0262059f95d1ac59f34a29f9e9d5c26b414e1921b0b76d5f162b54d67d0540a72d\"],[\"n_sigs_refund\",\"1\"],[\"sigflag\",\"SIG_ALL\"]]}]", blinding_factor: "9f395ca331cf075dd3a651037a088b99a76c60a3e49ecda22905e5eff7f92f18", blinded_message: "02ecc9ac363e78600d4b4dc84908d899e7c7eba9f5b93aa5c5d3bf5d7548319b50" },
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
