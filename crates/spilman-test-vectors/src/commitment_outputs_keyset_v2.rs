//! V2-keyset test vector for the deterministic commitment swap outputs.

/// Canonical name of the complete commitment-output compatibility fixture.
pub const SPILMAN_TEST_VECTOR_COMMITMENT_OUTPUTS_KEYSETV2_NAME: &str =
    "spilman-test-vector-commitment-outputs-keysetv2";

/// One complete commitment-output fixture entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitmentOutputTestVector {
    /// NUT-XX output context.
    pub context: &'static str,
    /// Cashu output amount.
    pub amount: u64,
    /// Per-denomination output index.
    pub index: usize,
    /// NUT-10 secret bytes, encoded as UTF-8 JSON.
    pub secret: &'static str,
    /// Deterministic NUT-28 ephemeral public key, stored as `p2pk_e` after unblinding.
    pub p2pk_e: &'static str,
    /// Deterministic P2BK blinded recipient public key stored in `Secret.data`.
    pub blinded_pubkey: &'static str,
    /// Cashu blinding factor.
    pub blinding_factor: &'static str,
    /// Resulting blinded message point.
    pub blinded_message: &'static str,
}

/// Return commitment outputs for a zero-fee 100-sat channel with a 50-sat
/// receiver balance. Entries are grouped by owner in each owner's
/// smallest-first deterministic order.
pub fn spilman_test_vector_commitment_outputs_keysetv2() -> [CommitmentOutputTestVector; 6] {
    [
        CommitmentOutputTestVector { context: "receiver", amount: 2, index: 0, secret: "[\"P2PK\",{\"data\":\"0395499a0b6977b755bd762b394dfea023e6829449989209b852e2baef3d5acc04\",\"nonce\":\"e7cd816bb2de9369901c3d058915cb08e64141df5fed1e7f816591463680ca29\",\"tags\":[]}]", p2pk_e: "03f83f09c1b594b8c959865ac9187bc84794867cf1f1f6d5f23e9fe39b5cc62823", blinded_pubkey: "0395499a0b6977b755bd762b394dfea023e6829449989209b852e2baef3d5acc04", blinding_factor: "997f96b9970fbbdfb5ad707a0678aca7f852234019a4ebfce78b03a5d5534005", blinded_message: "02edb30c85ffdf26a839211cb8fdb6e66a2683b63d3a219c18cda91a06ec6a8bf2" },
        CommitmentOutputTestVector { context: "receiver", amount: 16, index: 0, secret: "[\"P2PK\",{\"data\":\"03968acd8b22c3da2f7dfd82418ae566dd4f832d96992f9ccbd9f698c1bf07c0ba\",\"nonce\":\"82a7afe482d3bacc1f8cc2c6d05445ee2ecec26499698c2934b3685beb363080\",\"tags\":[]}]", p2pk_e: "033fcbf07fdeeafc79176cfa5b3084775c55d7a4244413b13519b53b7ebcc87983", blinded_pubkey: "03968acd8b22c3da2f7dfd82418ae566dd4f832d96992f9ccbd9f698c1bf07c0ba", blinding_factor: "8db1bc3dbd5b32a51d99d6ba0e91aaf9df2449aa27b70e12b3a8b065db409c44", blinded_message: "03a19de7bde70cd3da6da9c0249c8a4cd4240a20717e7144852c861b8290e9e4c7" },
        CommitmentOutputTestVector { context: "receiver", amount: 32, index: 0, secret: "[\"P2PK\",{\"data\":\"027d9a5bc962b7c0dbb6032556d6575707e02e5133e9fc6cb8c4c79a9163e02219\",\"nonce\":\"3de4b352b152e9f42a0bf1a80a2074c808022b85423839ceb962fc163ab5ccb1\",\"tags\":[]}]", p2pk_e: "0340c8ee89ad2f338ea2d6500527e1c9ffd97557567d3a4748ffa6961ec2d77e20", blinded_pubkey: "027d9a5bc962b7c0dbb6032556d6575707e02e5133e9fc6cb8c4c79a9163e02219", blinding_factor: "645c826ab04b1d7270f10d7c403c3ba8eea43252484ce9f0342720de35d75674", blinded_message: "03f0aad58d35ce66a5079fe9d24ff8862a04d7ffdcd6683773e80a67f6f2e461e0" },
        CommitmentOutputTestVector { context: "sender", amount: 2, index: 0, secret: "[\"P2PK\",{\"data\":\"030b30774438c74441f23c2ac465d417bcd8ea843540e4e2966347b314d6a426dc\",\"nonce\":\"1c2ea5c4c211ca037ccd134f0fa4feeb52751c73f4cfcbe25fd04a9a12881436\",\"tags\":[]}]", p2pk_e: "03060bb9b3f46ec85a8c3e2c6b9eb4aa4d342fb77f12a4bbf5f20d601630faf9eb", blinded_pubkey: "030b30774438c74441f23c2ac465d417bcd8ea843540e4e2966347b314d6a426dc", blinding_factor: "4cce8c264871220521a6ca7fa0e61e4af38348629d205e984228d378ae5fdc6a", blinded_message: "02432306a375dabf1d699278ad5ed5e7a0659c6b1ec7dd2fb924c86534a6cb534b" },
        CommitmentOutputTestVector { context: "sender", amount: 16, index: 0, secret: "[\"P2PK\",{\"data\":\"03f9c0f1e4a8c06d8210786dcbcb2f476953d523406eed124bb6c64d2654e81c4e\",\"nonce\":\"20790520e7ff1e36a0150443664111fee2496cc07632464387ae3ff6735ea80c\",\"tags\":[]}]", p2pk_e: "026b9a9bfd5f6f1720eb96a808d7937bf49ada33fc067cb751ab8bbe400ea37e3b", blinded_pubkey: "03f9c0f1e4a8c06d8210786dcbcb2f476953d523406eed124bb6c64d2654e81c4e", blinding_factor: "749bf464cf293c7d9fc181894e946498587251d6a39c6e4242bac03c715ec237", blinded_message: "02f8b5fc29575571508b6d0e503da0c4f298dc71098fb8d28c0f27fe82ae8e8a5a" },
        CommitmentOutputTestVector { context: "sender", amount: 32, index: 0, secret: "[\"P2PK\",{\"data\":\"02f04dbe714c4e574b656448843c816516674ed63ff4bda3970e8df7a203892abf\",\"nonce\":\"097a16413a89691abc4c196437b6d174a5b737d9e59d9e53d19e35e1e934e7d3\",\"tags\":[]}]", p2pk_e: "0227f12894d245777fbc258e8a1fc36a8af80d1bca020b3effdd3ed9b4edf9175f", blinded_pubkey: "02f04dbe714c4e574b656448843c816516674ed63ff4bda3970e8df7a203892abf", blinding_factor: "c68c1540afdd821f401c6163965ce3e45f7275c1485f6351529466b2bec19179", blinded_message: "0259f0b01c35e6331d95d25c0e45845fb03189964dc20a35bc6a90023a8c8aa71b" },
    ]
}

#[cfg(test)]
mod tests {
    use super::spilman_test_vector_commitment_outputs_keysetv2 as get_test_vector_details;
    use crate::stage2_p2bk_keyset_v2::derive_stage2_p2bk_reference_for;

    #[test]
    fn commitment_entries_match_independent_stage2_derivations() {
        for vector in get_test_vector_details() {
            let (context, recipient_pubkey) = match vector.context {
                "receiver" => (
                    "receiver_stage2",
                    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                ),
                "sender" => (
                    "sender_stage2",
                    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                ),
                _ => unreachable!("fixed vector has a valid context"),
            };
            let reference = derive_stage2_p2bk_reference_for(
                context,
                recipient_pubkey,
                vector.amount,
                vector.index,
            );
            assert_eq!(vector.p2pk_e, reference.ephemeral_pubkey);
            assert_eq!(vector.blinded_pubkey, reference.blinded_pubkey);
            assert!(vector.secret.contains(vector.blinded_pubkey));
        }
    }
}
