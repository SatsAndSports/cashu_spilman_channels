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
        CommitmentOutputTestVector { context: "receiver", amount: 2, index: 0, secret: "[\"P2PK\",{\"data\":\"03aae5610f300463773890d489bc8638324b7d9966c6aec461b9afe2859cf2be9f\",\"nonce\":\"008b267f22e9da9672d141c6ca72f069c464e1863909d82e4ccdd0fbca0fe658\",\"tags\":[]}]", p2pk_e: "0254f06f28d614849f7e90c53171b194c358a625864cdf26fec99c78553c6781c5", blinded_pubkey: "03aae5610f300463773890d489bc8638324b7d9966c6aec461b9afe2859cf2be9f", blinding_factor: "42a8442f1f234b0fd8727e653fc69ff73e66ea3c84b7689a76339d9ab3ff07bf", blinded_message: "02d177be1fe757258b4a1b520911be0308e58ca235197d31856e4d84f963382dea" },
        CommitmentOutputTestVector { context: "receiver", amount: 16, index: 0, secret: "[\"P2PK\",{\"data\":\"03f8d7134afdf587bf8d40d79ae4aab8905e3a2bb378493a46de13daadff24a2b4\",\"nonce\":\"fe4ac5c03c0dca0ef9af528fddb8975558d03ae7a7f73a93e3718d6f52f4c2f0\",\"tags\":[]}]", p2pk_e: "029927a0192b8c65ad0e4ddbfcb476b4f9f6c4deb8746a4810eb767cfa81d62195", blinded_pubkey: "03f8d7134afdf587bf8d40d79ae4aab8905e3a2bb378493a46de13daadff24a2b4", blinding_factor: "3a793efb2d8332e71a04a4f126ebdf7622546583a25f555dbd028a871858c55e", blinded_message: "0337c112530d05a669c8be0548d0c9d08583e2b247324686a65cc18a890a5d8826" },
        CommitmentOutputTestVector { context: "receiver", amount: 32, index: 0, secret: "[\"P2PK\",{\"data\":\"0397dfedc39293131c2d4c5f76169001e2b11057284dc9345e8178f3ce035660df\",\"nonce\":\"0c640e9c0e7b5c13d519e6a5dbae6d84fc8b71a2da736689fd950606aa3abd07\",\"tags\":[]}]", p2pk_e: "02224366f001c35581b8316a62160d4e5733f102757a1a824d8e41a9ad795d5a90", blinded_pubkey: "0397dfedc39293131c2d4c5f76169001e2b11057284dc9345e8178f3ce035660df", blinding_factor: "acdd0fcfceef385b839d58b70d27dae12d708729e4efefe31f63420c101fae3f", blinded_message: "03e05451988fcc86fb57b074cdcbd0b6de48e1cf6962ccc494ca15aa56d64d406e" },
        CommitmentOutputTestVector { context: "sender", amount: 2, index: 0, secret: "[\"P2PK\",{\"data\":\"02ff4d525e601d93409a27b86704fd4fef883bba75729cf88eb2e8d59de3a55c58\",\"nonce\":\"a5a204390c60cca38988fcedc3f77bef1f32272cef922082f3a8cb8de6fbc73d\",\"tags\":[]}]", p2pk_e: "028db3f60a69b312696ca1e54e49a0ea3b9b1aaaf3c1405b412333ac07771707de", blinded_pubkey: "02ff4d525e601d93409a27b86704fd4fef883bba75729cf88eb2e8d59de3a55c58", blinding_factor: "8c525518a63808137e793b3fdd1491b745e737b0cabb42047337825c717cd40a", blinded_message: "0336186b8e54341d63c7424ce259d4743b3804ac24025d2d9f4911d645f53ce46c" },
        CommitmentOutputTestVector { context: "sender", amount: 16, index: 0, secret: "[\"P2PK\",{\"data\":\"039da1bb99af72c4e3359961d06a27fcba0b09c6e9ced64682c5c58f8166df06b5\",\"nonce\":\"fa5eac4d875dbb343a5840d62a9b6fd0b90d1ee08f1a0b627ba7767c0c622881\",\"tags\":[]}]", p2pk_e: "02f7895660f690f1d498e2f215a7e6de772407b954d09b75e579ed4a284c3a28f7", blinded_pubkey: "039da1bb99af72c4e3359961d06a27fcba0b09c6e9ced64682c5c58f8166df06b5", blinding_factor: "5c8fbc6e15ed4b6ecf8ba42485db5cf8b4cd44840c60a12c2de289041163536f", blinded_message: "03431fe8b75f709a9bc7784d34ebc9612dc6b7d3a6ab10ccb5a0e6654fdd9dcae6" },
        CommitmentOutputTestVector { context: "sender", amount: 32, index: 0, secret: "[\"P2PK\",{\"data\":\"023725a2912497df0d49de8269b778e664b917e6c919e122fd099e2e99be03f1af\",\"nonce\":\"d19c3e67ae5c9aa3d737ccd349cb83c8f384ec5940d166238da8eef54fcd0cfe\",\"tags\":[]}]", p2pk_e: "02a1be7b930f67d26fd168214a18f5c208cb21cda5f6f08bbf61930cae109d5a39", blinded_pubkey: "023725a2912497df0d49de8269b778e664b917e6c919e122fd099e2e99be03f1af", blinding_factor: "51a394d16ba49c82f05813628ec414ab082198c9c7136b352df13b828244f00c", blinded_message: "039143524cc1929a645b93ca820dee2921cdb04633b894537436786c6a0653bdf9" },
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
