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
        CommitmentOutputTestVector { context: "receiver", amount: 2, index: 0, secret: "[\"P2PK\",{\"data\":\"03aae5610f300463773890d489bc8638324b7d9966c6aec461b9afe2859cf2be9f\",\"nonce\":\"008b267f22e9da9672d141c6ca72f069c464e1863909d82e4ccdd0fbca0fe658\",\"tags\":[]}]", p2pk_e: "0254f06f28d614849f7e90c53171b194c358a625864cdf26fec99c78553c6781c5", blinded_pubkey: "03aae5610f300463773890d489bc8638324b7d9966c6aec461b9afe2859cf2be9f", blinding_factor: "9c9107c949e3bb007439519cad428379702bfac828b33fcad7a5b885ba2a95bf", blinded_message: "033a81f9199fda2d0b6955a4114cd2ddffc52b2ddf89197b5a04bd806c8843399e" },
        CommitmentOutputTestVector { context: "receiver", amount: 16, index: 0, secret: "[\"P2PK\",{\"data\":\"03f8d7134afdf587bf8d40d79ae4aab8905e3a2bb378493a46de13daadff24a2b4\",\"nonce\":\"fe4ac5c03c0dca0ef9af528fddb8975558d03ae7a7f73a93e3718d6f52f4c2f0\",\"tags\":[]}]", p2pk_e: "029927a0192b8c65ad0e4ddbfcb476b4f9f6c4deb8746a4810eb767cfa81d62195", blinded_pubkey: "03f8d7134afdf587bf8d40d79ae4aab8905e3a2bb378493a46de13daadff24a2b4", blinding_factor: "3bc38b19a49bc506cee66eca9a779dcb4fc132aea294713150532fae82152e39", blinded_message: "03dc893fd2f3a9509d2f0ed30459aff829cede98826aea0a6ee7a80948c2d74e32" },
        CommitmentOutputTestVector { context: "receiver", amount: 32, index: 0, secret: "[\"P2PK\",{\"data\":\"0397dfedc39293131c2d4c5f76169001e2b11057284dc9345e8178f3ce035660df\",\"nonce\":\"0c640e9c0e7b5c13d519e6a5dbae6d84fc8b71a2da736689fd950606aa3abd07\",\"tags\":[]}]", p2pk_e: "02224366f001c35581b8316a62160d4e5733f102757a1a824d8e41a9ad795d5a90", blinded_pubkey: "0397dfedc39293131c2d4c5f76169001e2b11057284dc9345e8178f3ce035660df", blinding_factor: "de8dedd0c3484e02422ee298d7fa97cca44b80d82d7c6b7ab33743aa32d78e3d", blinded_message: "024e661853c27f2e83300b1ad45c85290861a6eb2d8567ae6595eb6e582770ddf1" },
        CommitmentOutputTestVector { context: "sender", amount: 2, index: 0, secret: "[\"P2PK\",{\"data\":\"02ff4d525e601d93409a27b86704fd4fef883bba75729cf88eb2e8d59de3a55c58\",\"nonce\":\"a5a204390c60cca38988fcedc3f77bef1f32272cef922082f3a8cb8de6fbc73d\",\"tags\":[]}]", p2pk_e: "028db3f60a69b312696ca1e54e49a0ea3b9b1aaaf3c1405b412333ac07771707de", blinded_pubkey: "02ff4d525e601d93409a27b86704fd4fef883bba75729cf88eb2e8d59de3a55c58", blinding_factor: "2c0d9ab01f983f1610a9f8a9b1a3773923bda5e8938b5a15b89c13f02ea0ccd9", blinded_message: "02cf1e71062b1e7ff01986cd0160174c7b039b4b94cd0ef5e1518fe776a1b3154d" },
        CommitmentOutputTestVector { context: "sender", amount: 16, index: 0, secret: "[\"P2PK\",{\"data\":\"039da1bb99af72c4e3359961d06a27fcba0b09c6e9ced64682c5c58f8166df06b5\",\"nonce\":\"fa5eac4d875dbb343a5840d62a9b6fd0b90d1ee08f1a0b627ba7767c0c622881\",\"tags\":[]}]", p2pk_e: "02f7895660f690f1d498e2f215a7e6de772407b954d09b75e579ed4a284c3a28f7", blinded_pubkey: "039da1bb99af72c4e3359961d06a27fcba0b09c6e9ced64682c5c58f8166df06b5", blinding_factor: "603d1b5b9c66de9a5144c19bbac91e943feccb8d5d408c7a1ce4092bc5bd4b8f", blinded_message: "02a2f5005d6b714b9c35e9806a9c9f45fd6d7055a112e4f22551c555ccb945d550" },
        CommitmentOutputTestVector { context: "sender", amount: 32, index: 0, secret: "[\"P2PK\",{\"data\":\"023725a2912497df0d49de8269b778e664b917e6c919e122fd099e2e99be03f1af\",\"nonce\":\"d19c3e67ae5c9aa3d737ccd349cb83c8f384ec5940d166238da8eef54fcd0cfe\",\"tags\":[]}]", p2pk_e: "02a1be7b930f67d26fd168214a18f5c208cb21cda5f6f08bbf61930cae109d5a39", blinded_pubkey: "023725a2912497df0d49de8269b778e664b917e6c919e122fd099e2e99be03f1af", blinding_factor: "df1c0c9bb910d9dcbace8fa188e38c72ec9e90474b9c574d789aa45b1c31b530", blinded_message: "035ff45bffcec127d65c52aad3fd866591cfd6cdb24cfc95761c1faed0647e1fb5" },
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
