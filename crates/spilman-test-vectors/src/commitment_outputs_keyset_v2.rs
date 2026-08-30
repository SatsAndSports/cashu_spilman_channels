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
        CommitmentOutputTestVector { context: "receiver", amount: 2, index: 0, secret: "[\"P2PK\",{\"data\":\"03976217324d65dd310860c16ed0ab60b9bb2a7e6bf9354d1d204899f17d6b1e12\",\"nonce\":\"008b267f22e9da9672d141c6ca72f069c464e1863909d82e4ccdd0fbca0fe658\",\"tags\":[]}]", p2pk_e: "035ccec34674ef9771472cdb1140a30d288a76040b9a402be53638866d3369ab2b", blinded_pubkey: "03976217324d65dd310860c16ed0ab60b9bb2a7e6bf9354d1d204899f17d6b1e12", blinding_factor: "42a8442f1f234b0fd8727e653fc69ff73e66ea3c84b7689a76339d9ab3ff07bf", blinded_message: "0225d53d34dfeec3151295621c0094165dd3d94bf4d0f7cf9f4bcd946a94eaaab5" },
        CommitmentOutputTestVector { context: "receiver", amount: 16, index: 0, secret: "[\"P2PK\",{\"data\":\"0355c22359dc1ab7f5c2f3bc90149f949aaffea848f38d3bba967a48d3776ad537\",\"nonce\":\"fe4ac5c03c0dca0ef9af528fddb8975558d03ae7a7f73a93e3718d6f52f4c2f0\",\"tags\":[]}]", p2pk_e: "02010f9d212bcdece828a68524d97ebe6c4506df314efb7ce0070d04f5084dc2bf", blinded_pubkey: "0355c22359dc1ab7f5c2f3bc90149f949aaffea848f38d3bba967a48d3776ad537", blinding_factor: "3a793efb2d8332e71a04a4f126ebdf7622546583a25f555dbd028a871858c55e", blinded_message: "02686997630f52fd739d62b94cd14358f1d4ba5daf3a6d6c3b10ee4479938ccdea" },
        CommitmentOutputTestVector { context: "receiver", amount: 32, index: 0, secret: "[\"P2PK\",{\"data\":\"02270ea899810d2f4064d4df8bfc356b5706ba8e236c93c1963f620c14794ad601\",\"nonce\":\"0c640e9c0e7b5c13d519e6a5dbae6d84fc8b71a2da736689fd950606aa3abd07\",\"tags\":[]}]", p2pk_e: "03b95460565471b30d35b7b96cb632391c680806dad65379a3bf93e5a66dcc936f", blinded_pubkey: "02270ea899810d2f4064d4df8bfc356b5706ba8e236c93c1963f620c14794ad601", blinding_factor: "acdd0fcfceef385b839d58b70d27dae12d708729e4efefe31f63420c101fae3f", blinded_message: "02160974d3b2928f741ce5833309d8c572faf4ce64aeb620e7163f34fcd82dff55" },
        CommitmentOutputTestVector { context: "sender", amount: 2, index: 0, secret: "[\"P2PK\",{\"data\":\"02493df89ad25a74a098b302fdd225344189cb2865c6d1edc2fcd730384888d246\",\"nonce\":\"a5a204390c60cca38988fcedc3f77bef1f32272cef922082f3a8cb8de6fbc73d\",\"tags\":[]}]", p2pk_e: "0378728c7baf110d9336a9ed523cf49c94473c30f0909cf5d8edfb5ab42a823add", blinded_pubkey: "02493df89ad25a74a098b302fdd225344189cb2865c6d1edc2fcd730384888d246", blinding_factor: "8c525518a63808137e793b3fdd1491b745e737b0cabb42047337825c717cd40a", blinded_message: "032bf5de6d21526305149bc2e08424ed024f74a644409f637902154b28dd2b7278" },
        CommitmentOutputTestVector { context: "sender", amount: 16, index: 0, secret: "[\"P2PK\",{\"data\":\"02b49021bc36f31cc22f4ee2b70dab41e5900b8d7681e6d415fdf0db2231c55ada\",\"nonce\":\"fa5eac4d875dbb343a5840d62a9b6fd0b90d1ee08f1a0b627ba7767c0c622881\",\"tags\":[]}]", p2pk_e: "030642bc7f978e74851befc286198a5121b909baf11f90c7b2db0b318062b0e5a9", blinded_pubkey: "02b49021bc36f31cc22f4ee2b70dab41e5900b8d7681e6d415fdf0db2231c55ada", blinding_factor: "5c8fbc6e15ed4b6ecf8ba42485db5cf8b4cd44840c60a12c2de289041163536f", blinded_message: "02a30cde253b234c36193de2b5b91254255ef42250b51628ca856bcebba76f4ecb" },
        CommitmentOutputTestVector { context: "sender", amount: 32, index: 0, secret: "[\"P2PK\",{\"data\":\"03b5b9b73e75d63ff6a43093ed2604fb056aa932620a80940e25a1d1de4455264f\",\"nonce\":\"d19c3e67ae5c9aa3d737ccd349cb83c8f384ec5940d166238da8eef54fcd0cfe\",\"tags\":[]}]", p2pk_e: "03600d205df80cea1ea916c7a3ea98009a001483aa4a35cfb96ca20ce707f58a74", blinded_pubkey: "03b5b9b73e75d63ff6a43093ed2604fb056aa932620a80940e25a1d1de4455264f", blinding_factor: "51a394d16ba49c82f05813628ec414ab082198c9c7136b352df13b828244f00c", blinded_message: "03c652d5f40b395d33be28c1547761101cf9f0c65c995b2f701644cb43966d42e0" },
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
