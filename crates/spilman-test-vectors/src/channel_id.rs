//! Test vector for canonical Offline Spilman channel-ID derivation.

use sha2::{Digest, Sha256};

use crate::channel_secret::spilman_test_vector_channel_secret_hkdf;

/// Canonical name of the channel-ID compatibility fixture.
pub const SPILMAN_TEST_VECTOR_CHANNEL_ID_KEYSETV2_NAME: &str =
    "spilman-test-vector-channel-id-keysetv2";
/// Canonical name of the trailing-slash channel-ID compatibility fixture.
pub const SPILMAN_TEST_VECTOR_CHANNEL_ID_KEYSETV2_MINT_TRAILING_SLASH_NAME: &str =
    "spilman-test-vector-channel-id-keysetv2-mint-trailing-slash";

const MINT: &str = "https://vector-mint.example";
const MINT_WITH_TRAILING_SLASH: &str = "https://vector-mint.example/";
const KEYSET_ID: &str = "01fd5a9250eb619ce33b33bf6e752634a5a8ca4bb629c6b48a99db9c94d09d310d";
const CAPACITY: u64 = 100;
const FUNDING_TOKEN_AMOUNT: u64 = 100;
const MAXIMUM_AMOUNT: u64 = 64;
const SETUP_TIMESTAMP: u64 = 1_700_000_000;
const EXPIRY_TIMESTAMP: u64 = 1_800_000_000;
const SENDER_PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const RECEIVER_PUBKEY: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const CHANNEL_ID_HEX: &str = "7af675f4f1b9843200d23060ebeb5bf5abea67fa511af79aefa4ba6a19b88c2e";

const PUBLIC_KEYS: &[(u64, &str)] = &[
    (
        1,
        "025940fded404beb21b53e2bdf8126c988b98389c7356e0b18102231999580a36c",
    ),
    (
        2,
        "02fd58fdb8a8939ab38e9ba3352167cdee914c71a3e20bdaa7df127ded477703ff",
    ),
    (
        4,
        "02a9bb3e42b765ce432a1e02bd3e5189b069416a4dd17b92a60b42335854269f60",
    ),
    (
        8,
        "02c5135a0793aebc1dde718788916fd2f763e8fa95ead4d211eacb965baeca6ae3",
    ),
    (
        16,
        "0356f90096d7bc3b34a002e5b057ddb7a44be6d6a21b1863aeb152ed248b6a03c4",
    ),
    (
        32,
        "02cfd62a904934c12c9418c0a1c729b57552ced0f2d3402064e1b3ecd60f76d912",
    ),
    (
        64,
        "03500bfa755ca5b8e97b88719de7bdd5cea3bb0fd25ce0f50e9dc7b47e19a297c6",
    ),
    (
        128,
        "0324a535f92e82a5a04b014d742e95a16b85fcf4318e5f792a6a01a87d29c7b048",
    ),
    (
        256,
        "02fd6baf9d791d5683c6801d5a9898dbed87c87f13520f5296a2e32a511f905296",
    ),
    (
        512,
        "039a25cccd5849f121ea38abd4252a78175223f91985399c7979a9c1169cf0c403",
    ),
    (
        1024,
        "03a35bd4f4bb07a470230a981960f9fb33acaa5523b6d28217d3d7cf4a14250cc8",
    ),
    (
        2048,
        "03ed874ebb9708b6d35d1f06864f19ce319efaf45543e1e8a7ab1cc27e4abab0c5",
    ),
    (
        4096,
        "032775aa538bb6252ec759b2ca6916ce400bc1f0bc2d24728cdcb7ca90fc08b946",
    ),
    (
        8192,
        "03a493c8d8c653c7bb12e0e7812b463086581537c52901b4eeb4b140470da1b323",
    ),
    (
        16384,
        "02b1aa5a46658beead8c75ffaad088f6f6b4f01525ad08eaa88d64091e3ef3878a",
    ),
    (
        32768,
        "023dc4f1fb0c22e85c10c53dbed19e8487b66b30d1b1abdf055df918f958afb096",
    ),
    (
        65536,
        "032ae7371305dcc9ad5b8749874ab8417d5d1685d91cf2f3dd38fe08f88ee34bd1",
    ),
    (
        131072,
        "030344a937f02e50dbd41a460ed65e44aa3ea94749f82d7217e26c124470749792",
    ),
    (
        262144,
        "02e902875fb29e9cef027c5f27de895b86a967684f5ad84d321fb6ad68df6087ae",
    ),
    (
        524288,
        "02adc12a3ab59b4dd077a1e7c2ddabb2c157315bd992d7bbc8d17eabdf5e351c52",
    ),
    (
        1048576,
        "035305b99c4861dc967f084d728b32c28418a52d2b731a96e958ae6079f09b5083",
    ),
    (
        2097152,
        "029d4ce4c99ca0c40f8e3086343b08df07b58f301b4695b5ab8cea7e16de36be94",
    ),
    (
        4194304,
        "03271e1cf5b9aa0d246ecc402bab0017e8bf55bd6e99045b85c0ed684bec119c3b",
    ),
    (
        8388608,
        "02d1567e5866e88bf846aee7cfb7f0219f201dd30656ed89b484d956eaa280e4e9",
    ),
    (
        16777216,
        "03edbbcea0f37e3c11113fcb1d1da120c1bc771fa1e98b8477639f5d7baad8daee",
    ),
    (
        33554432,
        "031bc3a038bb294887340ba8c7dbf520069ac1a7fc60fd67e32d248634f9b477ed",
    ),
    (
        67108864,
        "0209b736cd34ccb545bc2a9a7cb79e47fe575e2409ee9f8571dc2e776411893c70",
    ),
    (
        134217728,
        "024cd0e494ee09931b6fb860571b8dedf456c2c6928bd91b88fbd0d02105efea32",
    ),
    (
        268435456,
        "03a636f035481eb006825fed06c597d23a63db42e9068ad809d793f7ed2ab3ad8c",
    ),
    (
        536870912,
        "03e69698e1242cb31e26e447a56c19a0abfcaabc96e8e31138099d0e754cb06108",
    ),
    (
        1073741824,
        "021f8dbe172cc14b48654ce9a3b26c8945ce78e3071a3e472111267de7a674cf46",
    ),
    (
        2147483648,
        "022d410dc2dd4a4e14e4deda462afd1dd7a61a0a2a9f2d3b92b8c7b091bfd45598",
    ),
];

/// Fixed inputs and expected output for the channel-ID compatibility vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelIdTestVector {
    /// Canonical mint URL.
    pub mint: &'static str,
    /// Currency unit.
    pub unit: &'static str,
    /// Channel capacity.
    pub capacity: u64,
    /// Value of the funding token.
    pub funding_token_amount: u64,
    /// Mint-assigned keyset ID.
    pub keyset_id: &'static str,
    /// Keyset input fee in parts per thousand.
    pub input_fee_ppk: u64,
    /// Largest allowed deterministic output denomination.
    pub maximum_amount: u64,
    /// Channel setup timestamp.
    pub setup_timestamp: u64,
    /// Alice's compressed SEC1 public key.
    pub sender_pubkey: &'static str,
    /// Charlie's compressed SEC1 public key.
    pub receiver_pubkey: &'static str,
    /// Channel expiry timestamp.
    pub expiry_timestamp: u64,
    /// Channel-secret vector output.
    pub channel_secret: [u8; 32],
    /// Full public keyset from the deterministic real mint.
    pub public_keys: &'static [(u64, &'static str)],
    /// Exact UTF-8 input to SHA-256.
    pub canonical_preimage: &'static str,
    /// SHA-256 channel ID.
    pub channel_id: [u8; 32],
}

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value)
        .expect("test-vector hex must be valid")
        .try_into()
        .expect("test-vector hex must have the expected length")
}

/// Return the fixed values for `spilman-test-vector-channel-id-keysetv2`.
pub fn spilman_test_vector_channel_id_keysetv2() -> ChannelIdTestVector {
    let channel_secret = spilman_test_vector_channel_secret_hkdf().channel_secret;
    let canonical_preimage = concat!(
        "https://vector-mint.example|sat|100|100|",
        "01fd5a9250eb619ce33b33bf6e752634a5a8ca4bb629c6b48a99db9c94d09d310d",
        "|0|64|1700000000|",
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798|",
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        "|1800000000|",
        "acfc96a584e645524b017b75cfe0770c3b8dc2ba4f9cef6d99f2cb7bcee691cf"
    );
    ChannelIdTestVector {
        mint: MINT,
        unit: "sat",
        capacity: CAPACITY,
        funding_token_amount: FUNDING_TOKEN_AMOUNT,
        keyset_id: KEYSET_ID,
        input_fee_ppk: 0,
        maximum_amount: MAXIMUM_AMOUNT,
        setup_timestamp: SETUP_TIMESTAMP,
        sender_pubkey: SENDER_PUBKEY,
        receiver_pubkey: RECEIVER_PUBKEY,
        expiry_timestamp: EXPIRY_TIMESTAMP,
        channel_secret,
        public_keys: PUBLIC_KEYS,
        canonical_preimage,
        channel_id: decode_hex(CHANNEL_ID_HEX),
    }
}

/// Return the fixed values for the trailing-slash channel-ID fixture.
pub fn spilman_test_vector_channel_id_keysetv2_mint_trailing_slash() -> ChannelIdTestVector {
    ChannelIdTestVector {
        mint: MINT_WITH_TRAILING_SLASH,
        ..spilman_test_vector_channel_id_keysetv2()
    }
}

fn canonical_preimage(vector: ChannelIdTestVector) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        vector.mint.trim_end_matches('/'),
        vector.unit,
        vector.capacity,
        vector.funding_token_amount,
        vector.keyset_id,
        vector.input_fee_ppk,
        vector.maximum_amount,
        vector.setup_timestamp,
        vector.sender_pubkey,
        vector.receiver_pubkey,
        vector.expiry_timestamp,
        hex::encode(vector.channel_secret),
    )
}

/// Independently derive a channel-ID vector's normalized SHA-256 output.
///
/// # Panics
///
/// Panics if the derived canonical preimage differs from the fixed fixture.
pub fn derive_channel_id_reference(vector: ChannelIdTestVector) -> [u8; 32] {
    let preimage = canonical_preimage(vector);
    assert_eq!(
        preimage, vector.canonical_preimage,
        "channel-ID reference preimage must match the published fixture"
    );
    Sha256::digest(preimage.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::{
        derive_channel_id_reference,
        spilman_test_vector_channel_id_keysetv2 as get_test_vector_details,
        spilman_test_vector_channel_id_keysetv2_mint_trailing_slash as get_trailing_slash_test_vector_details,
        SPILMAN_TEST_VECTOR_CHANNEL_ID_KEYSETV2_MINT_TRAILING_SLASH_NAME,
        SPILMAN_TEST_VECTOR_CHANNEL_ID_KEYSETV2_NAME,
    };
    use crate::real_mint_keyset_v2::{generate_real_test_mint_keyset_v2, RealMintKeysetV2};

    #[test]
    fn spilman_test_vector_channel_id_keysetv2() {
        let vector = get_test_vector_details();
        assert_eq!(
            derive_channel_id_reference(vector),
            vector.channel_id,
            "{SPILMAN_TEST_VECTOR_CHANNEL_ID_KEYSETV2_NAME}: independent SHA-256 derivation"
        );
    }

    #[test]
    fn spilman_test_vector_channel_id_keysetv2_mint_trailing_slash() {
        let vector = get_trailing_slash_test_vector_details();
        assert_eq!(
            derive_channel_id_reference(vector),
            vector.channel_id,
            "{SPILMAN_TEST_VECTOR_CHANNEL_ID_KEYSETV2_MINT_TRAILING_SLASH_NAME}: independent normalized SHA-256 derivation"
        );
    }

    #[tokio::test]
    async fn channel_id_vector_uses_the_real_deterministic_mint_keyset() {
        let vector = get_test_vector_details();
        let expected = RealMintKeysetV2 {
            keyset_id: vector.keyset_id.to_owned(),
            input_fee_ppk: vector.input_fee_ppk,
            public_keys: vector
                .public_keys
                .iter()
                .map(|(amount, public_key)| (*amount, (*public_key).to_owned()))
                .collect(),
        };
        assert_eq!(
            generate_real_test_mint_keyset_v2()
                .await
                .expect("deterministic real test keyset"),
            expected,
            "{SPILMAN_TEST_VECTOR_CHANNEL_ID_KEYSETV2_NAME}: CDK V2 mint keyset derived from the fixed test mnemonic"
        );
    }
}
