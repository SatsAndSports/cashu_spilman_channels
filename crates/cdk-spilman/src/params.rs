//! Spilman Channel Parameters
//!
//! Contains the protocol parameters for a Spilman payment channel

/// Type alias for channel identifiers (hex-encoded).
pub type ChannelId = String;

use serde::{Deserialize, Serialize};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::{Parity, Scalar};
use cashu::nuts::{CurrencyUnit, SecretKey};
#[cfg(test)]
use cashu::nuts::{Id, Keys, PublicKey};
use cashu::util::hex;
#[cfg(test)]
use cashu::Amount;
use cashu::SECP256K1;
#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
use std::str::FromStr;

use super::deterministic::DeterministicSecretWithBlinding;
use super::keysets_and_amounts::KeysetInfo;

pub(crate) struct Stage2P2bkTweakInfo {
    #[allow(dead_code)]
    pub(crate) ephemeral_secret: SecretKey,
    #[allow(dead_code)]
    pub(crate) ephemeral_pubkey: cashu::nuts::PublicKey,
    #[allow(dead_code)]
    pub(crate) ephemeral_shared_secret_x: [u8; 32],
    #[allow(dead_code)]
    pub(crate) stage2_tweak_scalar: Scalar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage2Role {
    Sender,
    Receiver,
}

impl Stage2Role {
    fn stage2_context(self) -> &'static str {
        match self {
            Self::Sender => "sender_stage2",
            Self::Receiver => "receiver_stage2",
        }
    }

    fn pubkey(self, params: &ChannelParameters) -> &cashu::nuts::PublicKey {
        match self {
            Self::Sender => &params.sender_pubkey,
            Self::Receiver => &params.receiver_pubkey,
        }
    }
}

/// Parameters for a Spilman payment channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelParameters {
    /// Alice's public key (sender)
    pub sender_pubkey: cashu::nuts::PublicKey,
    /// Charlie's public key (receiver)
    pub receiver_pubkey: cashu::nuts::PublicKey,
    /// Mint URL (or "local" for in-process mint)
    pub mint: String,
    /// Currency unit for the channel
    pub unit: CurrencyUnit,
    /// Channel capacity: maximum final value (after both fee stages) that Charlie can receive
    pub capacity: u64,
    /// Total nominal value of the funding token (must satisfy: capacity <= forward(forward(funding_token_amount)))
    pub funding_token_amount: u64,
    /// Expiry timestamp after which Alice can reclaim funds (unix timestamp)
    pub expiry_timestamp: u64,
    /// Setup timestamp (unix timestamp when channel was created)
    pub setup_timestamp: u64,
    /// Keyset information (ID, keys, amounts, fees)
    pub keyset_info: KeysetInfo,
    /// Maximum amount for one output (amounts larger than this are filtered out)
    pub maximum_amount_for_one_output: u64,
    /// Channel secret: a domain-separated hash of the ECDH shared secret between Alice and Charlie
    pub channel_secret: [u8; 32],
}

/// Compute the channel secret from a secret key and counterparty's public key
///
/// Performs ECDH and then hashes the result with a domain separator so that
/// the raw Diffie-Hellman shared secret never leaves this function.
///
/// Returns: SHA256("Cashu_Spilman_channel_secret_v1" || ECDH(my_secret, their_pubkey))
pub fn compute_channel_secret(
    my_secret: &cashu::nuts::SecretKey,
    their_pubkey: &cashu::nuts::PublicKey,
) -> [u8; 32] {
    let raw_ecdh = SharedSecret::new(their_pubkey, my_secret).secret_bytes();
    let mut input = Vec::new();
    input.extend_from_slice(b"Cashu_Spilman_channel_secret_v1");
    input.extend_from_slice(&raw_ecdh);
    sha256::Hash::hash(&input).to_byte_array()
}

/// Helper to create a simple KeysetInfo for testing
#[cfg(test)]
pub(crate) fn mock_keyset_info(amounts: Vec<u64>, input_fee_ppk: u64) -> KeysetInfo {
    let mut keys_map = BTreeMap::new();
    let dummy_pubkey =
        PublicKey::from_str("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2")
            .unwrap();
    for &amt in &amounts {
        keys_map.insert(Amount::from(amt), dummy_pubkey);
    }

    let mut amounts_largest_first = amounts;
    amounts_largest_first.sort_by(|a, b| b.cmp(a));

    let active_keys = Keys::new(keys_map);
    let keyset_id = Id::v1_from_keys(&active_keys);

    KeysetInfo::new(
        keyset_id,
        CurrencyUnit::Sat,
        active_keys,
        input_fee_ppk,
        None,
    )
}

/// Derive a blinded secret key for P2BK signing
///
/// Computes k = p + r (mod n), handling BIP-340 parity.
/// If the pubkey has odd Y, we use k = -p + r instead.
///
/// This ensures that signing with k produces a valid signature for the blinded pubkey P' = P + r*G.
fn derive_blinded_secret_key(secret: &SecretKey, r: &Scalar) -> anyhow::Result<SecretKey> {
    // Get parity of the public key by accessing the underlying secp256k1 pubkey
    // Our wrapper's x_only_public_key() only returns XOnlyPublicKey, but the inner
    // secp256k1::PublicKey::x_only_public_key() returns (XOnlyPublicKey, Parity)
    let pubkey = secret.public_key();
    let inner_pubkey: &bitcoin::secp256k1::PublicKey = &pubkey;
    let (_, parity) = inner_pubkey.x_only_public_key();

    // Get the underlying secp256k1 secret key
    // We need to clone because negate() consumes self
    let inner_secret: bitcoin::secp256k1::SecretKey = **secret;

    // If parity is odd, negate the secret key before adding the tweak
    // This is because BIP-340 signing will use the negated key for odd-Y pubkeys
    let effective_secret = if parity == Parity::Odd {
        inner_secret.negate()
    } else {
        inner_secret
    };

    // Add the blinding scalar: k = p + r (or k = -p + r if odd parity)
    let blinded = effective_secret
        .add_tweak(r)
        .map_err(|e| anyhow::anyhow!("Failed to add blinding tweak: {}", e))?;

    Ok(blinded.into())
}

/// Derive a blinded pubkey for P2BK verification
///
/// This is the pubkey-side counterpart to `derive_blinded_secret_key`.
/// It computes the pubkey that corresponds to the blinded secret key.
///
/// For BIP-340 compatibility:
/// - If pubkey has even Y: P' = P + r*G
/// - If pubkey has odd Y:  P' = -P + r*G
///
/// This ensures that `k*G = P'` where `k` is the blinded secret key.
fn derive_blinded_pubkey(
    pubkey: &cashu::nuts::PublicKey,
    r: &Scalar,
) -> anyhow::Result<cashu::nuts::PublicKey> {
    // Get parity of the public key
    let inner_pubkey: &bitcoin::secp256k1::PublicKey = pubkey;
    let (_, parity) = inner_pubkey.x_only_public_key();

    // If parity is odd, negate the pubkey before adding the tweak
    // This matches what derive_blinded_secret_key does with the secret key
    let effective_pubkey = if parity == Parity::Odd {
        inner_pubkey.negate(&SECP256K1)
    } else {
        *inner_pubkey
    };

    // Add the tweak: P' = P + r*G (or P' = -P + r*G if odd parity)
    let blinded = effective_pubkey
        .add_exp_tweak(&SECP256K1, r)
        .map_err(|e| anyhow::anyhow!("Failed to blind pubkey: {}", e))?;

    Ok(blinded.into())
}

impl ChannelParameters {
    /// Create new channel parameters with a pre-computed channel secret
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sender_pubkey: cashu::nuts::PublicKey,
        receiver_pubkey: cashu::nuts::PublicKey,
        mint: String,
        unit: CurrencyUnit,
        capacity: u64,
        funding_token_amount: u64,
        expiry_timestamp: u64,
        setup_timestamp: u64,
        keyset_info: KeysetInfo,
        maximum_amount_for_one_output: u64,
        channel_secret: [u8; 32],
    ) -> anyhow::Result<Self> {
        // Validate input_fee_ppk is in valid range
        if keyset_info.input_fee_ppk > 999 {
            anyhow::bail!(
                "input_fee_ppk must be between 0 and 999 (inclusive), got {}",
                keyset_info.input_fee_ppk
            );
        }

        // Validate capacity <= forward(forward(funding_token_amount))
        let max_capacity = {
            let after_stage1 = keyset_info.deterministic_value_after_fees(
                funding_token_amount,
                maximum_amount_for_one_output,
            )?;
            keyset_info
                .deterministic_value_after_fees(after_stage1, maximum_amount_for_one_output)?
        };
        if capacity > max_capacity {
            anyhow::bail!(
                "capacity {} exceeds maximum achievable capacity {} for funding_token_amount {} \
                 (capacity must be <= forward(forward(funding_token_amount)))",
                capacity,
                max_capacity,
                funding_token_amount
            );
        }

        Ok(Self {
            sender_pubkey,
            receiver_pubkey,
            mint,
            unit,
            capacity,
            funding_token_amount,
            expiry_timestamp,
            setup_timestamp,
            keyset_info,
            maximum_amount_for_one_output,
            channel_secret,
        })
    }

    /// Create new channel parameters by computing the channel secret from a secret key
    ///
    /// This constructor computes the channel secret (hashed ECDH) automatically.
    /// It auto-detects whether the provided secret key belongs to Alice or Charlie by checking
    /// if its public key matches either party, then uses the counterparty's public key for ECDH.
    ///
    /// # Arguments
    /// * `my_secret` - Either Alice's or Charlie's secret key
    /// * All other arguments are the same as `new`
    ///
    /// # Errors
    /// Returns an error if the secret key's public key doesn't match either sender_pubkey or receiver_pubkey
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_secret_key(
        sender_pubkey: cashu::nuts::PublicKey,
        receiver_pubkey: cashu::nuts::PublicKey,
        mint: String,
        unit: CurrencyUnit,
        capacity: u64,
        funding_token_amount: u64,
        expiry_timestamp: u64,
        setup_timestamp: u64,
        keyset_info: KeysetInfo,
        maximum_amount_for_one_output: u64,
        my_secret: &SecretKey,
    ) -> anyhow::Result<Self> {
        let my_pubkey = my_secret.public_key();

        // Determine which party we are and get the counterparty's pubkey
        let their_pubkey = if my_pubkey == sender_pubkey {
            // We are Alice, use Charlie's pubkey
            &receiver_pubkey
        } else if my_pubkey == receiver_pubkey {
            // We are Charlie, use Alice's pubkey
            &sender_pubkey
        } else {
            anyhow::bail!(
                "Secret key's public key doesn't match either sender_pubkey or receiver_pubkey"
            );
        };

        // Compute channel secret (hashed ECDH)
        let channel_secret = compute_channel_secret(my_secret, their_pubkey);

        Self::new(
            sender_pubkey,
            receiver_pubkey,
            mint,
            unit,
            capacity,
            funding_token_amount,
            expiry_timestamp,
            setup_timestamp,
            keyset_info,
            maximum_amount_for_one_output,
            channel_secret,
        )
    }

    /// Create channel parameters from a JSON string and a secret key
    ///
    /// The JSON should contain: mint, unit, capacity, keyset_id, input_fee_ppk,
    /// maximum_amount, setup_timestamp, sender_pubkey, receiver_pubkey, expiry_timestamp
    /// (as produced by `get_channel_id_params_json`)
    ///
    /// Additional parameters needed:
    /// * `keyset_info` - Keyset information from the mint (keyset_id and input_fee_ppk must match JSON)
    /// * `my_secret` - Either Alice's or Charlie's secret key for ECDH
    pub fn from_json_with_secret_key(
        json_str: &str,
        keyset_info: KeysetInfo,
        my_secret: &SecretKey,
    ) -> anyhow::Result<Self> {
        // Parse JSON to get pubkeys for ECDH
        let json: serde_json::Value =
            serde_json::from_str(json_str).map_err(|e| anyhow::anyhow!("Invalid JSON: {}", e))?;

        let sender_pubkey_hex = json["sender_pubkey"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'sender_pubkey' field"))?;
        let sender_pubkey: cashu::nuts::PublicKey = sender_pubkey_hex
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid sender_pubkey: {}", e))?;

        let receiver_pubkey_hex = json["receiver_pubkey"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'receiver_pubkey' field"))?;
        let receiver_pubkey: cashu::nuts::PublicKey = receiver_pubkey_hex
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid receiver_pubkey: {}", e))?;

        // Determine counterparty and compute channel secret
        let my_pubkey = my_secret.public_key();
        let their_pubkey = if my_pubkey == sender_pubkey {
            &receiver_pubkey
        } else if my_pubkey == receiver_pubkey {
            &sender_pubkey
        } else {
            anyhow::bail!(
                "Secret key's public key doesn't match either sender_pubkey or receiver_pubkey"
            );
        };

        let channel_secret = compute_channel_secret(my_secret, their_pubkey);

        Self::from_json_with_channel_secret(json_str, keyset_info, channel_secret)
    }

    /// Create channel parameters from a JSON string with a pre-computed channel secret
    ///
    /// Same as `from_json` but takes the channel secret directly instead of computing it.
    pub fn from_json_with_channel_secret(
        json_str: &str,
        keyset_info: KeysetInfo,
        channel_secret: [u8; 32],
    ) -> anyhow::Result<Self> {
        let json: serde_json::Value =
            serde_json::from_str(json_str).map_err(|e| anyhow::anyhow!("Invalid JSON: {}", e))?;

        // Parse keyset_id and input_fee_ppk first to validate against keyset_info
        let keyset_id_str = json["keyset_id"]
            .as_str()
            .or_else(|| json["keysetId"].as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'keyset_id' field"))?;
        let json_keyset_id: cashu::nuts::Id = keyset_id_str
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid keyset_id: {}", e))?;

        let json_input_fee_ppk = json["input_fee_ppk"]
            .as_u64()
            .or_else(|| json["inputFeePpk"].as_u64())
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'input_fee_ppk' field"))?;

        // Validate keyset_info matches JSON
        if keyset_info.keyset_id != json_keyset_id {
            anyhow::bail!(
                "keyset_id mismatch: JSON has {}, KeysetInfo has {}",
                json_keyset_id,
                keyset_info.keyset_id
            );
        }
        if keyset_info.input_fee_ppk != json_input_fee_ppk {
            anyhow::bail!(
                "input_fee_ppk mismatch: JSON has {}, KeysetInfo has {}",
                json_input_fee_ppk,
                keyset_info.input_fee_ppk
            );
        }

        // Parse remaining fields
        let mint = json["mint"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'mint' field"))?
            .to_string();

        let unit_str = json["unit"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'unit' field"))?;
        let unit = match unit_str {
            "sat" => CurrencyUnit::Sat,
            "msat" => CurrencyUnit::Msat,
            "usd" => CurrencyUnit::Usd,
            "eur" => CurrencyUnit::Eur,
            _ => anyhow::bail!("Unknown unit: {}", unit_str),
        };

        let capacity = json["capacity"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'capacity' field"))?;

        let funding_token_amount = json["funding_token_amount"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'funding_token_amount' field"))?;

        let maximum_amount_for_one_output = json["maximum_amount"]
            .as_u64()
            .or_else(|| json["maximum_amount_for_one_output"].as_u64())
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'maximum_amount' field"))?;

        let setup_timestamp = json["setup_timestamp"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'setup_timestamp' field"))?;

        let sender_pubkey_hex = json["sender_pubkey"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'sender_pubkey' field"))?;
        let sender_pubkey: cashu::nuts::PublicKey = sender_pubkey_hex
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid sender_pubkey: {}", e))?;

        let receiver_pubkey_hex = json["receiver_pubkey"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'receiver_pubkey' field"))?;
        let receiver_pubkey: cashu::nuts::PublicKey = receiver_pubkey_hex
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid receiver_pubkey: {}", e))?;

        let expiry_timestamp = json["expiry_timestamp"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'expiry_timestamp' field"))?;

        Self::new(
            sender_pubkey,
            receiver_pubkey,
            mint,
            unit,
            capacity,
            funding_token_amount,
            expiry_timestamp,
            setup_timestamp,
            keyset_info,
            maximum_amount_for_one_output,
            channel_secret,
        )
    }

    /// Get channel capacity
    /// Returns the maximum final value (after both fee stages) that Charlie can receive
    pub fn get_capacity(&self) -> u64 {
        self.capacity
    }

    /// Get channel ID as raw bytes (32-byte SHA256 hash)
    /// The hash is computed over: mint|unit|capacity|funding_token_amount|keyset_id|input_fee_ppk|maximum_amount|setup_timestamp|sender_pubkey|receiver_pubkey|expiry_timestamp|channel_secret
    ///
    /// The channel_secret (channel_secret) is included implicitly — it does not
    /// appear in `get_channel_id_params_json()`. This means the channel ID can
    /// only be computed by the two parties who know the channel secret.
    pub fn get_channel_id_bytes(&self) -> [u8; 32] {
        let params_string = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.mint,
            self.unit_name(),
            self.capacity,
            self.funding_token_amount,
            self.keyset_info.keyset_id,
            self.keyset_info.input_fee_ppk,
            self.maximum_amount_for_one_output,
            self.setup_timestamp,
            self.sender_pubkey.to_hex(),
            self.receiver_pubkey.to_hex(),
            self.expiry_timestamp,
            hex::encode(self.channel_secret)
        );
        sha256::Hash::hash(params_string.as_bytes()).to_byte_array()
    }

    /// Get channel ID as a hex string
    pub fn get_channel_id(&self) -> String {
        hex::encode(self.get_channel_id_bytes())
    }

    /// Get a JSON string representation of the data that contributes to the channel ID
    /// This includes all parameters that define the channel unique identity.
    pub fn get_channel_id_params_json(&self) -> String {
        serde_json::json!({
            "mint": self.mint,
            "unit": self.unit_name(),
            "capacity": self.capacity,
            "funding_token_amount": self.funding_token_amount,
            "keyset_id": self.keyset_info.keyset_id.to_string(),
            "input_fee_ppk": self.keyset_info.input_fee_ppk,
            "maximum_amount": self.maximum_amount_for_one_output,
            "setup_timestamp": self.setup_timestamp,
            "sender_pubkey": self.sender_pubkey.to_hex(),
            "receiver_pubkey": self.receiver_pubkey.to_hex(),
            "expiry_timestamp": self.expiry_timestamp
        })
        .to_string()
    }

    /// Derive a blinding scalar for P2BK
    ///
    /// The `context` parameter specifies which blinded key to derive:
    /// - "sender_stage1" / "receiver_stage1" - for funding token 2-of-2
    /// - "sender_stage1_refund" - for funding token expiry refund
    ///
    /// Computes: SHA256("Cashu_Spilman_P2BK_v1" || channel_secret || "{channel_id}|{context}|{retry_counter}")
    /// Retries with incrementing retry_counter until a valid scalar in [1, n-1] is found.
    ///
    /// Note: This produces a SHARED blinding scalar for all proofs with the same context.
    /// For per-proof blinding (stage2), use `stage2_tweak_info_for_role()` instead.
    fn derive_blinding_scalar(&self, context: &str) -> anyhow::Result<Scalar> {
        let channel_id = self.get_channel_id();

        for retry_counter in 0u8..=255 {
            let text = format!("{}|{}|{}", channel_id, context, retry_counter);
            let mut input = Vec::new();
            input.extend_from_slice(b"Cashu_Spilman_P2BK_v1");
            input.extend_from_slice(&self.channel_secret);
            input.extend_from_slice(text.as_bytes());

            let hash = sha256::Hash::hash(&input);
            let bytes: [u8; 32] = hash.to_byte_array();

            // Try to create a valid scalar (must be in range [1, n-1])
            if let Ok(scalar) = Scalar::from_be_bytes(bytes) {
                // Scalar::from_be_bytes rejects values >= n, and we also reject zero
                if scalar != Scalar::ZERO {
                    return Ok(scalar);
                }
            }
        }

        anyhow::bail!("Failed to derive valid blinding scalar after 256 attempts")
    }

    /// Derive stage 2 P2BK tweak info for a specific output
    ///
    /// Uses the per-output ephemeral secret to compute a NUT-28 shared-secret tweak
    /// alongside the deterministic ephemeral key material for later metadata use.
    pub(crate) fn stage2_tweak_info_for_role(
        &self,
        role: Stage2Role,
        amount: u64,
        index: usize,
    ) -> anyhow::Result<Stage2P2bkTweakInfo> {
        let role_pubkey = role.pubkey(self);
        let ephemeral_secret = self.derive_stage2_p2bk_ephemeral_secret_for_output(
            role.stage2_context(),
            amount,
            index,
        )?;
        let ephemeral_pubkey = ephemeral_secret.public_key();
        let ephemeral_shared_secret_x =
            Self::derive_nut28_shared_secret_x(role_pubkey, &ephemeral_secret)?;
        let stage2_tweak_scalar =
            Self::derive__nut28_P2KB_shared_secret_scalar(&ephemeral_shared_secret_x, 0x00)?;

        Ok(Stage2P2bkTweakInfo {
            ephemeral_secret,
            ephemeral_pubkey,
            ephemeral_shared_secret_x,
            stage2_tweak_scalar,
        })
    }

    /// Derive a per-output ephemeral secret for stage 2 contexts
    ///
    /// Computes: SHA256("Cashu_Spilman_P2BK_ephemeral_v1" || channel_secret || "{channel_id}|{context}|{amount}|{index}|{retry_counter}")
    /// Retries with incrementing retry_counter until a valid secret key is found.
    fn derive_stage2_p2bk_ephemeral_secret_for_output(
        &self,
        context: &str,
        amount: u64,
        index: usize,
    ) -> anyhow::Result<SecretKey> {
        let channel_id = self.get_channel_id();

        for retry_counter in 0u8..=255 {
            let text = format!(
                "{}|{}|{}|{}|{}",
                channel_id, context, amount, index, retry_counter
            );
            let mut input = Vec::new();
            input.extend_from_slice(b"Cashu_Spilman_P2BK_ephemeral_v1");
            input.extend_from_slice(&self.channel_secret);
            input.extend_from_slice(text.as_bytes());

            let hash = sha256::Hash::hash(&input);
            let bytes: [u8; 32] = hash.to_byte_array();

            if let Ok(secret) = SecretKey::from_slice(&bytes) {
                return Ok(secret);
            }
        }

        anyhow::bail!("Failed to derive valid ephemeral secret for output after 256 attempts")
    }

    /// Derive the raw x-coordinate used by NUT-28 before the KDF step.
    fn derive_nut28_shared_secret_x(
        pubkey: &cashu::nuts::PublicKey,
        secret: &SecretKey,
    ) -> anyhow::Result<[u8; 32]> {
        let shared_point = pubkey.mul_tweak(&SECP256K1, &secret.as_scalar())?;
        Ok(shared_point.x_only_public_key().0.serialize())
    }

    /// Derive NUT-28 P2BK scalar from ephemeral shared secret x-coordinate.
    ///
    /// Spec: https://raw.githubusercontent.com/cashubtc/nuts/refs/heads/main/28.md
    #[allow(non_snake_case)]
    fn derive__nut28_P2KB_shared_secret_scalar(
        zx: &[u8; 32],
        i_byte: u8,
    ) -> anyhow::Result<Scalar> {
        let mut input = Vec::new();
        input.extend_from_slice(b"Cashu_P2BK_v1");
        input.extend_from_slice(zx);
        input.push(i_byte);

        let hash = sha256::Hash::hash(&input);
        let bytes: [u8; 32] = hash.to_byte_array();
        if let Ok(scalar) = Scalar::from_be_bytes(bytes) {
            if scalar != Scalar::ZERO {
                return Ok(scalar);
            }
        }

        input.push(0xff);
        let hash = sha256::Hash::hash(&input);
        let bytes: [u8; 32] = hash.to_byte_array();
        if let Ok(scalar) = Scalar::from_be_bytes(bytes) {
            if scalar != Scalar::ZERO {
                return Ok(scalar);
            }
        }

        anyhow::bail!("Failed to derive valid P2BK scalar")
    }

    /// Get the blinded sender (Alice) pubkey for stage 1 P2BK
    ///
    /// Computes the blinded pubkey that corresponds to Alice's blinded secret key.
    /// This handles BIP-340 parity: if Alice's pubkey has odd Y, we negate it first.
    ///
    /// The formula matches `derive_blinded_secret_key`:
    /// - If even Y: P' = P + r*G (matches k = p + r)
    /// - If odd Y:  P' = -P + r*G (matches k = -p + r)
    pub fn get_sender_blinded_pubkey_for_stage1(&self) -> anyhow::Result<cashu::nuts::PublicKey> {
        let r = self.derive_blinding_scalar("sender_stage1")?;
        derive_blinded_pubkey(&self.sender_pubkey, &r)
    }

    /// Get the blinded receiver (Charlie) pubkey for stage 1 P2BK
    ///
    /// Computes the blinded pubkey that corresponds to Charlie's blinded secret key.
    /// This handles BIP-340 parity: if Charlie's pubkey has odd Y, we negate it first.
    ///
    /// The formula matches `derive_blinded_secret_key`:
    /// - If even Y: P' = P + r*G (matches k = p + r)
    /// - If odd Y:  P' = -P + r*G (matches k = -p + r)
    pub fn get_receiver_blinded_pubkey_for_stage1(&self) -> anyhow::Result<cashu::nuts::PublicKey> {
        let r = self.derive_blinding_scalar("receiver_stage1")?;
        derive_blinded_pubkey(&self.receiver_pubkey, &r)
    }

    /// Derive the blinded sender secret key for stage 1 signing
    ///
    /// For P2BK, Alice must sign with a blinded private key k such that k*G = P'.
    /// This handles BIP-340 parity: if Alice's pubkey has odd Y, we negate her
    /// private key before adding the blinding scalar.
    pub fn get_sender_blinded_secret_key_for_stage1(
        &self,
        alice_secret: &SecretKey,
    ) -> anyhow::Result<SecretKey> {
        let r = self.derive_blinding_scalar("sender_stage1")?;
        derive_blinded_secret_key(alice_secret, &r)
    }

    /// Get the sender's P2BK blinding scalar for stage 1 signing.
    ///
    /// This is the tweak scalar that must be added to Alice's secret key
    /// (with BIP-340 parity handling) to produce the blinded signing key.
    /// Used by the external signer flow in SpilmanClientBridge.
    pub fn derive_sender_blinding_scalar_for_stage1(&self) -> anyhow::Result<Scalar> {
        self.derive_blinding_scalar("sender_stage1")
    }

    /// Get the receiver's P2BK blinding scalar for stage 1 signing.
    ///
    /// This is the tweak scalar that must be added to Charlie's secret key
    /// (with BIP-340 parity handling) to produce the blinded signing key.
    /// Used by the external signer flow in SpilmanBridge.
    pub fn derive_receiver_blinding_scalar_for_stage1(&self) -> anyhow::Result<Scalar> {
        self.derive_blinding_scalar("receiver_stage1")
    }

    /// Get the blinded sender (Alice) pubkey for stage 1 expiry refund
    ///
    /// Uses a DIFFERENT blinding tweak than the 2-of-2 spending path, so the mint
    /// cannot correlate Alice's refund to the normal channel close.
    pub fn get_sender_blinded_pubkey_for_stage1_refund(
        &self,
    ) -> anyhow::Result<cashu::nuts::PublicKey> {
        let r = self.derive_blinding_scalar("sender_stage1_refund")?;
        derive_blinded_pubkey(&self.sender_pubkey, &r)
    }

    /// Derive the blinded sender secret key for stage 1 expiry refund
    ///
    /// Uses a DIFFERENT blinding tweak than the 2-of-2 spending path.
    /// Alice uses this to sign when reclaiming funds after expiry.
    pub fn get_sender_blinded_secret_key_for_stage1_refund(
        &self,
        alice_secret: &SecretKey,
    ) -> anyhow::Result<SecretKey> {
        let r = self.derive_blinding_scalar("sender_stage1_refund")?;
        derive_blinded_secret_key(alice_secret, &r)
    }

    /// Derive the blinded receiver secret key for stage 1 signing
    ///
    /// For P2BK, Charlie must sign with a blinded private key k such that k*G = P'.
    /// This handles BIP-340 parity: if Charlie's pubkey has odd Y, we negate his
    /// private key before adding the blinding scalar.
    pub fn get_receiver_blinded_secret_key_for_stage1(
        &self,
        charlie_secret: &SecretKey,
    ) -> anyhow::Result<SecretKey> {
        let r = self.derive_blinding_scalar("receiver_stage1")?;
        derive_blinded_secret_key(charlie_secret, &r)
    }

    /// Get the blinded sender (Alice) pubkey for a specific stage 2 output
    ///
    /// Used for stage 1 outputs - each of Alice's proofs is locked to a UNIQUE
    /// blinded pubkey derived from (amount, index). She'll need to sign with
    /// the corresponding secret key in stage 2.
    ///
    /// This provides better privacy than a shared pubkey - the mint cannot
    /// trivially link proofs from the same channel closure.
    pub fn get_sender_blinded_pubkey_for_stage2_output(
        &self,
        amount: u64,
        index: usize,
    ) -> anyhow::Result<cashu::nuts::PublicKey> {
        let tweak_info = self.stage2_tweak_info_for_role(Stage2Role::Sender, amount, index)?;
        derive_blinded_pubkey(&self.sender_pubkey, &tweak_info.stage2_tweak_scalar)
    }

    /// Get the blinded receiver (Charlie) pubkey for a specific stage 2 output
    ///
    /// Used for stage 1 outputs - each of Charlie's proofs is locked to a UNIQUE
    /// blinded pubkey derived from (amount, index). He'll need to sign with
    /// the corresponding secret key in stage 2.
    ///
    /// This provides better privacy than a shared pubkey - the mint cannot
    /// trivially link proofs from the same channel closure.
    pub fn get_receiver_blinded_pubkey_for_stage2_output(
        &self,
        amount: u64,
        index: usize,
    ) -> anyhow::Result<cashu::nuts::PublicKey> {
        let tweak_info = self.stage2_tweak_info_for_role(Stage2Role::Receiver, amount, index)?;
        derive_blinded_pubkey(&self.receiver_pubkey, &tweak_info.stage2_tweak_scalar)
    }

    /// Derive the blinded sender secret key for a specific stage 2 output
    ///
    /// Alice uses this to sign when spending a specific stage 1 proof in stage 2.
    /// Each proof has a unique blinded secret key derived from (amount, index).
    pub fn get_sender_blinded_secret_key_for_stage2_output(
        &self,
        alice_secret: &SecretKey,
        amount: u64,
        index: usize,
    ) -> anyhow::Result<SecretKey> {
        let tweak_info = self.stage2_tweak_info_for_role(Stage2Role::Sender, amount, index)?;
        derive_blinded_secret_key(alice_secret, &tweak_info.stage2_tweak_scalar)
    }

    /// Derive the blinded receiver secret key for a specific stage 2 output
    ///
    /// Charlie uses this to sign when spending a specific stage 1 proof in stage 2.
    /// Each proof has a unique blinded secret key derived from (amount, index).
    pub fn get_receiver_blinded_secret_key_for_stage2_output(
        &self,
        charlie_secret: &SecretKey,
        amount: u64,
        index: usize,
    ) -> anyhow::Result<SecretKey> {
        let tweak_info = self.stage2_tweak_info_for_role(Stage2Role::Receiver, amount, index)?;
        derive_blinded_secret_key(charlie_secret, &tweak_info.stage2_tweak_scalar)
    }

    /// Get a string representation of the unit
    pub fn unit_name(&self) -> &str {
        match self.unit {
            CurrencyUnit::Sat => "sat",
            CurrencyUnit::Msat => "msat",
            CurrencyUnit::Usd => "usd",
            CurrencyUnit::Eur => "eur",
            _ => "units",
        }
    }

    /// Get the STAGE2 blinded pubkey for a stage 1 output context ("sender" or "receiver")
    ///
    /// Returns the stage2 blinded pubkey for use in stage 1 commitment outputs:
    /// - "receiver" → Charlie's per-proof blinded pubkey (stage2 context)
    /// - "sender" → Alice's per-proof blinded pubkey (stage2 context)
    /// - "funding" → error (funding uses 2-of-2 with stage1 blinded pubkeys)
    ///
    /// Uses "stage2" blinding context because these are the keys needed to sign in stage 2.
    /// Each proof gets a UNIQUE blinded pubkey derived from (amount, index) for better privacy.
    pub fn get_stage2_blinded_pubkey_for_stage1_output(
        &self,
        context: &str,
        amount: u64,
        index: usize,
    ) -> Result<cashu::nuts::PublicKey, anyhow::Error> {
        match context {
            "receiver" => self.get_receiver_blinded_pubkey_for_stage2_output(amount, index),
            "sender" => self.get_sender_blinded_pubkey_for_stage2_output(amount, index),
            "funding" => anyhow::bail!(
                "Funding context requires 2-of-2 blinded pubkeys, use new_funding() instead"
            ),
            _ => anyhow::bail!("Unknown context: {}", context),
        }
    }

    pub(crate) fn stage2_p2pk_e_for_role(
        &self,
        role: Stage2Role,
        amount: u64,
        index: usize,
    ) -> Result<cashu::nuts::PublicKey, anyhow::Error> {
        let tweak_info = self.stage2_tweak_info_for_role(role, amount, index)?;

        Ok(tweak_info.ephemeral_pubkey)
    }

    pub(crate) fn attach_stage2_p2pk_e(
        &self,
        proof: &mut cashu::nuts::Proof,
        role: Stage2Role,
        amount: u64,
        index: usize,
    ) -> Result<(), anyhow::Error> {
        proof.p2pk_e = Some(self.stage2_p2pk_e_for_role(role, amount, index)?);
        Ok(())
    }

    /// Create a deterministic output with blinding using the channel ID and channel secret
    /// Uses channel_secret, channel_id, context, amount, and index in the derivation per NUT-XX spec
    ///
    /// The context parameter specifies the role: "sender", "receiver", or "funding"
    /// - "sender"/"receiver" create simple P2PK outputs for commitments using stage2 blinded pubkeys
    /// - "funding" creates P2PK outputs with 2-of-2 multisig + expiry conditions
    pub fn create_deterministic_output_with_blinding(
        &self,
        context: &str,
        amount: u64,
        index: usize,
    ) -> Result<DeterministicSecretWithBlinding, anyhow::Error> {
        let channel_id = self.get_channel_id();

        // Derive deterministic nonce: SHA256(channel_secret || "{channel_id}|{context}|{amount}|nonce|{index}")
        let nonce_text = format!("{}|{}|{}|nonce|{}", channel_id, context, amount, index);
        let mut nonce_input = Vec::new();
        nonce_input.extend_from_slice(&self.channel_secret);
        nonce_input.extend_from_slice(nonce_text.as_bytes());

        let hash = sha256::Hash::hash(&nonce_input);
        let nonce = hex::encode(hash.to_byte_array());

        // Derive deterministic blinding factor: SHA256(channel_secret || "{channel_id}|{context}|{amount}|blinding|{index}")
        let blinding_text = format!("{}|{}|{}|blinding|{}", channel_id, context, amount, index);
        let mut blinding_input = Vec::new();
        blinding_input.extend_from_slice(&self.channel_secret);
        blinding_input.extend_from_slice(blinding_text.as_bytes());

        let hash = sha256::Hash::hash(&blinding_input);
        let blinding_factor = SecretKey::from_slice(hash.as_byte_array())?;

        // Handle funding context separately (requires 2-of-2 blinded pubkeys + expiry)
        if context == "funding" {
            DeterministicSecretWithBlinding::new_funding(
                self,
                nonce,
                blinding_factor,
                amount,
                index,
            )
        } else {
            // For sender/receiver contexts, create simple P2PK outputs with BLINDED pubkeys
            // Each proof gets a UNIQUE blinded pubkey derived from (amount, index)
            let pubkey =
                self.get_stage2_blinded_pubkey_for_stage1_output(context, amount, index)?;
            DeterministicSecretWithBlinding::new_p2pk(
                &pubkey,
                nonce,
                blinding_factor,
                amount,
                index,
            )
        }
    }

    /// Get the minimum funding token amount for a given capacity using double inverse
    ///
    /// This computes the minimum funding_token_amount needed to achieve at least
    /// the specified capacity after both fee stages, using the given keyset.
    ///
    /// Applies the inverse fee calculation twice to the capacity:
    /// 1. capacity → post-stage-1 nominal (accounting for stage 2 fees)
    /// 2. post-stage-1 nominal → funding token nominal (accounting for stage 1 fees)
    pub fn get_minimum_funding_token_amount(
        capacity: u64,
        keyset_info: &KeysetInfo,
        maximum_amount_for_one_output: u64,
    ) -> anyhow::Result<u64> {
        let max_amt = maximum_amount_for_one_output;

        // First inverse: capacity → post-stage-1 nominal (accounting for stage 2 fees)
        let first_inverse =
            keyset_info.inverse_deterministic_value_after_fees(capacity, max_amt)?;
        let post_stage1_nominal = first_inverse.nominal_value;

        // Second inverse: post-stage-1 nominal → funding token nominal (accounting for stage 1 fees)
        let second_inverse =
            keyset_info.inverse_deterministic_value_after_fees(post_stage1_nominal, max_amt)?;
        let funding_token_nominal = second_inverse.nominal_value;

        Ok(funding_token_nominal)
    }

    /// Get the total funding token amount
    ///
    /// Returns the explicit funding_token_amount field.
    pub fn get_total_funding_token_amount(&self) -> anyhow::Result<u64> {
        Ok(self.funding_token_amount)
    }

    /// Get the value available after stage 1 fees with a specific keyset
    pub fn get_value_after_stage1_with_keyset(
        &self,
        keyset_info: &KeysetInfo,
    ) -> anyhow::Result<u64> {
        // Apply forward to get actual value after stage 1 fees (spending the funding token)
        // using the provided keyset for the outputs
        let value_after_stage1 = keyset_info.deterministic_value_after_fees(
            self.funding_token_amount,
            self.maximum_amount_for_one_output,
        )?;

        Ok(value_after_stage1)
    }

    /// Get the value available after stage 1 fees
    ///
    /// Takes the funding token amount and applies the forward fee calculation
    /// to determine the actual amount available after the swap transaction (stage 1).
    ///
    /// This represents the total amount that will be distributed between Alice and Charlie
    /// in the commitment transaction outputs.
    ///
    /// Returns the actual value after stage 1 fees
    pub fn get_value_after_stage1(&self) -> anyhow::Result<u64> {
        self.get_value_after_stage1_with_keyset(&self.keyset_info)
    }

    /// Compute the actual de facto balance from an intended balance
    ///
    /// Due to output denomination constraints and fee rounding, the actual balance
    /// that can be created may differ slightly from the intended balance.
    ///
    /// This method:
    /// 1. Applies inverse to find the nominal value needed for the intended balance
    /// 2. Applies deterministic_value to that nominal to get the actual de facto balance
    ///
    /// Returns the actual balance that will be created
    pub fn get_de_facto_balance(&self, intended_balance: u64) -> anyhow::Result<u64> {
        let max_amt = self.maximum_amount_for_one_output;

        // Apply inverse to get nominal value needed
        let inverse_result = self
            .keyset_info
            .inverse_deterministic_value_after_fees(intended_balance, max_amt)?;
        let nominal_value = inverse_result.nominal_value;

        // Apply deterministic_value to get actual balance
        let actual_balance = self
            .keyset_info
            .deterministic_value_after_fees(nominal_value, max_amt)?;

        Ok(actual_balance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_roundtrip_preserves_channel_id() {
        // Create keypairs for Alice and Charlie
        let alice_secret = SecretKey::generate();
        let sender_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let receiver_pubkey = charlie_secret.public_key();

        // Create a keyset_info for testing (powers of 2 up to 64, with 100 ppk fee)
        let keyset_info = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 100);

        // Compute the minimum funding_token_amount for the desired capacity
        let funding_token_amount =
            ChannelParameters::get_minimum_funding_token_amount(1000, &keyset_info, 64)
                .expect("Failed to compute funding token amount");

        // Create channel parameters (as Alice)
        let original_params = ChannelParameters::new_with_secret_key(
            sender_pubkey,
            receiver_pubkey,
            "https://testmint.cash".to_string(),
            CurrencyUnit::Sat,
            1000, // capacity
            funding_token_amount,
            1700000000, // expiry_timestamp
            1699999000, // setup_timestamp
            keyset_info.clone(),
            64, // maximum_amount_for_one_output
            &alice_secret,
        )
        .expect("Failed to create original params");

        // Get the channel ID and JSON
        let original_channel_id = original_params.get_channel_id();
        let json = original_params.get_channel_id_params_json();

        println!("Channel ID: {}", original_channel_id);
        println!("JSON: {}", json);

        // Recreate from JSON (as Charlie this time, to also test ECDH works both ways)
        let reconstructed_params =
            ChannelParameters::from_json_with_secret_key(&json, keyset_info, &charlie_secret)
                .expect("Failed to reconstruct params from JSON");

        let reconstructed_channel_id = reconstructed_params.get_channel_id();

        println!("Reconstructed Channel ID: {}", reconstructed_channel_id);

        // Verify channel secrets match (ECDH is symmetric, so both sides derive the same result)
        assert_eq!(
            original_params.channel_secret, reconstructed_params.channel_secret,
            "Channel secrets should match (ECDH is symmetric)"
        );

        // Assert channel IDs match
        assert_eq!(
            original_channel_id, reconstructed_channel_id,
            "Channel IDs should match after JSON roundtrip"
        );
    }

    #[test]
    fn test_p2bk_blinded_pubkey_consistency() {
        // Test that blinded pubkeys are computed consistently regardless of which
        // party creates the ChannelParameters (Alice or Charlie)

        // Create keypairs for Alice and Charlie
        let alice_secret = SecretKey::generate();
        let sender_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let receiver_pubkey = charlie_secret.public_key();

        // Create keyset_info
        let keyset_info = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 100);

        let funding_token_amount =
            ChannelParameters::get_minimum_funding_token_amount(1000, &keyset_info, 64)
                .expect("Failed to compute funding token amount");

        // Alice creates params using her secret key
        let alice_params = ChannelParameters::new_with_secret_key(
            sender_pubkey,
            receiver_pubkey,
            "https://testmint.cash".to_string(),
            CurrencyUnit::Sat,
            1000, // capacity
            funding_token_amount,
            1700000000,
            1699999000,
            keyset_info.clone(),
            64,
            &alice_secret,
        )
        .expect("Failed to create Alice's params");

        // Charlie recreates params from JSON using his secret key
        let json = alice_params.get_channel_id_params_json();
        let charlie_params =
            ChannelParameters::from_json_with_secret_key(&json, keyset_info, &charlie_secret)
                .expect("Failed to create Charlie's params");

        // Verify channel secrets match (ECDH symmetry)
        assert_eq!(
            alice_params.channel_secret, charlie_params.channel_secret,
            "Channel secrets should match"
        );

        // Verify blinded sender pubkey is the same
        let alice_blinded_sender = alice_params
            .get_sender_blinded_pubkey_for_stage1()
            .expect("Alice failed to get blinded sender pubkey");
        let charlie_blinded_sender = charlie_params
            .get_sender_blinded_pubkey_for_stage1()
            .expect("Charlie failed to get blinded sender pubkey");
        assert_eq!(
            alice_blinded_sender.to_hex(),
            charlie_blinded_sender.to_hex(),
            "Blinded sender pubkeys should match"
        );

        // Verify blinded receiver pubkey is the same
        let alice_blinded_receiver = alice_params
            .get_receiver_blinded_pubkey_for_stage1()
            .expect("Alice failed to get blinded receiver pubkey");
        let charlie_blinded_receiver = charlie_params
            .get_receiver_blinded_pubkey_for_stage1()
            .expect("Charlie failed to get blinded receiver pubkey");
        assert_eq!(
            alice_blinded_receiver.to_hex(),
            charlie_blinded_receiver.to_hex(),
            "Blinded receiver pubkeys should match"
        );

        println!(
            "Alice's blinded sender pubkey: {}",
            alice_blinded_sender.to_hex()
        );
        println!(
            "Charlie's blinded sender pubkey: {}",
            charlie_blinded_sender.to_hex()
        );
        println!(
            "Alice's blinded receiver pubkey: {}",
            alice_blinded_receiver.to_hex()
        );
        println!(
            "Charlie's blinded receiver pubkey: {}",
            charlie_blinded_receiver.to_hex()
        );
    }

    #[test]
    fn test_p2bk_signature_roundtrip() {
        use bitcoin::secp256k1::Message;
        use cashu::SECP256K1;

        // Create keypairs for Alice and Charlie
        let alice_secret = SecretKey::generate();
        let sender_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let receiver_pubkey = charlie_secret.public_key();

        // Create keyset_info
        let keyset_info = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 100);

        let funding_token_amount =
            ChannelParameters::get_minimum_funding_token_amount(1000, &keyset_info, 64)
                .expect("Failed to compute funding token amount");

        // Alice creates params
        let alice_params = ChannelParameters::new_with_secret_key(
            sender_pubkey,
            receiver_pubkey,
            "https://testmint.cash".to_string(),
            CurrencyUnit::Sat,
            1000, // capacity
            funding_token_amount,
            1700000000,
            1699999000,
            keyset_info.clone(),
            64,
            &alice_secret,
        )
        .expect("Failed to create Alice's params");

        // Alice gets her blinded secret key and signs a message
        let blinded_secret = alice_params
            .get_sender_blinded_secret_key_for_stage1(&alice_secret)
            .expect("Failed to get blinded secret");

        let test_msg = b"test message to sign";
        let msg_hash = bitcoin::hashes::sha256::Hash::hash(test_msg);
        let msg = Message::from_digest_slice(msg_hash.as_ref()).unwrap();

        // Get the secp256k1 keypair for signing
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&SECP256K1, &*blinded_secret);
        let signature = SECP256K1.sign_schnorr(&msg, &keypair);

        println!("Message: {}", hex::encode(msg_hash.to_byte_array()));
        println!("Signature: {}", hex::encode(signature.serialize()));

        // Charlie recreates params and verifies
        let json = alice_params.get_channel_id_params_json();
        let charlie_params =
            ChannelParameters::from_json_with_secret_key(&json, keyset_info, &charlie_secret)
                .expect("Failed to create Charlie's params");

        // Charlie gets Alice's blinded pubkey
        let blinded_pubkey = charlie_params
            .get_sender_blinded_pubkey_for_stage1()
            .expect("Failed to get blinded sender pubkey");

        println!("Blinded pubkey: {}", blinded_pubkey.to_hex());

        // Charlie verifies the signature
        let verify_result = blinded_pubkey.verify(test_msg, &signature);
        assert!(
            verify_result.is_ok(),
            "Signature verification failed: {:?}",
            verify_result
        );
        println!("Signature verified successfully!");
    }

    #[test]
    fn test_stage2_ephemeral_shared_secret_matches_role_secret() {
        // Create keypairs for Alice and Charlie
        let alice_secret = SecretKey::generate();
        let sender_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let receiver_pubkey = charlie_secret.public_key();

        // Create keyset_info
        let keyset_info = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 100);

        let funding_token_amount =
            ChannelParameters::get_minimum_funding_token_amount(1000, &keyset_info, 64)
                .expect("Failed to compute funding token amount");

        let params = ChannelParameters::new_with_secret_key(
            sender_pubkey,
            receiver_pubkey,
            "https://testmint.cash".to_string(),
            CurrencyUnit::Sat,
            1000, // capacity
            funding_token_amount,
            1700000000,
            1699999000,
            keyset_info,
            64,
            &alice_secret,
        )
        .expect("Failed to create channel params");

        let sender_info = params
            .stage2_tweak_info_for_role(Stage2Role::Sender, 64, 0)
            .expect("Failed to derive sender stage2 tweak info");
        let sender_shared_from_alice = ChannelParameters::derive_nut28_shared_secret_x(
            &sender_info.ephemeral_pubkey,
            &alice_secret,
        )
        .expect("Failed to derive sender raw NUT-28 shared secret");
        assert_eq!(
            sender_shared_from_alice, sender_info.ephemeral_shared_secret_x,
            "Alice should derive the same shared secret x for sender_stage2"
        );
        #[cfg(feature = "wallet")]
        {
            let sender_kdf =
                cashu::nuts::nut28::ecdh_kdf(&alice_secret, &sender_info.ephemeral_pubkey, 0)
                    .expect("Failed to derive sender NUT-28 scalar");
            assert_eq!(
                sender_kdf.secret_bytes(),
                sender_info.stage2_tweak_scalar.to_be_bytes(),
                "Alice should derive the same NUT-28 scalar for sender_stage2"
            );
        }

        let receiver_info = params
            .stage2_tweak_info_for_role(Stage2Role::Receiver, 64, 0)
            .expect("Failed to derive receiver stage2 tweak info");
        let receiver_shared_from_charlie = ChannelParameters::derive_nut28_shared_secret_x(
            &receiver_info.ephemeral_pubkey,
            &charlie_secret,
        )
        .expect("Failed to derive receiver raw NUT-28 shared secret");
        assert_eq!(
            receiver_shared_from_charlie, receiver_info.ephemeral_shared_secret_x,
            "Charlie should derive the same shared secret x for receiver_stage2"
        );
        #[cfg(feature = "wallet")]
        {
            let receiver_kdf =
                cashu::nuts::nut28::ecdh_kdf(&charlie_secret, &receiver_info.ephemeral_pubkey, 0)
                    .expect("Failed to derive receiver NUT-28 scalar");
            assert_eq!(
                receiver_kdf.secret_bytes(),
                receiver_info.stage2_tweak_scalar.to_be_bytes(),
                "Charlie should derive the same NUT-28 scalar for receiver_stage2"
            );
        }
    }

    #[test]
    fn test_refund_blinded_pubkey_differs_from_sender() {
        // Test that the refund blinded pubkey uses a different tweak than the sender pubkey

        let alice_secret = SecretKey::generate();
        let sender_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let receiver_pubkey = charlie_secret.public_key();

        let keyset_info = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 100);

        let funding_token_amount =
            ChannelParameters::get_minimum_funding_token_amount(1000, &keyset_info, 64)
                .expect("Failed to compute funding token amount");

        let params = ChannelParameters::new_with_secret_key(
            sender_pubkey,
            receiver_pubkey,
            "https://testmint.cash".to_string(),
            CurrencyUnit::Sat,
            1000, // capacity
            funding_token_amount,
            1700000000,
            1699999000,
            keyset_info,
            64,
            &alice_secret,
        )
        .expect("Failed to create params");

        // Get the three pubkeys
        let raw_alice = params.sender_pubkey;
        let blinded_sender = params
            .get_sender_blinded_pubkey_for_stage1()
            .expect("Failed to get sender blinded pubkey");
        let blinded_refund = params
            .get_sender_blinded_pubkey_for_stage1_refund()
            .expect("Failed to get refund blinded pubkey");

        println!("Raw Alice pubkey:      {}", raw_alice.to_hex());
        println!("Blinded sender pubkey: {}", blinded_sender.to_hex());
        println!("Blinded refund pubkey: {}", blinded_refund.to_hex());

        // All three should be different
        assert_ne!(
            raw_alice.to_hex(),
            blinded_sender.to_hex(),
            "Blinded sender should differ from raw Alice pubkey"
        );
        assert_ne!(
            raw_alice.to_hex(),
            blinded_refund.to_hex(),
            "Blinded refund should differ from raw Alice pubkey"
        );
        assert_ne!(
            blinded_sender.to_hex(),
            blinded_refund.to_hex(),
            "Blinded sender and refund should use different tweaks"
        );

        println!("✓ All three pubkeys are distinct");
    }

    #[test]
    fn test_refund_signature_roundtrip() {
        use bitcoin::secp256k1::Message;
        use cashu::SECP256K1;

        // Test that signing with refund blinded key verifies against refund blinded pubkey

        let alice_secret = SecretKey::generate();
        let sender_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let receiver_pubkey = charlie_secret.public_key();

        let keyset_info = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 100);

        let funding_token_amount =
            ChannelParameters::get_minimum_funding_token_amount(1000, &keyset_info, 64)
                .expect("Failed to compute funding token amount");

        // Alice creates params
        let alice_params = ChannelParameters::new_with_secret_key(
            sender_pubkey,
            receiver_pubkey,
            "https://testmint.cash".to_string(),
            CurrencyUnit::Sat,
            1000, // capacity
            funding_token_amount,
            1700000000,
            1699999000,
            keyset_info.clone(),
            64,
            &alice_secret,
        )
        .expect("Failed to create Alice's params");

        // Alice gets her REFUND blinded secret key and signs a message
        let blinded_refund_secret = alice_params
            .get_sender_blinded_secret_key_for_stage1_refund(&alice_secret)
            .expect("Failed to get refund blinded secret");

        let test_msg = b"refund message to sign";
        let msg_hash = bitcoin::hashes::sha256::Hash::hash(test_msg);
        let msg = Message::from_digest_slice(msg_hash.as_ref()).unwrap();

        // Sign with refund blinded key
        let keypair =
            bitcoin::secp256k1::Keypair::from_secret_key(&SECP256K1, &*blinded_refund_secret);
        let signature = SECP256K1.sign_schnorr(&msg, &keypair);

        println!("Message: {}", hex::encode(msg_hash.to_byte_array()));
        println!("Signature: {}", hex::encode(signature.serialize()));

        // Charlie recreates params and verifies using REFUND blinded pubkey
        let json = alice_params.get_channel_id_params_json();
        let charlie_params =
            ChannelParameters::from_json_with_secret_key(&json, keyset_info, &charlie_secret)
                .expect("Failed to create Charlie's params");

        let blinded_refund_pubkey = charlie_params
            .get_sender_blinded_pubkey_for_stage1_refund()
            .expect("Failed to get refund blinded pubkey");

        println!("Refund blinded pubkey: {}", blinded_refund_pubkey.to_hex());

        // Verify the signature
        let verify_result = blinded_refund_pubkey.verify(test_msg, &signature);
        assert!(
            verify_result.is_ok(),
            "Refund signature verification failed: {:?}",
            verify_result
        );
        println!("✓ Refund signature verified successfully!");

        // Also verify that the WRONG pubkey (sender, not refund) fails
        let blinded_sender_pubkey = charlie_params
            .get_sender_blinded_pubkey_for_stage1()
            .expect("Failed to get sender blinded pubkey");

        let wrong_verify_result = blinded_sender_pubkey.verify(test_msg, &signature);
        assert!(
            wrong_verify_result.is_err(),
            "Signature should NOT verify against sender pubkey (wrong tweak)"
        );
        println!("✓ Signature correctly fails against sender pubkey (different tweak)");
    }

    #[test]
    fn test_channel_id_derivation() {
        let alice_sk = SecretKey::generate();
        let charlie_sk = SecretKey::generate();
        let channel_secret = compute_channel_secret(&alice_sk, &charlie_sk.public_key());

        let keyset = mock_keyset_info(vec![1, 2, 4, 8, 16], 0);

        let params = ChannelParameters {
            sender_pubkey: alice_sk.public_key(),
            receiver_pubkey: charlie_sk.public_key(),
            mint: "https://mint.host".to_string(),
            unit: CurrencyUnit::Sat,
            capacity: 1000,
            funding_token_amount: 1000,
            maximum_amount_for_one_output: 64,
            setup_timestamp: 1700000000,
            expiry_timestamp: 1700003600,
            keyset_info: keyset,
            channel_secret,
        };

        let channel_id = params.get_channel_id();
        assert_eq!(channel_id.len(), 64);
        assert_eq!(channel_id, params.get_channel_id()); // Idempotent
    }
}
