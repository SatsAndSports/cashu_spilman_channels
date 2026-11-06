//! Independent dual-mode channel reference. Channel derivation and point math
//! use RustCrypto; no production Spilman or Cashu transcript/tweak helpers.
use crate::channel_id::{spilman_test_vector_channel_id_keysetv2, ChannelIdTestVector};
use bitcoin::{
    bip32::{ChildNumber, Xpriv},
    secp256k1::{Keypair, Message, Secp256k1, SecretKey as SecpSecret},
    NetworkKind,
};
use hmac::{Hmac, KeyInit, Mac};
use k256::{
    elliptic_curve::sec1::ToSec1Point, AffinePoint, ProjectivePoint, PublicKey, Scalar, SecretKey,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn tagged(tag: &[u8], body: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(tag);
    Sha256::digest([hash.as_slice(), hash.as_slice(), body].concat()).into()
}
fn point(p: ProjectivePoint) -> String {
    hex::encode(AffinePoint::from(p).to_sec1_point(true).as_bytes())
}
fn scalar(bytes: &[u8]) -> Scalar {
    *SecretKey::from_slice(bytes)
        .expect("reference scalar")
        .to_nonzero_scalar()
        .as_ref()
}
fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}
fn hash_to_curve(secret: &str) -> ProjectivePoint {
    let hash = Sha256::digest(
        [
            b"Secp256k1_HashToCurve_Cashu_".as_slice(),
            secret.as_bytes(),
        ]
        .concat(),
    );
    for counter in 0u32..65536 {
        let x = Sha256::digest([hash.as_slice(), &counter.to_le_bytes()].concat());
        if let Ok(key) = PublicKey::from_sec1_bytes(&[&[2], x.as_slice()].concat()) {
            return ProjectivePoint::from(*key.as_affine());
        }
    }
    panic!("reference hash-to-curve exhausted")
}
fn mint_scalar(amount: u64) -> Scalar {
    let seed =
        bip39::Mnemonic::parse(crate::real_mint_keyset_v2::REAL_TEST_MINT_KEYSET_V2_MNEMONIC)
            .expect("public fixture mnemonic")
            .to_seed_normalized("");
    let unit_hash = Sha256::digest(b"SAT");
    let unit = u32::from_be_bytes(unit_hash[..4].try_into().expect("unit hash")) & 0x7fffffff;
    let path: Vec<_> = [129372, unit, 1, amount.trailing_zeros()]
        .map(|i| ChildNumber::from_hardened_idx(i).expect("reference index"))
        .into();
    let key = Xpriv::new_master(NetworkKind::Main, &seed)
        .expect("master key")
        .derive_priv(&Secp256k1::new(), &path)
        .expect("mint denomination key");
    scalar(&key.private_key.secret_bytes())
}

/// Same inputs as the ordinary channel-ID vector, with type 26/value 01 appended.
fn channel() -> ChannelIdTestVector {
    let mut channel = spilman_test_vector_channel_id_keysetv2();
    let mut bytes = hex::decode(channel.canonical_tlv).expect("ordinary TLV");
    bytes.extend([26, 1, 1]);
    channel.channel_id = tagged(b"Cashu_Spilman_channel_id", &bytes);
    channel
}

/// Independently derive the entire rerandomized channel family. Fixed mint R is
/// 0x42 repeated 32 times; deterministic DLEQ nonce is 7, for test use only.
///
/// # Panics
/// Panics if the fixed reference inputs or derived public mint keys are invalid.
pub fn vectors() -> Value {
    let channel = channel();
    let id = hex::encode(channel.channel_id);
    let stage1 = crate::stage1_key_tweaks_keyset_v2::derive_stage1_for_channel(channel);
    let r = [0x42; 32];
    let tweak = (0u32..)
        .find_map(|counter| {
            let hash = tagged(
                b"Cashu_OutputRerandomization_secp256k1_v1",
                &[r.as_slice(), &counter.to_be_bytes()].concat(),
            );
            SecretKey::from_slice(&hash).ok().map(|_| scalar(&hash))
        })
        .expect("reference tweak");
    let mut funding = Vec::new();
    let mut outputs = Vec::new();
    for (role, amounts) in [
        ("funding", vec![4, 32, 64]),
        ("receiver", vec![2, 16, 32]),
        ("sender", vec![2, 16, 32]),
    ] {
        for amount in amounts {
            let nonce = hex::encode(hmac(
                &channel.channel_secret,
                format!("{id}|{role}|{amount}|nonce|0").as_bytes(),
            ));
            let input = format!("{id}|{role}|{amount}|blinding|0");
            let mut blinding = hmac(&channel.channel_secret, input.as_bytes());
            if SecretKey::from_slice(&blinding).is_err() {
                blinding = hmac(
                    &channel.channel_secret,
                    &[input.as_bytes(), &[255]].concat(),
                );
            }
            let (data, ephemeral, tags) = if role == "funding" {
                (
                    stage1[0].blinded_pubkey.clone(),
                    String::new(),
                    json!([
                        ["pubkeys", stage1[1].blinded_pubkey],
                        ["locktime", channel.expiry_timestamp.to_string()],
                        ["n_sigs", "2"],
                        ["refund", stage1[2].blinded_pubkey],
                        ["n_sigs_refund", "1"],
                        ["sigflag", "SIG_ALL"]
                    ]),
                )
            } else {
                let (context, recipient) = if role == "receiver" {
                    ("receiver_stage2", channel.receiver_pubkey)
                } else {
                    ("sender_stage2", channel.sender_pubkey)
                };
                let derived = crate::stage2_p2bk_keyset_v2::derive_stage2_for_channel(
                    channel, context, recipient, amount, 0,
                );
                (derived.blinded_pubkey, derived.ephemeral_pubkey, json!([]))
            };
            let secret = json!(["P2PK", {"data": data, "nonce": nonce, "tags": tags}]).to_string();
            let y = hash_to_curve(&secret);
            let b = y + ProjectivePoint::GENERATOR * scalar(&blinding);
            let a = mint_scalar(amount);
            assert_eq!(
                point(ProjectivePoint::GENERATOR * a),
                channel
                    .public_keys
                    .iter()
                    .find(|(v, _)| *v == amount)
                    .expect("denomination")
                    .1
            );
            let mut output = json!({"role":role, "amount":amount, "index":0, "secret":secret,
                "blinding":hex::encode(blinding), "B":point(b), "C":point(y*a)});
            if role == "funding" {
                funding.push(output);
                continue;
            }
            let issued = b + ProjectivePoint::GENERATOR * tweak;
            let c = issued * a;
            let nonce = Scalar::from(7u64);
            let r1 = ProjectivePoint::GENERATOR * nonce;
            let r2 = issued * nonce;
            // NUT-12 hashes concatenated uncompressed SEC1 point hex strings.
            let transcript = [r1, r2, ProjectivePoint::GENERATOR * a, c]
                .iter()
                .map(|p| hex::encode(AffinePoint::from(*p).to_sec1_point(false).as_bytes()))
                .collect::<String>();
            let e: [u8; 32] = Sha256::digest(transcript.as_bytes()).into();
            let s = nonce + scalar(&e) * a;
            output["p2pk_e"] = json!(ephemeral);
            output["issued_B"] = json!(point(issued));
            output["effective_blinding"] =
                json!(hex::encode((scalar(&blinding) + tweak).to_bytes()));
            output["C_blind"] = json!(point(c));
            output["dleq"] = json!({"e":hex::encode(e), "s":hex::encode(s.to_bytes())});
            outputs.push(output);
        }
    }
    outputs.sort_by_key(|o| o["amount"].as_u64().expect("amount"));
    let mut transcript = Vec::new();
    fn frame(out: &mut Vec<u8>, data: &[u8]) {
        out.extend(
            u32::try_from(data.len())
                .expect("frame length")
                .to_be_bytes(),
        );
        out.extend(data);
    }
    frame(&mut transcript, &[]);
    for input in &funding {
        frame(
            &mut transcript,
            input["secret"].as_str().expect("secret").as_bytes(),
        );
        frame(
            &mut transcript,
            &hex::decode(input["C"].as_str().expect("point")).expect("hex"),
        );
    }
    for output in &outputs {
        let amount = output["amount"].as_u64().expect("amount");
        frame(
            &mut transcript,
            &amount.to_be_bytes()[(amount.leading_zeros() / 8) as usize..],
        );
        transcript.extend(Sha256::digest(
            hex::decode(output["B"].as_str().expect("point")).expect("hex"),
        ));
    }
    let digest = tagged(b"Cashu_SigAllRerandomized_v1", &transcript);
    let secp = Secp256k1::new();
    let signatures: Vec<_> = [1u64, 2]
        .into_iter()
        .zip(&stage1)
        .map(|(base, tweak)| {
            let key =
                SecpSecret::from_slice(&(Scalar::from(base) + scalar(&tweak.scalar)).to_bytes())
                    .expect("signer");
            secp.sign_schnorr_no_aux_rand(
                &Message::from_digest(digest),
                &Keypair::from_secret_key(&secp, &key),
            )
            .to_string()
        })
        .collect();
    json!({"name":"spilman-test-vector-rerandomized-keysetv2", "channel_id":id,
        "keyset_id":channel.keyset_id, "R":hex::encode(r), "tweak":hex::encode(tweak.to_bytes()),
        "stage1":stage1.iter().map(|s| json!({"context":s.context,"scalar":hex::encode(s.scalar),"pubkey":s.blinded_pubkey})).collect::<Vec<_>>(),
        "funding":funding,"outputs":outputs,"digest":hex::encode(digest),"signatures":signatures})
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn spilman_test_vector_rerandomized_keysetv2() {
        let v = vectors();
        assert_eq!(
            v["channel_id"],
            "4ac29fbee4af2638f606eb268ee68fcef5c012f23b85ce1d7bd0f0572cef4e55"
        );
        assert_eq!(
            v["digest"],
            "550e48d7ca225a71e32f840ded0d56cebb714614d794f45ecd9900851bc77fcf"
        );
        assert_eq!(
            hex::encode(Sha256::digest(v.to_string().as_bytes())),
            "c6b952995ca393daf7a892ce01de31cfd878bc68395d46022cc539ad2f8ce2d6"
        );
    }
}
