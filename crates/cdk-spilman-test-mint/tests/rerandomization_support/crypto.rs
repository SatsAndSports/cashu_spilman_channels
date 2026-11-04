//! Test-only independent transcript/tweak implementation, following nuts#463 at
//! 1d528eb2. Does not call CDK's rerandomized signing or tweaking helpers.
use anyhow::{ensure, Result};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Keypair, Message, Scalar, Secp256k1, SecretKey as SecpSecret};
use cashu::nuts::{BlindedMessage, Proof, PublicKey, SecretKey};

fn tagged(tag: &[u8], payload: &[u8]) -> [u8; 32] {
    let tag = sha256::Hash::hash(tag).to_byte_array();
    let mut bytes = Vec::from(tag);
    bytes.extend(tag);
    bytes.extend(payload);
    sha256::Hash::hash(&bytes).to_byte_array()
}

fn frame(bytes: &mut Vec<u8>, field: &[u8]) {
    bytes.extend(
        u32::try_from(field.len())
            .expect("test frame fits u32")
            .to_be_bytes(),
    );
    bytes.extend(field);
}

pub fn digest(inputs: &[Proof], outputs: &[BlindedMessage], raw_points: bool) -> [u8; 32] {
    let mut message = Vec::new();
    frame(&mut message, &[]);
    for proof in inputs {
        frame(&mut message, proof.secret.to_string().as_bytes());
        frame(&mut message, &proof.c.to_bytes());
    }
    for output in outputs {
        let amount = u64::from(output.amount).to_be_bytes();
        frame(
            &mut message,
            &amount[(u64::from(output.amount).leading_zeros() / 8) as usize..],
        );
        if raw_points {
            frame(&mut message, &output.blinded_secret.to_bytes());
        } else {
            message.extend(sha256::Hash::hash(&output.blinded_secret.to_bytes()).to_byte_array());
        }
    }
    tagged(b"Cashu_SigAllRerandomized_v1", &message)
}

pub fn sign_digest(digest: [u8; 32], signer: &SecretKey) -> String {
    let secp = Secp256k1::new();
    let secret = SecpSecret::from_slice(signer.as_secret_bytes()).expect("test key");
    secp.sign_schnorr_no_aux_rand(
        &Message::from_digest(digest),
        &Keypair::from_secret_key(&secp, &secret),
    )
    .to_string()
}

pub fn ordinary_signature(
    inputs: &[Proof],
    outputs: &[BlindedMessage],
    signer: &SecretKey,
) -> Result<String> {
    let mut message = String::new();
    for input in inputs {
        message.push_str(&input.secret.to_string());
        message.push_str(&input.c.to_hex());
    }
    for output in outputs {
        message.push_str(&output.amount.to_string());
        message.push_str(&output.blinded_secret.to_hex());
    }
    Ok(signer.sign(message.as_bytes())?.to_string())
}

pub fn tweak(r: &[u8; 32]) -> Result<Scalar> {
    for counter in 0..=u32::MAX {
        let mut payload = Vec::from(*r);
        payload.extend(counter.to_be_bytes());
        if let Ok(secret) = SecpSecret::from_slice(&tagged(
            b"Cashu_OutputRerandomization_secp256k1_v1",
            &payload,
        )) {
            return Ok(Scalar::from(secret));
        }
    }
    anyhow::bail!("no nonzero tweak")
}

pub fn derived(r: &[u8; 32], outputs: &[BlindedMessage]) -> Result<Vec<BlindedMessage>> {
    let t = tweak(r)?;
    outputs
        .iter()
        .map(|output| {
            let point =
                bitcoin::secp256k1::PublicKey::from_slice(&output.blinded_secret.to_bytes())?
                    .add_exp_tweak(&Secp256k1::new(), &t)?;
            let mut output = output.clone();
            output.blinded_secret = PublicKey::from(point);
            Ok(output)
        })
        .collect()
}

pub fn blinding(r: &SecretKey, mint_r: &[u8; 32]) -> Result<SecretKey> {
    let sum = SecpSecret::from_slice(r.as_secret_bytes())?.add_tweak(&tweak(mint_r)?)?;
    Ok(SecretKey::from_slice(&sum.secret_bytes())?)
}

pub fn vectors() -> Result<()> {
    ensure!(
        cashu::util::hex::encode(tweak(&[0x42; 32])?.to_be_bytes())
            == "ea8bfdd0711f5a0cdd1377930ed729ca779722a8a5f97156242fcef09965eeb5",
        "tweak vector"
    );
    let id = "009a1f293253e41e".parse()?;
    let g =
        PublicKey::from_hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")?;
    let two_g =
        PublicKey::from_hex("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")?;
    let outputs = vec![
        BlindedMessage::new(1.into(), id, g),
        BlindedMessage::new(2.into(), id, two_g),
    ];
    ensure!(
        cashu::util::hex::encode(digest(&[], &outputs[..1], false))
            == "12ba73147194f4528cf2e06b4a557daff57a1f2153938106af49d51c399bbe2a",
        "digest vector"
    );
    ensure!(
        derived(&[0x42; 32], &outputs)?[0].blinded_secret.to_hex()
            == "020f78ce253e2f82c3f92f2e2c529f0c2320d628f0456e360f14e7005565f35ee6",
        "point vector"
    );
    let input: Proof = serde_json::from_value(
        serde_json::json!({"amount":3,"id":id.to_string(),"secret":"example-input","C":g.to_hex()}),
    )?;
    let message = digest(&[input], &outputs, false);
    ensure!(
        cashu::util::hex::encode(message)
            == "1cf1d9ebb188c3bef26728eb68650d00bef181e24c4e6dcd5f102808183ec9fc",
        "input vector"
    );
    let key = SecretKey::from_slice(&{
        let mut bytes = [0; 32];
        bytes[31] = 1;
        bytes
    })?;
    ensure!(sign_digest(message, &key) == "d4d6e5d561a3e6430dfea89f9f786312c29aa88db0456f3828663c15d468aa7d71650eaa4718eca7e0db0b4217e728471ecd3d2b9e23feba50a57ee68b9bfe4e", "signature vector");
    Ok(())
}
