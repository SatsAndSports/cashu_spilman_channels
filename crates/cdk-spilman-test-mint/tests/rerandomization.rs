//! Milestone 1 only: real-process mint swap primitive, not rerandomized channels.
#![cfg(feature = "http")]
#[path = "rerandomization_support/crypto.rs"]
mod crypto;
#[path = "rerandomization_support/notifications.rs"]
mod notifications;
#[path = "rerandomization_support/process.rs"]
mod process;

use anyhow::{anyhow, ensure, Result};
use bitcoin::hashes::{sha256, Hash};
use cashu::dhke::{blind_message, construct_proofs};
use cashu::nuts::nut01::{Keys, KeysResponse};
use cashu::nuts::nut02::{Id, KeysetResponse};
use cashu::nuts::nut03::SwapResponse;
use cashu::nuts::nut04::MintResponse;
use cashu::nuts::nut09::RestoreResponse;
use cashu::nuts::nut11::P2PKWitness;
use cashu::nuts::nut14::HTLCWitness;
use cashu::nuts::{
    BlindedMessage, Conditions, Proof, Proofs, SecretKey, SigFlag, SpendingConditions, SwapRequest,
    Witness,
};
use cashu::secret::Secret;
use notifications::Subscription;
use process::MintProcess;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

struct Http {
    client: reqwest::Client,
    url: String,
}

impl Http {
    fn new(url: &str) -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()?,
            url: url.to_owned(),
        })
    }
    async fn get(&self, path: &str) -> Result<Value> {
        let response = self
            .client
            .get(format!("{}{path}", self.url))
            .send()
            .await?;
        ensure!(
            response.status().is_success(),
            "HTTP GET rejected: {}",
            response.status()
        );
        Ok(response.json().await?)
    }
    async fn post(&self, path: &str, body: impl Serialize) -> Result<Value> {
        let response = self
            .client
            .post(format!("{}{path}", self.url))
            .json(&body)
            .send()
            .await?;
        ensure!(
            response.status().is_success(),
            "HTTP POST rejected: {}",
            response.status()
        );
        Ok(response.json().await?)
    }
    async fn state(&self, inputs: &[Proof], expected: &str, r: Option<&str>) -> Result<()> {
        let ys = inputs
            .iter()
            .map(|p| p.y().map(|y| y.to_hex()))
            .collect::<Result<Vec<_>, _>>()?;
        let response = self.post("/v1/checkstate", json!({"Ys":ys})).await?;
        let states = response["states"]
            .as_array()
            .ok_or_else(|| anyhow!("missing states"))?;
        ensure!(states.len() == inputs.len(), "wrong state count");
        for (state, y) in states.iter().zip(ys) {
            ensure!(
                state["Y"] == y && state["state"] == expected,
                "wrong state identity/status"
            );
            ensure!(state["rerandomization_r"].as_str() == r, "wrong state R");
            if r.is_none() {
                ensure!(state.get("rerandomization_r").is_none(), "unexpected R");
            }
        }
        Ok(())
    }
    async fn reject(&self, request: &SwapRequest) -> Result<()> {
        let response = self
            .client
            .post(format!("{}/v1/swap", self.url))
            .json(request)
            .send()
            .await?;
        ensure!(response.status() == 400, "request was not rejected");
        let body: Value = response.json().await?;
        ensure!(
            body["code"].is_u64() && body.get("rerandomization_r").is_none(),
            "invalid rejection"
        );
        self.state(request.inputs(), "UNSPENT", None).await
    }
}

#[derive(Serialize, Deserialize)]
struct Prepared {
    outputs: Vec<BlindedMessage>,
    secrets: Vec<Secret>,
    rs: Vec<SecretKey>,
}

fn outputs(id: Id, secrets: Vec<Secret>) -> Result<Prepared> {
    let mut result = Prepared {
        outputs: Vec::new(),
        secrets: Vec::new(),
        rs: Vec::new(),
    };
    for secret in secrets {
        let (b, r) = blind_message(&secret.to_bytes(), None)?;
        result.outputs.push(BlindedMessage::new(1.into(), id, b));
        result.secrets.push(secret);
        result.rs.push(r);
    }
    Ok(result)
}

fn plain(id: Id, count: usize) -> Result<Prepared> {
    outputs(id, (0..count).map(|_| Secret::generate()).collect())
}

fn request(
    inputs: Proofs,
    outputs: Vec<BlindedMessage>,
    signer: &SecretKey,
    rerandomize: bool,
) -> Result<SwapRequest> {
    let mut request = SwapRequest::new(inputs, outputs);
    let signature = if rerandomize {
        request = request.with_rerandomization();
        crypto::sign_digest(
            crypto::digest(request.inputs(), request.outputs(), false),
            signer,
        )
    } else {
        crypto::ordinary_signature(request.inputs(), request.outputs(), signer)?
    };
    request.inputs_mut()[0].witness = Some(Witness::P2PKWitness(P2PKWitness {
        signatures: vec![signature],
    }));
    Ok(request)
}

async fn keyset(http: &Http) -> Result<(Id, Keys)> {
    let sets: KeysetResponse = serde_json::from_value(http.get("/v1/keysets").await?)?;
    let set = sets
        .keysets
        .into_iter()
        .find(|s| s.active && s.unit.to_string() == "sat")
        .ok_or_else(|| anyhow!("no SAT keyset"))?;
    ensure!(
        set.input_fee_ppk == 0,
        "fixture requires explicit zero-fee configuration"
    );
    let response: KeysResponse =
        serde_json::from_value(http.get(&format!("/v1/keys/{}", set.id)).await?)?;
    let keys = response
        .keysets
        .into_iter()
        .find(|s| s.id == set.id)
        .ok_or_else(|| anyhow!("keys missing"))?
        .keys;
    Ok((set.id, keys))
}

async fn mint(http: &Http, id: Id, keys: &Keys, count: usize) -> Result<Proofs> {
    let quote = http
        .post(
            "/v1/mint/quote/bolt11",
            json!({"amount":count,"unit":"sat"}),
        )
        .await?;
    let quote = quote["quote"]
        .as_str()
        .ok_or_else(|| anyhow!("no quote id"))?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if http.get(&format!("/v1/mint/quote/bolt11/{quote}")).await?["state"] == "PAID" {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    let prepared = plain(id, count)?;
    let response: MintResponse = serde_json::from_value(
        http.post(
            "/v1/mint/bolt11",
            json!({"quote":quote,"outputs":prepared.outputs}),
        )
        .await?,
    )?;
    Ok(construct_proofs(
        response.signatures,
        prepared.rs,
        prepared.secrets,
        keys,
    )?)
}

async fn ordinary(
    http: &Http,
    inputs: Proofs,
    prepared: Prepared,
    keys: &Keys,
    explicit_false: bool,
) -> Result<Proofs> {
    let original = inputs.clone();
    let mut request = json!({"inputs":inputs,"outputs":prepared.outputs});
    if explicit_false {
        request["rerandomize"] = json!(false);
    }
    let result = http.post("/v1/swap", request).await?;
    ensure!(
        result.get("rerandomization_r").is_none(),
        "ordinary response R"
    );
    http.state(&original, "SPENT", None).await?;
    let result: SwapResponse = serde_json::from_value(result)?;
    Ok(construct_proofs(
        result.signatures,
        prepared.rs,
        prepared.secrets,
        keys,
    )?)
}

fn unblind(prepared: Prepared, response: SwapResponse, keys: &Keys) -> Result<Proofs> {
    let r = response
        .rerandomization_r
        .ok_or_else(|| anyhow!("missing committed R"))?
        .0;
    ensure!(
        response.signatures.len() == prepared.outputs.len(),
        "wrong signature count"
    );
    let derived = crypto::derived(&r, &prepared.outputs)?;
    for (signature, output) in response.signatures.iter().zip(&derived) {
        ensure!(
            signature.keyset_id == output.keyset_id && signature.amount == output.amount,
            "changed output metadata/order"
        );
        signature.verify_dleq(
            keys.amount_key(output.amount)
                .ok_or_else(|| anyhow!("missing key"))?,
            output.blinded_secret,
        )?;
    }
    let effective = prepared
        .rs
        .iter()
        .map(|b| crypto::blinding(b, &r))
        .collect::<Result<Vec<_>>>()?;
    let proofs = construct_proofs(response.signatures, effective, prepared.secrets, keys)?;
    for proof in &proofs {
        proof.verify_dleq(
            keys.amount_key(proof.amount)
                .ok_or_else(|| anyhow!("missing key"))?,
        )?;
    }
    Ok(proofs)
}

fn recovery_r(states: &Value, inputs: &[Proof]) -> Result<String> {
    let states = states["states"]
        .as_array()
        .ok_or_else(|| anyhow!("missing states"))?;
    ensure!(
        !inputs.is_empty() && states.len() == inputs.len(),
        "incomplete recovery states"
    );
    let r = states[0]["rerandomization_r"]
        .as_str()
        .ok_or_else(|| anyhow!("missing R"))?;
    ensure!(
        r.len() == 64
            && r.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "noncanonical R"
    );
    for (state, input) in states.iter().zip(inputs) {
        ensure!(
            state["Y"] == input.y()?.to_hex()
                && state["state"] == "SPENT"
                && state["rerandomization_r"] == r,
            "recovery requires all matching inputs spent with one R"
        );
    }
    Ok(r.to_owned())
}

async fn spend(http: &Http, proofs: Proofs, id: Id, keys: &Keys) -> Result<()> {
    let count = proofs.len();
    let _ = ordinary(http, proofs, plain(id, count)?, keys, false).await?;
    Ok(())
}

async fn p2pk(http: &Http, input: Proof, id: Id, keys: &Keys, signer: &SecretKey) -> Result<Proof> {
    let secret: Secret = SpendingConditions::new_p2pk(
        signer.public_key(),
        Some(Conditions {
            sig_flag: SigFlag::SigAll,
            ..Default::default()
        }),
    )
    .try_into()?;
    ordinary(http, vec![input], outputs(id, vec![secret])?, keys, false)
        .await?
        .pop()
        .ok_or_else(|| anyhow!("locked input missing"))
}

async fn htlc(http: &Http, input: Proof, id: Id, keys: &Keys, refund: bool) -> Result<()> {
    let receiver = SecretKey::generate();
    let refund_key = SecretKey::generate();
    let hash = sha256::Hash::hash(&[0x42; 32]).to_string();
    let secret: Secret = SpendingConditions::new_htlc_hash(
        &hash,
        Some(Conditions {
            sig_flag: SigFlag::SigAll,
            pubkeys: Some(vec![receiver.public_key()]),
            locktime: refund.then_some(1),
            refund_keys: refund.then_some(vec![refund_key.public_key()]),
            ..Default::default()
        }),
    )?
    .try_into()?;
    let locked = ordinary(http, vec![input], outputs(id, vec![secret])?, keys, false).await?;
    let prepared = plain(id, 1)?;
    let mut request = SwapRequest::new(locked, prepared.outputs.clone()).with_rerandomization();
    let signer = if refund { &refund_key } else { &receiver };
    let preimage = if refund {
        String::new()
    } else {
        cashu::util::hex::encode([0x42; 32])
    };
    request.inputs_mut()[0].witness = Some(Witness::HTLCWitness(HTLCWitness {
        preimage: preimage.clone(),
        signatures: Some(vec![crypto::ordinary_signature(
            request.inputs(),
            request.outputs(),
            signer,
        )?]),
    }));
    http.reject(&request).await?;
    let signature = crypto::sign_digest(
        crypto::digest(request.inputs(), request.outputs(), false),
        signer,
    );
    request.inputs_mut()[0].witness = Some(Witness::HTLCWitness(HTLCWitness {
        preimage,
        signatures: Some(vec![signature]),
    }));
    let result = http.post("/v1/swap", &request).await?;
    let r = result["rerandomization_r"]
        .as_str()
        .ok_or_else(|| anyhow!("HTLC R missing"))?;
    http.state(request.inputs(), "SPENT", Some(r)).await?;
    spend(
        http,
        unblind(prepared, serde_json::from_value(result)?, keys)?,
        id,
        keys,
    )
    .await
}

#[test]
fn proposal_vectors_are_independent() -> Result<()> {
    crypto::vectors()
}

#[test]
fn recovery_rejects_pending_missing_mismatched_or_noncanonical_states() -> Result<()> {
    let input: Proof = serde_json::from_value(
        json!({"amount":1,"id":"009a1f293253e41e","secret":"test","C":SecretKey::generate().public_key().to_hex()}),
    )?;
    let inputs = vec![input.clone(), input.clone()];
    let state =
        json!({"Y":input.y()?.to_hex(),"state":"SPENT","rerandomization_r":"ab".repeat(32)});
    let good = json!({"states":[state.clone(),state]});
    ensure!(
        recovery_r(&good, &inputs)? == "ab".repeat(32),
        "valid recovery"
    );
    for (field, value) in [
        ("state", json!("PENDING")),
        ("rerandomization_r", Value::Null),
        ("rerandomization_r", json!("ac".repeat(32))),
        ("Y", json!(SecretKey::generate().public_key().to_hex())),
    ] {
        let mut invalid = good.clone();
        invalid["states"][1][field] = value;
        ensure!(
            recovery_r(&invalid, &inputs).is_err(),
            "inconsistent recovery accepted"
        );
    }
    let mut invalid = good.clone();
    invalid["states"][0]["rerandomization_r"] = json!("AB".repeat(32));
    invalid["states"][1]["rerandomization_r"] = json!("AB".repeat(32));
    ensure!(
        recovery_r(&invalid, &inputs).is_err(),
        "noncanonical recovery accepted"
    );
    ensure!(
        recovery_r(&json!({"states":[]}), &inputs).is_err(),
        "empty recovery accepted"
    );
    Ok(())
}

#[tokio::test]
async fn real_process_both_modes_authorization_and_restart_recovery() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(90), scenarios()).await?
}

async fn scenarios() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut process = MintProcess::start(&directory.path().join("mint.sqlite")).await?;
    let http = Http::new(&process.url)?;
    ensure!(
        http.get("/v1/info").await?["nuts"]["3"]["rerandomize"] == true,
        "capability missing"
    );
    let (id, keys) = keyset(&http).await?;
    let mut purse = mint(&http, id, &keys, 16).await?;
    let signer = SecretKey::generate();
    // Bare proofs are not SIG_ALL and cannot opt into this mode.
    http.reject(&request(
        vec![purse[0].clone()],
        plain(id, 1)?.outputs,
        &signer,
        true,
    )?)
    .await?;

    // Two-party authorization is still required: one valid signature cannot
    // replace the existing threshold, nor can ordinary/mode signatures mix.
    let second = SecretKey::generate();
    let secret: Secret = SpendingConditions::new_p2pk(
        signer.public_key(),
        Some(Conditions {
            sig_flag: SigFlag::SigAll,
            pubkeys: Some(vec![second.public_key()]),
            num_sigs: Some(2),
            ..Default::default()
        }),
    )
    .try_into()?;
    let locked = ordinary(
        &http,
        vec![purse.pop().ok_or_else(|| anyhow!("purse"))?],
        outputs(id, vec![secret])?,
        &keys,
        false,
    )
    .await?;
    let prepared = plain(id, 1)?;
    let mut multisig = request(locked, prepared.outputs.clone(), &signer, true)?;
    http.reject(&multisig).await?;
    let additional = crypto::sign_digest(
        crypto::digest(multisig.inputs(), multisig.outputs(), false),
        &second,
    );
    if let Some(Witness::P2PKWitness(witness)) = &mut multisig.inputs_mut()[0].witness {
        witness.signatures.push(additional);
    }
    let result: SwapResponse = serde_json::from_value(http.post("/v1/swap", multisig).await?)?;
    spend(&http, unblind(prepared, result, &keys)?, id, &keys).await?;

    // Missing and false flags retain ordinary output, state, and restore semantics.
    let mut ordinary_restores = Vec::new();
    for explicit_false in [false, true] {
        let input = purse.pop().ok_or_else(|| anyhow!("purse exhausted"))?;
        let prepared = plain(id, 1)?;
        let originals = prepared.outputs.clone();
        ordinary_restores.push((input.clone(), originals.clone()));
        let mut sub = Subscription::open(&http.url, input.y()?).await?;
        let _ = ordinary(&http, vec![input], prepared, &keys, explicit_false).await?;
        sub.spent(None).await?;
        let restored: RestoreResponse = serde_json::from_value(
            http.post("/v1/restore", json!({"outputs":originals}))
                .await?,
        )?;
        ensure!(
            restored.signatures.len() == 1 && restored.outputs == originals,
            "ordinary restore changed"
        );
    }

    // Pre-sign an original output through an unrelated ordinary swap.
    let prepared = plain(id, 1)?;
    http.post(
        "/v1/swap",
        SwapRequest::new(
            vec![purse.pop().ok_or_else(|| anyhow!("purse"))?],
            prepared.outputs.clone(),
        ),
    )
    .await?;
    let locked = p2pk(
        &http,
        purse.pop().ok_or_else(|| anyhow!("purse"))?,
        id,
        &keys,
        &signer,
    )
    .await?;
    let good = request(vec![locked], prepared.outputs.clone(), &signer, true)?;
    let mut sub = Subscription::open(&http.url, good.inputs()[0].y()?).await?;
    let result = http.post("/v1/swap", &good).await?;
    let r = result["rerandomization_r"]
        .as_str()
        .ok_or_else(|| anyhow!("R missing"))?;
    ensure!(
        r.len() == 64
            && r.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "noncanonical R"
    );
    sub.spent(Some(r)).await?;
    http.state(good.inputs(), "SPENT", Some(r)).await?;
    spend(
        &http,
        unblind(prepared, serde_json::from_value(result)?, &keys)?,
        id,
        &keys,
    )
    .await?;

    // Negative authorization: no silent downgrade and no alternative transcript.
    let locked = p2pk(
        &http,
        purse.pop().ok_or_else(|| anyhow!("purse"))?,
        id,
        &keys,
        &signer,
    )
    .await?;
    let prepared = plain(id, 1)?;
    let ordinary_signed = request(
        vec![locked.clone()],
        prepared.outputs.clone(),
        &signer,
        false,
    )?;
    let mut wrong: Value = serde_json::to_value(ordinary_signed)?;
    wrong["rerandomize"] = json!(true);
    http.reject(&serde_json::from_value(wrong)?).await?;
    let good = request(
        vec![locked.clone()],
        prepared.outputs.clone(),
        &signer,
        true,
    )?;
    let mut wrong = good.clone();
    wrong.inputs_mut()[0].witness = Some(Witness::P2PKWitness(P2PKWitness {
        signatures: vec![crypto::sign_digest(
            crypto::digest(wrong.inputs(), wrong.outputs(), true),
            &signer,
        )],
    }));
    http.reject(&wrong).await?;
    let mut wrong = serde_json::to_value(&good)?;
    wrong["rerandomize"] = json!(false);
    http.reject(&serde_json::from_value(wrong)?).await?;
    let result: SwapResponse = serde_json::from_value(http.post("/v1/swap", &good).await?)?;
    spend(&http, unblind(prepared, result, &keys)?, id, &keys).await?;

    for refund in [false, true] {
        htlc(
            &http,
            purse.pop().ok_or_else(|| anyhow!("purse"))?,
            id,
            &keys,
            refund,
        )
        .await?;
    }

    // Two inputs/outputs: duplicate originals, tampering and output reordering.
    let mut inputs = Vec::new();
    for _ in 0..2 {
        inputs.push(
            p2pk(
                &http,
                purse.pop().ok_or_else(|| anyhow!("purse"))?,
                id,
                &keys,
                &signer,
            )
            .await?,
        );
    }
    let prepared = plain(id, 2)?;
    let good = request(inputs, prepared.outputs.clone(), &signer, true)?;
    let duplicate = request(
        good.inputs().clone(),
        vec![prepared.outputs[0].clone(); 2],
        &signer,
        true,
    )?;
    http.reject(&duplicate).await?;
    let mut wrong = good.clone();
    wrong.outputs_mut().reverse();
    http.reject(&wrong).await?;
    let mut wrong = good.clone();
    wrong.outputs_mut()[0].blinded_secret = SecretKey::generate().public_key();
    http.reject(&wrong).await?;
    let mut wrong = good.clone();
    wrong.outputs_mut()[0].amount = 2.into();
    http.reject(&wrong).await?;

    // Persist recovery material before sending, then discard the success body.
    let state_path = directory.path().join("recovery.json");
    std::fs::write(&state_path, serde_json::to_vec(&(good.clone(), prepared))?)?;
    let mut subscriptions = Vec::new();
    for input in good.inputs() {
        subscriptions.push(Subscription::open(&http.url, input.y()?).await?);
    }
    let response = http
        .client
        .post(format!("{}/v1/swap", http.url))
        .json(&good)
        .send()
        .await?;
    ensure!(response.status().is_success(), "discarded swap failed");
    drop(response);
    // R is deliberately learned from spent state, not the discarded body.
    let state=http.post("/v1/checkstate",json!({"Ys":good.inputs().iter().map(|p|p.y().map(|y|y.to_hex())).collect::<Result<Vec<_>,_>>()?})).await?;
    let committed_r = recovery_r(&state, good.inputs())?;
    http.state(good.inputs(), "SPENT", Some(&committed_r))
        .await?;
    for sub in &mut subscriptions {
        sub.spent(Some(&committed_r)).await?;
    }
    drop(subscriptions);
    process.restart().await?;
    let http = Http::new(&process.url)?;
    for (input, originals) in ordinary_restores {
        http.state(&[input], "SPENT", None).await?;
        let restored: RestoreResponse = serde_json::from_value(
            http.post("/v1/restore", json!({"outputs":originals}))
                .await?,
        )?;
        ensure!(
            restored.signatures.len() == 1 && restored.outputs == originals,
            "ordinary restore changed after restart"
        );
    }
    let (request, prepared): (SwapRequest, Prepared) =
        serde_json::from_slice(&std::fs::read(state_path)?)?;
    let restarted_state=http.post("/v1/checkstate",json!({"Ys":request.inputs().iter().map(|p|p.y().map(|y|y.to_hex())).collect::<Result<Vec<_>,_>>()?})).await?;
    let recovered_r = recovery_r(&restarted_state, request.inputs())?;
    ensure!(recovered_r == committed_r, "R changed after restart");
    http.state(request.inputs(), "SPENT", Some(&committed_r))
        .await?;
    for input in request.inputs() {
        Subscription::open(&http.url, input.y()?)
            .await?
            .spent(Some(&committed_r))
            .await?;
    }
    let r: cashu::nuts::nut03::RerandomizationR = serde_json::from_value(json!(recovered_r))?;
    let derived = crypto::derived(&r.0, &prepared.outputs)?;
    let originals: RestoreResponse = serde_json::from_value(
        http.post("/v1/restore", json!({"outputs":prepared.outputs}))
            .await?,
    )?;
    ensure!(
        originals.signatures.is_empty(),
        "mint stored originals rather than derived outputs"
    );
    let restored: RestoreResponse =
        serde_json::from_value(http.post("/v1/restore", json!({"outputs":derived})).await?)?;
    ensure!(
        restored.outputs == derived && restored.signatures.len() == 2,
        "restore identity/order mismatch"
    );
    let result = SwapResponse {
        signatures: restored.signatures,
        rerandomization_r: Some(r),
    };
    spend(&http, unblind(prepared, result, &keys)?, id, &keys).await?;
    // Ordinary swaps are still ordinary after the same database restarts.
    let funding = mint(&http, id, &keys, 2).await?;
    let _ = ordinary(&http, funding, plain(id, 2)?, &keys, true).await?;
    process.stop().await?;
    Ok(())
}
