//! Mode binding, two-party authorization and complete issued-proof verification.
use cashu::nuts::{
    BlindSignature, CurrencyUnit, Id, Keys, Proof, SecretKey, SpendingConditionVerification,
    SwapRequest, SwapResponse,
};
use cdk_spilman::{
    BalanceUpdateMessage, ChannelParameters, CommitmentMode, CommitmentOutputs,
    DeterministicOutputsForOneContext, EstablishedChannel, KeysetInfo,
};

fn fixture(mode: CommitmentMode) -> (EstablishedChannel, SecretKey, SecretKey, SecretKey) {
    let alice = SecretKey::generate();
    let charlie = SecretKey::generate();
    let mint = SecretKey::generate();
    let keys = Keys::new(
        [1u64, 2, 4, 8, 16, 32, 64]
            .into_iter()
            .map(|v| (v.into(), mint.public_key()))
            .collect(),
    );
    let info = KeysetInfo::new(Id::v1_from_keys(&keys), CurrencyUnit::Sat, keys, 0, None);
    let params = ChannelParameters::new_with_secret_key(
        alice.public_key(),
        charlie.public_key(),
        "https://mint.example".to_owned(),
        CurrencyUnit::Sat,
        64,
        64,
        u64::MAX - 1,
        1,
        info,
        0,
        &alice,
    )
    .expect("valid channel parameters")
    .with_commitment_mode(mode);
    let outputs = DeterministicOutputsForOneContext::new("funding".to_owned(), 64, params.clone())
        .expect("valid funding amounts")
        .get_secrets_with_blinding()
        .expect("derive funding outputs");
    let proofs: Vec<Proof> = outputs
        .iter()
        .map(|output| {
            let message = output
                .to_blinded_message(output.amount.into(), params.keyset_info.keyset_id)
                .expect("valid funding point");
            let signature = BlindSignature::new(
                message.amount,
                cashu::dhke::sign_message(&mint, &message.blinded_secret)
                    .expect("sign funding point"),
                message.keyset_id,
                &message.blinded_secret,
                &mint,
            )
            .expect("construct funding DLEQ");
            cashu::dhke::construct_proofs(
                vec![signature],
                vec![output.blinding_factor.clone()],
                vec![output.secret.clone()],
                &params.keyset_info.active_keys,
            )
            .expect("unblind funding issuance")
            .remove(0)
        })
        .collect();
    (
        EstablishedChannel::new(params, proofs).expect("valid funded channel"),
        alice,
        charlie,
        mint,
    )
}

#[test]
fn mode_is_authenticated_and_json_rejects_invalid_values() {
    let (channel, _, _, _) = fixture(CommitmentMode::Ordinary);
    let ordinary = channel.params;
    let alternate = ordinary
        .clone()
        .with_commitment_mode(CommitmentMode::Rerandomized);
    assert_ne!(ordinary.get_channel_id(), alternate.get_channel_id());
    for params in [&ordinary, &alternate] {
        let json = params.get_channel_id_params_json();
        assert_eq!(
            json.contains("commitment_mode"),
            params.commitment_mode == CommitmentMode::Rerandomized
        );
        let restored = ChannelParameters::from_json_with_channel_secret(
            &json,
            params.keyset_info.clone(),
            params.channel_secret,
        )
        .unwrap();
        assert_eq!(params.get_channel_id(), restored.get_channel_id());
        assert_eq!(params.commitment_mode, restored.commitment_mode);
    }
    for value in [
        serde_json::json!(null),
        serde_json::json!(1),
        serde_json::json!("unknown"),
        serde_json::json!(true),
    ] {
        let mut json: serde_json::Value =
            serde_json::from_str(&ordinary.get_channel_id_params_json()).unwrap();
        json["commitment_mode"] = value;
        assert!(ChannelParameters::from_json_with_channel_secret(
            &json.to_string(),
            ordinary.keyset_info.clone(),
            ordinary.channel_secret
        )
        .is_err());
    }
}

#[test]
fn both_parties_sign_the_same_mode_specific_digest_and_complete_issuance() {
    for mode in [CommitmentMode::Ordinary, CommitmentMode::Rerandomized] {
        let (channel, alice, charlie, mint) = fixture(mode);
        let outputs = CommitmentOutputs::for_balance(23, &channel.params).unwrap();
        let mut request = outputs
            .create_swap_request(channel.funding_proofs.clone(), None)
            .unwrap();
        assert_eq!(
            request.is_rerandomized(),
            mode == CommitmentMode::Rerandomized
        );
        let digest = request.sig_all_message_hash();
        request
            .sign_sig_all(
                channel
                    .params
                    .get_sender_blinded_secret_key_for_stage1(&alice)
                    .unwrap(),
            )
            .unwrap();
        let update = BalanceUpdateMessage::from_signed_swap_request(
            channel.params.get_channel_id(),
            23,
            &request,
        )
        .unwrap();
        update.verify_sender_signature(&channel).unwrap();
        let mut wrong_balance = update.clone();
        wrong_balance.amount += 1;
        assert!(wrong_balance.verify_sender_signature(&channel).is_err());
        request
            .sign_sig_all(
                channel
                    .params
                    .get_receiver_blinded_secret_key_for_stage1(&charlie)
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(digest, request.sig_all_message_hash());
        request.verify_full_sig_all_check().unwrap();
        let wrong_mode = SwapRequest::new(request.inputs().clone(), request.outputs().clone());
        let wrong_mode = if request.is_rerandomized() {
            wrong_mode
        } else {
            wrong_mode.with_rerandomization()
        };
        assert!(wrong_mode.verify_full_sig_all_check().is_err());

        let randomness = (mode == CommitmentMode::Rerandomized)
            .then_some(cashu::nuts::nut03::RerandomizationR([42; 32]));
        let issued =
            cdk_spilman::swap_completion::swap_restore_request(&request, randomness).unwrap();
        let signatures: Vec<_> = issued
            .outputs
            .iter()
            .map(|output| {
                BlindSignature::new(
                    output.amount,
                    cashu::dhke::sign_message(&mint, &output.blinded_secret).unwrap(),
                    output.keyset_id,
                    &output.blinded_secret,
                    &mint,
                )
                .unwrap()
            })
            .collect();
        let response = SwapResponse {
            signatures,
            rerandomization_r: randomness,
        };
        let proofs = outputs
            .complete_swap_response(response.clone(), &channel.params.keyset_info)
            .unwrap();
        assert_eq!(
            proofs
                .iter()
                .map(|p| u64::from(p.proof.amount))
                .sum::<u64>(),
            64
        );
        for proof in proofs {
            proof.proof.verify_dleq(mint.public_key()).unwrap();
        }
        let mut wrong_randomness = response.clone();
        wrong_randomness.rerandomization_r = if randomness.is_some() {
            None
        } else {
            Some(cashu::nuts::nut03::RerandomizationR([42; 32]))
        };
        assert!(outputs
            .complete_swap_response(wrong_randomness, &channel.params.keyset_info)
            .is_err());
        if randomness.is_some() {
            let mut wrong_randomness = response;
            wrong_randomness.rerandomization_r =
                Some(cashu::nuts::nut03::RerandomizationR([43; 32]));
            assert!(outputs
                .complete_swap_response(wrong_randomness, &channel.params.keyset_info)
                .is_err());
        }
    }
}

struct RestoreMint {
    state: cashu::nuts::CheckStateResponse,
    issued: cashu::nuts::RestoreResponse,
    queries: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl cdk_spilman::MintConnection for RestoreMint {
    async fn process_swap(&self, _: SwapRequest) -> anyhow::Result<SwapResponse> {
        panic!("recovery must never submit")
    }
    async fn check_state(
        &self,
        _: Vec<cashu::nuts::PublicKey>,
    ) -> anyhow::Result<cashu::nuts::CheckStateResponse> {
        Ok(self.state.clone())
    }
    async fn post_restore(
        &self,
        request: cashu::nuts::RestoreRequest,
    ) -> anyhow::Result<cashu::nuts::RestoreResponse> {
        self.queries
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut response = cashu::nuts::RestoreResponse {
            outputs: vec![],
            signatures: vec![],
        };
        for query in request.outputs {
            for (output, signature) in self.issued.outputs.iter().zip(&self.issued.signatures) {
                if query.blinded_secret == output.blinded_secret {
                    response.outputs.push(query.clone());
                    response.signatures.push(signature.clone());
                }
            }
        }
        Ok(response)
    }
}

#[tokio::test]
async fn sender_recovers_issued_points_and_rejects_missing_or_inconsistent_funding_evidence() {
    use cashu::nuts::nut03::RerandomizationR;
    use cdk_spilman::{ChannelRecovery, SpilmanChannelSender};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let (mut channel, alice, _, mint_key) = fixture(CommitmentMode::Rerandomized);
    // Use two funding proofs to exercise consistency across the entire input set.
    channel.params.maximum_amount_for_one_output = 32;
    let funding =
        DeterministicOutputsForOneContext::new("funding".to_owned(), 64, channel.params.clone())
            .unwrap()
            .get_secrets_with_blinding()
            .unwrap();
    channel.funding_proofs = funding
        .iter()
        .map(|o| {
            let message = o
                .to_blinded_message(o.amount.into(), channel.params.keyset_info.keyset_id)
                .unwrap();
            let signature = BlindSignature::new(
                message.amount,
                cashu::dhke::sign_message(&mint_key, &message.blinded_secret).unwrap(),
                message.keyset_id,
                &message.blinded_secret,
                &mint_key,
            )
            .unwrap();
            cashu::dhke::construct_proofs(
                vec![signature],
                vec![o.blinding_factor.clone()],
                vec![o.secret.clone()],
                &channel.params.keyset_info.active_keys,
            )
            .unwrap()
            .remove(0)
        })
        .collect();
    let commitment = CommitmentOutputs::for_balance(23, &channel.params).unwrap();
    let request = commitment
        .create_swap_request(channel.funding_proofs.clone(), None)
        .unwrap();
    let randomness = RerandomizationR([42; 32]);
    let outputs = cdk_spilman::swap_completion::swap_restore_request(&request, Some(randomness))
        .unwrap()
        .outputs;
    let signatures = outputs
        .iter()
        .map(|o| {
            BlindSignature::new(
                o.amount,
                cashu::dhke::sign_message(&mint_key, &o.blinded_secret).unwrap(),
                o.keyset_id,
                &o.blinded_secret,
                &mint_key,
            )
            .unwrap()
        })
        .collect();
    let states = channel
        .funding_proofs
        .iter()
        .map(|p| {
            let mut state =
                cashu::nuts::ProofState::from((p.y().unwrap(), cashu::nuts::State::Spent));
            state.rerandomization_r = Some(randomness);
            state
        })
        .collect();
    let mut mint = RestoreMint {
        state: cashu::nuts::CheckStateResponse { states },
        issued: cashu::nuts::RestoreResponse {
            outputs,
            signatures,
        },
        queries: AtomicUsize::new(0),
    };
    let keys = vec![channel.params.keyset_info.clone()];
    let sender = SpilmanChannelSender::new(alice, channel);
    let ChannelRecovery::Recovered { payout, .. } =
        sender.recover_funds(&mint, &[], &keys).await.unwrap()
    else {
        panic!("expected recovered sender payout")
    };
    assert_eq!(
        payout
            .proofs
            .iter()
            .map(|p| u64::from(p.amount))
            .sum::<u64>(),
        41
    );
    for proof in payout.proofs {
        proof.verify_dleq(mint_key.public_key()).unwrap();
    }
    assert!(mint.queries.load(Ordering::Relaxed) > 0);

    for invalid in [None, Some(RerandomizationR([43; 32]))] {
        mint.state.states[0].rerandomization_r = invalid;
        mint.queries.store(0, Ordering::Relaxed);
        assert!(sender.recover_funds(&mint, &[], &keys).await.is_err());
        assert_eq!(mint.queries.load(Ordering::Relaxed), 0);
    }
    for state in &mut mint.state.states {
        state.rerandomization_r = None;
    }
    assert!(sender.recover_funds(&mint, &[], &keys).await.is_err());
    assert_eq!(mint.queries.load(Ordering::Relaxed), 0);
}
