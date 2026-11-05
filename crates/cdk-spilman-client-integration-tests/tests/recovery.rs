//! Ordinary channel reconciliation: real mint races, direct and over HTTP.
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Result};
use async_trait::async_trait;
use cashu::dhke::{blind_message, construct_proofs};
use cashu::nuts::{
    BlindedMessage, CheckStateRequest, CheckStateResponse, CurrencyUnit, Proof, PublicKey,
    RestoreRequest, RestoreResponse, SecretKey, State, SwapRequest, SwapResponse,
};
use cashu::secret::Secret;
use cdk_spilman::{
    parse_keyset_info_from_json, ChannelFunding, ChannelParameters, ChannelRecovery, ChannelState,
    DeterministicOutputsForOneContext, EstablishedChannel, FundingState, MintConnection,
    PaymentProof, PreparedClose, PreparedSenderRefund, SelectedOutputKeyset, SenderRecoverySource,
    SpilmanBridge, SpilmanChannelSender, SpilmanHost,
};
use cdk_spilman_test_mint::{build_router, TestMintHelper, TestServerHost};

#[derive(Clone, Copy)]
enum StateFault {
    Force(State),
    Mixed,
    Missing,
    Duplicate,
    WrongIdentity,
    Reverse,
    Fail,
}

#[derive(Clone, Copy)]
enum RestoreFault {
    Empty,
    Partial,
    Fail,
}

struct Connection {
    mint: Arc<cdk::Mint>,
    url: Option<String>,
    client: reqwest::Client,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    calls: Mutex<Vec<&'static str>>,
    state_fault: Option<StateFault>,
    restore_fault: Option<RestoreFault>,
    lose_swap_reply: AtomicBool,
}

impl Connection {
    async fn new(mint: Arc<cdk::Mint>, http: bool) -> Result<Self> {
        let mut result = Self {
            mint,
            url: None,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()?,
            task: None,
            calls: Mutex::new(Vec::new()),
            state_fault: None,
            restore_fault: None,
            lose_swap_reply: AtomicBool::new(false),
        };
        if http {
            let router = build_router(Arc::clone(&result.mint)).await?;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            result.url = Some(format!("http://{}", listener.local_addr()?));
            result.task = Some(tokio::spawn(
                async move { axum::serve(listener, router).await },
            ));
        }
        Ok(result)
    }

    async fn post<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        request: &T,
    ) -> Result<R> {
        let response = self
            .client
            .post(format!(
                "{}{path}",
                self.url.as_ref().expect("HTTP connection")
            ))
            .json(request)
            .send()
            .await?;
        ensure!(
            response.status().is_success(),
            "mint HTTP rejected: {}",
            response.status()
        );
        Ok(response.json().await?)
    }

    fn reset_calls(&self) {
        self.calls.lock().expect("call log").clear();
    }

    fn assert_state_only(&self) {
        assert_eq!(*self.calls.lock().expect("call log"), vec!["state"]);
    }

    fn assert_state_before_restore(&self) {
        let calls = self.calls.lock().expect("call log");
        assert_eq!(calls.first(), Some(&"state"));
        assert!(calls[1..].iter().all(|call| *call == "restore"));
        assert!(calls.len() > 1);
    }

    async fn stop(&mut self) -> Result<()> {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
        self.mint.stop().await?;
        Ok(())
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

#[async_trait]
impl MintConnection for Connection {
    async fn process_swap(&self, request: SwapRequest) -> Result<SwapResponse> {
        self.calls.lock().expect("call log").push("swap");
        let response = if self.url.is_some() {
            self.post("/v1/swap", &request).await?
        } else {
            self.mint.process_swap_request(request).await?
        };
        ensure!(
            !self.lose_swap_reply.swap(false, Ordering::SeqCst),
            "injected lost swap reply after commit"
        );
        Ok(response)
    }

    async fn post_restore(&self, request: RestoreRequest) -> Result<RestoreResponse> {
        self.calls.lock().expect("call log").push("restore");
        if matches!(self.restore_fault, Some(RestoreFault::Fail)) {
            anyhow::bail!("injected restore failure");
        }
        if matches!(self.restore_fault, Some(RestoreFault::Empty)) {
            return Ok(RestoreResponse {
                outputs: vec![],
                signatures: vec![],
            });
        }
        let mut response = if self.url.is_some() {
            self.post("/v1/restore", &request).await?
        } else {
            self.mint.restore(request).await?
        };
        if matches!(self.restore_fault, Some(RestoreFault::Partial)) {
            response.signatures.clear();
        }
        Ok(response)
    }

    async fn check_state(&self, ys: Vec<PublicKey>) -> Result<CheckStateResponse> {
        self.calls.lock().expect("call log").push("state");
        if matches!(self.state_fault, Some(StateFault::Fail)) {
            anyhow::bail!("injected state failure");
        }
        let request = CheckStateRequest { ys };
        let mut response: CheckStateResponse = if self.url.is_some() {
            self.post("/v1/checkstate", &request).await?
        } else {
            self.mint.check_state(&request).await?
        };
        match self.state_fault {
            Some(StateFault::Force(state)) => {
                for s in &mut response.states {
                    s.state = state;
                }
            }
            Some(StateFault::Mixed) => {
                response.states[0].state = State::Spent;
            }
            Some(StateFault::Missing) => {
                response.states.pop();
            }
            Some(StateFault::Duplicate) => {
                response.states[1] = response.states[0].clone();
            }
            Some(StateFault::WrongIdentity) => {
                response.states[0].y = SecretKey::generate().public_key();
            }
            Some(StateFault::Reverse) => response.states.reverse(),
            _ => {}
        }
        Ok(response)
    }
}

struct Fixture {
    connection: Connection,
    sender: SpilmanChannelSender,
    receiver: SpilmanBridge<TestServerHost, ()>,
    close: PreparedClose,
    refund: PreparedSenderRefund,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs()
}

impl Fixture {
    async fn new(http: bool) -> Result<Self> {
        let helper = TestMintHelper::new().await?;
        let connection = Connection::new(helper.mint(), http).await?;
        let keyset_json = helper.keyset_info_json()?;
        let keyset = parse_keyset_info_from_json(&keyset_json).map_err(anyhow::Error::msg)?;
        let alice = SecretKey::generate();
        let charlie = SecretKey::generate();
        let params = ChannelParameters::new_with_secret_key(
            alice.public_key(),
            charlie.public_key(),
            connection
                .url
                .clone()
                .unwrap_or_else(|| "https://test-mint".to_string()),
            CurrencyUnit::Sat,
            32,
            32,
            now() - 1,
            now() - 100,
            keyset.clone(),
            8,
            &alice,
        )?;
        let outputs =
            DeterministicOutputsForOneContext::new("funding".to_string(), 32, params.clone())?;
        let funding = connection
            .process_swap(SwapRequest::new(
                helper.mint_proofs(32).await?,
                outputs.get_blinded_messages(None)?,
            ))
            .await?;
        let secrets = outputs.get_secrets_with_blinding()?;
        let funding_proofs = construct_proofs(
            funding.signatures,
            secrets.iter().map(|s| s.blinding_factor.clone()).collect(),
            secrets.iter().map(|s| s.secret.clone()).collect(),
            &keyset.active_keys,
        )?;
        let sender =
            SpilmanChannelSender::new(alice, EstablishedChannel::new(params, funding_proofs)?);
        assert!(sender.channel.funding_proofs.len() > 1);
        let (_, signed) = sender.create_signed_balance_update(7)?;
        let signature = cdk_spilman::get_signatures_from_swap_request(&signed)?
            .remove(0)
            .to_string();
        let payment = PaymentProof {
            balance: 7,
            signature,
        };
        let host = TestServerHost::new(charlie);
        host.add_keyset(
            &sender.channel.params.mint,
            keyset.keyset_id,
            keyset_json.clone(),
        );
        host.save_funding(
            &sender.channel_id(),
            ChannelFunding {
                params_json: sender.channel.params.get_channel_id_params_json(),
                funding_proofs_json: serde_json::to_string(&sender.channel.funding_proofs)?,
                channel_secret_hex: cashu::util::hex::encode(sender.channel.params.channel_secret),
                keyset_info_json: keyset_json.clone(),
            },
            payment.clone(),
        );
        host.mark_channel_closing(
            &sender.channel_id(),
            sender.channel.params.expiry_timestamp,
            payment,
        )
        .map_err(anyhow::Error::msg)?;
        let receiver = SpilmanBridge::new(host);
        let close = receiver
            .prepare_close_for_closing_channel_with_output_keyset(
                &sender.channel_id(),
                SelectedOutputKeyset {
                    id: keyset.keyset_id.to_string(),
                    info_json: keyset_json,
                },
            )
            .map_err(|error| anyhow::anyhow!(error.reason))?;
        let refund = sender.channel.prepare_sender_refund_after_expiry(
            sender.alice_secret.clone(),
            now(),
            keyset,
            [1; 32],
        )?;
        connection.reset_calls();
        Ok(Self {
            connection,
            sender,
            receiver,
            close,
            refund,
        })
    }

    async fn alice(&self) -> Result<ChannelRecovery<cdk_spilman::RecoveredSenderFunds>> {
        self.sender
            .recover_funds(
                &self.connection,
                std::slice::from_ref(&self.refund),
                std::slice::from_ref(&self.sender.channel.params.keyset_info),
            )
            .await
    }

    async fn charlie(&self) -> Result<ChannelRecovery<cdk_spilman::CompletedClose>> {
        self.receiver
            .recover_close(
                &self.sender.channel_id(),
                std::slice::from_ref(&self.close),
                &self.connection,
            )
            .await
    }
}

async fn spend(f: &Fixture, proofs: Vec<Proof>, expected: u64) -> Result<()> {
    assert_eq!(
        proofs.iter().map(|p| u64::from(p.amount)).sum::<u64>(),
        expected
    );
    let keys = &f.sender.channel.params.keyset_info;
    for p in &proofs {
        p.verify_dleq(keys.active_keys.amount_key(p.amount).expect("amount key"))?;
    }
    let mut outputs = Vec::new();
    let mut secrets = Vec::new();
    let mut rs = Vec::new();
    for amount in [1, 2, 4, 8, 16, 32] {
        if expected & amount == 0 {
            continue;
        }
        let secret = Secret::generate();
        let (b, r) = blind_message(&secret.to_bytes(), None)?;
        outputs.push(BlindedMessage::new(amount.into(), keys.keyset_id, b));
        secrets.push(secret);
        rs.push(r);
    }
    let response = f
        .connection
        .process_swap(SwapRequest::new(proofs, outputs))
        .await?;
    let loose = construct_proofs(response.signatures, rs, secrets, &keys.active_keys)?;
    assert_eq!(
        loose.iter().map(|p| u64::from(p.amount)).sum::<u64>(),
        expected
    );
    Ok(())
}

async fn rotate_refund_keys(f: &Fixture) -> Result<cdk_spilman::KeysetInfo> {
    let rotated = f
        .connection
        .mint
        .rotate_keyset(
            CurrencyUnit::Sat,
            vec![1, 2, 4, 8, 16, 32, 64],
            0,
            true,
            None,
        )
        .await?;
    let keys = f
        .connection
        .mint
        .keyset_pubkeys(&rotated.id)?
        .keysets
        .remove(0)
        .keys;
    Ok(cdk_spilman::KeysetInfo::new(
        rotated.id,
        CurrencyUnit::Sat,
        keys,
        0,
        None,
    ))
}

#[tokio::test(flavor = "multi_thread")]
async fn keyset_only_refund_recovers_either_candidate_through_shared_points() -> Result<()> {
    for http in [false, true] {
        for winner in [0, 1] {
            let mut f = Fixture::new(http).await?;
            if winner == 0 {
                f.connection
                    .process_swap(f.refund.swap_request.clone())
                    .await?;
            }
            let keys = rotate_refund_keys(&f).await?;
            let b = f
                .refund
                .with_output_keyset(&f.sender.channel, &f.sender.alice_secret, keys)?;
            let candidates = [f.refund.clone(), b];
            if winner == 1 {
                f.connection.lose_swap_reply.store(true, Ordering::SeqCst);
                assert!(f
                    .connection
                    .process_swap(candidates[1].swap_request.clone())
                    .await
                    .is_err());
            }
            let ChannelRecovery::Recovered { payout, .. } = f
                .sender
                .recover_funds(&f.connection, &candidates, &[])
                .await?
            else {
                panic!("missing refund payout")
            };
            assert_eq!(
                payout.source,
                SenderRecoverySource::Refund {
                    attempt_index: winner
                }
            );
            for proof in &payout.proofs {
                proof.verify_dleq(
                    candidates[winner]
                        .output_keyset
                        .active_keys
                        .amount_key(proof.amount)
                        .unwrap(),
                )?;
            }
            // Spend recovered ordinary proofs into currently active keys.
            let outputs = payout
                .proofs
                .iter()
                .map(|p| {
                    let (point, _) = blind_message(&Secret::generate().to_bytes(), None).unwrap();
                    BlindedMessage::new(p.amount, candidates[1].output_keyset.keyset_id, point)
                })
                .collect();
            f.connection
                .process_swap(SwapRequest::new(payout.proofs, outputs))
                .await?;
            f.connection.stop().await?;
        }
    }
    Ok(())
}

// Submission reaches the adapter but is held before mint execution, allowing
// Charlie to commit. This is a controlled race, not two successful spends.
struct HoldRefund<'a> {
    inner: &'a Connection,
    entered: tokio::sync::Notify,
}
#[async_trait]
impl MintConnection for HoldRefund<'_> {
    async fn process_swap(&self, _: SwapRequest) -> Result<SwapResponse> {
        self.entered.notify_one();
        std::future::pending().await
    }
    async fn post_restore(&self, request: RestoreRequest) -> Result<RestoreResponse> {
        self.inner.post_restore(request).await
    }
    async fn check_state(&self, ys: Vec<PublicKey>) -> Result<CheckStateResponse> {
        self.inner.check_state(ys).await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn close_wins_after_alice_submits_one_or_two_refund_candidates() -> Result<()> {
    for http in [false, true] {
        for two in [false, true] {
            let f = Fixture::new(http).await?;
            let gate = HoldRefund {
                inner: &f.connection,
                entered: tokio::sync::Notify::new(),
            };
            let a = gate.process_swap(f.refund.swap_request.clone());
            tokio::pin!(a);
            tokio::select! { _ = &mut a => panic!("held A returned"), _ = gate.entered.notified() => {} }
            let mut candidates = vec![f.refund.clone()];
            let mut close = f.close.clone();
            if two {
                let keys = rotate_refund_keys(&f).await?;
                // The exact A replay reaches the real mint and loses to rotation.
                assert!(f
                    .connection
                    .process_swap(f.refund.swap_request.clone())
                    .await
                    .is_err());
                candidates.push(f.refund.with_output_keyset(
                    &f.sender.channel,
                    &f.sender.alice_secret,
                    keys.clone(),
                )?);
                close = f.receiver.prepare_close_for_closing_channel_with_output_keyset(
                    &f.sender.channel_id(), SelectedOutputKeyset { id: keys.keyset_id.to_string(),
                        info_json: serde_json::json!({"keysetId":keys.keyset_id.to_string(),"unit":"sat","keys":keys.active_keys,"inputFeePpk":0}).to_string() }
                ).map_err(|e| anyhow::anyhow!(e.reason))?;
            }
            let b = gate.process_swap(candidates.last().unwrap().swap_request.clone());
            tokio::pin!(b);
            if two {
                tokio::select! { _ = &mut b => panic!("held B returned"), _ = gate.entered.notified() => {} }
            }
            f.connection
                .process_swap(serde_json::from_value(close.swap_request.clone())?)
                .await?;
            for candidate in &candidates {
                assert!(f
                    .connection
                    .process_swap(candidate.swap_request.clone())
                    .await
                    .is_err());
            }
            let close_keys = parse_keyset_info_from_json(&close.output_keyset_info.to_string())
                .map_err(anyhow::Error::msg)?;
            let ChannelRecovery::Recovered { payout, .. } = f
                .sender
                .recover_funds(
                    &f.connection,
                    &candidates,
                    std::slice::from_ref(&close_keys),
                )
                .await?
            else {
                panic!("missing close share")
            };
            assert_eq!(payout.source, SenderRecoverySource::ReceiverClose);
            let sum = payout
                .proofs
                .iter()
                .map(|p| u64::from(p.amount))
                .sum::<u64>();
            assert!(sum > 0 && sum < f.refund.output_amount_raw);
            let outputs = payout
                .proofs
                .iter()
                .map(|p| {
                    let (point, _) = blind_message(&Secret::generate().to_bytes(), None).unwrap();
                    BlindedMessage::new(p.amount, close_keys.keyset_id, point)
                })
                .collect();
            f.connection
                .process_swap(SwapRequest::new(payout.proofs, outputs))
                .await?;
            // Gate futures only borrow the connection; shut down the mint after
            // this scope via its shared handle.
            f.connection.mint.stop().await?;
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn close_wins_refund_falls_back_and_both_payouts_are_spendable() -> Result<()> {
    for http in [false, true] {
        let mut f = Fixture::new(http).await?;
        // Both requests are prepared. Charlie wins; the successful reply is discarded.
        f.connection.lose_swap_reply.store(true, Ordering::SeqCst);
        assert!(f
            .connection
            .process_swap(serde_json::from_value(f.close.swap_request.clone())?)
            .await
            .is_err());
        assert!(f
            .connection
            .process_swap(f.refund.swap_request.clone())
            .await
            .is_err());
        f.connection.reset_calls();
        let ChannelRecovery::Recovered { payout: alice, .. } = f.alice().await? else {
            panic!("Alice did not recover close payout")
        };
        assert_eq!(alice.source, SenderRecoverySource::ReceiverClose);
        f.connection.assert_state_before_restore();
        f.connection.reset_calls();
        let ChannelRecovery::Recovered {
            payout: charlie, ..
        } = f.charlie().await?
        else {
            panic!("Charlie did not recover close")
        };
        f.connection.assert_state_before_restore();
        assert_eq!(charlie.receiver_sum, 7);
        assert_eq!(charlie.sender_sum, 25);
        // Recovery does not mutate the host lifecycle or import proofs.
        assert_eq!(
            f.receiver
                .host()
                .get_channel_state(&f.sender.channel_id())
                .unwrap(),
            Some(ChannelState::Closing)
        );
        spend(&f, alice.proofs, 25).await?;
        spend(&f, serde_json::from_str(&charlie.receiver_proofs_json)?, 7).await?;
        f.connection.stop().await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn refund_wins_even_with_an_extra_signature() -> Result<()> {
    for http in [false, true] {
        let mut f = Fixture::new(http).await?;
        let mut awkward = f.refund.swap_request.clone();
        awkward.sign_sig_all(SecretKey::generate())?;
        f.connection.lose_swap_reply.store(true, Ordering::SeqCst);
        assert!(f.connection.process_swap(awkward).await.is_err());
        assert!(f
            .connection
            .process_swap(serde_json::from_value(f.close.swap_request.clone())?)
            .await
            .is_err());
        f.connection.reset_calls();
        let ChannelRecovery::Recovered { payout, .. } = f.alice().await? else {
            panic!("refund not recovered")
        };
        assert_eq!(
            payout.source,
            SenderRecoverySource::Refund { attempt_index: 0 }
        );
        f.connection.assert_state_before_restore();
        assert_eq!(
            f.connection.calls.lock().unwrap().len(),
            2,
            "must not discover close after verified refund"
        );
        spend(&f, payout.proofs, 32).await?;
        f.connection.reset_calls();
        assert!(matches!(
            f.charlie().await?,
            ChannelRecovery::SpentNoKnownPayout(_)
        ));
        f.connection.assert_state_before_restore();
        f.connection.stop().await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn state_gates_restoration_and_rejects_incomplete_or_wrong_evidence() -> Result<()> {
    let mut f = Fixture::new(false).await?;
    for (fault, expected) in [
        (None, FundingState::Unspent),
        (Some(StateFault::Reverse), FundingState::Unspent),
        (
            Some(StateFault::Force(State::Pending)),
            FundingState::Pending,
        ),
        (Some(StateFault::Mixed), FundingState::Mixed),
    ] {
        f.connection.state_fault = fault;
        f.connection.reset_calls();
        let state = f.sender.channel.inspect_funding(&f.connection).await?;
        assert_eq!(state.state(), expected);
        assert_eq!(
            state.response().states.len(),
            f.sender.channel.funding_proofs.len()
        );
        f.connection.reset_calls();
        let alice = f.alice().await?;
        assert!(matches!(
            alice,
            ChannelRecovery::Unspent(_) | ChannelRecovery::Pending(_) | ChannelRecovery::Mixed(_)
        ));
        f.connection.assert_state_only();
        f.connection.reset_calls();
        let charlie = f.charlie().await?;
        assert!(matches!(
            charlie,
            ChannelRecovery::Unspent(_) | ChannelRecovery::Pending(_) | ChannelRecovery::Mixed(_)
        ));
        f.connection.assert_state_only();
    }
    for fault in [
        StateFault::Missing,
        StateFault::Duplicate,
        StateFault::WrongIdentity,
        StateFault::Fail,
        StateFault::Force(State::Reserved),
    ] {
        f.connection.state_fault = Some(fault);
        f.connection.reset_calls();
        assert!(f.alice().await.is_err());
        f.connection.assert_state_only();
        f.connection.reset_calls();
        assert!(f.charlie().await.is_err());
        f.connection.assert_state_only();
    }
    f.connection.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_restore_is_not_a_failure_and_failed_restore_is_not_absence() -> Result<()> {
    let mut f = Fixture::new(false).await?;
    f.connection
        .process_swap(f.refund.swap_request.clone())
        .await?;
    for fault in [RestoreFault::Partial, RestoreFault::Fail] {
        f.connection.restore_fault = Some(fault);
        f.connection.reset_calls();
        assert!(f.alice().await.is_err());
        assert_eq!(
            *f.connection.calls.lock().unwrap(),
            vec!["state", "restore"],
            "failed refund restore must not enable discovery"
        );
        // Charlie's empty close restore is valid; inject a nonempty invalid response
        // by forcing a restore error instead of pretending it establishes refund.
        f.connection.restore_fault = Some(RestoreFault::Fail);
        f.connection.reset_calls();
        assert!(f.charlie().await.is_err());
        f.connection.assert_state_before_restore();
    }
    f.connection.restore_fault = Some(RestoreFault::Empty);
    assert!(matches!(
        f.alice().await?,
        ChannelRecovery::SpentNoKnownPayout(_)
    ));
    assert!(matches!(
        f.charlie().await?,
        ChannelRecovery::SpentNoKnownPayout(_)
    ));
    f.connection.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn attempts_are_authenticated_before_mint_io() -> Result<()> {
    let mut f = Fixture::new(false).await?;
    let mut wrong = f.refund.clone();
    wrong.channel_id = "wrong".to_string();
    assert!(f
        .sender
        .recover_funds(&f.connection, &[wrong], &[])
        .await
        .is_err());
    assert!(f.connection.calls.lock().unwrap().is_empty());
    let mut wrong = f.close.clone();
    wrong.balance += 1;
    assert!(f
        .receiver
        .recover_close(&f.sender.channel_id(), &[wrong], &f.connection)
        .await
        .is_err());
    assert!(f.connection.calls.lock().unwrap().is_empty());
    f.connection.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn partial_post_expiry_spend_is_mixed_not_a_classified_refund() -> Result<()> {
    let mut f = Fixture::new(true).await?;
    let proof = f.sender.channel.funding_proofs[0].clone();
    let secret = Secret::generate();
    let (b, _) = blind_message(&secret.to_bytes(), None)?;
    let output = BlindedMessage::new(proof.amount, proof.keyset_id, b);
    let mut partial = SwapRequest::new(vec![proof], vec![output]);
    partial.sign_sig_all(
        f.sender
            .channel
            .params
            .get_sender_blinded_secret_key_for_stage1_refund(&f.sender.alice_secret)?,
    )?;
    f.connection.process_swap(partial).await?;
    f.connection.reset_calls();
    assert!(matches!(f.charlie().await?, ChannelRecovery::Mixed(_)));
    f.connection.assert_state_only();
    f.connection.reset_calls();
    assert!(matches!(f.alice().await?, ChannelRecovery::Mixed(_)));
    f.connection.assert_state_only();
    // The host may abandon collection after expiry; no refund/close fact is invented.
    assert!(f
        .connection
        .process_swap(serde_json::from_value(f.close.swap_request.clone())?)
        .await
        .is_err());
    f.connection.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn historical_close_attempts_and_sender_discovery_use_verified_output_keys() -> Result<()> {
    let mut f = Fixture::new(false).await?;
    let rotated = f
        .connection
        .mint
        .rotate_keyset(
            CurrencyUnit::Sat,
            vec![1, 2, 4, 8, 16, 32, 64],
            0,
            true,
            None,
        )
        .await?;
    let keys = f
        .connection
        .mint
        .keyset_pubkeys(&rotated.id)?
        .keysets
        .remove(0)
        .keys;
    let info = serde_json::json!({"keysetId": rotated.id.to_string(), "unit":"sat", "keys":keys, "inputFeePpk":0}).to_string();
    let successor = f
        .receiver
        .prepare_close_for_closing_channel_with_output_keyset(
            &f.sender.channel_id(),
            SelectedOutputKeyset {
                id: rotated.id.to_string(),
                info_json: info.clone(),
            },
        )
        .map_err(|e| anyhow::anyhow!(e.reason))?;
    f.connection
        .process_swap(serde_json::from_value(successor.swap_request.clone())?)
        .await?;
    f.connection.reset_calls();
    // Restore may find the same point issued under the successor's keys. It is
    // invalid for the predecessor but must be tried against the retained successor.
    let attempts = [f.close.clone(), successor];
    let ChannelRecovery::Recovered { payout, .. } = f
        .receiver
        .recover_close(&f.sender.channel_id(), &attempts, &f.connection)
        .await?
    else {
        panic!("successor not restored")
    };
    assert_eq!((payout.receiver_sum, payout.sender_sum), (7, 25));
    f.connection.assert_state_before_restore();
    let keysets = [
        f.sender.channel.params.keyset_info.clone(),
        parse_keyset_info_from_json(&info).map_err(anyhow::Error::msg)?,
    ];
    let ChannelRecovery::Recovered { payout, .. } = f
        .sender
        .recover_funds(&f.connection, std::slice::from_ref(&f.refund), &keysets)
        .await?
    else {
        panic!("sender discovery failed")
    };
    assert_eq!(payout.source, SenderRecoverySource::ReceiverClose);
    assert!(payout.proofs.iter().all(|p| p.keyset_id == rotated.id));
    assert_eq!(
        payout
            .proofs
            .iter()
            .map(|p| u64::from(p.amount))
            .sum::<u64>(),
        25
    );
    // A malformed nonempty close restore is unresolved, not absence or a refund.
    f.connection.restore_fault = Some(RestoreFault::Partial);
    assert!(f
        .receiver
        .recover_close(&f.sender.channel_id(), &attempts, &f.connection)
        .await
        .is_err());
    assert!(f
        .sender
        .recover_funds(&f.connection, std::slice::from_ref(&f.refund), &keysets)
        .await
        .is_err());
    f.connection.stop().await?;
    Ok(())
}
