use super::contract::primitives::Participants;
use super::state::RunningState;
use crate::kdf::derive_delta;
use crate::protocol::message::{MessageChannel, SignatureMessage};
use crate::protocol::presignature::{Presignature, PresignatureId, PresignatureManager};
use crate::protocol::Chain;
use crate::rpc::RpcChannel;
use crate::storage::error::StoreError;
use crate::storage::PresignatureStorage;
use crate::types::SignatureProtocol;
use crate::util::AffinePointExt as _;

use cait_sith::protocol::{Action, InitializationError, Participant, ProtocolError};
use cait_sith::{FullSignature, PresignOutput};
use chrono::Utc;
use k256::Secp256k1;
use mpc_contract::config::ProtocolConfig;
use mpc_crypto::{derive_key, PublicKey};
use mpc_primitives::{SignArgs, SignId};
use rand::rngs::StdRng;
use rand::seq::{IteratorRandom, SliceRandom};
use rand::SeedableRng;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::{mpsc, RwLock};

use near_account_id::AccountId;

/// This is the maximum amount of sign requests that we can accept in the network.
const MAX_SIGN_REQUESTS: usize = 1024;

/// All relevant info pertaining to an Indexed sign request from an indexer.
#[derive(Debug, Clone, PartialEq)]
pub struct IndexedSignRequest {
    pub id: SignId,
    pub args: SignArgs,
    pub chain: Chain,
    pub timestamp: Instant,
}

/// The sign request for the node to process. This contains relevant info for the node
/// to generate a signature such as what has been indexed and what the node needs to maintain
/// metadata-wise to generate the signature.
#[derive(Debug, Clone, PartialEq)]
pub struct SignRequest {
    pub indexed: IndexedSignRequest,
    pub proposer: Participant,
    pub participants: Vec<Participant>,
}

pub struct SignQueue {
    me: Participant,
    sign_rx: Arc<RwLock<mpsc::Receiver<IndexedSignRequest>>>,
    my_requests: VecDeque<SignRequest>,
    other_requests: VecDeque<SignRequest>,
}

impl SignQueue {
    pub fn channel() -> (
        mpsc::Sender<IndexedSignRequest>,
        mpsc::Receiver<IndexedSignRequest>,
    ) {
        mpsc::channel(MAX_SIGN_REQUESTS)
    }

    pub fn new(me: Participant, sign_rx: Arc<RwLock<mpsc::Receiver<IndexedSignRequest>>>) -> Self {
        Self {
            me,
            sign_rx,
            my_requests: VecDeque::new(),
            other_requests: VecDeque::new(),
        }
    }

    pub fn len_mine(&self) -> usize {
        self.my_requests.len()
    }

    pub fn is_empty_mine(&self) -> bool {
        self.len_mine() == 0
    }

    pub fn len(&self) -> usize {
        self.my_requests.len() + self.other_requests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub async fn organize(
        &mut self,
        threshold: usize,
        stable: &Participants,
        my_account_id: &AccountId,
    ) {
        let mut sign_rx = self.sign_rx.write().await;
        while let Ok(indexed) = {
            match sign_rx.try_recv() {
                err @ Err(TryRecvError::Disconnected) => {
                    tracing::error!("sign queue channel disconnected");
                    err
                }
                other => other,
            }
        } {
            let mut rng = StdRng::from_seed(indexed.args.entropy);
            let subset = stable.keys().cloned().choose_multiple(&mut rng, threshold);
            let in_subset = subset.contains(&self.me);
            let proposer = *subset.choose(&mut rng).unwrap();
            let is_mine = proposer == self.me;
            let sign_id = indexed.id.clone();

            tracing::info!(
                ?sign_id,
                ?subset,
                ?proposer,
                in_subset,
                is_mine,
                "sign queue: organizing request"
            );

            if in_subset {
                tracing::info!(
                    ?sign_id,
                    "saving sign request: node is in the signer subset"
                );

                let request = SignRequest {
                    indexed,
                    proposer,
                    participants: subset,
                };
                if is_mine {
                    crate::metrics::NUM_SIGN_REQUESTS_MINE
                        .with_label_values(&[my_account_id.as_str()])
                        .inc();
                    self.my_requests.push_back(request);
                } else {
                    self.other_requests.push_back(request);
                }
            } else {
                tracing::info!(
                    ?sign_id,
                    "skipping sign request: node is NOT in the signer subset"
                );
            }
        }
    }

    pub fn retry(&mut self, request: SignRequest) {
        // NOTE: this prioritizes old requests first then tries to do new ones if there's enough presignatures.
        // TODO: we need to decide how to prioritize certain requests over others such as with gas or time of
        // when the request made it into the NEAR network.
        // issue: https://github.com/near/mpc-recovery/issues/596
        if request.proposer == self.me {
            self.my_requests.push_front(request);
        } else {
            self.other_requests.push_front(request);
        }
    }

    pub fn take_mine(&mut self) -> Option<SignRequest> {
        self.my_requests.pop_front()
    }

    pub fn take(&mut self) -> Option<SignRequest> {
        self.other_requests.pop_front()
    }

    pub fn expire(&mut self, cfg: &ProtocolConfig) {
        self.other_requests.retain(|request| {
            request.indexed.timestamp.elapsed()
                < Duration::from_millis(cfg.signature.generation_timeout_total)
        });
    }
}

pub enum PresignatureStatus {
    Proposer(Presignature),
    Waiting(PresignatureStorage),
}

// TODO: make this SignatureError
pub enum SignatureResult {
    Ready(SignatureGenerator),
    TimeoutTotal(SignatureGenerator),
    Timeout(SignatureGenerator),
    ProtocolError(SignatureGenerator, ProtocolError),
    TaskCancelled,
}

impl std::fmt::Debug for SignatureResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureResult::Ready(_) => write!(f, "SignaturePoll::Ready"),
            SignatureResult::Timeout(_) => write!(f, "SignaturePoll::Timeout"),
            SignatureResult::TimeoutTotal(_) => write!(f, "SignaturePoll::TimeoutTotal"),
            SignatureResult::TaskCancelled => write!(f, "SignaturePoll::TaskCancelled"),
            SignatureResult::ProtocolError(_, err) => {
                write!(f, "SignaturePoll::ProtocolError({err:?})")
            }
        }
    }
}

/// An ongoing signature generator.
pub struct SignatureGenerator {
    rpc: RpcChannel,
    outbox: MessageChannel,
    inbox_rx: mpsc::Receiver<SignatureMessage>,

    epoch: u64,
    me: Participant,
    public_key: PublicKey,
    protocol: SignatureProtocol,
    presignature_id: PresignatureId,
    request: SignRequest,
    timestamp: Instant,
    timeout: Duration,
    timeout_total: Duration,
}

fn start_sign(
    me: Participant,
    public_key: PublicKey,
    presignature: Presignature,
    request: &SignRequest,
) -> Result<
    Box<impl cait_sith::protocol::Protocol<Output = FullSignature<Secp256k1>>>,
    InitializationError,
> {
    let SignRequest {
        participants,
        indexed,
        ..
    } = request;
    let IndexedSignRequest { id, args, .. } = indexed;

    tracing::info!(
        sign_id = ?id,
        ?me,
        presignature_id = presignature.id,
        participants = ?request.participants,
        "starting protocol to generate a new signature",
    );

    let PresignOutput { big_r, k, sigma } = presignature.output;
    let delta = derive_delta(id.request_id, args.entropy, big_r);
    // TODO: Check whether it is okay to use invert_vartime instead
    let output = PresignOutput {
        big_r: (big_r * delta).to_affine(),
        k: k * delta.invert().unwrap(),
        sigma: (sigma + args.epsilon * k) * delta.invert().unwrap(),
    };
    Ok(Box::new(cait_sith::sign(
        participants,
        me,
        derive_key(public_key, args.epsilon),
        output,
        args.payload,
    )?))
}

impl SignatureGenerator {
    pub async fn spawn(
        epoch: u64,
        rpc: RpcChannel,
        outbox: MessageChannel,
        me: Participant,
        status: PresignatureStatus,
        request: SignRequest,
        public_key: PublicKey,
        cfg: ProtocolConfig,
        // TODO: better error type than InitializationError
    ) -> Result<Self, InitializationError> {
        let mut inbox_rx = outbox.subscribe_sign(epoch, &request.indexed.id).await;
        let presignature = match status {
            PresignatureStatus::Proposer(presignature) => presignature,
            PresignatureStatus::Waiting(storage) => {
                // Wait for the first message to arrive into the inbox, otherwise expire out with timeout:
                let started = Instant::now();
                let timeout = Duration::from_millis(cfg.signature.generation_timeout);
                let first_msg = match tokio::time::timeout(timeout, inbox_rx.recv()).await {
                    Ok(Some(msg)) => msg,
                    _ => {
                        return Err(InitializationError::BadParameters(
                            "joining signature protocol has not received initial message for presignature"
                                .to_string(),
                        ));
                    }
                };

                let timeout_remaining = timeout - started.elapsed();
                // Proposer has chosen the presignature, so we can take it from the storage:
                let presignature = match storage
                    .take(&first_msg.presignature_id, Some(timeout_remaining))
                    .await
                {
                    Ok(presignature) => presignature,
                    Err(StoreError::Timeout(_)) => {
                        return Err(InitializationError::BadParameters(
                            "timeout: presignature could not be found".to_string(),
                        ));
                    }
                    Err(err) => {
                        return Err(InitializationError::BadParameters(format!(
                            "presignature cannot be found: {err:?}",
                        )));
                    }
                };

                tracing::info!(
                    presignature.id,
                    "joining signature protocol, found presignature"
                );

                presignature
            }
        };

        Ok(Self {
            rpc: rpc.clone(),
            outbox: outbox.clone(),
            inbox_rx,
            epoch,
            me,
            public_key,
            presignature_id: presignature.id,
            protocol: start_sign(me, public_key, presignature, &request)?,
            request,
            timestamp: Instant::now(),
            timeout: Duration::from_millis(cfg.signature.generation_timeout),
            timeout_total: Duration::from_millis(cfg.signature.generation_timeout_total),
        })
    }

    pub async fn run(mut self) -> SignatureResult {
        'task: loop {
            'inbound: loop {
                let msg = match self.inbox_rx.try_recv() {
                    Ok(msg) => msg,
                    Err(TryRecvError::Empty) => {
                        break 'inbound;
                    }
                    Err(TryRecvError::Disconnected) => {
                        tracing::warn!("inbox channel closed");
                        break 'task SignatureResult::TaskCancelled;
                    }
                };

                if msg.presignature_id == self.presignature_id {
                    self.protocol.message(msg.from, msg.data);
                }
            }

            'compute: loop {
                if self.request.indexed.timestamp.elapsed() >= self.timeout_total {
                    tracing::warn!(
                        sign_id = ?self.request.indexed.id,
                        "signature protocol timeout completely",
                    );
                    break 'task SignatureResult::TimeoutTotal(self);
                }

                if self.timestamp.elapsed() >= self.timeout {
                    tracing::warn!(sign_id = ?self.request.indexed.id, "signature protocol timeout");
                    break 'task SignatureResult::Timeout(self);
                }

                let action = match self.protocol.poke() {
                    Ok(action) => action,
                    Err(err) => {
                        break 'task SignatureResult::ProtocolError(self, err);
                    }
                };
                match action {
                    Action::Wait => {
                        // TODO: add interval.tick here:
                        break 'compute;
                    }
                    Action::SendMany(data) => {
                        for to in self.request.participants.iter() {
                            if *to == self.me {
                                continue;
                            }
                            self.outbox
                                .send(
                                    self.me,
                                    *to,
                                    SignatureMessage {
                                        id: self.request.indexed.id.clone(),
                                        proposer: self.request.proposer,
                                        presignature_id: self.presignature_id,
                                        epoch: self.epoch,
                                        from: self.me,
                                        data: data.clone(),
                                        timestamp: Utc::now().timestamp() as u64,
                                    },
                                )
                                .await;
                        }
                    }
                    Action::SendPrivate(to, data) => {
                        self.outbox
                            .send(
                                self.me,
                                to,
                                SignatureMessage {
                                    id: self.request.indexed.id.clone(),
                                    proposer: self.request.proposer,
                                    presignature_id: self.presignature_id,
                                    epoch: self.epoch,
                                    from: self.me,
                                    data,
                                    timestamp: Utc::now().timestamp() as u64,
                                },
                            )
                            .await
                    }
                    Action::Return(output) => {
                        let sign_id = self.request.indexed.id.clone();
                        tracing::info!(
                            ?sign_id,
                            me = ?self.me,
                            presignature_id = ?self.presignature_id,
                            big_r = ?output.big_r.to_base58(),
                            s = ?output.s,
                            elapsed = ?self.timestamp.elapsed(),
                            "completed signature generation"
                        );
                        if self.request.proposer == self.me {
                            self.rpc
                                .publish(self.public_key, self.request.clone(), output);
                        }

                        break 'task SignatureResult::Ready(self);
                    }
                }
            }
        }
    }
}

struct SignatureTask {
    task: tokio::task::JoinHandle<SignatureResult>,
}

impl SignatureTask {
    fn spawn(
        epoch: u64,
        rpc: &RpcChannel,
        outbox: &MessageChannel,
        me: Participant,
        public_key: PublicKey,
        status: PresignatureStatus,
        request: SignRequest,
        cfg: &ProtocolConfig,
    ) -> Self {
        let gen = SignatureGenerator::spawn(
            epoch,
            rpc.clone(),
            outbox.clone(),
            me,
            status,
            request,
            public_key,
            cfg.clone(),
        );
        let task = tokio::spawn(async move {
            let gen = gen.await.unwrap();
            gen.run().await
        });
        Self { task }
    }
}

pub struct SignatureManager {
    /// Ongoing signature generation protocols.
    generators: HashMap<SignId, SignatureTask>,
    /// Set of completed signatures
    completed: HashMap<(SignId, PresignatureId), Instant>,
    /// Sign queue that maintains all requests coming in from indexer.
    sign_queue: SignQueue,

    me: Participant,
    my_account_id: AccountId,
    threshold: usize,
    public_key: PublicKey,
    epoch: u64,

    rpc: RpcChannel,
    outbox: MessageChannel,
}

impl SignatureManager {
    pub fn new(
        me: Participant,
        my_account_id: &AccountId,
        threshold: usize,
        public_key: PublicKey,
        epoch: u64,
        sign_rx: Arc<RwLock<mpsc::Receiver<IndexedSignRequest>>>,
        rpc: &RpcChannel,
        msg: &MessageChannel,
    ) -> Self {
        Self {
            generators: HashMap::new(),
            completed: HashMap::new(),
            sign_queue: SignQueue::new(me, sign_rx),
            me,
            my_account_id: my_account_id.clone(),
            threshold,
            public_key,
            epoch,
            rpc: rpc.clone(),
            outbox: msg.clone(),
        }
    }

    pub fn me(&self) -> Participant {
        self.me
    }

    /// Starts a new signature generation protocol where our node is the proposer.
    pub async fn generate(
        &mut self,
        presignature: Presignature,
        request: SignRequest,
        cfg: &ProtocolConfig,
    ) -> Result<(), InitializationError> {
        let sign_id = request.indexed.id.clone();
        self.generators.insert(
            sign_id,
            SignatureTask::spawn(
                self.epoch,
                &self.rpc,
                &self.outbox,
                self.me,
                self.public_key,
                PresignatureStatus::Proposer(presignature),
                request,
                cfg,
            ),
        );
        crate::metrics::NUM_TOTAL_HISTORICAL_SIGNATURE_GENERATORS
            .with_label_values(&[self.my_account_id.as_str()])
            .inc();
        Ok(())
    }

    async fn process_finished(&mut self) {
        if self.generators.is_empty() {
            return;
        }

        let finished_tasks = self
            .generators
            .iter()
            .map_while(|(sign_id, generator)| generator.task.is_finished().then(|| sign_id.clone()))
            .collect::<Vec<_>>();

        for sign_id in finished_tasks {
            let Some(generator) = self.generators.remove(&sign_id) else {
                tracing::warn!(?sign_id, "unexpected, signature task not found");
                continue;
            };
            let outcome = match generator.task.await {
                Ok(result) => result,
                Err(err) => {
                    tracing::warn!(?err, "signature task failed");
                    // TODO: check timeout for timeout and retry
                    continue;
                }
            };
            match outcome {
                SignatureResult::Ready(generator) => {
                    crate::metrics::SIGN_GENERATION_LATENCY
                        .with_label_values(&[self.my_account_id.as_str()])
                        .observe(generator.timestamp.elapsed().as_secs_f64());

                    self.completed
                        .insert((sign_id, generator.presignature_id), Instant::now());
                }
                SignatureResult::Timeout(generator) => {
                    self.completed
                        .insert((sign_id, generator.presignature_id), Instant::now());
                    tracing::warn!("signature failed to be produced in time; retrying");

                    if generator.request.proposer == self.me {
                        crate::metrics::SIGNATURE_GENERATOR_FAILURES
                            .with_label_values(&[self.my_account_id.as_str()])
                            .inc();
                    }
                    self.sign_queue.retry(generator.request);
                }
                SignatureResult::ProtocolError(generator, err) => {
                    self.completed
                        .insert((sign_id.clone(), generator.presignature_id), Instant::now());
                    tracing::warn!(?err, "signature generation failed; retrying");

                    if generator.request.proposer == self.me {
                        crate::metrics::SIGNATURE_GENERATOR_FAILURES
                            .with_label_values(&[self.my_account_id.as_str()])
                            .inc();
                    }
                    self.sign_queue.retry(generator.request);
                }
                SignatureResult::TimeoutTotal(generator) => {
                    self.completed
                        .insert((sign_id.clone(), generator.presignature_id), Instant::now());
                    tracing::warn!("signature total timeout expended; trashing request");
                    if generator.request.proposer == self.me {
                        crate::metrics::SIGNATURE_GENERATOR_FAILURES
                            .with_label_values(&[self.my_account_id.as_str()])
                            .inc();
                        crate::metrics::SIGNATURE_FAILURES
                            .with_label_values(&[self.my_account_id.as_str()])
                            .inc();
                    }
                }
                SignatureResult::TaskCancelled => {
                    tracing::warn!("signature task cancelled");
                    // self.completed
                    //     .insert((sign_id.clone(), generator.presignature_id), Instant::now());
                }
            }
        }
    }

    pub async fn handle_requests(
        &mut self,
        stable: &Participants,
        presignature_manager: &mut PresignatureManager,
        cfg: &ProtocolConfig,
    ) {
        if stable.len() < self.threshold {
            tracing::warn!(
                "Require at least {} stable participants to handle_requests, got {}: {:?}",
                self.threshold,
                stable.len(),
                stable.keys_vec()
            );
            return;
        }

        self.sign_queue.expire(cfg);
        self.sign_queue
            .organize(self.threshold, stable, &self.my_account_id)
            .await;
        crate::metrics::SIGN_QUEUE_SIZE
            .with_label_values(&[self.my_account_id.as_str()])
            .set(self.sign_queue.len() as i64);
        crate::metrics::SIGN_QUEUE_MINE_SIZE
            .with_label_values(&[self.my_account_id.as_str()])
            .set(self.sign_queue.len_mine() as i64);

        while let Some(presignature) = {
            if self.sign_queue.is_empty_mine() {
                None
            } else {
                presignature_manager.take_mine().await
            }
        } {
            let Some(my_request) = self.sign_queue.take_mine() else {
                tracing::warn!("unexpected state, no more requests to handle");
                continue;
            };

            let participants =
                stable.intersection(&[&presignature.participants, &my_request.participants]);
            if participants.len() < self.threshold {
                tracing::warn!(
                    participants = ?participants.keys_vec(),
                    "intersection of stable participants and presignature participants is less than threshold, trashing presignature"
                );
                // TODO: do not insert back presignature when we have a clear model for data consistency
                // between nodes and utilizing only presignatures that meet threshold requirements.
                presignature_manager.insert(presignature, true, true).await;
                continue;
            }

            let sign_id = my_request.indexed.id.clone();
            let presignature_id = presignature.id;
            if let Err(InitializationError::BadParameters(err)) =
                self.generate(presignature, my_request, cfg).await
            {
                tracing::warn!(
                    ?sign_id,
                    presignature_id,
                    ?err,
                    "failed to start signature generation: trashing presignature"
                );
                continue;
            }
        }

        while let Some(request) = self.sign_queue.take() {
            let sign_id = request.indexed.id.clone();
            tracing::info!(?sign_id, "joining protocol to generate a new signature");
            let task = SignatureTask::spawn(
                self.epoch,
                &self.rpc,
                &self.outbox,
                self.me,
                self.public_key,
                PresignatureStatus::Waiting(presignature_manager.presignature_storage.clone()),
                request,
                cfg,
            );
            crate::metrics::NUM_TOTAL_HISTORICAL_SIGNATURE_GENERATORS
                .with_label_values(&[self.my_account_id.as_str()])
                .inc();
            self.generators.insert(sign_id, task);
        }
    }

    /// Garbage collect all the completed signatures.
    pub fn garbage_collect(&mut self, cfg: &ProtocolConfig) {
        let before = self.completed.len();
        self.completed.retain(|_, timestamp| {
            timestamp.elapsed() < Duration::from_millis(cfg.signature.garbage_timeout)
        });
        let garbage_collected = before.saturating_sub(self.completed.len());
        if garbage_collected > 0 {
            tracing::debug!(
                "garbage collected {} completed signatures",
                garbage_collected
            );
        }
    }

    pub fn refresh_gc(&mut self, sign_id: &SignId, presignature_id: PresignatureId) -> bool {
        let entry = self
            .completed
            .entry((sign_id.clone(), presignature_id))
            .and_modify(|e| *e = Instant::now());
        matches!(entry, Entry::Occupied(_))
    }

    pub fn execute(
        state: &RunningState,
        stable: &Participants,
        protocol_cfg: &ProtocolConfig,
    ) -> tokio::task::JoinHandle<()> {
        let presignature_manager = state.presignature_manager.clone();
        let signature_manager = state.signature_manager.clone();
        let stable = stable.clone();
        let protocol_cfg = protocol_cfg.clone();

        // NOTE: signatures should only use stable and not active participants. The difference here is that
        // stable participants utilizes more than the online status of a node, such as whether or not their
        // block height is up to date, such that they too can process signature requests. If they cannot
        // then they are considered unstable and should not be a part of signature generation this round.

        tokio::task::spawn(tokio::task::unconstrained(async move {
            let mut signature_manager = signature_manager.write().await;
            let mut presignature_manager = presignature_manager.write().await;
            signature_manager
                .handle_requests(&stable, &mut presignature_manager, &protocol_cfg)
                .await;
            drop(presignature_manager);
            signature_manager.process_finished().await;
            // signature_manager.poke(rpc).await;
        }))
    }
}
