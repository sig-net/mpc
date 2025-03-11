use super::consensus::ConsensusCtx;
use super::contract::primitives::intersect_vec;
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
use cait_sith::PresignOutput;
use chrono::Utc;
use mpc_contract::config::ProtocolConfig;
use mpc_crypto::{derive_key, PublicKey};
use mpc_primitives::{SignArgs, SignId};
use rand::rngs::StdRng;
use rand::seq::{IteratorRandom, SliceRandom};
use rand::SeedableRng;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::fmt;
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

impl SignRequest {
    pub fn id(&self) -> &SignId {
        &self.indexed.id
    }
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

    fn contains(&self, sign_id: &SignId) -> bool {
        self.my_requests
            .iter()
            .any(|req| &req.indexed.id == sign_id)
            || self
                .other_requests
                .iter()
                .any(|req| &req.indexed.id == sign_id)
    }

    pub async fn organize(
        &mut self,
        threshold: usize,
        stable: &[Participant],
        my_account_id: &AccountId,
    ) {
        let mut stable = stable.to_vec();
        stable.sort();

        let mut sign_rx = self.sign_rx.write().await;
        while let Ok(indexed) = {
            match sign_rx.try_recv() {
                err @ Err(TryRecvError::Disconnected) => {
                    tracing::error!(target: "sign[queue]", "channel disconnected");
                    err
                }
                other => other,
            }
        } {
            let sign_id = indexed.id.clone();
            if self.contains(&sign_id) {
                tracing::info!(?sign_id, "skipping sign request: already in the sign queue");
                continue;
            }
            crate::metrics::NUM_UNIQUE_SIGN_REQUESTS
                .with_label_values(&[indexed.chain.as_str(), my_account_id.as_str()])
                .inc();
            let mut rng = StdRng::from_seed(indexed.args.entropy);
            let subset = stable.iter().copied().choose_multiple(&mut rng, threshold);
            let in_subset = subset.contains(&self.me);
            let proposer = *subset.choose(&mut rng).unwrap();
            let is_mine = proposer == self.me;

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

/// The handling of a possible pending Presignature that might or might not have
/// been proposed yet by a proposer node.
pub enum PresignatureStatus {
    Proposed(Presignature),
    Waiting(PresignatureStorage),
}

impl PresignatureStatus {
    /// Fetch the presignature.
    /// If the node is a proposer and already chose it, then simply return it.
    /// If the node is a non-proposer, then wait for it to pop into storage.
    /// Timeout on the generation timeout config of `SignatureConfig`.
    pub async fn fetch(
        self,
        inbox: &mut mpsc::Receiver<SignatureMessage>,
        cfg: &ProtocolConfig,
    ) -> Result<(Presignature, Option<SignatureMessage>), SignatureTaskError> {
        let storage = match self {
            PresignatureStatus::Proposed(presignature) => return Ok((presignature, None)),
            PresignatureStatus::Waiting(storage) => storage,
        };
        // Wait for the first message to arrive into the inbox, otherwise expire out with timeout:
        let started = Instant::now();
        let timeout = Duration::from_millis(cfg.signature.generation_timeout);
        let first_msg = match tokio::time::timeout(timeout, inbox.recv()).await {
            Ok(Some(msg)) => msg,
            Ok(None) => return Err(SignatureTaskError::Cancelled),
            _ => return Err(SignatureTaskError::TimeoutPresignatureNetwork),
        };

        let timeout_remaining = timeout - started.elapsed();
        // Proposer has chosen the presignature, so we can take it from the storage:
        let presignature = match storage
            .take(&first_msg.presignature_id, Some(timeout_remaining))
            .await
        {
            Ok(presignature) => presignature,
            Err(StoreError::Timeout(_)) => {
                return Err(SignatureTaskError::TimeoutPresignatureStorage(
                    first_msg.presignature_id,
                ))
            }
            Err(err) => {
                return Err(SignatureTaskError::Storage(err));
            }
        };

        tracing::info!(presignature.id, "sig[task].acceptor found presignature");

        Ok((presignature, Some(first_msg)))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureTaskError {
    #[error("sign[task] exhausted timeout")]
    Timeout(SignatureGenerator),
    #[error("sign[task] exhausted total timeout")]
    TimeoutTotal(SignatureGenerator),
    #[error("sign[task] protocol init failure: {0:?}")]
    Init(#[from] InitializationError),
    #[error("sign[task] protocol failure: {0:?}")]
    Protocol(ProtocolError, SignatureGenerator),
    #[error("sign[task] cancelled")]
    Cancelled,
    #[error("sign[task] could not find proposed presignature in time")]
    TimeoutPresignatureNetwork,
    #[error("sign[task] could not find stored presignature={0} in time")]
    TimeoutPresignatureStorage(PresignatureId),
    #[error("sign[task] store error: {0:?}")]
    Storage(#[from] StoreError),
}

type SignatureTaskResult = Result<SignatureGenerator, SignatureTaskError>;
type SignatureTask = tokio::task::JoinHandle<SignatureTaskResult>;

fn start_sign(
    me: Participant,
    public_key: PublicKey,
    presignature: Presignature,
    request: &SignRequest,
) -> Result<SignatureProtocol, SignatureTaskError> {
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
        "creating protocol to generate a new signature",
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

/// An ongoing signature generator.
pub struct SignatureGenerator {
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

impl fmt::Debug for SignatureGenerator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureGenerator")
            .field("epoch", &self.epoch)
            .field("presignature_id", &self.presignature_id)
            .field("public_key", &self.public_key)
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

impl SignatureGenerator {
    pub fn spawn(
        epoch: u64,
        me: Participant,
        status: PresignatureStatus,
        request: SignRequest,
        public_key: PublicKey,

        rpc: &RpcChannel,
        outbox: &MessageChannel,
        cfg: &ProtocolConfig,
    ) -> SignatureTask {
        let cfg = cfg.clone();
        let rpc = rpc.clone();
        let outbox = outbox.clone();
        tokio::spawn(async move {
            let timestamp = Instant::now();
            let mut inbox = outbox.subscribe_sign(epoch, &request.indexed.id).await;
            let (presignature, first_msg) = status.fetch(&mut inbox, &cfg).await?;

            let presignature_id = presignature.id;
            let mut protocol = start_sign(me, public_key, presignature, &request)?;
            if let Some(first_msg) = first_msg {
                // The first message was taken from the inbox so we need to send to the protocol here,
                // otherwise this message will be missed from the entirety of the protocol.
                protocol.message(first_msg.from, first_msg.data);
            }

            let generator = Self {
                epoch,
                me,
                public_key,
                presignature_id,
                protocol,
                request,
                timestamp,
                timeout: Duration::from_millis(cfg.signature.generation_timeout),
                timeout_total: Duration::from_millis(cfg.signature.generation_timeout_total),
            };

            generator.run(inbox, rpc, outbox).await
        })
    }

    pub async fn run(
        mut self,
        mut inbox: mpsc::Receiver<SignatureMessage>,
        rpc: RpcChannel,
        outbox: MessageChannel,
    ) -> SignatureTaskResult {
        'task: loop {
            'inbound: loop {
                let msg = match inbox.try_recv() {
                    Ok(msg) => msg,
                    Err(TryRecvError::Empty) => {
                        break 'inbound;
                    }
                    Err(TryRecvError::Disconnected) => {
                        break 'task Err(SignatureTaskError::Cancelled);
                    }
                };

                if msg.presignature_id == self.presignature_id {
                    self.protocol.message(msg.from, msg.data);
                }
            }

            'compute: loop {
                if self.request.indexed.timestamp.elapsed() >= self.timeout_total {
                    break 'task Err(SignatureTaskError::TimeoutTotal(self));
                }

                if self.timestamp.elapsed() >= self.timeout {
                    break 'task Err(SignatureTaskError::Timeout(self));
                }

                let action = match self.protocol.poke() {
                    Ok(action) => action,
                    Err(err) => {
                        break 'task Err(SignatureTaskError::Protocol(err, self));
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
                            outbox
                                .send(
                                    self.me,
                                    *to,
                                    SignatureMessage {
                                        id: self.request.id().clone(),
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
                        outbox
                            .send(
                                self.me,
                                to,
                                SignatureMessage {
                                    id: self.request.id().clone(),
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
                        tracing::info!(
                            sign_id = ?self.request.id(),
                            me = ?self.me,
                            presignature_id = ?self.presignature_id,
                            big_r = ?output.big_r.to_base58(),
                            s = ?output.s,
                            elapsed = ?self.timestamp.elapsed(),
                            "completed signature generation"
                        );
                        if self.request.proposer == self.me {
                            rpc.publish(self.public_key, self.request.clone(), output);
                        }

                        break 'task Ok(self);
                    }
                }
            }
        }
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

    presignatures: PresignatureStorage,
    rpc: RpcChannel,
    outbox: MessageChannel,
}

impl SignatureManager {
    pub fn new(
        ctx: &impl ConsensusCtx,
        me: Participant,
        threshold: usize,
        public_key: PublicKey,
        epoch: u64,
    ) -> Self {
        Self {
            generators: HashMap::new(),
            completed: HashMap::new(),
            sign_queue: SignQueue::new(me, ctx.sign_rx()),
            me,
            my_account_id: ctx.my_account_id().clone(),
            threshold,
            public_key,
            epoch,

            presignatures: ctx.presignature_storage().clone(),
            rpc: ctx.rpc_channel().clone(),
            outbox: ctx.msg_channel().clone(),
        }
    }

    pub fn me(&self) -> Participant {
        self.me
    }

    /// Starts a new signature generation protocol where our node is the proposer.
    pub async fn spawn_generation(
        &mut self,
        status: PresignatureStatus,
        request: SignRequest,
        cfg: &ProtocolConfig,
    ) {
        let entry = match &status {
            PresignatureStatus::Proposed(_) => "proposer starting",
            PresignatureStatus::Waiting(_) => "acceptor joining",
        };
        tracing::info!(sign_id = ?request.indexed.id, "sign[task]: {entry} protocol to generate a new signature");

        let sign_id = request.indexed.id.clone();
        let sign_task = SignatureGenerator::spawn(
            self.epoch,
            self.me,
            status,
            request,
            self.public_key,
            &self.rpc,
            &self.outbox,
            cfg,
        );
        self.generators.insert(sign_id, sign_task);
        crate::metrics::NUM_TOTAL_HISTORICAL_SIGNATURE_GENERATORS
            .with_label_values(&[self.my_account_id.as_str()])
            .inc();
    }

    async fn process_finished(&mut self) {
        if self.generators.is_empty() {
            return;
        }

        let finished_tasks = self
            .generators
            .iter()
            .map_while(|(sign_id, task)| task.is_finished().then(|| sign_id.clone()))
            .collect::<Vec<_>>();

        for sign_id in finished_tasks {
            let Some(task) = self.generators.remove(&sign_id) else {
                tracing::warn!(?sign_id, "sig[task] not found");
                continue;
            };
            let outcome = match task.await {
                Ok(outcome) => outcome,
                Err(err) => {
                    tracing::warn!(
                        ?sign_id,
                        ?err,
                        "sign[task] cancelled or panicked, trashing request"
                    );
                    continue;
                }
            };
            let err = match outcome {
                Err(err) => err,
                Ok(generator) => {
                    self.completed
                        .insert((sign_id, generator.presignature_id), Instant::now());
                    crate::metrics::SIGN_GENERATION_LATENCY
                        .with_label_values(&[self.my_account_id.as_str()])
                        .observe(generator.timestamp.elapsed().as_secs_f64());
                    continue;
                }
            };

            match err {
                SignatureTaskError::Storage(err) => {
                    // TODO: handle this case properly
                }
                err @ (SignatureTaskError::TimeoutPresignatureStorage(_)
                | SignatureTaskError::TimeoutPresignatureNetwork) => {
                    tracing::warn!(?sign_id, ?err, "sign[task] presignature fetch timeout");
                }
                SignatureTaskError::TimeoutTotal(generator) => {
                    tracing::warn!(
                        ?sign_id,
                        "sign[task] exhausted total timeout, trashing request"
                    );
                    self.completed
                        .insert((sign_id, generator.presignature_id), Instant::now());
                    if generator.request.proposer == self.me {
                        crate::metrics::SIGNATURE_GENERATOR_FAILURES
                            .with_label_values(&[self.my_account_id.as_str()])
                            .inc();
                        crate::metrics::SIGNATURE_FAILURES
                            .with_label_values(&[self.my_account_id.as_str()])
                            .inc();
                    }
                }
                SignatureTaskError::Timeout(generator) => {
                    tracing::warn!(?sign_id, "sign[task] timeout, retrying...");
                    self.completed
                        .insert((sign_id, generator.presignature_id), Instant::now());
                    if generator.request.proposer == self.me {
                        crate::metrics::SIGNATURE_GENERATOR_FAILURES
                            .with_label_values(&[self.my_account_id.as_str()])
                            .inc();
                    }
                    self.sign_queue.retry(generator.request);
                }
                SignatureTaskError::Init(err) => {
                    tracing::warn!(
                        ?sign_id,
                        ?err,
                        "sign[task] bad init parameters, tashing request"
                    );
                }
                SignatureTaskError::Protocol(err, generator) => {
                    tracing::warn!(?sign_id, ?err, "sign[task] protocol failed, retrying...");
                    self.completed
                        .insert((sign_id.clone(), generator.presignature_id), Instant::now());

                    if generator.request.proposer == self.me {
                        crate::metrics::SIGNATURE_GENERATOR_FAILURES
                            .with_label_values(&[self.my_account_id.as_str()])
                            .inc();
                    }
                    self.sign_queue.retry(generator.request);
                }
                SignatureTaskError::Cancelled => {
                    tracing::warn!(?sign_id, "sign[task] has been cancelled");
                }
            }
        }
    }

    pub async fn handle_requests(
        &mut self,
        stable: &[Participant],
        presignature_manager: &mut PresignatureManager,
        cfg: &ProtocolConfig,
    ) {
        if stable.len() < self.threshold {
            tracing::warn!(
                "require at least {} stable participants to handle_requests, got {}: {:?}",
                self.threshold,
                stable.len(),
                stable,
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
                intersect_vec(&[stable, &presignature.participants, &my_request.participants]);
            if participants.len() < self.threshold {
                tracing::warn!(
                    ?participants,
                    "intersection of stable participants and presignature participants is less than threshold, trashing presignature"
                );
                // TODO: do not insert back presignature when we have a clear model for data consistency
                // between nodes and utilizing only presignatures that meet threshold requirements.
                presignature_manager.insert(presignature, true, true).await;
                self.sign_queue.retry(my_request);
                continue;
            }

            self.spawn_generation(PresignatureStatus::Proposed(presignature), my_request, cfg)
                .await;
        }

        // TODO: might want to handle the case of bad init somehow
        while let Some(request) = self.sign_queue.take() {
            let status = PresignatureStatus::Waiting(self.presignatures.clone());
            self.spawn_generation(status, request, cfg).await;
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
        stable: &[Participant],
        protocol_cfg: &ProtocolConfig,
    ) -> tokio::task::JoinHandle<()> {
        let presignature_manager = state.presignature_manager.clone();
        let signature_manager = state.signature_manager.clone();
        let stable = stable.to_vec();
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
        }))
    }
}
