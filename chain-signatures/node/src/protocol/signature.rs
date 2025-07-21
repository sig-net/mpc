use super::contract::primitives::intersect_vec;
use super::MpcSignProtocol;
use crate::config::Config;
use crate::kdf::derive_delta;
use crate::mesh::MeshState;
use crate::protocol::message::{MessageChannel, PositMessage, PositProtocolId, SignatureMessage};
use crate::protocol::posit::{PositAction, PositInternalAction, Positor, Posits};
use crate::protocol::presignature::PresignatureId;
use crate::protocol::Chain;
use crate::rpc::RpcChannel;
use crate::storage::presignature_storage::{PresignatureTaken, PresignatureTakenDropper};
use crate::storage::PresignatureStorage;
use crate::types::SignatureProtocol;
use crate::util::{AffinePointExt, JoinMap};

use cait_sith::protocol::{Action, InitializationError, Participant};
use cait_sith::PresignOutput;
use chrono::Utc;
use k256::Secp256k1;
use mpc_contract::config::ProtocolConfig;
use mpc_crypto::{derive_key, PublicKey};
use mpc_primitives::{SignArgs, SignId};
use rand::rngs::StdRng;
use rand::seq::{IteratorRandom, SliceRandom};
use rand::SeedableRng;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::{mpsc, oneshot, watch, RwLock};
use tokio::task::{JoinHandle, JoinSet};

use near_account_id::AccountId;

/// This is the maximum amount of sign requests that we can accept in the network.
const MAX_SIGN_REQUESTS: usize = 1024;

/// All relevant info pertaining to an Indexed sign request from an indexer.
#[derive(Debug, Clone, PartialEq)]
pub struct IndexedSignRequest {
    pub id: SignId,
    pub args: SignArgs,
    pub chain: Chain,
    pub unix_timestamp_indexed: u64,
    pub timestamp_sign_queue: Option<Instant>,
    pub total_timeout: Duration,
}

#[allow(clippy::large_enum_variant)]
pub enum PendingRequest {
    Available(SignRequest),
    Pending(SignId, oneshot::Receiver<SignRequest>),
}

impl PendingRequest {
    fn id(&self) -> SignId {
        match self {
            Self::Available(request) => request.indexed.id,
            Self::Pending(id, _) => *id,
        }
    }

    async fn fetch(self, timeout: Duration) -> Option<SignRequest> {
        match self {
            PendingRequest::Available(request) => Some(request),
            PendingRequest::Pending(sign_id, channel) => {
                match tokio::time::timeout(timeout, channel).await {
                    Ok(Ok(request)) => Some(request),
                    Ok(Err(_)) => {
                        tracing::warn!(
                            ?sign_id,
                            "pending sign request channel closed before receiving request"
                        );
                        None
                    }
                    Err(_) => {
                        tracing::warn!(
                            ?sign_id,
                            ?timeout,
                            "timeout waiting for pending sign request"
                        );
                        None
                    }
                }
            }
        }
    }
}

/// The sign request for the node to process. This contains relevant info for the node
/// to generate a signature such as what has been indexed and what the node needs to maintain
/// metadata-wise to generate the signature.
#[derive(Debug, Clone, PartialEq)]
pub struct SignRequest {
    pub indexed: IndexedSignRequest,
    pub proposer: Participant,
    pub participants: Vec<Participant>,
    pub stable: Vec<Participant>,
}

pub struct SignQueue {
    me: Participant,
    sign_rx: Arc<RwLock<mpsc::Receiver<IndexedSignRequest>>>,
    /// The requests that belong to us where we will the propose the signature to the chain.
    my_requests: VecDeque<SignId>,
    /// Set of requests that failed to be processed during signature generation and need to
    /// be reorganized with a potentially newer set of stable participants.
    failed_requests: VecDeque<SignId>,
    /// The pool of requests that we are about to process or are currently processing. Only
    /// to be removed when fully timing out or when the request is completed.
    requests: HashMap<SignId, SignRequest>,
    /// The set of pending request listeners that are waiting for a sign request to be indexed.
    /// They will be notified when a sign request is available.
    pending: HashMap<SignId, oneshot::Sender<SignRequest>>,
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
            requests: HashMap::new(),
            failed_requests: VecDeque::new(),
            pending: HashMap::new(),
        }
    }

    pub fn len_mine(&self) -> usize {
        self.my_requests.len()
    }

    pub fn is_empty_mine(&self) -> bool {
        self.len_mine() == 0
    }

    /// Length of requests that are currently in the sign queue. This includes all requests that
    /// our node has observed, which means this does not include pending requests.
    pub fn len(&self) -> usize {
        self.requests.len()
    }

    /// Returns true if the sign queue is empty. Excludes pending requests.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn contains(&self, sign_id: &SignId) -> bool {
        self.requests.contains_key(sign_id)
    }

    fn organize_request(
        &self,
        threshold: usize,
        stable: &[Participant],
        indexed: IndexedSignRequest,
        reorganize: bool,
    ) -> SignRequest {
        let sign_id = indexed.id;
        // NOTE: reorganize, will use the same entropy for reorganizing the participants. The only
        // thing that would be different is the passed in stable participants.
        let mut rng = StdRng::from_seed(indexed.args.entropy);
        let subset = stable.iter().copied().choose_multiple(&mut rng, threshold);
        let in_subset = subset.contains(&self.me);
        let proposer = *subset.choose(&mut rng).unwrap();
        let is_mine = proposer == self.me;

        tracing::info!(
            ?stable,
            ?sign_id,
            ?subset,
            ?proposer,
            me = ?self.me,
            in_subset,
            is_mine,
            "sign queue: {}organizing request",
            if reorganize { "re" } else { "" },
        );

        let request = SignRequest {
            indexed,
            proposer,
            participants: subset,
            stable: stable.to_vec(),
        };

        if in_subset {
            tracing::info!(
                ?sign_id,
                "saving sign request: node is in the {}signer subset",
                if reorganize { "reorganized " } else { "" },
            );
        } else {
            tracing::info!(
                ?sign_id,
                "skipping sign request: node is NOT in the {}signer subset",
                if reorganize { "reorganized " } else { "" },
            );
        }

        request
    }

    pub async fn organize(
        &mut self,
        threshold: usize,
        stable: &[Participant],
        my_account_id: &AccountId,
    ) {
        let mut stable = stable.to_vec();
        stable.sort();

        // Reorganize the failed requests with a potentially newer list of stable participants.
        self.organize_failed(threshold, &stable, my_account_id);

        // try and organize the new incoming requests.
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
            let sign_id = indexed.id;
            if self.contains(&sign_id) {
                tracing::info!(?sign_id, "skipping sign request: already in the sign queue");
                continue;
            }
            crate::metrics::NUM_UNIQUE_SIGN_REQUESTS
                .with_label_values(&[indexed.chain.as_str(), my_account_id.as_str()])
                .inc();

            let request = self.organize_request(threshold, &stable, indexed, false);
            let is_mine = request.proposer == self.me;
            if is_mine {
                self.my_requests.push_back(sign_id);
                crate::metrics::NUM_SIGN_REQUESTS_MINE
                    .with_label_values(&[my_account_id.as_str()])
                    .inc();
            }
            if let Some(pending) = self.pending.remove(&sign_id) {
                if pending.send(request.clone()).is_err() {
                    tracing::warn!(
                        ?sign_id,
                        "pending sign request channel closed before able to send request"
                    );
                }
            }

            self.requests.insert(sign_id, request);
        }
    }

    fn organize_failed(
        &mut self,
        threshold: usize,
        stable: &[Participant],
        my_account_id: &AccountId,
    ) {
        while let Some(id) = self.failed_requests.pop_front() {
            let Some(request) = self.requests.remove(&id) else {
                continue;
            };

            let (reorganized, request) = if request.stable == stable {
                // just use the same request if the participants are the same
                (false, request)
            } else {
                let request = self.organize_request(threshold, stable, request.indexed, true);
                (true, request)
            };

            // NOTE: this prioritizes old requests first then tries to do new ones if there's enough presignatures.
            // TODO: we need to decide how to prioritize certain requests over others such as with gas or time of
            // when the request made it into the NEAR network.
            // issue: https://github.com/near/mpc-recovery/issues/596
            if request.proposer == self.me {
                self.my_requests.push_front(request.indexed.id);
                if reorganized {
                    crate::metrics::NUM_SIGN_REQUESTS_MINE
                        .with_label_values(&[my_account_id.as_str()])
                        .inc();
                }
            }

            self.requests.insert(request.indexed.id, request);
        }
    }

    pub fn push_failed(&mut self, sign_id: SignId) {
        self.failed_requests.push_back(sign_id);
    }

    pub fn take_mine(&mut self) -> Option<SignRequest> {
        let id = self.my_requests.pop_front()?;
        self.requests.get(&id).cloned()
    }

    pub fn get_or_pending(&mut self, id: &SignId) -> PendingRequest {
        if let Some(request) = self.requests.get(id) {
            PendingRequest::Available(request.clone())
        } else {
            let (tx, rx) = oneshot::channel();
            self.pending.insert(*id, tx);
            PendingRequest::Pending(*id, rx)
        }
    }

    pub fn expire(&mut self, cfg: &ProtocolConfig) {
        self.requests.retain(|_, request| {
            request.indexed.timestamp_sign_queue.is_none_or(|t| {
                t.elapsed() < Duration::from_millis(cfg.signature.generation_timeout_total)
            })
        });
        self.my_requests.retain(|id| {
            let Some(request) = self.requests.get(id) else {
                // if we are unable to find the corresponding request, we can remove it.
                return false;
            };
            crate::util::duration_between_unix(
                request.indexed.unix_timestamp_indexed,
                crate::util::current_unix_timestamp(),
            ) < request.indexed.total_timeout
        });
        self.failed_requests.retain(|id| {
            let Some(request) = self.requests.get(id) else {
                // if we are unable to find the corresponding request, we can remove it.
                return false;
            };
            crate::util::duration_between_unix(
                request.indexed.unix_timestamp_indexed,
                crate::util::current_unix_timestamp(),
            ) < request.indexed.total_timeout
        });
    }

    pub fn remove(&mut self, sign_id: SignId) -> Option<SignRequest> {
        self.requests.remove(&sign_id)
    }
}

enum SignError {
    Retry,
    TotalTimeout,
    Aborted,
}

/// An ongoing signature generator.
struct SignatureGenerator {
    protocol: SignatureProtocol,
    dropper: PresignatureTakenDropper,
    request: SignRequest,
    public_key: PublicKey,
    created: Instant,
    timeout: Duration,
    timeout_total: Duration,
    inbox: mpsc::Receiver<SignatureMessage>,
    msg: MessageChannel,
    rpc: RpcChannel,
}

impl SignatureGenerator {
    #[allow(clippy::too_many_arguments)]
    async fn new(
        me: Participant,
        request: PendingRequest,
        presignature: PendingPresignature,
        participants: Vec<Participant>,
        public_key: PublicKey,
        cfg: ProtocolConfig,
        msg: MessageChannel,
        rpc: RpcChannel,
    ) -> Result<Self, InitializationError> {
        let sign_id = request.id();
        let request = request
            .fetch(Duration::from_millis(cfg.signature.generation_timeout))
            .await
            .ok_or_else(|| {
                InitializationError::BadParameters(format!(
                    "sign request {sign_id:?} not found or timeout"
                ))
            })?;
        let presignature_id = presignature.id();
        let taken = presignature
            .fetch(me, Duration::from_millis(cfg.signature.generation_timeout))
            .await
            .ok_or_else(|| {
                InitializationError::BadParameters(format!(
                    "presignature {presignature_id} not found or timeout",
                ))
            })?;

        let indexed = &request.indexed;
        let sign_id = indexed.id;
        tracing::info!(
            ?me,
            ?sign_id,
            presignature_id,
            "starting protocol to generate a new signature",
        );

        let (presignature, dropper) = taken.take();
        let PresignOutput { big_r, k, sigma } = presignature.output;
        let delta = derive_delta(indexed.id.request_id, indexed.args.entropy, big_r);
        // TODO: Check whether it is okay to use invert_vartime instead
        let output: PresignOutput<Secp256k1> = PresignOutput {
            big_r: (big_r * delta).to_affine(),
            k: k * delta.invert().unwrap(),
            sigma: (sigma + indexed.args.epsilon * k) * delta.invert().unwrap(),
        };
        let protocol = Box::new(cait_sith::sign(
            &participants,
            me,
            derive_key(public_key, indexed.args.epsilon),
            output,
            indexed.args.payload,
        )?);
        let inbox = msg.subscribe_signature(sign_id, presignature_id).await;
        Ok(Self {
            protocol,
            dropper,
            request,
            public_key,
            created: Instant::now(),
            timeout: Duration::from_millis(cfg.signature.generation_timeout),
            timeout_total: Duration::from_millis(cfg.signature.generation_timeout_total),
            inbox,
            msg,
            rpc,
        })
    }

    fn timeout(&self) -> bool {
        self.created.elapsed() >= self.timeout
    }

    fn timeout_total(&self) -> bool {
        let timestamp = self
            .request
            .indexed
            .timestamp_sign_queue
            .as_ref()
            .unwrap_or(&self.created);
        timestamp.elapsed() >= self.timeout_total
    }

    async fn run(
        mut self,
        me: Participant,
        epoch: u64,
        my_account_id: AccountId,
    ) -> Result<(), SignError> {
        let accrued_wait_delay = crate::metrics::SIGNATURE_ACCRUED_WAIT_DELAY
            .with_label_values(&[my_account_id.as_str()]);
        let poke_counts =
            crate::metrics::SIGNATURE_POKES_CNT.with_label_values(&[my_account_id.as_str()]);
        let signature_generator_failures_metric = crate::metrics::SIGNATURE_GENERATOR_FAILURES
            .with_label_values(&[my_account_id.as_str()]);
        let signature_failures_metric =
            crate::metrics::SIGNATURE_FAILURES.with_label_values(&[my_account_id.as_str()]);
        let poke_latency =
            crate::metrics::SIGNATURE_POKE_CPU_TIME.with_label_values(&[my_account_id.as_str()]);

        let sign_id = self.request.indexed.id;
        let presignature_id = self.dropper.id;

        let mut total_wait = Duration::from_millis(0);
        let mut total_pokes = 0;
        let mut poke_last_time = self.created;
        crate::metrics::SIGNATURE_BEFORE_POKE_DELAY
            .with_label_values(&[my_account_id.as_str()])
            .observe(self.created.elapsed().as_millis() as f64);

        loop {
            if self.timeout_total() {
                tracing::warn!(
                    ?sign_id,
                    presignature_id,
                    "signature generation timeout, exhausted all attempts"
                );
                if self.request.proposer == me {
                    signature_generator_failures_metric.inc();
                    signature_failures_metric.inc();
                }
                break Err(SignError::TotalTimeout);
            }

            if self.timeout() {
                tracing::warn!(
                    ?sign_id,
                    presignature_id,
                    "signature generation timeout, retrying..."
                );
                if self.request.proposer == me {
                    signature_generator_failures_metric.inc();
                }
                break Err(SignError::Retry);
            }

            let poke_start_time = Instant::now();
            let action = match self.protocol.poke() {
                Ok(action) => action,
                Err(err) => {
                    tracing::error!(
                        ?sign_id,
                        ?err,
                        "signature generation failed on protocol advancement",
                    );
                    break Err(SignError::Retry);
                }
            };

            total_wait += poke_start_time - poke_last_time;
            total_pokes += 1;
            poke_last_time = Instant::now();
            poke_latency.observe(poke_start_time.elapsed().as_millis() as f64);

            match action {
                Action::Wait => {
                    // Wait for the next set of messages to arrive.
                    let Some(msg) = self.inbox.recv().await else {
                        break Err(SignError::Aborted);
                    };
                    self.protocol.message(msg.from, msg.data);
                }
                Action::SendMany(data) => {
                    for to in self.request.participants.iter() {
                        if *to == me {
                            continue;
                        }
                        self.msg
                            .send(
                                me,
                                *to,
                                SignatureMessage {
                                    id: sign_id,
                                    proposer: self.request.proposer,
                                    presignature_id: self.dropper.id,
                                    epoch,
                                    from: me,
                                    data: data.clone(),
                                    timestamp: Utc::now().timestamp() as u64,
                                },
                            )
                            .await;
                    }
                }
                Action::SendPrivate(to, data) => {
                    self.msg
                        .send(
                            me,
                            to,
                            SignatureMessage {
                                id: sign_id,
                                proposer: self.request.proposer,
                                presignature_id,
                                epoch,
                                from: me,
                                data,
                                timestamp: Utc::now().timestamp() as u64,
                            },
                        )
                        .await;
                }
                Action::Return(output) => {
                    tracing::info!(
                        ?sign_id,
                        ?me,
                        presignature_id,
                        big_r = ?output.big_r.to_base58(),
                        s = ?output.s,
                        elapsed = ?self.created.elapsed(),
                        "completed signature generation"
                    );

                    accrued_wait_delay.observe(total_wait.as_millis() as f64);
                    poke_counts.observe(total_pokes as f64);
                    crate::metrics::SIGN_GENERATION_LATENCY
                        .with_label_values(&[my_account_id.as_str()])
                        .observe(self.created.elapsed().as_secs_f64());

                    if self.request.proposer == me {
                        self.rpc
                            .publish(self.public_key, self.request.clone(), output);
                    }

                    break Ok(());
                }
            }
        }
    }
}

impl Drop for SignatureGenerator {
    fn drop(&mut self) {
        let msg = self.msg.clone();
        let sign_id = self.request.indexed.id;
        let presignature_id = self.dropper.id;
        tokio::spawn(async move {
            msg.unsubscribe_signature(sign_id, presignature_id).await;
            msg.filter_sign(sign_id, presignature_id).await;
        });
    }
}

pub struct SignatureSpawner {
    /// Presignature storage that maintains all presignatures.
    presignatures: PresignatureStorage,
    /// Ongoing signature generation protocols.
    ongoing: JoinMap<(SignId, PresignatureId), Result<(), SignError>>,
    /// Sign queue that maintains all requests coming in from indexer.
    sign_queue: SignQueue,
    /// The protocol posits that are currently in progress.
    posits: Posits<(SignId, PresignatureId), PresignatureTaken>,

    me: Participant,
    my_account_id: AccountId,
    threshold: usize,
    public_key: PublicKey,
    epoch: u64,
    msg: MessageChannel,
    rpc: RpcChannel,
}

impl SignatureSpawner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        me: Participant,
        my_account_id: &AccountId,
        threshold: usize,
        public_key: PublicKey,
        epoch: u64,
        sign_rx: Arc<RwLock<mpsc::Receiver<IndexedSignRequest>>>,
        presignatures: &PresignatureStorage,
        msg: MessageChannel,
        rpc: RpcChannel,
    ) -> Self {
        Self {
            presignatures: presignatures.clone(),
            ongoing: JoinMap::new(),
            sign_queue: SignQueue::new(me, sign_rx),
            posits: Posits::new(me),
            me,
            my_account_id: my_account_id.clone(),
            threshold,
            public_key,
            epoch,
            msg,
            rpc,
        }
    }

    /// Starts a new signature generation protocol.
    async fn propose_posit(
        &mut self,
        request: &SignRequest,
        taken: PresignatureTaken,
        participants: &[Participant],
    ) {
        let sign_id = request.indexed.id;
        let presignature_id = taken.presignature.id;
        tracing::info!(
            ?sign_id,
            presignature_id,
            "proposing protocol to generate a new signature"
        );

        self.posits
            .propose((sign_id, presignature_id), taken, participants);
        for &p in participants.iter() {
            if p == self.me {
                continue;
            }

            self.msg
                .send(
                    self.me,
                    p,
                    PositMessage {
                        id: PositProtocolId::Signature(sign_id, presignature_id),
                        from: self.me,
                        action: PositAction::Propose,
                    },
                )
                .await;
        }
    }

    // TODO: we really need to refactor how posits are handled since the dependencies are being waited upon
    // in a different places vs the `process_posit` function. This will be hard to read and tract down where
    // things are being handled.
    async fn process_posit(
        &mut self,
        sign_id: SignId,
        presignature_id: PresignatureId,
        request: Option<SignRequest>,
        from: Participant,
        action: PositAction,
        cfg: ProtocolConfig,
    ) {
        let internal_action = if self.ongoing.contains_key(&(sign_id, presignature_id)) {
            tracing::warn!(
                ?sign_id,
                presignature_id,
                "signature is already in the ongoing generation"
            );
            PositInternalAction::Reply(PositAction::Reject)
        } else if matches!(action, PositAction::Propose) {
            if let Some(request) = request {
                if request.proposer == from {
                    self.posits
                        .act((sign_id, presignature_id), from, self.threshold, &action)
                } else {
                    PositInternalAction::Reply(PositAction::Reject)
                }
            } else {
                PositInternalAction::Reply(PositAction::Reject)
            }
        } else {
            self.posits
                .act((sign_id, presignature_id), from, self.threshold, &action)
        };

        match internal_action {
            PositInternalAction::None => {}
            PositInternalAction::Abort => {
                tracing::warn!(
                    ?sign_id,
                    presignature_id,
                    from = ?from,
                    "signature posit action was rejected"
                );
                self.sign_queue.push_failed(sign_id);
            }
            PositInternalAction::Reply(action) => {
                if matches!(action, PositAction::Reject) {
                    // proposer can potentially be wrong, let's reorder our participants for this sign request:
                    self.sign_queue.push_failed(sign_id);
                }

                self.msg
                    .send(
                        self.me,
                        from,
                        PositMessage {
                            id: PositProtocolId::Signature(sign_id, presignature_id),
                            from: self.me,
                            action,
                        },
                    )
                    .await;
            }
            PositInternalAction::StartProtocol(participants, positor) => {
                if positor.is_proposer() {
                    for &p in &participants {
                        if p == self.me {
                            continue;
                        }
                        self.msg
                            .send(
                                self.me,
                                p,
                                PositMessage {
                                    id: PositProtocolId::Signature(sign_id, presignature_id),
                                    from: self.me,
                                    action: PositAction::Start(participants.clone()),
                                },
                            )
                            .await;
                    }
                }

                let request = self.sign_queue.get_or_pending(&sign_id);
                let presignature = match positor {
                    Positor::Proposer(_proposer, taken) => PendingPresignature::Available(taken),
                    Positor::Deliberator(proposer) => PendingPresignature::InStorage(
                        presignature_id,
                        proposer,
                        self.presignatures.clone(),
                    ),
                };
                self.generate(request, presignature, participants, cfg)
                    .await;
            }
        }
    }

    /// Starts a new presignature generation protocol.
    async fn generate(
        &mut self,
        request: PendingRequest,
        presignature: PendingPresignature,
        participants: Vec<Participant>,
        cfg: ProtocolConfig,
    ) {
        let me = self.me;
        let epoch = self.epoch;
        let public_key = self.public_key;
        let sign_id = request.id();
        let presignature_id = presignature.id();
        let my_account_id = self.my_account_id.clone();
        let msg = self.msg.clone();
        let rpc = self.rpc.clone();
        let task = async move {
            let generator = match SignatureGenerator::new(
                me,
                request,
                presignature,
                participants,
                public_key,
                cfg,
                msg,
                rpc,
            )
            .await
            {
                Ok(generator) => generator,
                Err(InitializationError::BadParameters(err)) => {
                    tracing::warn!(
                        ?sign_id,
                        presignature_id,
                        ?err,
                        "unable to start signature generation on START"
                    );
                    return Err(SignError::Retry);
                }
            };

            crate::metrics::NUM_TOTAL_HISTORICAL_SIGNATURE_GENERATORS
                .with_label_values(&[my_account_id.as_str()])
                .inc();

            generator.run(me, epoch, my_account_id).await
        };

        self.ongoing.spawn((sign_id, presignature_id), task);
    }

    async fn handle_requests(&mut self, stable: &[Participant], cfg: &ProtocolConfig) {
        if stable.len() < self.threshold {
            tracing::warn!(
                ?stable,
                threshold = self.threshold,
                "not enough stable participants to handle requests"
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

        let mut retry = Vec::new();
        while let Some(taken) = {
            if self.sign_queue.is_empty_mine() {
                None
            } else {
                self.presignatures.take_mine(self.me).await
            }
        } {
            let Some(my_request) = self.sign_queue.take_mine() else {
                tracing::warn!(
                    presignature = ?taken.presignature,
                    "unexpected, no more requests to handle. presignature will be removed",
                );
                continue;
            };

            let participants = intersect_vec(&[
                stable,
                &taken.presignature.participants,
                &my_request.participants,
            ]);
            if participants.len() < self.threshold {
                tracing::warn!(
                    sign_id = ?my_request.indexed.id,
                    presignature_id = ?taken.presignature.id,
                    ?participants,
                    "intersection < threshold, trashing presignature"
                );
                retry.push(my_request.indexed.id);
                continue;
            }

            self.propose_posit(&my_request, taken, &participants).await;
        }

        for sign_id in retry {
            self.sign_queue.push_failed(sign_id);
        }
    }

    async fn run(mut self, mesh_state: watch::Receiver<MeshState>, cfg: watch::Receiver<Config>) {
        // NOTE: signatures should only use stable and not active participants. The difference here is that
        // stable participants utilizes more than the online status of a node, such as whether or not their
        // block height is up to date, such that they too can process signature requests. If they cannot
        // then they are considered unstable and should not be a part of signature generation this round.

        let mut check_requests_interval = tokio::time::interval(Duration::from_millis(100));
        let mut posits = self.msg.subscribe_signature_posit().await;
        let mut pending_posits = JoinSet::new();

        loop {
            tokio::select! {
                Some((sign_id, presignature_id, from, action)) = posits.recv() => {
                    let request = self.sign_queue.get_or_pending(&sign_id);
                    let timeout = Duration::from_millis(cfg.borrow().protocol.signature.generation_timeout);
                    pending_posits.spawn(async move {
                        let request = request.fetch(timeout).await;
                        (sign_id, presignature_id, request, from, action)
                    });
                }
                Some(pending_posit) = pending_posits.join_next() => {
                    let (sign_id, presignature_id, request, from, action) = match pending_posit {
                        Ok(posit) => posit,
                        Err(_) => {
                            tracing::warn!("signature posit fetching request interrupted");
                            continue;
                        },
                    };

                    let protocol = cfg.borrow().protocol.clone();
                    self.process_posit(sign_id, presignature_id, request, from, action, protocol).await;
                }
                // `join_next` returns None on the set being empty, so don't handle that case
                Some(result) = self.ongoing.join_next(), if !self.ongoing.is_empty() => {
                    let ((sign_id, _presignature_id), result) = match result {
                        Ok(outcome) => outcome,
                        Err((sign_id, presignature_id)) => {
                            tracing::warn!(?sign_id, presignature_id, "signature generation task interrupted");
                            continue;
                        }
                    };

                    match result {
                        Err(SignError::Retry) => {
                            self.sign_queue.push_failed(sign_id);
                        }
                        Ok(()) | Err(SignError::TotalTimeout) | Err(SignError::Aborted) => {
                            self.sign_queue.remove(sign_id);
                        }
                    }
                }
                _ = check_requests_interval.tick() => {
                    let stable = mesh_state.borrow().stable.clone();
                    let protocol = cfg.borrow().protocol.clone();
                    self.handle_requests(&stable, &protocol).await;
                }
            }
        }
    }
}

impl Drop for SignatureSpawner {
    fn drop(&mut self) {
        let msg = self.msg.clone();
        tokio::spawn(msg.unsubscribe_signature_posit());
    }
}

pub struct SignatureSpawnerTask {
    handle: JoinHandle<()>,
}

impl SignatureSpawnerTask {
    pub fn run(
        me: Participant,
        threshold: usize,
        epoch: u64,
        ctx: &MpcSignProtocol,
        public_key: PublicKey,
    ) -> Self {
        let spawner = SignatureSpawner::new(
            me,
            &ctx.my_account_id,
            threshold,
            public_key,
            epoch,
            ctx.sign_rx.clone(),
            &ctx.presignature_storage,
            ctx.msg_channel.clone(),
            ctx.rpc_channel.clone(),
        );

        Self {
            handle: tokio::spawn(spawner.run(ctx.mesh_state.clone(), ctx.config.clone())),
        }
    }

    pub fn abort(&self) {
        // NOTE: since dropping the handle here, PresignatureSpawner will drop their JoinSet/JoinMap
        // which will also abort all ongoing presignature generation tasks. This is important to note
        // since we do not want to leak any presignature generation tasks when we are resharing, and
        // potentially wasting compute.
        self.handle.abort();
    }
}

impl Drop for SignatureSpawnerTask {
    fn drop(&mut self) {
        self.abort();
    }
}

enum PendingPresignature {
    Available(PresignatureTaken),
    InStorage(PresignatureId, Participant, PresignatureStorage),
}

impl PendingPresignature {
    pub fn id(&self) -> PresignatureId {
        match self {
            PendingPresignature::Available(taken) => taken.presignature.id,
            PendingPresignature::InStorage(id, _, _) => *id,
        }
    }

    pub async fn fetch(self, me: Participant, timeout: Duration) -> Option<PresignatureTaken> {
        let (id, storage, owner) = match self {
            PendingPresignature::Available(taken) => return Some(taken),
            PendingPresignature::InStorage(id, owner, storage) => (id, storage, owner),
        };

        let presignature = tokio::time::timeout(timeout, async {
            // TODO: we can make storage wait for presignature to be available instead of here
            let mut interval = tokio::time::interval(Duration::from_millis(50));
            loop {
                interval.tick().await;
                if let Some(presignature) = storage.take(id, owner, me).await {
                    break presignature;
                };
            }
        })
        .await;

        match presignature {
            Ok(presignature) => Some(presignature),
            Err(_) => {
                tracing::warn!(
                    id,
                    ?timeout,
                    "timeout waiting for presignature to be available"
                );
                None
            }
        }
    }
}
