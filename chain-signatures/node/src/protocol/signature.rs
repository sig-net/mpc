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
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::task::JoinHandle;

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
}

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

    async fn get(self, timeout: Duration) -> Option<SignRequest> {
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
    /// Set of request that failed to be processed during signature generation
    failed_requests: VecDeque<SignId>,
    /// The pool of rqeuests that we are about to process or are currently processing. Only
    /// to be removed when fully timing out or when the request is completed.
    requests: HashMap<SignId, SignRequest>,

    /// The set of pending requset listeners that are waiting for a sign request to be indexed.
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
            // my_requests: VecDeque::new(),
            // other_requests: HashMap::new(),
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

    pub fn len(&self) -> usize {
        self.requests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn contains(&self, sign_id: &SignId) -> bool {
        self.requests.contains_key(sign_id) || self.failed_requests.iter().any(|r| r == sign_id)
    }

    fn organize_request(
        &self,
        threshold: usize,
        stable: &[Participant],
        indexed: IndexedSignRequest,
        reorganize: bool,
    ) -> SignRequest {
        let sign_id = indexed.id.clone();
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
            if let Some(pending) = self.pending.remove(&request.indexed.id) {
                if pending.send(request.clone()).is_err() {
                    tracing::warn!(
                        ?sign_id,
                        "pending sign request channel closed before able to send request"
                    );
                }
            }

            self.requests.insert(request.indexed.id, request);
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

    pub fn push_failed(&mut self, request: &SignRequest) {
        self.failed_requests.push_back(request.indexed.id);
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
        self.my_requests.retain(|id| {
            let Some(request) = self.requests.get(id) else {
                return false;
            };
            crate::util::duration_between_unix(
                request.indexed.unix_timestamp_indexed,
                crate::util::current_unix_timestamp(),
            ) < Duration::from_millis(cfg.signature.generation_timeout_total)
        });
        self.failed_requests.retain(|id| {
            let Some(request) = self.requests.get(id) else {
                return false;
            };
            crate::util::duration_between_unix(
                request.indexed.unix_timestamp_indexed,
                crate::util::current_unix_timestamp(),
            ) < Duration::from_millis(cfg.signature.generation_timeout_total)
        });
        self.requests.retain(|_, request| {
            request.indexed.timestamp_sign_queue.is_none_or(|t| {
                t.elapsed() < Duration::from_millis(cfg.signature.generation_timeout_total)
            })
        });
    }

    pub fn remove(&mut self, sign_id: SignId) -> Option<SignRequest> {
        self.my_requests.retain(|id| *id != sign_id);
        self.requests.remove(&sign_id)
    }
}

/// An ongoing signature generator.
pub struct SignatureGenerator {
    protocol: SignatureProtocol,
    dropper: PresignatureTakenDropper,
    request: SignRequest,
    public_key: PublicKey,
    timestamp: Instant,
    timeout: Duration,
    timeout_total: Duration,
    /// latest poked time, total acrued wait time and total pokes per signature protocol
    poked_latest: Option<(Instant, Duration, u64)>,
    inbox: mpsc::Receiver<SignatureMessage>,
    msg: MessageChannel,
    rpc: RpcChannel,
}

impl SignatureGenerator {
    async fn new(
        me: Participant,
        pending_request: PendingRequest,
        pending_presignature: PendingPresignature,
        participants: Vec<Participant>,
        public_key: PublicKey,
        cfg: ProtocolConfig,
        msg: MessageChannel,
        rpc: RpcChannel,
    ) -> Result<Self, InitializationError> {
        let request = pending_request
            .get(Duration::from_millis(cfg.signature.generation_timeout))
            .await
            .ok_or_else(|| {
                InitializationError::BadParameters(format!("sign request not found or timeout"))
            })?;
        let presignature_id = pending_presignature.id();
        let taken = pending_presignature
            .fetch(me, Duration::from_millis(cfg.signature.generation_timeout))
            .await
            .ok_or_else(|| {
                InitializationError::BadParameters(format!(
                    "presignature {presignature_id} not found or timed out",
                ))
            })?;

        let sign_id = request.indexed.id;
        tracing::info!(
            ?me,
            ?sign_id,
            presignature_id = taken.presignature.id,
            "starting protocol to generate a new signature",
        );

        let SignRequest { indexed, .. } = &request;
        let IndexedSignRequest {
            id: SignId { request_id },
            args,
            ..
        } = indexed;

        let (presignature, dropper) = taken.take();
        let PresignOutput { big_r, k, sigma } = presignature.output;
        let delta = derive_delta(*request_id, args.entropy, big_r);
        // TODO: Check whether it is okay to use invert_vartime instead
        let output: PresignOutput<Secp256k1> = PresignOutput {
            big_r: (big_r * delta).to_affine(),
            k: k * delta.invert().unwrap(),
            sigma: (sigma + args.epsilon * k) * delta.invert().unwrap(),
        };
        let protocol = Box::new(cait_sith::sign(
            &participants,
            me,
            derive_key(public_key, args.epsilon),
            output,
            args.payload,
        )?);
        let inbox = msg.subscribe_signature(request.indexed.id).await;
        Ok(Self {
            protocol,
            dropper,
            request,
            public_key,
            timestamp: Instant::now(),
            timeout: Duration::from_millis(cfg.signature.generation_timeout),
            timeout_total: Duration::from_millis(cfg.signature.generation_timeout_total),
            poked_latest: None,
            inbox,
            msg,
            rpc,
        })
    }

    fn timeout(&self) -> bool {
        self.timestamp.elapsed() >= self.timeout
    }

    fn timeout_total(&self) -> bool {
        let timestamp = self
            .request
            .indexed
            .timestamp_sign_queue
            .as_ref()
            .unwrap_or_else(|| &self.timestamp);
        timestamp.elapsed() >= self.timeout_total
    }

    async fn run(mut self, me: Participant, epoch: u64, my_account_id: AccountId) {
        let signature_before_poke_delay_metric = crate::metrics::SIGNATURE_BEFORE_POKE_DELAY
            .with_label_values(&[my_account_id.as_str()]);
        let signature_accrued_wait_delay_metric = crate::metrics::SIGNATURE_ACCRUED_WAIT_DELAY
            .with_label_values(&[my_account_id.as_str()]);
        let signature_pokes_cnt_metric =
            crate::metrics::SIGNATURE_POKES_CNT.with_label_values(&[my_account_id.as_str()]);
        let signature_generator_failures_metric = crate::metrics::SIGNATURE_GENERATOR_FAILURES
            .with_label_values(&[my_account_id.as_str()]);
        let signature_failures_metric =
            crate::metrics::SIGNATURE_FAILURES.with_label_values(&[my_account_id.as_str()]);
        let signature_poke_cpu_time_metric =
            crate::metrics::SIGNATURE_POKE_CPU_TIME.with_label_values(&[my_account_id.as_str()]);

        let sign_id = self.request.indexed.id.clone();
        let presign_id = self.dropper.id;

        loop {
            if self.timeout_total() {
                tracing::warn!(
                    ?sign_id,
                    presign_id,
                    "signature generation timeout, exhausted all attempts"
                );
                if self.request.proposer == me {
                    signature_generator_failures_metric.inc();
                    signature_failures_metric.inc();
                }
                break;
            }

            if self.timeout() {
                tracing::warn!(
                    ?sign_id,
                    presign_id,
                    "signature generation timeout, retrying..."
                );
                if self.request.proposer == me {
                    signature_generator_failures_metric.inc();
                }
                break;
            }

            let generator_poke_time = Instant::now();
            let action = match self.protocol.poke() {
                Ok(action) => action,
                Err(err) => {
                    tracing::error!(
                        ?sign_id,
                        ?err,
                        "signature generation failed on protocol advancement",
                    );
                    break;
                }
            };
            match action {
                Action::Wait => {
                    // Wait for the next set of messages to arrive.
                    let Some(msg) = self.inbox.recv().await else {
                        break;
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
                                    id: sign_id.clone(),
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
                    let (total_wait, total_pokes) =
                        if let Some((last_poked, total_wait, total_pokes)) = &self.poked_latest {
                            (
                                *total_wait + (generator_poke_time - *last_poked),
                                total_pokes + 1,
                            )
                        } else {
                            let start_time = self.timestamp;
                            signature_before_poke_delay_metric
                                .observe((generator_poke_time - start_time).as_millis() as f64);
                            (Duration::from_millis(0), 1)
                        };
                    self.poked_latest = Some((Instant::now(), total_wait, total_pokes));
                    signature_poke_cpu_time_metric
                        .observe(generator_poke_time.elapsed().as_millis() as f64);
                }
                Action::SendPrivate(to, data) => {
                    self.msg
                        .send(
                            me,
                            to,
                            SignatureMessage {
                                id: sign_id.clone(),
                                proposer: self.request.proposer,
                                presignature_id: presign_id,
                                epoch,
                                from: me,
                                data,
                                timestamp: Utc::now().timestamp() as u64,
                            },
                        )
                        .await;
                    let (total_wait, total_pokes) =
                        if let Some((last_poked, total_wait, total_pokes)) = &self.poked_latest {
                            (
                                *total_wait + (generator_poke_time - *last_poked),
                                total_pokes + 1,
                            )
                        } else {
                            let start_time = self.timestamp;
                            signature_before_poke_delay_metric
                                .observe((generator_poke_time - start_time).as_millis() as f64);
                            (Duration::from_millis(0), 1)
                        };
                    self.poked_latest = Some((Instant::now(), total_wait, total_pokes));
                    signature_poke_cpu_time_metric
                        .observe(generator_poke_time.elapsed().as_millis() as f64);
                }
                Action::Return(output) => {
                    tracing::info!(
                        ?sign_id,
                        ?me,
                        presign_id,
                        big_r = ?output.big_r.to_base58(),
                        s = ?output.s,
                        elapsed = ?self.timestamp.elapsed(),
                        "completed signature generation"
                    );
                    crate::metrics::SIGN_GENERATION_LATENCY
                        .with_label_values(&[my_account_id.as_str()])
                        .observe(self.timestamp.elapsed().as_secs_f64());

                    if self.request.proposer == me {
                        self.rpc
                            .publish(self.public_key, self.request.clone(), output);
                    }
                    if let Some((last_poked, total_wait, total_pokes)) = self.poked_latest {
                        let elapsed = generator_poke_time - last_poked;
                        let total_wait = total_wait + elapsed;
                        let total_pokes = total_pokes + 1;
                        signature_accrued_wait_delay_metric.observe(total_wait.as_millis() as f64);
                        signature_pokes_cnt_metric.observe(total_pokes as f64);
                    }
                    signature_poke_cpu_time_metric
                        .observe(generator_poke_time.elapsed().as_millis() as f64);

                    break;
                }
            }
        }
    }
}

impl Drop for SignatureGenerator {
    fn drop(&mut self) {
        let msg = self.msg.clone();
        let sign_id = self.request.indexed.id.clone();
        let presign_id = self.dropper.id;
        tokio::spawn(async move {
            msg.filter_sign(sign_id, presign_id).await;
        });
    }
}

pub struct SignatureSpawner {
    /// Presignature storage that maintains all presignatures.
    presignatures: PresignatureStorage,
    /// Ongoing signature generation protocols.
    ongoing: JoinMap<SignId, ()>,
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

    async fn process_posit(
        &mut self,
        sign_id: SignId,
        presignature_id: PresignatureId,
        from: Participant,
        action: PositAction,
        cfg: ProtocolConfig,
    ) {
        let internal_action = if self.ongoing.contains_key(&sign_id) {
            tracing::warn!(
                ?sign_id,
                presignature_id,
                "signature is already in the ongoing generation"
            );
            PositInternalAction::None
        } else {
            self.posits
                .act((sign_id, presignature_id), from, self.threshold, &action)
        };

        match internal_action {
            PositInternalAction::None => {}
            PositInternalAction::Reply(action) => {
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

                let pending_request = self.sign_queue.get_or_pending(&sign_id);
                let pending_presignature = match positor {
                    Positor::Proposer(_proposer, taken) => PendingPresignature::Available(taken),
                    Positor::Deliberator(proposer) => PendingPresignature::InStorage(
                        presignature_id,
                        proposer,
                        self.presignatures.clone(),
                    ),
                };
                self.generate(pending_request, pending_presignature, participants, cfg)
                    .await;
            }
        }
    }

    /// Starts a new presignature generation protocol.
    async fn generate(
        &mut self,
        pending_request: PendingRequest,
        pending_presignature: PendingPresignature,
        participants: Vec<Participant>,
        cfg: ProtocolConfig,
    ) {
        let me = self.me;
        let epoch = self.epoch;
        let public_key = self.public_key;
        let sign_id = pending_request.id();
        let presignature_id = pending_presignature.id();
        let my_account_id = self.my_account_id.clone();
        let msg = self.msg.clone();
        let rpc = self.rpc.clone();
        let task = async move {
            let generator = match SignatureGenerator::new(
                me,
                pending_request,
                pending_presignature,
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
                    return;
                }
            };

            crate::metrics::NUM_TOTAL_HISTORICAL_SIGNATURE_GENERATORS
                .with_label_values(&[my_account_id.as_str()])
                .inc();

            generator.run(me, epoch, my_account_id).await;
        };

        self.ongoing.spawn(sign_id, task);
    }

    pub async fn handle_requests(&mut self, stable: &[Participant], cfg: &ProtocolConfig) {
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
                retry.push(my_request);
                continue;
            }

            // TODO: need to handle retry logic.
            self.propose_posit(&my_request, taken, &participants).await;
        }

        for request in retry {
            self.sign_queue.push_failed(&request);
        }
    }

    async fn run(mut self, mesh_state: Arc<RwLock<MeshState>>, cfg: Arc<RwLock<Config>>) {
        // NOTE: signatures should only use stable and not active participants. The difference here is that
        // stable participants utilizes more than the online status of a node, such as whether or not their
        // block height is up to date, such that they too can process signature requests. If they cannot
        // then they are considered unstable and should not be a part of signature generation this round.

        let mut check_requests_interval = tokio::time::interval(Duration::from_millis(100));
        let mut posits = self.msg.subscribe_signature_posit().await;

        loop {
            tokio::select! {
                Some((sign_id, presignature_id, from, action)) = posits.recv() => {
                    let cfg = {
                        let cfg = cfg.read().await;
                        cfg.protocol.clone()
                    };
                    self.process_posit(sign_id, presignature_id, from, action, cfg).await;
                }
                // `join_next` returns None on the set being empty, so don't handle that case
                Some(result) = self.ongoing.join_next(), if !self.ongoing.is_empty() => {
                    let sign_id = match result {
                        Ok((sign_id, _)) => sign_id,
                        Err(sign_id) => {
                            tracing::warn!(?sign_id, "signature generation task interrupted");
                            sign_id
                        }
                    };

                    self.sign_queue.remove(sign_id);
                }
                _ = check_requests_interval.tick() => {
                    let stable = {
                        let state = mesh_state.read().await;
                        state.stable.clone()
                    };
                    let protocol_cfg = {
                        let config = cfg.read().await;
                        config.protocol.clone()
                    };

                    if !self.sign_queue.is_empty() && stable.len() < self.threshold {
                        tracing::warn!(?stable, "not enough stable participants to handle requests");
                        continue;
                    }
                    self.handle_requests(&stable, &protocol_cfg).await;
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

        // TODO: check if unconstrained actually gives us better signature perf
        // tokio::task::unconstrained
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
        let (id, owner, storage) = match self {
            PendingPresignature::Available(taken) => return Some(taken),
            PendingPresignature::InStorage(id, storage, owner) => (id, storage, owner),
        };

        let presignature = tokio::time::timeout(timeout, async {
            let mut interval = tokio::time::interval(Duration::from_millis(200));
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
