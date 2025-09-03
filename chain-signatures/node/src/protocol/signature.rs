use super::contract::primitives::intersect_vec;
use super::MpcSignProtocol;
use crate::config::Config;
use crate::kdf::derive_delta;
use crate::mesh::MeshState;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::message::{MessageChannel, PositMessage, PositProtocolId, SignatureMessage};
use crate::protocol::posit::{PositAction, PositInternalAction, Positor, Posits};
use crate::protocol::presignature::PresignatureId;
use crate::protocol::Chain;
use crate::rpc::{ContractStateWatcher, RpcChannel};
use crate::sign_queue::{SignQueueHandle, QueuedSignRequest};
use crate::sign_respond_tx::SignRespondSignatureChannel;
use crate::storage::presignature_storage::{PresignatureTaken, PresignatureTakenDropper};
use crate::storage::PresignatureStorage;
use crate::types::SignatureProtocol;
use crate::util::{AffinePointExt, JoinMap};

use crate::protocol::SignRequestType;
use cait_sith::protocol::{Action, InitializationError, Participant};
use cait_sith::PresignOutput;
use chrono::Utc;
use k256::Secp256k1;
use mpc_contract::config::ProtocolConfig;
use mpc_crypto::{derive_key, PublicKey};
use mpc_primitives::{SignArgs, SignId};
use rand::rngs::StdRng;
use rand::seq::IteratorRandom;
use rand::SeedableRng;
use std::collections::{BTreeSet, HashMap, VecDeque};
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
    pub sign_request_type: SignRequestType,
    pub participants: Option<Vec<Participant>>,
}

impl IndexedSignRequest {
    /// Create a minimal IndexedSignRequest for compatibility when we only have a SignId
    /// This is a temporary workaround and should be replaced with proper request lookup
    pub fn default_for_sign_id(sign_id: SignId) -> Self {
        use std::time::{Duration, Instant};
        use crate::protocol::Chain;
        
        Self {
            id: sign_id,
            args: SignArgs {
                payload: [0; 32],
                epsilon: [0; 32],
                entropy: [0; 32],
                path: String::new(),
                key_version: 0,
            },
            chain: Chain::Eth,
            unix_timestamp_indexed: 0,
            timestamp_sign_queue: Some(Instant::now()),
            total_timeout: Duration::from_secs(300), // 5 minutes default
            sign_request_type: SignRequestType::SignRespond(Default::default()),
            participants: None,
        }
    }
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
    pub stable: BTreeSet<Participant>,
    pub round: usize,
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
        stable: &BTreeSet<Participant>,
        participants: &Participants,
        indexed: IndexedSignRequest,
        initial_round: usize,
    ) -> SignRequest {
        let sign_id = indexed.id;
        let reorganize = initial_round > 0;
        let mut participants = if indexed.participants.is_some() {
            indexed.participants.clone().unwrap()
        } else {
            participants.keys().cloned().collect()
        };
        participants.sort();

        // Simple round-robin selection of the proposer, using only inputs that
        // are guaranteed to be the same on all nodes.
        fn proposer_per_round(
            round: usize,
            participants: &[Participant],
            entropy: &[u8; 32],
        ) -> Participant {
            // if entropy is random, using one byte is as good as using all
            let index = entropy[0] as usize + round;
            participants[index % participants.len()]
        }

        let max_rounds = initial_round + 512;
        // Use the smallest round that selects a stable proposer.
        let (round, proposer) = (initial_round..max_rounds)
            .map(|round| {
                (
                    round,
                    proposer_per_round(round, &participants, &indexed.args.entropy),
                )
            })
            .find(|(_, potential_proposer)| stable.contains(potential_proposer))
            // on exhausting all rounds, just pick one at random and have posits error out.
            .unwrap_or_else(|| {
                (
                    max_rounds,
                    *stable
                        .iter()
                        .choose(&mut StdRng::from_seed(indexed.args.entropy))
                        .unwrap(),
                )
            });

        let is_mine = proposer == self.me;
        tracing::info!(
            ?stable,
            ?sign_id,
            ?proposer,
            me = ?self.me,
            is_mine,
            "sign queue: {}organizing request",
            if reorganize { "re" } else { "" },
        );

        let request = SignRequest {
            indexed,
            proposer,
            stable: stable.clone(),
            round,
        };

        if is_mine {
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
        stable: &BTreeSet<Participant>,
        participants: &Participants,
        my_account_id: &AccountId,
    ) {
        // Reorganize the failed requests with a potentially newer list of stable participants.
        self.organize_failed(stable, participants, my_account_id);

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

            let request = self.organize_request(stable, participants, indexed, 0);
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
        stable: &BTreeSet<Participant>,
        participants: &Participants,
        my_account_id: &AccountId,
    ) {
        while let Some(id) = self.failed_requests.pop_front() {
            let Some(request) = self.requests.remove(&id) else {
                continue;
            };

            let (reorganized, request) = if &request.stable == stable {
                // just use the same request if the participants are the same
                (false, request)
            } else {
                let request =
                    self.organize_request(stable, participants, request.indexed, request.round);
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
    participants: Vec<Participant>,
    request: SignRequest,
    public_key: PublicKey,
    created: Instant,
    timeout: Duration,
    timeout_total: Duration,
    inbox: mpsc::Receiver<SignatureMessage>,
    msg: MessageChannel,
    rpc: RpcChannel,
    sign_respond_signature_channel: SignRespondSignatureChannel,
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
        sign_respond_signature_channel: SignRespondSignatureChannel,
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
            participants,
            request,
            public_key,
            created: Instant::now(),
            timeout: Duration::from_millis(cfg.signature.generation_timeout),
            timeout_total: Duration::from_millis(cfg.signature.generation_timeout_total),
            inbox,
            msg,
            rpc,
            sign_respond_signature_channel,
        })
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

    /// Receive the next message for the signature protocol; error out on the timeout being reached
    /// or the channel having been closed (aborted).
    async fn recv(&mut self) -> Result<SignatureMessage, SignError> {
        let sign_id = self.request.indexed.id;
        let presignature_id = self.dropper.id;
        match tokio::time::timeout(
            self.timeout.saturating_sub(self.created.elapsed()),
            self.inbox.recv(),
        )
        .await
        {
            Ok(Some(msg)) => Ok(msg),
            Ok(None) => {
                tracing::warn!(?sign_id, presignature_id, "signature generation aborted");
                Err(SignError::Aborted)
            }
            Err(_err) => {
                tracing::warn!(
                    ?sign_id,
                    presignature_id,
                    "signature generation timeout, retrying..."
                );
                Err(SignError::Retry)
            }
        }
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
                    let msg = self.recv().await.inspect_err(|_| {
                        if self.request.proposer == me {
                            signature_generator_failures_metric.inc();
                        }
                    })?;
                    self.protocol.message(msg.from, msg.data);
                }
                Action::SendMany(data) => {
                    for &to in self.participants.iter() {
                        if to == me {
                            continue;
                        }
                        self.msg
                            .send(
                                me,
                                to,
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
                        self.rpc.publish(
                            self.public_key,
                            self.request.clone(),
                            output,
                            self.participants.clone(),
                        );
                    } else if let SignRequestType::SignRespond(_) =
                        self.request.indexed.sign_request_type
                    {
                        self.sign_respond_signature_channel.send(
                            self.public_key,
                            self.request.clone(),
                            output,
                            self.participants.clone(),
                        );
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
    /// Sign queue handle that communicates with the SignQueue task.
    sign_queue: SignQueueHandle,
    /// The protocol posits that are currently in progress.
    posits: Posits<(SignId, PresignatureId), PresignatureTaken>,

    me: Participant,
    my_account_id: AccountId,
    threshold: usize,
    public_key: PublicKey,
    epoch: u64,
    msg: MessageChannel,
    rpc: RpcChannel,
    sign_respond_signature_channel: SignRespondSignatureChannel,
}

impl SignatureSpawner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        me: Participant,
        my_account_id: &AccountId,
        threshold: usize,
        public_key: PublicKey,
        epoch: u64,
        sign_queue: SignQueueHandle,
        presignatures: &PresignatureStorage,
        msg: MessageChannel,
        rpc: RpcChannel,
        sign_respond_signature_channel: SignRespondSignatureChannel,
    ) -> Self {
        Self {
            presignatures: presignatures.clone(),
            ongoing: JoinMap::new(),
            sign_queue,
            posits: Posits::new(me),
            me,
            my_account_id: my_account_id.clone(),
            threshold,
            public_key,
            epoch,
            msg,
            rpc,
            sign_respond_signature_channel,
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
                let _ = self.sign_queue.fail_request(sign_id, true).await;
            }
            PositInternalAction::Reply(action) => {
                if matches!(action, PositAction::Reject) {
                    // proposer can potentially be wrong, let's reorder our participants for this sign request:
                    let _ = self.sign_queue.fail_request(sign_id, true).await;
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

                // TODO: The new queue doesn't support pending requests the same way
                // For now, we'll create a minimal request or skip this functionality
                // This needs to be properly implemented based on the actual requirements
                let request = match self.sign_queue.get_request_status(sign_id).await {
                    Ok(Some(_status)) => {
                        // We have the request, but need to construct SignRequest
                        // This is a temporary workaround
                        SignRequest {
                            indexed: IndexedSignRequest::default_for_sign_id(sign_id),
                            proposer: self.me,
                            stable: BTreeSet::new(),
                            round: 0,
                        }
                    }
                    _ => {
                        // Request not found or error, create minimal request
                        SignRequest {
                            indexed: IndexedSignRequest::default_for_sign_id(sign_id),
                            proposer: self.me,
                            stable: BTreeSet::new(),
                            round: 0,
                        }
                    }
                };
                let presignature = match positor {
                    Positor::Proposer(_proposer, taken) => PendingPresignature::Available(taken),
                    Positor::Deliberator(proposer) => PendingPresignature::InStorage(
                        presignature_id,
                        proposer,
                        self.presignatures.clone(),
                    ),
                };
                self.generate(
                    request,
                    presignature,
                    participants,
                    cfg,
                    self.sign_respond_signature_channel.clone(),
                )
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
        sign_respond_signature_channel: SignRespondSignatureChannel,
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
                sign_respond_signature_channel,
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

    async fn handle_requests(
        &mut self,
        stable: &BTreeSet<Participant>,
        participants: &Participants,
        cfg: &ProtocolConfig,
    ) {
        if stable.len() < self.threshold {
            tracing::warn!(
                ?stable,
                threshold = self.threshold,
                "not enough stable participants to handle requests"
            );
            return;
        }

        // TODO: Implement expiry logic in SignQueue task
        // self.sign_queue.expire(cfg);
        
        // Get queue statistics for metrics
        let stats = self.sign_queue.get_stats().await.unwrap_or_default();
        crate::metrics::SIGN_QUEUE_SIZE
            .with_label_values(&[self.my_account_id.as_str()])
            .set(stats.total_requests as i64);
        crate::metrics::SIGN_QUEUE_MINE_SIZE
            .with_label_values(&[self.my_account_id.as_str()])
            .set(stats.my_pending_requests as i64);

        let mut retry = Vec::new();
        while let Some(taken) = {
            if stats.my_pending_requests == 0 {
                None
            } else {
                self.presignatures.take_mine(self.me).await
            }
        } {
            let Some(my_request) = self.sign_queue.get_next_request().await.unwrap_or(None) else {
                tracing::warn!(
                    presignature = ?taken.presignature,
                    "unexpected, no more requests to handle. presignature will be removed",
                );
                continue;
            };

            // Convert QueuedSignRequest to SignRequest for compatibility
            let sign_request = SignRequest {
                indexed: my_request.indexed.clone(),
                proposer: my_request.proposer,
                stable: my_request.stable.clone(),
                round: my_request.round,
            };

            let stable = stable.iter().copied().collect::<Vec<_>>();
            let participants = intersect_vec(&[&stable, &taken.presignature.participants]);
            if participants.len() < self.threshold {
                tracing::warn!(
                    sign_id = ?sign_request.indexed.id,
                    presignature_id = ?taken.presignature.id,
                    ?participants,
                    "intersection < threshold, trashing presignature"
                );
                retry.push(sign_request.indexed.id);
                continue;
            }

            self.propose_posit(&sign_request, taken, &participants).await;
        }

        for sign_id in retry {
            let _ = self.sign_queue.fail_request(sign_id, true).await;
        }
    }

    async fn run(
        mut self,
        contract: ContractStateWatcher,
        mesh_state: watch::Receiver<MeshState>,
        cfg: watch::Receiver<Config>,
    ) {
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
                    // TODO: Implement proper request lookup for the new queue
                    // For now, create a minimal request
                    let request = SignRequest {
                        indexed: IndexedSignRequest::default_for_sign_id(sign_id),
                        proposer: self.me,
                        stable: BTreeSet::new(),
                        round: 0,
                    };
                    let timeout = Duration::from_millis(cfg.borrow().protocol.signature.generation_timeout);
                    pending_posits.spawn(async move {
                        // Since we're creating the request directly, we don't need to fetch it
                        (sign_id, presignature_id, Some(request), from, action)
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
                            let _ = self.sign_queue.fail_request(sign_id, true).await;
                        }
                        Ok(()) | Err(SignError::TotalTimeout) | Err(SignError::Aborted) => {
                            let _ = self.sign_queue.complete_request(sign_id).await;
                        }
                    }
                }
                _ = check_requests_interval.tick() => {
                    let Some(participants) = contract.participants() else {
                        continue;
                    };
                    let stable = mesh_state.borrow().stable.clone();
                    let protocol = cfg.borrow().protocol.clone();
                    self.handle_requests(&stable, &participants, &protocol).await;
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
            ctx.sign_respond_signature_channel.clone(),
        );

        Self {
            handle: tokio::spawn(spawner.run(
                ctx.contract.clone(),
                ctx.mesh_state.clone(),
                ctx.config.clone(),
            )),
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
