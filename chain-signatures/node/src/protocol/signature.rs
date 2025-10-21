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
use crate::sign_bidirectional::SignBidirectionalSignatureChannel;
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
    attempts: Attempts,
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

#[derive(Debug, Clone, PartialEq)]
pub struct Attempts {
    attempts: u32,
    next_retry_at: Instant,
}

impl Default for Attempts {
    fn default() -> Self {
        Self::new()
    }
}

impl Attempts {
    pub fn new() -> Self {
        Self {
            attempts: 0,
            next_retry_at: Instant::now(),
        }
    }

    pub fn schedule_next_attempt(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
        self.next_retry_at = Instant::now() + self.compute_retry_delay();
    }

    pub fn is_ready(&self, now: Instant) -> bool {
        self.next_retry_at <= now
    }

    pub fn is_ready_now(&self) -> bool {
        self.is_ready(Instant::now())
    }

    pub fn mark_ready(&mut self, now: Instant) {
        self.next_retry_at = now;
    }

    fn compute_retry_delay(&self) -> Duration {
        Duration::ZERO
    }
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

        SignRequest {
            indexed,
            proposer,
            stable: stable.clone(),
            round,
            attempts: Attempts::new(),
        }
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

            let mut request = self.organize_request(stable, participants, indexed, 0);
            if request.indexed.timestamp_sign_queue.is_none() {
                request.indexed.timestamp_sign_queue = Some(Instant::now());
            }
            let is_mine = request.proposer == self.me;
            if is_mine {
                self.my_requests.push_front(sign_id);
                crate::metrics::NUM_SIGN_REQUESTS_MINE
                    .with_label_values(&[my_account_id.as_str()])
                    .inc();
            }
            if let Some(pending) = self.pending.remove(&sign_id) {
                tracing::info!(?sign_id, proposer = ?request.proposer, "sign queue received pending request");
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
        let now = Instant::now();
        let len = self.failed_requests.len();
        for _ in 0..len {
            let Some(id) = self.failed_requests.pop_front() else {
                break;
            };

            let Some(mut request) = self.requests.remove(&id) else {
                continue;
            };

            if !request.attempts.is_ready(now) {
                self.requests.insert(id, request);
                self.failed_requests.push_back(id);
                continue;
            }

            let mut reorganized = false;
            if &request.stable != stable {
                let attempts = request.attempts;
                request =
                    self.organize_request(stable, participants, request.indexed, request.round);
                request.attempts = attempts;
                reorganized = true;
            }

            // Ensure the request is marked ready before requeueing it.
            request.attempts.mark_ready(now);

            if request.indexed.timestamp_sign_queue.is_none() {
                request.indexed.timestamp_sign_queue = Some(now);
            }

            if request.proposer == self.me {
                // Older retries are appended to the back so newly indexed requests run first.
                self.my_requests.push_back(request.indexed.id);
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
        if let Some(request) = self.requests.get_mut(&sign_id) {
            request.attempts.schedule_next_attempt();

            if !self.failed_requests.contains(&sign_id) {
                self.failed_requests.push_back(sign_id);
            }
        } else {
            tracing::warn!(?sign_id, "failed sign request missing from queue");
        }
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

    pub fn expire(&mut self, _cfg: &ProtocolConfig) {
        self.my_requests.retain(|id| self.requests.contains_key(id));
        self.failed_requests
            .retain(|id| self.requests.contains_key(id));
    }

    pub fn remove(&mut self, sign_id: SignId) -> Option<SignRequest> {
        self.pending.remove(&sign_id);
        self.my_requests.retain(|id| id != &sign_id);
        self.failed_requests.retain(|id| id != &sign_id);
        self.requests.remove(&sign_id)
    }
}

enum SignError {
    Retry,
    Aborted,
}

/// An ongoing signature generator.
struct SignatureGenerator {
    protocol: SignatureProtocol,
    dropper: PresignatureTakenDropper,
    participants: Vec<Participant>,
    me: Participant,
    request: SignRequest,
    public_key: PublicKey,
    created: Instant,
    timeout: Duration,
    inbox: mpsc::Receiver<SignatureMessage>,
    msg: MessageChannel,
    rpc: RpcChannel,

    sign_bidirectional_signature_channel: SignBidirectionalSignatureChannel,
    #[cfg(feature = "debug-page")]
    debug_view: crate::web::debug::DebugPageTaskHandle,
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
        sign_bidirectional_signature_channel: SignBidirectionalSignatureChannel,
        _my_account_id: &AccountId,
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
            me,
            request,
            public_key,
            created: Instant::now(),
            timeout: Duration::from_millis(cfg.signature.generation_timeout),
            inbox,
            msg,
            rpc,
            sign_bidirectional_signature_channel,
            #[cfg(feature = "debug-page")]
            debug_view: crate::web::debug::register_task(
                _my_account_id.to_string(),
                format!("SignatureGenerator {sign_id:#?}"),
            ),
        })
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
                tracing::warn!(
                    ?sign_id,
                    presignature_id,
                    proposer = ?self.request.proposer,
                    me = ?self.me,
                    "signature generation aborted",
                );
                Err(SignError::Aborted)
            }
            Err(_err) => {
                tracing::warn!(
                    ?sign_id,
                    presignature_id,
                    proposer = ?self.request.proposer,
                    me = ?self.me,
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
            let poke_start_time = Instant::now();
            let action = match self.protocol.poke() {
                Ok(action) => action,
                Err(err) => {
                    tracing::error!(
                        ?sign_id,
                        ?err,
                        "signature generation failed on protocol advancement",
                    );
                    if self.request.proposer == me {
                        signature_generator_failures_metric.inc();
                    }
                    break Err(SignError::Retry);
                }
            };

            total_wait += poke_start_time - poke_last_time;
            total_pokes += 1;
            poke_last_time = Instant::now();
            poke_latency.observe(poke_start_time.elapsed().as_millis() as f64);
            #[cfg(feature = "debug-page")]
            self.render_debug(total_pokes);

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
                    } else if let SignRequestType::SignBidirectional(_) =
                        self.request.indexed.sign_request_type
                    {
                        self.sign_bidirectional_signature_channel.send(
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

    #[cfg(feature = "debug-page")]
    fn render_debug(&self, total_pokes: i32) {
        let markup = maud::html! {
            p { (format!("{total_pokes} pokes")) }
        };
        self.debug_view.send(markup);
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
    sign_bidirectional_signature_channel: SignBidirectionalSignatureChannel,
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
        sign_bidirectional_signature_channel: SignBidirectionalSignatureChannel,
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
            sign_bidirectional_signature_channel,
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
        mut request: Option<SignRequest>,
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
            match request.take() {
                Some(req) => {
                    if req.proposer == from {
                        self.posits
                            .act((sign_id, presignature_id), from, self.threshold, &action)
                    } else {
                        tracing::warn!(
                            ?sign_id,
                            presignature_id,
                            expected_proposer = ?req.proposer,
                            actual_proposer = ?from,
                            "rejecting signature posit: proposer mismatch",
                        );
                        PositInternalAction::Reply(PositAction::Reject)
                    }
                }
                None => {
                    tracing::warn!(
                        ?sign_id,
                        presignature_id,
                        ?from,
                        "rejecting signature posit: sign request not yet available locally",
                    );
                    PositInternalAction::Reply(PositAction::Reject)
                }
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
                self.start_generation(positor, sign_id, presignature_id, participants, cfg)
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
        sign_bidirectional_signature_channel: SignBidirectionalSignatureChannel,
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
                sign_bidirectional_signature_channel,
                &my_account_id,
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

    async fn start_generation(
        &mut self,
        positor: Positor<PresignatureTaken>,
        sign_id: SignId,
        presignature_id: PresignatureId,
        participants: Vec<Participant>,
        cfg: ProtocolConfig,
    ) {
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
        self.generate(
            request,
            presignature,
            participants,
            cfg,
            self.sign_bidirectional_signature_channel.clone(),
        )
        .await;
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

        self.sign_queue.expire(cfg);
        self.sign_queue
            .organize(stable, participants, &self.my_account_id)
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

            let stable = stable.iter().copied().collect::<Vec<_>>();
            let participants = intersect_vec(&[&stable, &taken.presignature.participants]);
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
        let mut expiration_interval = tokio::time::interval(Duration::from_secs(20));
        let mut posits = self.msg.subscribe_signature_posit().await;
        let mut pending_posits = JoinSet::new();

        loop {
            tokio::select! {
                _ = expiration_interval.tick() => {
                    for ((sign_id, presignature_id), action) in self.posits.expire_and_start(self.threshold, Duration::from_secs(60)) {
                        let (participants, positor) = match action {
                            PositInternalAction::StartProtocol(participants, positor) => (participants, positor),
                            PositInternalAction::Abort => {
                                tracing::warn!(
                                    ?sign_id,
                                    presignature_id,
                                    "signature posit aborting on expiration, retrying..."
                                );
                                self.sign_queue.push_failed(sign_id);
                                continue;
                            },
                            _ => continue,
                        };
                        let protocol = cfg.borrow().protocol.clone();
                        self.start_generation(positor, sign_id, presignature_id, participants, protocol).await;
                    }
                }
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
                            crate::metrics::SIGNATURE_FAILURES
                                .with_label_values(&[self.my_account_id.as_str()])
                                .inc();
                            self.sign_queue.push_failed(sign_id);
                        }
                        Ok(()) | Err(SignError::Aborted) => {
                            self.sign_queue.remove(sign_id);
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
            ctx.sign_bidirectional_signature_channel.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ParticipantInfo;
    use k256::Scalar;
    use near_account_id::AccountId;
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn make_indexed_request(id: SignId) -> IndexedSignRequest {
        IndexedSignRequest {
            id,
            args: SignArgs {
                entropy: id.request_id,
                epsilon: Scalar::ONE,
                payload: Scalar::ONE,
                path: "test".to_string(),
                key_version: 0,
            },
            chain: Chain::Ethereum,
            unix_timestamp_indexed: 0,
            timestamp_sign_queue: None,
            total_timeout: Duration::from_secs(60),
            sign_request_type: SignRequestType::Sign,
            participants: None,
        }
    }

    fn setup_queue() -> (
        Participant,
        BTreeSet<Participant>,
        Participants,
        SignQueue,
        AccountId,
        mpsc::Sender<IndexedSignRequest>,
    ) {
        let (tx, rx) = SignQueue::channel();
        let me = Participant::from(0u32);
        let other = Participant::from(1u32);
        let mut stable = BTreeSet::new();
        stable.insert(me);
        stable.insert(other);

        let mut participants_map = Participants::default();
        participants_map.insert(&me, ParticipantInfo::new(0));
        participants_map.insert(&other, ParticipantInfo::new(1));

        let account_id = AccountId::from_str("me.near").unwrap();
        let queue = SignQueue::new(me, Arc::new(RwLock::new(rx)));

        (me, stable, participants_map, queue, account_id, tx)
    }

    #[tokio::test]
    async fn retries_wait_until_ready() {
        let (me, stable, participants, mut queue, account_id, _tx) = setup_queue();

        let sign_id = SignId::new([1; 32]);
        let mut indexed = make_indexed_request(sign_id);
        indexed.participants = Some(vec![me]);
        let request = queue.organize_request(&stable, &participants, indexed, 0);
        queue.requests.insert(sign_id, request);
        queue.push_failed(sign_id);

        {
            let request = queue.requests.get_mut(&sign_id).unwrap();
            request.attempts.next_retry_at = Instant::now() + Duration::from_secs(10);
        }

        queue.organize_failed(&stable, &participants, &account_id);
        assert!(queue.my_requests.is_empty());
        assert!(queue.failed_requests.contains(&sign_id));

        {
            let request = queue.requests.get_mut(&sign_id).unwrap();
            request.attempts.next_retry_at = Instant::now() - Duration::from_secs(1);
        }

        queue.organize_failed(&stable, &participants, &account_id);
        assert_eq!(queue.my_requests.len(), 1);
        assert_eq!(queue.my_requests.front(), Some(&sign_id));
        assert!(queue
            .requests
            .get(&sign_id)
            .unwrap()
            .attempts
            .is_ready_now());
        assert!(!queue.failed_requests.contains(&sign_id));
    }

    #[tokio::test]
    async fn prioritizes_new_requests_over_old_retries() {
        let (me, stable, participants, mut queue, account_id, tx) = setup_queue();

        let old_id = SignId::new([5; 32]);
        let mut old_indexed = make_indexed_request(old_id);
        old_indexed.participants = Some(vec![me]);
        let old_request = queue.organize_request(&stable, &participants, old_indexed, 0);
        queue.requests.insert(old_id, old_request);
        queue.push_failed(old_id);
        queue
            .requests
            .get_mut(&old_id)
            .unwrap()
            .attempts
            .next_retry_at = Instant::now() - Duration::from_millis(100);

        let new_id = SignId::new([9; 32]);
        let mut new_indexed = make_indexed_request(new_id);
        new_indexed.participants = Some(vec![me]);
        tx.try_send(new_indexed).unwrap();

        queue.organize(&stable, &participants, &account_id).await;

        let first = queue.take_mine().expect("new request present");
        assert_eq!(first.indexed.id, new_id);
        let second = queue.take_mine().expect("old request present");
        assert_eq!(second.indexed.id, old_id);
        assert!(queue.my_requests.is_empty());
    }

    #[test]
    fn push_failed_is_ready_immediately() {
        let (me, stable, participants, mut queue, _account_id, _tx) = setup_queue();

        let sign_id = SignId::new([3; 32]);
        let mut indexed = make_indexed_request(sign_id);
        indexed.participants = Some(vec![me]);
        let request = queue.organize_request(&stable, &participants, indexed, 0);
        queue.requests.insert(sign_id, request);

        queue.push_failed(sign_id);
        assert_eq!(queue.failed_requests.len(), 1);
        let attempts = &queue.requests.get(&sign_id).unwrap().attempts;
        assert_eq!(attempts.attempts, 1);
        assert!(attempts.next_retry_at <= Instant::now());
        assert!(attempts.is_ready(Instant::now()));

        queue.push_failed(sign_id);
        let attempts = &queue.requests.get(&sign_id).unwrap().attempts;
        assert_eq!(attempts.attempts, 2);
        assert_eq!(queue.failed_requests.len(), 1);
        assert!(attempts.next_retry_at <= Instant::now());
        assert!(attempts.is_ready(Instant::now()));
    }
}
