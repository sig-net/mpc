use super::contract::primitives::intersect_vec;
use super::MpcSignProtocol;
use crate::config::Config;
use crate::kdf::derive_delta;
use crate::mesh::MeshState;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::message::{MessageChannel, PositMessage, PositProtocolId, SignatureMessage};
use crate::protocol::posit::PositAction;
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
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::{mpsc, oneshot, watch, RwLock};
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

        SignRequest {
            indexed,
            proposer,
            stable: stable.clone(),
            round,
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

            let request = self.organize_request(stable, participants, indexed, 0);
            let is_mine = request.proposer == self.me;
            if is_mine {
                self.my_requests.push_back(sign_id);
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

#[derive(Debug, Clone, Copy)]
enum SignError {
    Retry,
    TotalTimeout,
    Aborted,
}

/// A single posit counter that tracks participants accepting/rejecting a proposal.
/// This is used by individual signature tasks instead of the global Posits mapping.
struct SinglePositCounter {
    participants: HashSet<Participant>,
    accepts: HashSet<Participant>,
    rejects: HashSet<Participant>,
    created: Instant,
}

impl SinglePositCounter {
    fn new(me: Participant, participants: &[Participant]) -> Self {
        let mut accepts = HashSet::new();
        accepts.insert(me);
        Self {
            participants: participants.iter().copied().collect(),
            accepts,
            rejects: HashSet::new(),
            created: Instant::now(),
        }
    }

    fn enough_accepts(&self, threshold: usize) -> bool {
        self.accepts.len() >= threshold
    }

    fn enough_rejects(&self, threshold: usize) -> bool {
        self.rejects.len() > self.participants.len() - threshold
    }

    fn meets_totality(&self) -> bool {
        self.accepts.len() + self.rejects.len() == self.participants.len()
    }

    fn process_action(&mut self, from: Participant, action: &PositAction) -> bool {
        if !self.participants.contains(&from) {
            return false;
        }
        match action {
            PositAction::Accept => {
                self.accepts.insert(from);
            }
            PositAction::Reject => {
                self.rejects.insert(from);
            }
            _ => return false,
        }
        true
    }
}

/// Actions that can be returned from processing a posit action in a signature task
enum SignatureTaskPositAction {
    /// Not enough votes yet, continue waiting
    Waiting,
    /// Enough rejects received, task rejected
    Reject,
    /// Enough accepts received, ready to start generation
    Ready {
        participants: Vec<Participant>,
        proposer: Participant,
    },
}

/// Result of processing a posit message in a signature task
enum SignatureTaskMessageResult {
    /// No action needed, still waiting
    None,
    /// Reject the proposal
    Reject,
    /// Ready to start generation (proposer received enough accepts)
    Ready {
        participants: Vec<Participant>,
        proposer: Participant,
    },
    /// Start generation (received Start message)
    StartGeneration {
        participants: Vec<Participant>,
    },
}

/// Represents a complete signature workflow including posit negotiation and signature generation.
/// This task goes through three phases:
/// 1. Posit: Handles consensus on who should be the proposer
/// 2. Generating: Actual signature generation using presignature
/// 3. Complete: Terminal state tracking success or failure
enum SignatureTaskPhase {
    /// Posit negotiation phase
    Posit {
        counter: SinglePositCounter,
        proposer: Participant,
        participants: Vec<Participant>,
    },
    /// Signature generation phase
    Generating {
        generator: Box<SignatureGenerator>,
    },
    /// Terminal states
    Complete(Result<(), SignError>),
}

/// A single signature generation task that combines posit and generator phases
pub struct SignatureTask {
    sign_id: SignId,
    presignature_id: PresignatureId,
    request: SignRequest,
    phase: SignatureTaskPhase,
    /// The presignature taken from storage, held during posit phase
    presignature: Option<PresignatureTaken>,
    created: Instant,
    timeout_total: Duration,
    me: Participant,
    threshold: usize,
}

impl SignatureTask {
    /// Create a new signature task starting in Posit phase (proposer mode with presignature)
    fn new_proposer(
        me: Participant,
        sign_id: SignId,
        presignature_id: PresignatureId,
        request: SignRequest,
        presignature: PresignatureTaken,
        participants: Vec<Participant>,
        threshold: usize,
        timeout_total: Duration,
    ) -> Self {
        let proposer = request.proposer;
        let counter = SinglePositCounter::new(me, &participants);

        Self {
            sign_id,
            presignature_id,
            request,
            phase: SignatureTaskPhase::Posit {
                counter,
                proposer,
                participants,
            },
            presignature: Some(presignature),
            created: Instant::now(),
            timeout_total,
            me,
            threshold,
        }
    }

    /// Create a new signature task starting in Posit phase (deliberator mode without presignature)
    fn new_deliberator(
        me: Participant,
        sign_id: SignId,
        presignature_id: PresignatureId,
        request: SignRequest,
        proposer: Participant,
        participants: Vec<Participant>,
        threshold: usize,
        timeout_total: Duration,
    ) -> Self {
        let counter = SinglePositCounter::new(me, &participants);

        Self {
            sign_id,
            presignature_id,
            request,
            phase: SignatureTaskPhase::Posit {
                counter,
                proposer,
                participants,
            },
            presignature: None, // Deliberator will fetch from storage later
            created: Instant::now(),
            timeout_total,
            me,
            threshold,
        }
    }

    /// Check if total timeout has been exceeded
    fn timeout_total(&self) -> bool {
        self.created.elapsed() >= self.timeout_total
    }

    /// Check if this task is complete
    fn is_complete(&self) -> bool {
        matches!(self.phase, SignatureTaskPhase::Complete(_))
    }

    /// Get the result if the task is complete
    fn result(&self) -> Option<Result<(), SignError>> {
        match &self.phase {
            SignatureTaskPhase::Complete(result) => Some(*result),
            _ => None,
        }
    }

    /// Process a posit message and return what action to take
    /// This is the main entry point for all posit message handling
    fn process_message(
        &mut self,
        from: Participant,
        action: &PositAction,
    ) -> SignatureTaskMessageResult {
        // If we're not in posit phase, reject the message
        if !self.in_posit_phase() {
            return SignatureTaskMessageResult::Reject;
        }

        match action {
            PositAction::Propose => {
                // Should never receive Propose - tasks are created on Propose
                SignatureTaskMessageResult::Reject
            }
            PositAction::Accept | PositAction::Reject => {
                self.process_posit_action(from, action)
            }
            PositAction::Start(participants) => {
                // Transition to generation phase
                SignatureTaskMessageResult::StartGeneration {
                    participants: participants.clone(),
                }
            }
        }
    }

    /// Process a posit action during the Posit phase
    /// Returns the next action to take, or None if still waiting for more accepts/rejects
    fn process_posit_action(&mut self, from: Participant, action: &PositAction) -> SignatureTaskMessageResult {
        match &mut self.phase {
            SignatureTaskPhase::Posit {
                counter,
                proposer,
                participants,
            } => {
                if !counter.process_action(from, action) {
                    return SignatureTaskMessageResult::None;
                }

                // Check for enough rejects
                if counter.enough_rejects(self.threshold) {
                    tracing::info!(
                        sign_id = ?self.sign_id,
                        ?from,
                        "received enough REJECTs, aborting signature posit"
                    );
                    self.phase = SignatureTaskPhase::Complete(Err(SignError::Aborted));
                    return SignatureTaskMessageResult::Reject;
                }

                // Check if we have enough accepts for the proposed participants
                if counter.meets_totality() {
                    let accepted_participants = counter.accepts.iter().copied().collect::<Vec<_>>();
                    tracing::info!(
                        sign_id = ?self.sign_id,
                        ?accepted_participants,
                        "enough accepts received, ready for generation phase"
                    );
                    return SignatureTaskMessageResult::Ready {
                        participants: accepted_participants,
                        proposer: *proposer,
                    };
                }

                SignatureTaskMessageResult::None
            }
            _ => SignatureTaskMessageResult::None,
        }
    }

    /// Transition to the generation phase
    fn start_generation(&mut self, generator: Box<SignatureGenerator>) {
        self.phase = SignatureTaskPhase::Generating { generator };
    }

    /// Mark the task as complete
    fn complete(&mut self, result: Result<(), SignError>) {
        self.phase = SignatureTaskPhase::Complete(result);
    }

    /// Check if we're in Posit phase
    fn in_posit_phase(&self) -> bool {
        matches!(self.phase, SignatureTaskPhase::Posit { .. })
    }

    /// Check if we're in Generating phase
    fn in_generating_phase(&self) -> bool {
        matches!(self.phase, SignatureTaskPhase::Generating { .. })
    }

    /// Handle posit expiration (timeout during posit phase)
    fn handle_posit_expiration(&mut self, threshold: usize) -> Option<SignatureTaskPositAction> {
        match &mut self.phase {
            SignatureTaskPhase::Posit {
                counter,
                proposer,
                participants,
            } => {
                // Check if we have enough accepts despite timeout
                if counter.enough_accepts(threshold) {
                    let accepted_participants = counter.accepts.iter().copied().collect::<Vec<_>>();
                    tracing::info!(
                        sign_id = ?self.sign_id,
                        ?accepted_participants,
                        "posit expired with enough accepts, ready for generation phase"
                    );
                    return Some(SignatureTaskPositAction::Ready {
                        participants: accepted_participants,
                        proposer: *proposer,
                    });
                }

                // Not enough accepts, abort the task
                tracing::info!(
                    sign_id = ?self.sign_id,
                    accepts_count = counter.accepts.len(),
                    ?threshold,
                    "posit expired without enough accepts, aborting"
                );
                self.phase = SignatureTaskPhase::Complete(Err(SignError::TotalTimeout));
                Some(SignatureTaskPositAction::Reject)
            }
            _ => None,
        }
    }
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
            request,
            public_key,
            created: Instant::now(),
            timeout: Duration::from_millis(cfg.signature.generation_timeout),
            timeout_total: Duration::from_millis(cfg.signature.generation_timeout_total),
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
    /// Consolidated signature tasks combining posit + generation.
    tasks: HashMap<(SignId, PresignatureId), SignatureTask>,
    /// Buffer for posit messages that arrived before the task was created
    pending_posit_messages: HashMap<(SignId, PresignatureId), Vec<(Participant, PositAction)>>,

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
            tasks: HashMap::new(),
            pending_posit_messages: HashMap::new(),
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
        cfg: &ProtocolConfig,
    ) {
        let sign_id = request.indexed.id;
        let presignature_id = taken.presignature.id;
        tracing::info!(
            ?sign_id,
            presignature_id,
            "proposing protocol to generate a new signature"
        );

        // Create a new consolidated SignatureTask
        let timeout_total = request.indexed.total_timeout;
        let participants_vec = participants.to_vec();
        let task = SignatureTask::new_proposer(
            self.me,
            sign_id,
            presignature_id,
            request.clone(),
            taken,
            participants_vec,
            self.threshold,
            timeout_total,
        );
        self.tasks.insert((sign_id, presignature_id), task);

        // Process any pending posit messages that arrived before the task was created
        if let Some(pending_messages) = self.pending_posit_messages.remove(&(sign_id, presignature_id)) {
            tracing::debug!(
                ?sign_id,
                presignature_id,
                count = pending_messages.len(),
                "draining pending posit messages"
            );
            for (msg_from, msg_action) in pending_messages {
                let task = self.tasks.get_mut(&(sign_id, presignature_id)).unwrap();
                let result = task.process_message(msg_from, &msg_action);
                self.handle_task_result(sign_id, presignature_id, result, cfg).await;
            }
        }

        // Send propose messages to all participants
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

    /// Handle a posit message - either forward to task or buffer until task is created
    async fn handle_posit_message(
        &mut self,
        sign_id: SignId,
        presignature_id: PresignatureId,
        from: Participant,
        action: PositAction,
        cfg: &ProtocolConfig,
    ) {
        tracing::debug!(
            ?sign_id,
            presignature_id,
            ?from,
            ?action,
            "handling posit message"
        );

        // Ignore messages from ourselves
        if from == self.me {
            tracing::debug!(
                ?sign_id,
                presignature_id,
                "ignoring posit message from self"
            );
            return;
        }

        // Check if signature generation is already ongoing
        if self.ongoing.contains_key(&(sign_id, presignature_id)) {
            tracing::warn!(
                ?sign_id,
                presignature_id,
                "signature generation is already ongoing, ignoring posit message"
            );
            return;
        }

        // Special handling for Propose - create deliberator task
        if matches!(action, PositAction::Propose) {
            tracing::debug!(
                ?sign_id,
                presignature_id,
                ?from,
                "processing Propose action, checking for request"
            );

            // Check if we have the SignRequest available now (without blocking)
            let request_pending = self.sign_queue.get_or_pending(&sign_id);
            // Try to get it immediately without waiting
            let request_opt = tokio::time::timeout(Duration::from_millis(1), request_pending.fetch(Duration::from_millis(1))).await;
            
            let request = match request_opt {
                Ok(Some(req)) if req.proposer == from => {
                    tracing::debug!(
                        ?sign_id,
                        presignature_id,
                        "successfully got request, proposer matches"
                    );
                    req
                }
                Ok(Some(req)) => {
                    tracing::warn!(
                        ?sign_id,
                        presignature_id,
                        expected_proposer = ?req.proposer,
                        actual_proposer = ?from,
                        "rejecting signature posit: proposer mismatch",
                    );
                    self.msg
                        .send(
                            self.me,
                            from,
                            PositMessage {
                                id: PositProtocolId::Signature(sign_id, presignature_id),
                                from: self.me,
                                action: PositAction::Reject,
                            },
                        )
                        .await;
                    return;
                }
                _ => {
                    // Request not yet available - buffer this Propose message
                    tracing::debug!(
                        ?sign_id,
                        presignature_id,
                        ?from,
                        "request not yet available, buffering Propose message"
                    );
                    self.pending_posit_messages
                        .entry((sign_id, presignature_id))
                        .or_insert_with(Vec::new)
                        .push((from, action));
                    return;
                }
            };

            // Create deliberator task
            let participants = request.stable.iter().copied().collect::<Vec<_>>();
            let timeout_total = request.indexed.total_timeout;
            tracing::debug!(
                ?sign_id,
                presignature_id,
                ?from,
                ?participants,
                "creating deliberator task"
            );
            let task = SignatureTask::new_deliberator(
                self.me,
                sign_id,
                presignature_id,
                request.clone(),
                from,
                participants,
                self.threshold,
                timeout_total,
            );
            self.tasks.insert((sign_id, presignature_id), task);

            // Process any pending messages directly through the task (no recursion)
            if let Some(pending_messages) = self.pending_posit_messages.remove(&(sign_id, presignature_id)) {
                tracing::debug!(
                    ?sign_id,
                    presignature_id,
                    count = pending_messages.len(),
                    "processing pending posit messages"
                );
                for (msg_from, msg_action) in pending_messages {
                    let task = self.tasks.get_mut(&(sign_id, presignature_id)).unwrap();
                    let result = task.process_message(msg_from, &msg_action);
                    self.handle_task_result(sign_id, presignature_id, result, cfg).await;
                }
            }

            // Send Accept back
            tracing::debug!(
                ?sign_id,
                presignature_id,
                to = ?from,
                "sending Accept message"
            );
            self.msg
                .send(
                    self.me,
                    from,
                    PositMessage {
                        id: PositProtocolId::Signature(sign_id, presignature_id),
                        from: self.me,
                        action: PositAction::Accept,
                    },
                )
                .await;
            return;
        }

        // Forward message to task if it exists
        if let Some(task) = self.tasks.get_mut(&(sign_id, presignature_id)) {
            let result = task.process_message(from, &action);
            self.handle_task_result(sign_id, presignature_id, result, cfg).await;
        } else {
            // Buffer the message until task is created
            tracing::debug!(
                ?sign_id,
                presignature_id,
                ?from,
                ?action,
                "buffering posit message until task is created"
            );
            self.pending_posit_messages
                .entry((sign_id, presignature_id))
                .or_insert_with(Vec::new)
                .push((from, action));
        }
    }

    /// Handle the result from processing a message in a task
    async fn handle_task_result(
        &mut self,
        sign_id: SignId,
        presignature_id: PresignatureId,
        result: SignatureTaskMessageResult,
        cfg: &ProtocolConfig,
    ) {
        match result {
            SignatureTaskMessageResult::None => {
                // Nothing to do
            }
            SignatureTaskMessageResult::Reject => {
                tracing::warn!(
                    ?sign_id,
                    presignature_id,
                    "signature task rejected"
                );
                self.sign_queue.push_failed(sign_id);
            }
            SignatureTaskMessageResult::Ready { participants, proposer } => {
                // Got enough accepts! Start generation
                tracing::info!(
                    ?sign_id,
                    presignature_id,
                    ?participants,
                    "received enough ACCEPTs, starting signature generation"
                );

                // Send Start messages to all participants if we're the proposer
                if proposer == self.me {
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

                // Start generation
                self.start_generation(sign_id, presignature_id, participants, proposer, cfg).await;
            }
            SignatureTaskMessageResult::StartGeneration { participants } => {
                // Received Start message from proposer
                tracing::info!(
                    ?sign_id,
                    presignature_id,
                    ?participants,
                    "received Start message, beginning signature generation"
                );

                // Extract proposer from task
                let task = self.tasks.get(&(sign_id, presignature_id)).unwrap();
                let proposer = match &task.phase {
                    SignatureTaskPhase::Posit { proposer, .. } => *proposer,
                    _ => {
                        tracing::error!(?sign_id, presignature_id, "task not in posit phase");
                        return;
                    }
                };

                self.start_generation(sign_id, presignature_id, participants, proposer, cfg).await;
            }
        }
    }

    /// Start signature generation for a task
    async fn start_generation(
        &mut self,
        sign_id: SignId,
        presignature_id: PresignatureId,
        participants: Vec<Participant>,
        proposer: Participant,
        cfg: &ProtocolConfig,
    ) {
        // Extract presignature from task
        let task = self.tasks.get_mut(&(sign_id, presignature_id)).unwrap();
        let presignature = if let Some(taken) = task.presignature.take() {
            PendingPresignature::Available(taken)
        } else {
            PendingPresignature::InStorage(presignature_id, proposer, self.presignatures.clone())
        };

        let request = self.sign_queue.get_or_pending(&sign_id);
        self.generate(
            request,
            presignature,
            participants,
            cfg.clone(),
            self.sign_bidirectional_signature_channel.clone(),
        )
        .await;
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

        // Process any pending Propose messages now that requests have been organized
        let pending_keys: Vec<_> = self.pending_posit_messages.keys().copied().collect();
        for (sign_id, presignature_id) in pending_keys {
            if let Some(pending_msgs) = self.pending_posit_messages.remove(&(sign_id, presignature_id)) {
                tracing::debug!(
                    ?sign_id,
                    presignature_id,
                    count = pending_msgs.len(),
                    "retrying pending posit messages after queue organization"
                );
                for (from, action) in pending_msgs {
                    self.handle_posit_message(sign_id, presignature_id, from, action, cfg).await;
                }
            }
        }

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

            self.propose_posit(&my_request, taken, &participants, cfg).await;
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

        loop {
            tokio::select! {
                _ = expiration_interval.tick() => {
                    // Check all tasks for expiration (60 second posit timeout)
                    let posit_timeout = Duration::from_secs(60);
                    let expired_tasks: Vec<_> = self.tasks.iter_mut()
                        .filter(|(_, task)| task.in_posit_phase() && task.created.elapsed() >= posit_timeout)
                        .filter_map(|((sign_id, presignature_id), task)| {
                            task.handle_posit_expiration(self.threshold)
                                .map(|action| ((*sign_id, *presignature_id), action))
                        })
                        .collect();

                    for ((sign_id, presignature_id), action) in expired_tasks {
                        match action {
                            SignatureTaskPositAction::Ready { participants, proposer } => {
                                tracing::info!(
                                    ?sign_id,
                                    presignature_id,
                                    ?participants,
                                    "posit expired with enough accepts, starting generation"
                                );

                                // Send Start messages if we're the proposer
                                if proposer == self.me {
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

                                // Extract presignature and start generation
                                let task = self.tasks.get_mut(&(sign_id, presignature_id)).unwrap();
                                let presignature = if let Some(taken) = task.presignature.take() {
                                    // Proposer has presignature already
                                    PendingPresignature::Available(taken)
                                } else {
                                    // Deliberator fetches from storage
                                    PendingPresignature::InStorage(presignature_id, proposer, self.presignatures.clone())
                                };
                                
                                let request = self.sign_queue.get_or_pending(&sign_id);
                                let protocol = cfg.borrow().protocol.clone();
                                self.generate(
                                    request,
                                    presignature,
                                    participants,
                                    protocol,
                                    self.sign_bidirectional_signature_channel.clone(),
                                )
                                .await;
                            }
                            SignatureTaskPositAction::Reject => {
                                tracing::warn!(
                                    ?sign_id,
                                    presignature_id,
                                    "signature posit aborting on expiration, retrying..."
                                );
                                self.sign_queue.push_failed(sign_id);
                            }
                            _ => {}
                        }
                    }
                }
                Some((sign_id, presignature_id, from, action)) = posits.recv() => {
                    let protocol = cfg.borrow().protocol.clone();
                    self.handle_posit_message(sign_id, presignature_id, from, action, &protocol).await;
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
                            // Also clean up any associated tasks
                            // Find and remove tasks for this sign_id
                            self.tasks.retain(|(sid, _), _| sid != &sign_id);
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
