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
        // Auto-accept for ourselves
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
    StartGeneration { participants: Vec<Participant> },
    /// Need to create deliberator task (received Propose but no task exists yet)
    CreateDeliberator { from: Participant },
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
    /// Signature generation phase (actual generation runs in spawned task)
    Generating,
    /// Terminal states
    Complete(Result<(), SignError>),
}

/// A single signature generation task that combines posit and generator phases
pub struct SignatureTask {
    sign_id: SignId,
    /// Current presignature_id being used (changes on retry)
    presignature_id: Option<PresignatureId>,
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
    /// Returns the task and a list of Propose messages to send
    fn new_proposer(
        me: Participant,
        sign_id: SignId,
        presignature_id: PresignatureId,
        request: SignRequest,
        presignature: PresignatureTaken,
        participants: Vec<Participant>,
        threshold: usize,
        timeout_total: Duration,
    ) -> (Self, Vec<(Participant, PositMessage)>) {
        let proposer = request.proposer;
        let counter = SinglePositCounter::new(me, &participants);

        let task = Self {
            sign_id,
            presignature_id: Some(presignature_id),
            request,
            phase: SignatureTaskPhase::Posit {
                counter,
                proposer,
                participants: participants.clone(),
            },
            presignature: Some(presignature),
            created: Instant::now(),
            timeout_total,
            me,
            threshold,
        };

        // Generate Propose messages to send to all participants
        let messages = participants
            .iter()
            .filter(|&&p| p != me)
            .map(|&p| {
                (
                    p,
                    PositMessage {
                        id: PositProtocolId::Signature(sign_id, presignature_id),
                        from: me,
                        action: PositAction::Propose,
                    },
                )
            })
            .collect();

        (task, messages)
    }

    /// Create a new signature task starting in Posit phase (deliberator mode without presignature)
    /// Returns Accept message to send back to proposer
    fn new_deliberator(
        me: Participant,
        sign_id: SignId,
        presignature_id: PresignatureId,
        request: SignRequest,
        proposer: Participant,
        participants: Vec<Participant>,
        threshold: usize,
        timeout_total: Duration,
    ) -> (Self, PositMessage) {
        let counter = SinglePositCounter::new(me, &participants);

        let task = Self {
            sign_id,
            presignature_id: Some(presignature_id),
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
        };

        let accept_message = PositMessage {
            id: PositProtocolId::Signature(sign_id, presignature_id),
            from: me,
            action: PositAction::Accept,
        };

        (task, accept_message)
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
        // Ignore messages during generation phase
        if self.in_generating_phase() {
            return SignatureTaskMessageResult::None;
        }

        // If we're complete, ignore messages
        if self.is_complete() {
            return SignatureTaskMessageResult::None;
        }

        match action {
            PositAction::Propose => {
                // Only deliberators should receive Propose after task creation
                // Proposer creates the task and immediately has it in Posit phase
                // So if we get a Propose, it's a duplicate - ignore it
                SignatureTaskMessageResult::None
            }
            PositAction::Accept | PositAction::Reject => self.process_posit_action(from, action),
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
    fn process_posit_action(
        &mut self,
        from: Participant,
        action: &PositAction,
    ) -> SignatureTaskMessageResult {
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

    /// Transition to the generation phase (actual generation runs in spawned task)
    fn start_generation(&mut self) {
        self.phase = SignatureTaskPhase::Generating;
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
        matches!(self.phase, SignatureTaskPhase::Generating)
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

    /// Spawn a complete signature task (posit + generation) as an async task
    /// This handles the entire lifecycle: posit negotiation -> generation -> completion
    #[allow(clippy::too_many_arguments)]
    async fn spawn(
        me: Participant,
        sign_id: SignId,
        presignature_id: PresignatureId,
        request: SignRequest,
        presignature: Option<PresignatureTaken>,
        participants: Vec<Participant>,
        threshold: usize,
        public_key: PublicKey,
        epoch: u64,
        my_account_id: AccountId,
        presignatures: PresignatureStorage,
        msg: MessageChannel,
        rpc: RpcChannel,
        sign_bidirectional_signature_channel: SignBidirectionalSignatureChannel,
        cfg: ProtocolConfig,
        mut task_rx: mpsc::Receiver<SignatureTaskMessage>,
    ) -> Result<(), SignError> {
        // Phase 1: Posit negotiation
        let proposer = request.proposer;
        let is_proposer = me == proposer;

        tracing::debug!(
            ?sign_id,
            ?me,
            ?proposer,
            is_proposer,
            "signature task starting"
        );

        let mut counter = SinglePositCounter::new(me, &participants);
        let presignature = presignature;

        // If we're a deliberator (not proposer), send Accept to proposer
        if !is_proposer {
            tracing::debug!(?sign_id, ?me, ?proposer, "deliberator sending Accept");
            msg.send(
                me,
                proposer,
                PositMessage {
                    id: PositProtocolId::Signature(sign_id, presignature_id),
                    from: me,
                    action: PositAction::Accept,
                },
            )
            .await;
            tracing::debug!(?sign_id, ?me, ?proposer, "deliberator sent Accept");
        }

        // Posit timeout (60 seconds)
        let posit_timeout = Duration::from_secs(60);
        let posit_deadline = tokio::time::sleep(posit_timeout);
        tokio::pin!(posit_deadline);

        let accepted_participants = loop {
            tokio::select! {
                Some(task_msg) = task_rx.recv() => {
                    match task_msg {
                        SignatureTaskMessage::PositMessage { from, action } => {
                            if !counter.process_action(from, &action) {
                                continue;
                            }

                            // Check for enough rejects
                            if counter.enough_rejects(threshold) {
                                tracing::info!(?sign_id, ?from, "received enough REJECTs, aborting");
                                return Err(SignError::Aborted);
                            }

                            // Only complete early if we have totality (everyone voted)
                            // Otherwise wait for timeout even if we have enough accepts
                            if counter.meets_totality() {
                                break counter.accepts.iter().copied().collect::<Vec<_>>();
                            }
                        }
                    }
                }
                _ = &mut posit_deadline => {
                    // Posit expired
                    if counter.enough_accepts(threshold) {
                        tracing::info!(?sign_id, "posit expired with enough accepts");
                        break counter.accepts.iter().copied().collect::<Vec<_>>();
                    } else {
                        tracing::info!(?sign_id, "posit expired without enough accepts");
                        return Err(SignError::TotalTimeout);
                    }
                }
            }
        };

        tracing::info!(
            ?sign_id,
            presignature_id,
            ?accepted_participants,
            "posit complete, starting generation"
        );

        // Phase 2: Signature generation
        let presignature = if let Some(taken) = presignature {
            PendingPresignature::Available(taken)
        } else {
            PendingPresignature::InStorage(presignature_id, proposer, presignatures)
        };

        let pending_request = PendingRequest::Available(request);
        let generator = SignatureGenerator::new(
            me,
            pending_request,
            presignature,
            accepted_participants,
            public_key,
            cfg,
            msg,
            rpc,
            sign_bidirectional_signature_channel,
            &my_account_id,
        )
        .await
        .map_err(|_| SignError::Retry)?;

        generator.run(me, epoch, my_account_id).await
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

/// Message types that can be sent to a running signature task
enum SignatureTaskMessage {
    PositMessage {
        from: Participant,
        action: PositAction,
    },
}

pub struct SignatureSpawner {
    /// Presignature storage that maintains all presignatures.
    presignatures: PresignatureStorage,
    /// Sign queue that maintains all requests coming in from indexer.
    sign_queue: SignQueue,
    /// Consolidated signature tasks - one per sign_id, each task is an async task handling complete lifecycle
    tasks: JoinMap<SignId, Result<(), SignError>>,
    /// Channels to send messages to running tasks
    task_channels: HashMap<SignId, mpsc::Sender<SignatureTaskMessage>>,
    /// Buffer for posit messages that arrived before the task was created
    /// Maps sign_id -> list of (presignature_id, from, action)
    pending_posit_messages: HashMap<SignId, Vec<(PresignatureId, Participant, PositAction)>>,

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
            sign_queue: SignQueue::new(me, sign_rx),
            tasks: JoinMap::new(),
            task_channels: HashMap::new(),
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

    /// Creates a proposer task for a new sign request
    async fn create_proposer_task(
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
            "spawning proposer task to generate a new signature"
        );

        // Create channel for task communication
        let (tx, rx) = mpsc::channel(100);
        self.task_channels.insert(sign_id, tx);

        // Send Propose messages to all participants
        let participants_vec = participants.to_vec();
        for &p in &participants_vec {
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

        // Process any pending posit messages that arrived before the task was created
        if let Some(pending_messages) = self.pending_posit_messages.remove(&sign_id) {
            tracing::debug!(
                ?sign_id,
                count = pending_messages.len(),
                "sending pending posit messages to task"
            );
            for (msg_presignature_id, msg_from, msg_action) in pending_messages {
                // Only process messages for the current presignature_id
                if msg_presignature_id != presignature_id {
                    continue;
                }
                if let Some(ch) = self.task_channels.get(&sign_id) {
                    let _ = ch
                        .send(SignatureTaskMessage::PositMessage {
                            from: msg_from,
                            action: msg_action,
                        })
                        .await;
                }
            }
        }

        // Spawn the async task
        self.tasks.spawn(
            sign_id,
            SignatureTask::spawn(
                self.me,
                sign_id,
                presignature_id,
                request.clone(),
                Some(taken),
                participants_vec,
                self.threshold,
                self.public_key,
                self.epoch,
                self.my_account_id.clone(),
                self.presignatures.clone(),
                self.msg.clone(),
                self.rpc.clone(),
                self.sign_bidirectional_signature_channel.clone(),
                cfg.clone(),
                rx,
            ),
        );
    }

    /// Handle a posit message - creates deliberator task on Propose if request available, otherwise routes to task
    async fn handle_posit_message(
        &mut self,
        sign_id: SignId,
        presignature_id: PresignatureId,
        from: Participant,
        action: PositAction,
        cfg: &ProtocolConfig,
    ) {
        // Ignore messages from ourselves
        if from == self.me {
            return;
        }

        // Special case: Propose creates deliberator task if request is available
        if matches!(action, PositAction::Propose) && self.task_channels.get(&sign_id).is_none() {
            tracing::debug!(?sign_id, ?from, "received Propose, checking for request");
            // Check if we have the request in our sign queue
            if let Some(request) = self.sign_queue.requests.get(&sign_id).cloned() {
                tracing::info!(?sign_id, ?from, "creating deliberator task for Propose");
                // Verify proposer matches
                if request.proposer != from {
                    tracing::warn!(
                        ?sign_id,
                        presignature_id,
                        expected_proposer = ?request.proposer,
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

                // Create deliberator task
                let participants = request.stable.iter().copied().collect::<Vec<_>>();

                // Create channel for task communication
                let (tx, rx) = mpsc::channel(100);
                self.task_channels.insert(sign_id, tx.clone());

                // Process any buffered messages for this task
                if let Some(pending_messages) = self.pending_posit_messages.remove(&sign_id) {
                    for (msg_presignature_id, msg_from, msg_action) in pending_messages {
                        // Only process messages for the current presignature_id
                        if msg_presignature_id != presignature_id {
                            continue;
                        }
                        let _ = tx
                            .send(SignatureTaskMessage::PositMessage {
                                from: msg_from,
                                action: msg_action,
                            })
                            .await;
                    }
                }

                // Spawn the deliberator task (no presignature, will fetch from storage)
                self.tasks.spawn(
                    sign_id,
                    SignatureTask::spawn(
                        self.me,
                        sign_id,
                        presignature_id,
                        request.clone(),
                        None, // Deliberator fetches from storage
                        participants,
                        self.threshold,
                        self.public_key,
                        self.epoch,
                        self.my_account_id.clone(),
                        self.presignatures.clone(),
                        self.msg.clone(),
                        self.rpc.clone(),
                        self.sign_bidirectional_signature_channel.clone(),
                        cfg.clone(),
                        rx,
                    ),
                );
                return;
            }
            // Request not available yet - buffer the Propose
        }

        // If task channel exists, forward message to it
        if let Some(ch) = self.task_channels.get(&sign_id) {
            let _ = ch
                .send(SignatureTaskMessage::PositMessage { from, action })
                .await;
        } else {
            // No task - buffer message
            tracing::debug!(?sign_id, ?from, ?action, "buffering message - no task yet");
            self.pending_posit_messages
                .entry(sign_id)
                .or_insert_with(Vec::new)
                .push((presignature_id, from, action));
        }
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

        // Process buffered Propose messages now that requests have been organized
        // This allows deliberator tasks to be created if the request arrived after the Propose
        let pending_keys: Vec<_> = self.pending_posit_messages.keys().copied().collect();
        for sign_id in pending_keys {
            if let Some(pending_msgs) = self.pending_posit_messages.remove(&sign_id) {
                for (presignature_id, from, action) in pending_msgs {
                    self.handle_posit_message(sign_id, presignature_id, from, action, cfg)
                        .await;
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

            self.create_proposer_task(&my_request, taken, &participants, cfg)
                .await;
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
        let mut check_requests_interval = tokio::time::interval(Duration::from_millis(100));
        let mut posits = self.msg.subscribe_signature_posit().await;

        loop {
            tokio::select! {
                Some((sign_id, presignature_id, from, action)) = posits.recv() => {
                    let protocol = cfg.borrow().protocol.clone();
                    self.handle_posit_message(sign_id, presignature_id, from, action, &protocol).await;
                }
                Some(result) = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    let (sign_id, result) = match result {
                        Ok(outcome) => outcome,
                        Err(sign_id) => {
                            tracing::warn!(?sign_id, "signature task interrupted");
                            // Clean up channel
                            self.task_channels.remove(&sign_id);
                            continue;
                        }
                    };

                    // Clean up channel
                    self.task_channels.remove(&sign_id);

                    match result {
                        Err(SignError::Retry) => {
                            tracing::info!(?sign_id, "signature task failed, retrying");
                            self.sign_queue.push_failed(sign_id);
                        }
                        Ok(()) => {
                            tracing::info!(?sign_id, "signature task completed successfully");
                            self.sign_queue.remove(sign_id);
                        }
                        Err(SignError::TotalTimeout) | Err(SignError::Aborted) => {
                            tracing::warn!(?sign_id, ?result, "signature task terminated");
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
