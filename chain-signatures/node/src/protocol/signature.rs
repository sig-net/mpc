use crate::backlog::Backlog;
use crate::config::Config;
use crate::kdf::derive_delta;
use crate::mesh::MeshState;
use crate::metrics::requests::{
    record_request_latency, record_request_latency_since, SignRequestStep, SIGN_REQUEST_LOOPS,
};
use crate::protocol::contract::primitives::intersect_vec;
use crate::protocol::message::{
    MessageChannel, PositMessage, PositProtocolId, SignatureMessage, Subscriber,
};
use crate::protocol::posit::{PositAction, SinglePositCounter};
use crate::protocol::presignature::PresignatureId;
use crate::protocol::SignKind;
use crate::protocol::{Chain, ProtocolState};
use crate::rpc::{ContractStateWatcher, GovernanceInfo, RpcChannel};
use crate::sign_bidirectional::PublishState;
use crate::storage::presignature_storage::{
    PresignatureReservation, PresignatureTaken, PresignatureTakenDropper,
};
use crate::storage::PresignatureStorage;
use crate::stream::ops::SignBidirectionalEvent;
use crate::types::SignatureProtocol;
use crate::util::{AffinePointExt, JoinMap, TimeoutBudget};

use cait_sith::protocol::{Action, InitializationError, Participant};
use cait_sith::PresignOutput;
use chrono::Utc;
use k256::Secp256k1;
use mpc_contract::config::ProtocolConfig;
use mpc_crypto::derive_key;
use mpc_primitives::{SignArgs, SignId};
use rand::rngs::StdRng;
use rand::seq::IteratorRandom;
use rand::SeedableRng;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

/// The round interval to search for a proposer in the organizing phase.
const ROUND_INTERVAL: usize = 512;

/// Max number of concurrent proposers, with unlimited deliberators.
const MAX_CONCURRENT_PROPOSERS: usize = 4;

/// The default timeout budget for organizing and posit phases.
///
/// Tests have stable network conditions and don't benefit from a longer
/// timeout. It only makes them run for longer.
const ORGANIZE_POSIT_TIMEOUT: Duration = Duration::from_secs(if cfg!(feature = "test-feature") {
    5
} else {
    20
});

/// A proposer tries to include all eligible deliberators but will go ahead with
/// a subset after this timeout, if above the minimum threshold.
const ACCEPT_POSIT_TIMEOUT: Duration = Duration::from_millis(500);

/// Metric channel label shared by every entry in `SignatureSpawner.inboxes`.
const SIGN_POSIT_INBOX_LABEL: &str = "sign_posit_inbox";

/// All relevant info pertaining to an indexed sign request.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct IndexedSignRequest {
    pub id: SignId,
    pub args: SignArgs,
    pub chain: Chain,
    /// Unix timestamp when the request was indexed by MPC node.
    /// Preserved across recoveries to maintain original request creation time.
    pub unix_timestamp_indexed: u64,
    pub kind: SignKind,
}

impl IndexedSignRequest {
    pub fn new(
        id: SignId,
        args: SignArgs,
        chain: Chain,
        unix_timestamp_indexed: u64,
        kind: SignKind,
    ) -> Self {
        Self {
            id,
            args,
            chain,
            unix_timestamp_indexed,
            kind,
        }
    }

    pub fn sign(id: SignId, args: SignArgs, chain: Chain, unix_timestamp_indexed: u64) -> Self {
        Self::new(id, args, chain, unix_timestamp_indexed, SignKind::Sign)
    }

    pub fn sign_bidirectional(
        id: SignId,
        args: SignArgs,
        chain: Chain,
        unix_timestamp_indexed: u64,
        event: SignBidirectionalEvent,
    ) -> Self {
        Self::new(
            id,
            args,
            chain,
            unix_timestamp_indexed,
            SignKind::SignBidirectional(event),
        )
    }

    pub fn respond_bidirectional(
        id: SignId,
        args: SignArgs,
        chain: Chain,
        unix_timestamp_indexed: u64,
        tx: crate::protocol::RespondBidirectionalTx,
    ) -> Self {
        Self::new(
            id,
            args,
            chain,
            unix_timestamp_indexed,
            SignKind::RespondBidirectional(tx),
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Sign {
    Request(IndexedSignRequest),
    Completion(SignId),
}

#[derive(Debug, Clone, Copy)]
enum SignError {
    Aborted,
}

#[derive(Debug)]
pub enum SignLimitError {
    Timeout,
    Closed,
}

#[derive(Debug)]
struct SignLimitState {
    limit: usize,
    debt: usize,
}

#[derive(Clone, Debug)]
pub struct SignLimiter {
    semaphore: Arc<Semaphore>,
    state: Arc<RwLock<SignLimitState>>,
}

#[derive(Debug)]
pub struct SignPermit {
    permit: Option<OwnedSemaphorePermit>,
    state: Arc<RwLock<SignLimitState>>,
}

impl SignLimiter {
    pub fn new(limit: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(limit)),
            state: Arc::new(RwLock::new(SignLimitState { limit, debt: 0 })),
        }
    }

    /// Updates the limits for concurrent slots
    pub fn update(&self, new_limit: usize) {
        let mut state = match self.state.write() {
            Ok(state) => state,
            Err(err) => {
                tracing::error!(new_limit, ?err, "unable to update SignLimiter limits");
                return;
            }
        };
        let old_limit = std::mem::replace(&mut state.limit, new_limit);

        // add more permits if the limit increased
        if new_limit > old_limit {
            let mut permits_to_add = new_limit - old_limit;
            if permits_to_add > 0 {
                let forgiven = permits_to_add.min(state.debt);
                state.debt -= forgiven;
                permits_to_add -= forgiven;
                self.semaphore.add_permits(permits_to_add);
            }
            return;
        }

        // remove permits or add to a debt where when the permit is dropped, we forget it.
        let permits_to_remove = old_limit - new_limit;
        if permits_to_remove == 0 {
            return;
        }

        let forgotten = self.semaphore.forget_permits(permits_to_remove);
        if forgotten < permits_to_remove {
            state.debt += permits_to_remove - forgotten;
        }
    }

    /// Try to acquire a spot with a timeout just in case we do not receive the slot in time.
    /// Returns a permit if successful, error otherwise.
    pub async fn acquire(&self, timeout: Duration) -> Result<SignPermit, SignLimitError> {
        let permit =
            match tokio::time::timeout(timeout, self.semaphore.clone().acquire_owned()).await {
                Ok(Ok(permit)) => permit,
                // note, acquire error is effectively the same as closed.
                Ok(Err(_acquire_err)) => return Err(SignLimitError::Closed),
                Err(_timeout) => return Err(SignLimitError::Timeout),
            };

        Ok(SignPermit {
            permit: Some(permit),
            state: Arc::clone(&self.state),
        })
    }

    pub fn limits(&self) -> usize {
        match self.state.read() {
            Ok(state) => state.limit,
            Err(err) => {
                tracing::error!(?err, "failed to acquire lock in SignLimiter::limits");
                0
            }
        }
    }
}

impl Drop for SignPermit {
    fn drop(&mut self) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        let mut state = match self.state.write() {
            Ok(state) => state,
            Err(err) => {
                tracing::error!(?err, "failed to acquire lock in SignPermit drop");
                return;
            }
        };
        if state.debt > 0 {
            state.debt -= 1;
            permit.forget();
        }
    }
}

struct SignState {
    round: usize,
    indexed: IndexedSignRequest,
    mesh_state: watch::Receiver<MeshState>,
    /// Budget for the current organizing+posit attempt.
    budget: TimeoutBudget,
    permit: Option<SignPermit>,
    /// The highest round sent by a peer
    highest_seen_round: usize,
    /// Posit message for `highest_seen_round` round.
    ///
    /// These are later processed, if the task reaches the `highest_seen_round`
    /// as a deliberator. Proposers do not reprocess old messages. A valid peer
    /// would not have sent a posit message before the proposer proposes.
    ///
    /// INVARIANT: All messages stored here are for `highest_seen_round`. Must
    /// be cleared when `highest_seen_round` changes.
    buffered_messages: VecDeque<SignTaskMessage>,
}

impl SignState {
    fn new(indexed: IndexedSignRequest, mesh_state: watch::Receiver<MeshState>) -> Self {
        Self {
            round: 0,
            indexed,
            mesh_state,
            budget: TimeoutBudget::new(ORGANIZE_POSIT_TIMEOUT),
            permit: None,
            highest_seen_round: 0,
            buffered_messages: VecDeque::new(),
        }
    }

    fn indexed(&self) -> &IndexedSignRequest {
        &self.indexed
    }

    fn bump_round(&mut self) {
        let prev_round = self.round;
        self.round = std::cmp::max(self.round + 1, self.highest_seen_round);
        // Reset the budget for the new attempt
        self.budget.reset(ORGANIZE_POSIT_TIMEOUT);
        self.permit = None;
        tracing::debug!(prev_round, new_round = self.round, "bumped round");
    }

    /// When receiving posit message for future rounds, store them away until
    /// that round is reached.
    fn store_future_posit_message(&mut self, msg: SignTaskMessage) {
        let SignTaskMessage::PositMessage {
            round: peer_round, ..
        } = msg;

        if peer_round < self.highest_seen_round {
            return;
        }
        if peer_round > self.highest_seen_round {
            self.highest_seen_round = peer_round;
            self.buffered_messages.clear();
        }
        self.buffered_messages.push_back(msg);
    }

    /// Remove a buffered message for processing, if there is one for the
    /// current round.
    fn take_buffered_posit_message(&mut self) -> Option<SignTaskMessage> {
        if self.highest_seen_round == self.round {
            self.buffered_messages.pop_front()
        } else {
            None
        }
    }
}

struct SignPositor {
    proposer: Participant,
    active: BTreeSet<Participant>,
    presignature_id: PresignatureId,
    presignature: Option<PresignatureReservation>,
}

struct SignGenerating {
    proposer: Participant,
    presignature_id: PresignatureId,
    presignature: Option<PresignatureReservation>,
    accepted_participants: Vec<Participant>,
}

enum SignPhase {
    Organizing(SignOrganizer),
    Posit(SignPositor),
    Generating(SignGenerating),
    Complete(Result<(), SignError>),
}

impl SignPhase {
    async fn advance(
        &mut self,
        ctx: &mut SignTask,
        state: &mut SignState,
        task_rx: &mut mpsc::Receiver<SignTaskMessage>,
    ) -> SignPhase {
        match self {
            SignPhase::Organizing(phase) => phase.advance(ctx, state).await,
            SignPhase::Posit(phase) => phase.advance(ctx, state, task_rx).await,
            SignPhase::Generating(phase) => phase.advance(ctx, state).await,
            SignPhase::Complete(result) => SignPhase::Complete(*result),
        }
    }
}

struct SignOrganizer;

impl SignOrganizer {
    fn proposer_per_round(
        round: usize,
        participants: &[Participant],
        entropy: &[u8; 32],
    ) -> Participant {
        let index = entropy[0] as usize + round;
        participants[index % participants.len()]
    }

    /// Waits for threshold active participants to be present.
    async fn wait_active(
        &self,
        ctx: &mut SignTask,
        state: &mut SignState,
        threshold: usize,
    ) -> Option<BTreeSet<Participant>> {
        let sign_id = ctx.sign_id;
        let mut once = true;

        loop {
            let active_count = {
                let active: BTreeSet<_> =
                    state.mesh_state.borrow().active().keys().copied().collect();
                if active.len() >= threshold {
                    return Some(active);
                }
                active.len()
            };

            if once {
                tracing::info!(
                    ?sign_id,
                    active_count,
                    ?threshold,
                    "waiting for enough active participants"
                );
                once = false;
            }

            if state.mesh_state.changed().await.is_err() {
                return None;
            }
        }
    }

    async fn advance(&mut self, ctx: &mut SignTask, state: &mut SignState) -> SignPhase {
        let sign_id = ctx.sign_id;
        let threshold = ctx.governance.threshold;
        let me = ctx.governance.me;
        let entropy = state.indexed.args.entropy;
        let participants = ctx
            .governance
            .participants
            .iter()
            .copied()
            .collect::<Vec<_>>();

        ctx.is_proposer.store(false, Ordering::Relaxed);

        tracing::info!(?sign_id, round = ?state.round, "entering organizing phase");
        let (active, proposer, is_proposer) = {
            let Some(active) = self.wait_active(ctx, state, threshold).await else {
                tracing::warn!(?sign_id, round = ?state.round, "no active participants, reorganizing");
                state.bump_round();
                return SignPhase::Organizing(SignOrganizer);
            };

            let max_rounds = state.round + ROUND_INTERVAL;
            let (selected_round, proposer) = (state.round..max_rounds)
                .map(|r| (r, Self::proposer_per_round(r, &participants, &entropy)))
                .find(|(_, potential_proposer)| active.contains(potential_proposer))
                .unwrap_or_else(|| {
                    (
                        max_rounds,
                        *active
                            .iter()
                            .choose(&mut StdRng::from_seed(entropy))
                            .unwrap(),
                    )
                });

            state.round = selected_round;

            let is_proposer = proposer == me;
            ctx.is_proposer.store(is_proposer, Ordering::Relaxed);

            tracing::info!(
                ?sign_id,
                round = selected_round,
                ?proposer,
                ?me,
                is_proposer,
                active_count = active.len(),
                "organized: selected proposer"
            );

            (active, proposer, is_proposer)
        };

        if is_proposer {
            let remaining = state.budget.remaining();
            tracing::info!(
                ?sign_id,
                round = ?state.round,
                timeout = ?remaining,
                limit = ctx.limiter.limits(),
                "proposer waiting for concurrency slot"
            );

            let permit = match ctx.limiter.acquire(remaining).await {
                Ok(permit) => permit,
                Err(SignLimitError::Timeout) => {
                    tracing::warn!(
                        ?sign_id,
                        round = ?state.round,
                        "proposer timeout waiting for concurrency slot, reorganizing"
                    );
                    state.bump_round();
                    return SignPhase::Organizing(SignOrganizer);
                }
                Err(SignLimitError::Closed) => {
                    tracing::error!(?sign_id, "proposer semaphore closed");
                    return SignPhase::Complete(Err(SignError::Aborted));
                }
            };

            state.permit = Some(permit);
        } else {
            state.permit = None;
        }

        let (presignature_id, presignature, active) = if is_proposer {
            tracing::info!(?sign_id, round = ?state.round, "proposer waiting for presignature");
            let active = active.iter().copied().collect::<Vec<_>>();
            let remaining = state.budget.remaining();
            let fetch = tokio::time::timeout(remaining, async {
                // IDs that were found unsuitable this round (kept in redis, skipped next peek)
                let mut local_skip: Vec<PresignatureId> = Vec::new();
                loop {
                    if let Some(reservation) = ctx.presignatures.peek_mine(&local_skip).await {
                        let holders = reservation.holders();
                        let participants = intersect_vec(&[holders, &active]);
                        if participants.len() < ctx.governance.threshold {
                            tracing::warn!(
                                ?sign_id,
                                id = reservation.id,
                                ?holders,
                                ?active,
                                "skipping presignature due to inactive participants, returning to pool"
                            );
                            local_skip.push(reservation.id);
                            // drop: in-memory reservation released, presignature stays in redis
                            continue;
                        }

                        break (reservation, participants);
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            })
            .await;

            let (reservation, participants) = match fetch {
                Ok(value) => value,
                Err(_) => {
                    tracing::warn!(
                        ?sign_id,
                        round = ?state.round,
                        "proposer timeout waiting for presignature, reorganizing"
                    );
                    state.bump_round();
                    return SignPhase::Organizing(SignOrganizer);
                }
            };

            let presignature_id = reservation.id;

            tracing::info!(?sign_id, ?presignature_id, "proposer got presignature");

            // broadcast to participants and let them reject if they don't have the presignature.
            for &p in &participants {
                if p == ctx.governance.me {
                    continue;
                }
                ctx.msg
                    .send(
                        ctx.governance.me,
                        p,
                        PositMessage {
                            id: PositProtocolId::Signature(sign_id, presignature_id, state.round),
                            from: ctx.governance.me,
                            action: PositAction::Propose,
                        },
                    )
                    .await;
            }

            // Update active to only include participants that are in both the presignature and active set
            let active = participants.into_iter().collect::<BTreeSet<_>>();
            (presignature_id, Some(reservation), active)
        } else {
            (PresignatureId::default(), None, active)
        };

        SignPhase::Posit(SignPositor {
            proposer,
            active,
            presignature_id,
            presignature,
        })
    }
}

impl SignPositor {
    /// Deliberator waits for the proposer to send a Propose message with a presignature_id.
    async fn wait_propose(
        ctx: &mut SignTask,
        state: &mut SignState,
        task_rx: &mut mpsc::Receiver<SignTaskMessage>,
        proposer: Participant,
    ) -> Result<PresignatureId, SignPhase> {
        let sign_id = ctx.sign_id;
        let round = state.round;
        let remaining = state.budget.remaining();
        let outcome = tokio::time::timeout(remaining, async {
            loop {
                // Prioritize buffered messages, if any for the current round
                let task_msg = match state.take_buffered_posit_message() {
                    Some(buffered) => buffered,
                    None => {
                        let Some(task_msg) = task_rx.recv().await else {
                            continue;
                        };
                        task_msg
                    }
                };

                let SignTaskMessage::PositMessage {
                    presignature_id,
                    from,
                    action,
                    round: peer_round,
                } = &task_msg;

                // reject any messages with a different round than ours
                //
                // note: Rejecting messages of older rounds is always the right
                // choice. But for newer messages, we could buffer them and try
                // that round later. What we must not do is immediately jump to
                // that higher round, or else any peer could force themselves to
                // be the proposer every time.
                if state.round > *peer_round {
                    ctx.msg
                        .send(
                            ctx.governance.me,
                            *from,
                            PositMessage {
                                id: PositProtocolId::Signature(
                                    sign_id,
                                    *presignature_id,
                                    *peer_round,
                                ),
                                from: ctx.governance.me,
                                action: PositAction::Reject,
                            },
                        )
                        .await;
                    continue;
                }

                // Message can't be processed now but is crucial to make progress later.
                // Note that we must first try and finish the current round and
                // not immediately jump to that higher round. Otherwise, any peer
                // could force themselves to be the proposer every time.
                if state.round < *peer_round {
                    tracing::info!(
                        peer_round,
                        my_round = state.round,
                        "Storing message for future round, as deliberator",
                    );
                    state.store_future_posit_message(task_msg);
                    continue;
                }

                if !matches!(action, PositAction::Propose) {
                    tracing::warn!(
                        round = peer_round,
                        ?action,
                        "Got unexpected posit message while waiting for propose"
                    );
                    continue;
                }

                if from == &proposer {
                    tracing::info!(
                        ?sign_id,
                        ?presignature_id,
                        ?from,
                        "deliberator received Propose"
                    );

                    // Check if we have access to this presignature (in storage or generating)
                    if !ctx.presignatures.contains(*presignature_id).await {
                        tracing::warn!(
                            ?sign_id,
                            presignature_id,
                            "deliberator does not have access to proposed presignature, rejecting"
                        );
                        ctx.msg
                            .send(
                                ctx.governance.me,
                                proposer,
                                PositMessage {
                                    id: PositProtocolId::Signature(
                                        sign_id,
                                        *presignature_id,
                                        state.round,
                                    ),
                                    from: ctx.governance.me,
                                    action: PositAction::Reject,
                                },
                            )
                            .await;
                        continue;
                    }

                    break Ok(*presignature_id);
                } else {
                    tracing::warn!(
                        ?sign_id,
                        ?from,
                        ?proposer,
                        "received Propose from non-proposer, rejecting"
                    );

                    ctx.msg
                        .send(
                            ctx.governance.me,
                            *from,
                            PositMessage {
                                id: PositProtocolId::Signature(
                                    sign_id,
                                    *presignature_id,
                                    state.round,
                                ),
                                from: ctx.governance.me,
                                action: PositAction::Reject,
                            },
                        )
                        .await;
                }
            }
        })
        .await;

        let presignature_id = match outcome {
            Ok(Ok(id)) => id,
            Ok(Err(phase)) => return Err(phase),
            Err(_) => {
                tracing::warn!(
                    ?sign_id,
                    ?round,
                    ?proposer,
                    me=?ctx.governance.me,
                    "deliberator timeout waiting for Propose, reorganizing"
                );
                state.bump_round();
                return Err(SignPhase::Organizing(SignOrganizer));
            }
        };

        // received propose, send Accept
        ctx.msg
            .send(
                ctx.governance.me,
                proposer,
                PositMessage {
                    id: PositProtocolId::Signature(sign_id, presignature_id, state.round),
                    from: ctx.governance.me,
                    action: PositAction::Accept,
                },
            )
            .await;

        Ok(presignature_id)
    }

    async fn advance(
        &mut self,
        ctx: &mut SignTask,
        state: &mut SignState,
        task_rx: &mut mpsc::Receiver<SignTaskMessage>,
    ) -> SignPhase {
        let proposer = self.proposer;
        let active = self.active.clone();
        let mut presignature_id = self.presignature_id;
        let presignature = self.presignature.take();

        let sign_id = ctx.sign_id;
        let round = state.round;
        let is_proposer = proposer == ctx.governance.me;
        let is_deliberator = !is_proposer;

        tracing::info!(
            ?sign_id,
            ?presignature_id,
            ?round,
            is_proposer,
            "entering posit phase"
        );

        if is_deliberator {
            tracing::info!(
                ?sign_id,
                ?round,
                ?proposer,
                "deliberator waiting for Propose"
            );

            presignature_id = match Self::wait_propose(ctx, state, task_rx, proposer).await {
                Ok(id) => id,
                Err(phase) => return phase,
            }
        }

        // GUARANTEE: at least threshold participants from organizing phase.
        let posit_participants = active.iter().copied().collect::<Vec<_>>();
        let mut counter = SinglePositCounter::new(ctx.governance.me, &posit_participants);

        let remaining = state.budget.remaining();
        let posit_deadline = tokio::time::sleep(remaining);
        tokio::pin!(posit_deadline);
        let accept_deadline = tokio::time::sleep(ACCEPT_POSIT_TIMEOUT);
        tokio::pin!(accept_deadline);
        let mut accept_deadline_reached = false;

        let accepted_participants = loop {
            tokio::select! {
                Some(task_msg) = task_rx.recv() => {
                    let SignTaskMessage::PositMessage { round: peer_round , ..} = task_msg;

                    // Ignore messages for older rounds
                    if state.round > peer_round {
                        continue;
                    }

                    // Message can't be processed now but is crucial to make progress later.
                    // Note that we must first try and finish the current round and
                    // not immediately jump to that higher round. Otherwise, any peer
                    // could force themselves to be the proposer every time.
                    if state.round < peer_round {
                        tracing::info!(
                            peer_round,
                            my_round = state.round,
                            "Storing message for future round",
                        );
                        state.store_future_posit_message(task_msg);
                        continue;
                    }

                    let SignTaskMessage::PositMessage { presignature_id: _, round: _peer_round, from, action } = task_msg;

                    if is_deliberator {
                        if let PositAction::Start(participants) = action {
                            if from != proposer {
                                tracing::warn!(?sign_id, ?round, ?from, ?proposer, "received Start from non-proposer, ignoring");
                                continue;
                            }

                            if participants.len() < ctx.governance.threshold {
                                tracing::warn!(
                                    ?sign_id,
                                    ?round,
                                    "not enough start participants"
                                );
                                state.bump_round();
                                return SignPhase::Organizing(SignOrganizer);
                            }

                            tracing::info!(?sign_id, participant = ?ctx.governance.me, ?participants, "deliberator received Start");
                            break participants;
                        }
                    } else {
                        if !counter.process_action(from, &action) {
                            continue;
                        }

                        if counter.enough_rejects(ctx.governance.threshold) {
                            tracing::warn!(?sign_id, ?round, ?from, "received enough REJECTs, reorganizing");
                            if let Some(_reservation) = presignature {
                                tracing::warn!(?sign_id, "returning presignature to pool due to REJECTs");
                            }
                            state.bump_round();
                            return SignPhase::Organizing(SignOrganizer);
                        }

                        // Starting as soon as we have enough accepts leaves
                        // participants accepting a bit later in a bad state.
                        // They will try to become propose in later rounds,
                        // wasting Presignatures, memory and CPU time.
                        //
                        // Instead, wait for at least the `accept_deadline`,
                        // only nodes answer slower will be left out. This isn't
                        // perfect but much better than always forcing nodes
                        // into the bad state.
                        let ready_to_go = counter.meets_totality() ||  accept_deadline_reached;
                        if ready_to_go && counter.enough_accepts(ctx.governance.threshold) {
                            let participants = Self::start_with_current_accepts(
                                ctx,
                                state,
                                counter,
                                sign_id,
                                presignature_id
                            ).await;
                            break participants;
                        }
                    }
                }
                _ = &mut posit_deadline => {
                    if is_proposer {
                        tracing::warn!(
                            ?sign_id,
                            accepts = counter.accepts.len(),
                            threshold = ctx.governance.threshold,
                            ?round,
                            "proposer posit deadline reached, expiring round"
                        );
                        if let Some(_reservation) = presignature {
                            tracing::warn!(?sign_id, "returning presignature to pool due to proposer timeout");
                        }
                    } else {
                        tracing::warn!(?sign_id, me=?ctx.governance.me, ?proposer, "deliberator posit timeout waiting for Start, reorganizing");
                    }

                    state.bump_round();
                    return SignPhase::Organizing(SignOrganizer);
                }
                _ = &mut accept_deadline, if is_proposer && !accept_deadline_reached => {
                    accept_deadline_reached = true;
                    if counter.enough_accepts(ctx.governance.threshold) {
                        let participants = Self::start_with_current_accepts(
                            ctx,
                            state,
                            counter,
                            sign_id,
                            presignature_id
                        ).await;
                        break participants;
                    }
                }

            }
        };

        SignPhase::Generating(SignGenerating {
            proposer,
            presignature_id,
            presignature,
            accepted_participants,
        })
    }

    async fn start_with_current_accepts(
        ctx: &SignTask,
        state: &mut SignState,
        counter: SinglePositCounter,
        sign_id: SignId,
        presignature_id: PresignatureId,
    ) -> Vec<Participant> {
        let participants = counter.accepts.into_iter().collect::<Vec<_>>();
        tracing::info!(?sign_id, round=?state.round, me = ?ctx.governance.me, ?participants, "proposer broadcasting Start");

        for &p in &participants {
            if p == ctx.governance.me {
                continue;
            }
            ctx.msg
                .send(
                    ctx.governance.me,
                    p,
                    PositMessage {
                        id: PositProtocolId::Signature(sign_id, presignature_id, state.round),
                        from: ctx.governance.me,
                        action: PositAction::Start(participants.clone()),
                    },
                )
                .await;
        }
        participants
    }
}

impl SignGenerating {
    async fn advance(&mut self, ctx: &SignTask, state: &mut SignState) -> SignPhase {
        let sign_id = ctx.sign_id;
        let round = state.round;

        tracing::info!(
            ?sign_id,
            presignature_id = ?self.presignature_id,
            participants = ?self.accepted_participants,
            "posit complete, starting generation"
        );

        let presignature_pending = if let Some(reservation) = self.presignature.take() {
            // Commit: actually remove from Redis now that posit succeeded and generation starts
            match reservation.commit().await {
                Some(taken) => PendingPresignature::Available(Box::new(taken)),
                None => {
                    tracing::warn!(
                        ?sign_id,
                        ?round,
                        "failed to commit presignature reservation, reorganizing"
                    );
                    state.bump_round();
                    return SignPhase::Organizing(SignOrganizer);
                }
            }
        } else {
            PendingPresignature::InStorage(
                self.presignature_id,
                self.proposer,
                ctx.presignatures.clone(),
            )
        };

        let generator = match SignGenerator::new(
            ctx,
            self.proposer,
            state.indexed().clone(),
            presignature_pending,
            self.accepted_participants.clone(),
            &ctx.node_account_id,
        )
        .await
        {
            Ok(gen) => gen,
            Err(err) => {
                tracing::warn!(
                    ?sign_id,
                    ?round,
                    ?err,
                    "failed to create generator, reorganizing"
                );
                state.bump_round();
                return SignPhase::Organizing(SignOrganizer);
            }
        };

        // Track that we've created a generator
        crate::metrics::protocols::NUM_TOTAL_HISTORICAL_SIGNATURE_GENERATORS.inc();

        match generator.run(ctx).await {
            Ok(()) => SignPhase::Complete(Ok(())),
            Err(err) => {
                tracing::warn!(
                    ?sign_id,
                    ?round,
                    ?err,
                    me=?ctx.governance.me,
                    "signature generation failed, reorganizing"
                );
                state.bump_round();
                SignPhase::Organizing(SignOrganizer)
            }
        }
    }
}

/// An ongoing signature generator.
struct SignGenerator {
    protocol: SignatureProtocol,
    dropper: PresignatureTakenDropper,
    participants: Vec<Participant>,
    proposer: Participant,
    indexed: IndexedSignRequest,
    created: Instant,
    timeout: Duration,
    inbox: mpsc::Receiver<SignatureMessage>,
    msg: MessageChannel, // Needed for Drop

    #[cfg(feature = "debug-page")]
    debug_view: crate::web::debug::DebugPageTaskHandle,
}

impl SignGenerator {
    async fn new(
        ctx: &SignTask,
        proposer: Participant,
        indexed: IndexedSignRequest,
        presignature: PendingPresignature,
        participants: Vec<Participant>,
        _node_account_id: &near_account_id::AccountId,
    ) -> Result<Self, InitializationError> {
        #[cfg(feature = "debug-page")]
        let node_account_id = _node_account_id;
        #[cfg(not(feature = "debug-page"))]
        let _ = _node_account_id;

        let presignature_id = presignature.id();
        let taken = presignature
            .fetch(Duration::from_millis(ctx.cfg.signature.generation_timeout))
            .await
            .ok_or_else(|| {
                InitializationError::BadParameters(format!(
                    "presignature {presignature_id} not found or timeout",
                ))
            })?;

        let sign_id = indexed.id;
        tracing::info!(
            me = ?ctx.governance.me,
            ?sign_id,
            ?presignature_id,
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
            ctx.governance.me,
            derive_key(ctx.governance.public_key, indexed.args.epsilon),
            output,
            indexed.args.payload,
        )?);
        let inbox = ctx.msg.subscribe_signature(sign_id, presignature_id).await;
        Ok(Self {
            protocol,
            dropper,
            participants,
            proposer,
            indexed,
            created: Instant::now(),
            timeout: Duration::from_millis(ctx.cfg.signature.generation_timeout),
            inbox,
            msg: ctx.msg.clone(),
            #[cfg(feature = "debug-page")]
            debug_view: crate::web::debug::register_task(
                node_account_id.to_string(),
                format!("SignatureGenerator {sign_id:#?}"),
            ),
        })
    }

    /// Receive the next message for the signature protocol; error out on the timeout being reached
    async fn recv(&mut self) -> Result<SignatureMessage, SignError> {
        let sign_id = self.indexed.id;
        let presignature_id = self.dropper.id;
        match tokio::time::timeout(
            self.timeout.saturating_sub(self.created.elapsed()),
            self.inbox.recv(),
        )
        .await
        {
            Ok(Some(msg)) => Ok(msg),
            Ok(None) => {
                tracing::warn!(?sign_id, ?presignature_id, "signature generation aborted");
                Err(SignError::Aborted)
            }
            Err(_err) => {
                tracing::warn!(?sign_id, ?presignature_id, "signature generation timeout");
                Err(SignError::Aborted)
            }
        }
    }

    async fn run(mut self, ctx: &SignTask) -> Result<(), SignError> {
        let me = ctx.governance.me;
        let epoch = ctx.governance.epoch;

        let sign_id = self.indexed.id;
        let presignature_id = self.dropper.id;

        let mut total_wait = Duration::from_millis(0);
        let mut total_pokes = 0;
        let mut poke_last_time = self.created;
        crate::metrics::protocols::SIGNATURE_BEFORE_POKE_DELAY
            .observe(self.created.elapsed().as_millis() as f64);

        loop {
            let poke_start_time = Instant::now();
            let action = match self.protocol.poke() {
                Ok(action) => action,
                Err(err) => {
                    crate::metrics::protocols::SIGNATURE_GENERATOR_FAILURES.inc();
                    if self.proposer == me {
                        crate::metrics::protocols::SIGNATURE_GENERATOR_MINE_FAILURES.inc();
                    }
                    tracing::error!(
                        ?sign_id,
                        ?err,
                        "signature generation failed on protocol advancement",
                    );
                    break Err(SignError::Aborted);
                }
            };

            total_wait += poke_start_time - poke_last_time;
            total_pokes += 1;
            poke_last_time = Instant::now();
            crate::metrics::protocols::SIGNATURE_POKE_CPU_TIME
                .observe(poke_start_time.elapsed().as_millis() as f64);
            #[cfg(feature = "debug-page")]
            self.render_debug(total_pokes);

            match action {
                Action::Wait => {
                    // Wait for the next set of messages to arrive.
                    let msg = self.recv().await.inspect_err(|_| {
                        crate::metrics::protocols::SIGNATURE_GENERATOR_FAILURES.inc();
                        if self.proposer == me {
                            crate::metrics::protocols::SIGNATURE_GENERATOR_MINE_FAILURES.inc();
                        }
                    })?;
                    self.protocol.message(msg.from, msg.data);
                }
                Action::SendMany(data) => {
                    for &to in self.participants.iter() {
                        if to == me {
                            continue;
                        }
                        ctx.msg
                            .send(
                                me,
                                to,
                                SignatureMessage {
                                    id: sign_id,
                                    proposer: self.proposer,
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
                    ctx.msg
                        .send(
                            me,
                            to,
                            SignatureMessage {
                                id: sign_id,
                                proposer: self.proposer,
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
                    let big_r = output.big_r;
                    let s = output.s;
                    tracing::info!(
                        ?sign_id,
                        ?me,
                        ?presignature_id,
                        big_r = ?big_r.to_base58(),
                        ?s,
                        elapsed = ?self.created.elapsed(),
                        "completed signature generation"
                    );

                    crate::metrics::protocols::SIGNATURE_ACCRUED_WAIT_DELAY
                        .observe(total_wait.as_millis() as f64);
                    crate::metrics::protocols::SIGNATURE_POKES_CNT.observe(total_pokes as f64);
                    crate::metrics::protocols::SIGN_GENERATION_LATENCY
                        .observe(self.created.elapsed().as_secs_f64());
                    crate::metrics::protocols::SIGNATURE_GENERATOR_SUCCESS.inc();

                    let is_proposer = self.proposer == me;
                    if let Some(publish) = publish_status(
                        ctx.governance.public_key,
                        &self.indexed,
                        &output,
                        self.participants.clone(),
                        is_proposer,
                    ) {
                        if let Err(err) = ctx
                            .backlog
                            .mark_publishing(self.indexed.chain, &sign_id, publish)
                            .await
                        {
                            tracing::warn!(
                                ?sign_id,
                                ?err,
                                "failed to mark publishing for sign request"
                            );
                        }
                    }

                    if is_proposer {
                        crate::metrics::protocols::SIGNATURE_GENERATOR_MINE_SUCCESS.inc();
                        ctx.rpc.publish(
                            ctx.governance.public_key,
                            self.indexed.clone(),
                            output,
                            self.participants.clone(),
                        );
                    }

                    if let SignKind::SignBidirectional(event) = &self.indexed.kind {
                        // Note: The promotion to Bidirectional will happen when we receive the
                        // SignatureRespondedEvent in the Solana indexer, which has the signature data.
                        // For now, we just complete the signature generation. The indexer will handle the promotion.
                        tracing::info!(
                            ?sign_id,
                            source_chain = ?self.indexed.chain,
                            target_chain = ?event.target_chain().ok(),
                            "generated signature for bidirectional request, awaiting indexer to process"
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

fn publish_status(
    public_key: mpc_crypto::PublicKey,
    indexed: &IndexedSignRequest,
    output: &cait_sith::FullSignature<Secp256k1>,
    participants: Vec<Participant>,
    is_proposer: bool,
) -> Option<PublishState> {
    let expected_public_key = derive_key(public_key, indexed.args.epsilon);
    let signature = crate::kdf::into_signature(
        &expected_public_key,
        &output.big_r,
        &output.s,
        indexed.args.payload,
    )
    .ok()?;
    let publish = PublishState {
        signature,
        participants,
        is_proposer,
    };

    Some(publish)
}

impl Drop for SignGenerator {
    fn drop(&mut self) {
        let msg = self.msg.clone();
        let sign_id = self.indexed.id;
        let presignature_id = self.dropper.id;
        tokio::spawn(async move {
            msg.unsubscribe_signature(sign_id, presignature_id).await;
            msg.filter_sign(sign_id, presignature_id).await;
        });
    }
}

/// Per-request accumulator for the three looping phases in `SignTask::run`:
/// Organizing, Posit, Generating. Times are summed across attempts so each
/// histogram observation covers the full request even when the state machine
/// loops back. Indexing/AwaitingGeneration/Responding/Total are emitted
/// elsewhere and ignored by `add`.
///
/// Additivity caveat: without governance pauses, all five stages sum to
/// Total. Resharing or other transitions out of `Running` mid-request show
/// idle time only in Total, so the equality holds as `<=` in that case.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
struct PhaseDurations {
    organizing: Duration,
    posit: Duration,
    generating: Duration,
}

impl PhaseDurations {
    fn add(&mut self, step: SignRequestStep, elapsed: Duration) {
        match step {
            SignRequestStep::Organizing => self.organizing += elapsed,
            SignRequestStep::Posit => self.posit += elapsed,
            SignRequestStep::Generating => self.generating += elapsed,
            // Emitted elsewhere; listed explicitly so adding a new variant
            // forces a deliberate decision here.
            SignRequestStep::Indexing
            | SignRequestStep::AwaitingGeneration
            | SignRequestStep::Responding
            | SignRequestStep::Total => {}
        }
    }

    fn emit(self, chain: Chain) {
        record_request_latency(chain, SignRequestStep::Organizing, "ok", self.organizing);
        record_request_latency(chain, SignRequestStep::Posit, "ok", self.posit);
        record_request_latency(chain, SignRequestStep::Generating, "ok", self.generating);
    }
}

struct SignTask {
    governance: GovernanceInfo,
    sign_id: SignId,
    presignatures: PresignatureStorage,
    msg: MessageChannel,
    rpc: RpcChannel,

    // TODO: will be used in the future when we move requests channels
    // into the backlog.
    #[allow(dead_code)]
    backlog: Backlog,

    cfg: ProtocolConfig,
    contract: ContractStateWatcher,
    is_proposer: Arc<AtomicBool>,
    limiter: SignLimiter,
    node_account_id: near_account_id::AccountId,
}

impl SignTask {
    async fn run(
        mut self,
        indexed: IndexedSignRequest,
        mesh_state: watch::Receiver<MeshState>,
        mut task_rx: mpsc::Receiver<SignTaskMessage>,
    ) -> Result<(), SignError> {
        let sign_id = self.sign_id;
        tracing::info!(?sign_id, governance = ?self.governance, "signature task starting...");

        let mut state = SignState::new(indexed, mesh_state);
        let mut phase = SignPhase::Organizing(SignOrganizer);
        let mut contract_watcher = self.contract.clone();

        // NOTE: even if we start the SignTask while in resharing, we will not advance
        // since we won't in the running state
        let mut is_running = self.governance.is_running;

        // Sum per-phase time across loop attempts; emit on Complete(Ok) only.
        let mut durations = PhaseDurations::default();

        loop {
            let phase_start = Instant::now();
            let current_phase_step = match &phase {
                SignPhase::Organizing(_) => Some(SignRequestStep::Organizing),
                SignPhase::Posit(_) => Some(SignRequestStep::Posit),
                SignPhase::Generating(_) => Some(SignRequestStep::Generating),
                SignPhase::Complete(_) => None,
            };

            tokio::select! {
                Some(contract_state) = contract_watcher.next_state() => {
                    // `phase.advance` was cancelled. Attribute its partial
                    // elapsed time only if `is_running` was true; otherwise
                    // the branch was gated off and the iteration was idle.
                    if is_running {
                        if let Some(step) = current_phase_step {
                            durations.add(step, phase_start.elapsed());
                        }
                    }
                    is_running = self.refresh_governance(&contract_state);
                    if is_running {
                        // we're back into running, reset to SignOrganizer
                        phase = SignPhase::Organizing(SignOrganizer);
                    } else {
                        tracing::info!(
                            ?sign_id,
                            gov = ?self.governance,
                            "signature task paused waiting for running governance"
                        );
                    }
                }
                // This branch in tokio::select will get cancelled since the future for next contract
                // state is reached first. This effectively pauses this branch from executing and
                // further advancing the signature organization/positing/generation flow.
                new_phase = phase.advance(&mut self, &mut state, &mut task_rx), if is_running => {
                    if let Some(step) = current_phase_step {
                        durations.add(step, phase_start.elapsed());
                        if matches!(&new_phase, SignPhase::Organizing(_)) {
                            SIGN_REQUEST_LOOPS
                                .with_label_values(&[
                                    state.indexed().chain.as_str(),
                                    step.as_str(),
                                ])
                                .inc();
                        }
                    }

                    match new_phase {
                        SignPhase::Complete(result) => {
                            if result.is_ok() {
                                durations.emit(state.indexed().chain);
                            }
                            return result;
                        }
                        new_phase => phase = new_phase,
                    }
                }
            };
        }
    }

    /// Refresh the governance info from the contract state, returning whether we are
    /// in a running state with valid governance info after the refresh.
    fn refresh_governance(&mut self, contract_state: &ProtocolState) -> bool {
        if let Some(governance) = contract_state.governance(&self.node_account_id) {
            self.governance = governance;
        } else {
            self.governance.is_running = false;
        }
        self.governance.is_running
    }
}

/// Message types that can be sent to a running signature task
enum SignTaskMessage {
    PositMessage {
        presignature_id: PresignatureId,
        round: usize,
        from: Participant,
        action: PositAction,
    },
}

pub struct SignatureSpawner {
    contract: ContractStateWatcher,
    /// Presignature storage that maintains all presignatures.
    presignatures: PresignatureStorage,
    /// Consolidated signature tasks - one per sign_id, each task is an async task handling complete lifecycle
    tasks: JoinMap<SignId, Result<(), SignError>>,
    /// Buffered inboxes for posit messages, allowing us to queue before tasks spawn
    inboxes: HashMap<SignId, Subscriber<SignTaskMessage>>,
    /// Tracks delay watcher tasks that will increment the delayed metric when response time exceeds expected
    delayed_watchers: HashMap<SignId, JoinHandle<()>>,
    mesh_state: watch::Receiver<MeshState>,
    /// Limiter that limits the amount of sign tasks from progressing and utilizing
    /// too much compute otherwise the whole system will be flooded with requests.
    limiter: SignLimiter,

    msg: MessageChannel,
    rpc: RpcChannel,
    backlog: Backlog,
    node_account_id: near_account_id::AccountId,
}

impl SignatureSpawner {
    fn observe_queue_size(&self) {
        crate::metrics::requests::SIGN_QUEUE_SIZE.set(self.tasks.len() as i64);
    }

    /// Creates a signature task for a new sign request
    /// The task will handle organizing, posit, and generation internally
    fn spawn_task(
        &mut self,
        governance: &GovernanceInfo,
        indexed: IndexedSignRequest,
        cfg: ProtocolConfig,
    ) {
        let sign_id = indexed.id;
        tracing::info!(?sign_id, "spawning signature task");

        // Spawn a reactive watcher task that increments the delayed metric
        // if the signature is not completed within the expected response time
        let chain = indexed.chain;
        let unix_timestamp_indexed = indexed.unix_timestamp_indexed;
        let expected_response_time_secs = chain.expected_response_time_secs();
        let already_elapsed = crate::util::unix_elapsed(unix_timestamp_indexed);
        let remaining_time =
            Duration::from_secs(expected_response_time_secs).saturating_sub(already_elapsed);
        let is_proposer = Arc::new(AtomicBool::new(false));
        // prevent incrementing delayed metric for already delayed requests
        if remaining_time > Duration::from_secs(0) {
            let is_proposer = Arc::clone(&is_proposer);
            let watcher = tokio::spawn(async move {
                tokio::time::sleep(remaining_time).await;
                let elapsed = crate::util::unix_elapsed(unix_timestamp_indexed);
                tracing::warn!(
                    ?sign_id,
                    ?chain,
                    elapsed_secs = elapsed.as_secs(),
                    expected_secs = expected_response_time_secs,
                    "signature request delayed beyond expected response time"
                );

                if is_proposer.load(Ordering::Relaxed) {
                    crate::metrics::requests::SIGN_REQUEST_DELAYED
                        .with_label_values(&[chain.as_str()])
                        .inc();
                }
            });
            self.delayed_watchers.insert(sign_id, watcher);
        }

        // Subscribe to (or create) the posit inbox for this sign request
        let inbox = self
            .inboxes
            .entry(sign_id)
            .or_insert_with(|| Subscriber::unsubscribed(SIGN_POSIT_INBOX_LABEL));
        let rx = inbox.subscribe();
        inbox.report_capacity();

        let task = SignTask {
            governance: governance.clone(),
            sign_id,
            presignatures: self.presignatures.clone(),
            msg: self.msg.clone(),
            rpc: self.rpc.clone(),
            backlog: self.backlog.clone(),
            cfg,
            contract: self.contract.clone(),
            is_proposer,
            limiter: self.limiter.clone(),
            node_account_id: self.node_account_id.clone(),
        };

        // Spawn the async task with organizing loop
        self.tasks
            .spawn(sign_id, task.run(indexed, self.mesh_state.clone(), rx));
    }

    /// Handle a posit message - routes to existing task or buffers if task not yet created
    async fn handle_posit(
        &mut self,
        me: Participant,
        sign_id: SignId,
        presignature_id: PresignatureId,
        round: usize,
        from: Participant,
        action: PositAction,
    ) {
        // Ignore messages from ourselves
        if from == me {
            return;
        }
        let inbox = self
            .inboxes
            .entry(sign_id)
            .or_insert_with(|| Subscriber::unsubscribed(SIGN_POSIT_INBOX_LABEL));
        let _ = inbox
            .send(SignTaskMessage::PositMessage {
                presignature_id,
                round,
                from,
                action,
            })
            .await;
        inbox.report_capacity();
    }

    fn handle_completion(&mut self, sign_id: SignId) {
        if let Some(inbox) = self.inboxes.remove(&sign_id) {
            inbox.clear_capacity_global();
        }
        self.abort_delayed_watcher(sign_id, "completion");
        if self.tasks.abort(sign_id) {
            tracing::info!(?sign_id, "aborting signature task due to completion event");
        } else {
            tracing::info!(?sign_id, "task already completed or unable to be aborted");
        }
    }

    fn handle_task_exit(&mut self, result: Result<(SignId, Result<(), SignError>), SignId>) {
        self.observe_queue_size();
        let (sign_id, result) = match result {
            Ok(outcome) => outcome,
            Err(sign_id) => {
                tracing::warn!(?sign_id, "signature task interrupted");
                if let Some(inbox) = self.inboxes.remove(&sign_id) {
                    inbox.clear_capacity_global();
                }
                self.abort_delayed_watcher(sign_id, "interruption");
                return;
            }
        };
        if let Some(inbox) = self.inboxes.remove(&sign_id) {
            inbox.clear_capacity_global();
        }
        self.abort_delayed_watcher(sign_id, "task completion");
        match result {
            Ok(()) => {
                tracing::info!(?sign_id, "signature task completed successfully");
            }
            Err(SignError::Aborted) => {
                tracing::warn!(?sign_id, "signature task terminated");
            }
        }
    }

    fn abort_delayed_watcher(&mut self, sign_id: SignId, reason: &str) {
        if let Some(watcher) = self.delayed_watchers.remove(&sign_id) {
            tracing::info!(?sign_id, reason = %reason, "aborting delayed watcher");
            watcher.abort();
        } else {
            tracing::debug!(?sign_id, reason = %reason, "no delayed watcher to abort");
        }
    }

    fn handle_request(&mut self, governance: &GovernanceInfo, sign: Sign, cfg: &ProtocolConfig) {
        match sign {
            Sign::Completion(sign_id) => {
                self.handle_completion(sign_id);
            }
            Sign::Request(request) => {
                let sign_id = request.id;

                // Skip if we already have a task handling this request.
                // Use tasks instead of inbox map since it may already contain buffered messages
                // (e.g. a Propose arriving before the indexer notifies us), so we must only look
                // at the task map to decide whether the request is truly a duplicate.
                if self.tasks.contains_key(&sign_id) {
                    tracing::info!(?sign_id, "skipping duplicate sign request");
                    return;
                }

                record_request_latency_since(
                    request.chain,
                    SignRequestStep::AwaitingGeneration,
                    "ok",
                    request.unix_timestamp_indexed,
                );

                self.spawn_task(governance, request, cfg.clone());
            }
        }

        self.observe_queue_size();
    }

    async fn run(mut self, mut sign_rx: mpsc::Receiver<Sign>, mut cfg: watch::Receiver<Config>) {
        let mut posits = self.msg.subscribe_signature_posit().await;
        let mut protocol = cfg.borrow().protocol.clone();

        let mut contract_watcher = self.contract.clone();

        // GUARANTEE: contract is in a running state with valid governance info
        // before we start processing any messages
        let mut governance = contract_watcher.wait_governance().await;

        loop {
            tokio::select! {
                sign = sign_rx.recv() => {
                    let Some(sign) = sign else {
                        tracing::warn!("signature spawner sign_rx closed, terminating");
                        break;
                    };
                    self.handle_request(&governance, sign, &protocol);
                }
                Some((sign_id, presignature_id, round, from, action)) = posits.recv() => {
                    self.handle_posit(governance.me, sign_id, presignature_id, round, from, action).await;
                }
                Some(result) = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    self.handle_task_exit(result);
                }
                Ok(()) = cfg.changed() => {
                    protocol = cfg.borrow().protocol.clone();
                }
                Some(state) = contract_watcher.next_state() => {
                    if let Some(new_governance) = state.governance(&self.node_account_id) {
                        governance = new_governance;
                    }
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
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        my_account_id: near_account_id::AccountId,
        sign_rx: mpsc::Receiver<Sign>,
        contract: ContractStateWatcher,
        config: watch::Receiver<Config>,
        presignature_storage: PresignatureStorage,
        mesh_state: watch::Receiver<MeshState>,
        msg_channel: MessageChannel,
        rpc_channel: RpcChannel,
        backlog: Backlog,
    ) -> Self {
        let spawner = SignatureSpawner {
            contract,
            tasks: JoinMap::new(),
            inboxes: HashMap::new(),
            delayed_watchers: HashMap::new(),
            presignatures: presignature_storage,
            mesh_state,
            limiter: SignLimiter::new(MAX_CONCURRENT_PROPOSERS),
            msg: msg_channel,
            rpc: rpc_channel,
            backlog,
            node_account_id: my_account_id,
        };

        Self {
            handle: tokio::spawn(spawner.run(sign_rx, config)),
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
    Available(Box<PresignatureTaken>),
    InStorage(PresignatureId, Participant, PresignatureStorage),
}

impl PendingPresignature {
    pub fn id(&self) -> PresignatureId {
        match self {
            PendingPresignature::Available(taken) => taken.artifact.id,
            PendingPresignature::InStorage(id, _, _) => *id,
        }
    }

    pub async fn fetch(self, timeout: Duration) -> Option<PresignatureTaken> {
        let (id, storage, owner) = match self {
            PendingPresignature::Available(taken) => return Some(*taken),
            PendingPresignature::InStorage(id, owner, storage) => (id, storage, owner),
        };

        let presignature = tokio::time::timeout(timeout, async {
            // TODO: we can make storage wait for presignature to be available instead of here
            let mut interval = tokio::time::interval(Duration::from_millis(250));
            loop {
                interval.tick().await;
                if let Some(presignature) = storage.take(id, owner).await {
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

#[cfg(feature = "test-feature")]
pub fn organize_posit_timeout() -> Duration {
    ORGANIZE_POSIT_TIMEOUT
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::contract::primitives::{ParticipantInfo, Participants};
    use crate::protocol::contract::{ResharingContractState, RunningContractState};
    use crate::protocol::presignature::Presignature;
    use crate::protocol::ProtocolState;

    use cait_sith::protocol::Participant;
    use deadpool_redis::Runtime;

    #[test]
    fn sign_task_refreshes_and_pauses_on_resharing() {
        let account_id: near_account_id::AccountId = "p-0".parse().unwrap();
        let mut participants = Participants::default();
        participants.insert(&Participant::from(0), ParticipantInfo::new(0));

        let governance = GovernanceInfo {
            me: Participant::from(0),
            threshold: 1,
            epoch: 0,
            public_key: k256::AffinePoint::default(),
            participants: [Participant::from(0)].into_iter().collect(),
            is_running: true,
        };

        let redis_cfg = deadpool_redis::Config::from_url("redis://127.0.0.1/");
        let pool = redis_cfg.create_pool(Some(Runtime::Tokio1)).unwrap();
        let presignatures = Presignature::storage(&pool, &account_id);
        let (_inbox, _outbox, msg_channel) = MessageChannel::new();
        let (rpc_tx, _rpc_rx) = mpsc::channel(1);
        let rpc_channel = RpcChannel { tx: rpc_tx };
        let (contract, _tx) = ContractStateWatcher::with_running(
            &account_id,
            k256::AffinePoint::default(),
            1,
            participants.clone(),
        );

        let mut sign_task = SignTask {
            governance: governance.clone(),
            sign_id: SignId::new([0u8; 32]),
            presignatures,
            msg: msg_channel,
            rpc: rpc_channel,
            backlog: Backlog::new(),
            cfg: ProtocolConfig::default(),
            contract,
            is_proposer: Arc::new(AtomicBool::new(false)),
            limiter: SignLimiter::new(1),
            node_account_id: account_id.clone(),
        };

        let initial = RunningContractState {
            epoch: 0,
            public_key: k256::AffinePoint::default(),
            participants: participants.clone(),
            candidates: Default::default(),
            join_votes: Default::default(),
            leave_votes: Default::default(),
            threshold: 1,
        };
        assert!(sign_task.refresh_governance(&ProtocolState::Running(initial)));
        assert_eq!(sign_task.governance.epoch, 0);
        assert_eq!(sign_task.governance.threshold, 1);
        assert_eq!(sign_task.governance.me, Participant::from(0));

        let resharing = ResharingContractState {
            old_epoch: 0,
            old_participants: participants.clone(),
            new_participants: participants.clone(),
            threshold: 1,
            public_key: k256::AffinePoint::default(),
            finished_votes: Default::default(),
            cancel_votes: Default::default(),
        };

        // refreshing here should yield false where we are no longer in running.
        assert!(!sign_task.refresh_governance(&ProtocolState::Resharing(resharing)));

        let running = RunningContractState {
            epoch: 1,
            public_key: k256::AffinePoint::default(),
            participants,
            candidates: Default::default(),
            join_votes: Default::default(),
            leave_votes: Default::default(),
            threshold: 1,
        };

        assert!(sign_task.refresh_governance(&ProtocolState::Running(running)));
        assert_eq!(sign_task.governance.epoch, 1);
        assert_eq!(sign_task.governance.threshold, 1);
        assert_eq!(sign_task.governance.me, Participant::from(0));
    }

    #[test]
    fn phase_durations_sum_per_phase_across_attempts() {
        // Simulates a request that loops Organizing -> Posit -> Organizing ->
        // Posit -> Generating before completing. Each `add` mirrors one
        // iteration of the SignTask::run phase loop.
        let mut d = PhaseDurations::default();
        d.add(SignRequestStep::Organizing, Duration::from_millis(100));
        d.add(SignRequestStep::Posit, Duration::from_millis(200));
        // back-edge: Posit failed and we re-entered Organizing
        d.add(SignRequestStep::Organizing, Duration::from_millis(50));
        d.add(SignRequestStep::Posit, Duration::from_millis(150));
        d.add(SignRequestStep::Generating, Duration::from_millis(500));

        assert_eq!(d.organizing, Duration::from_millis(150));
        assert_eq!(d.posit, Duration::from_millis(350));
        assert_eq!(d.generating, Duration::from_millis(500));
    }

    #[test]
    fn phase_durations_ignore_steps_not_part_of_sign_task() {
        // These variants are not part of SignTask: Indexing is emitted by
        // the indexer modules, AwaitingGeneration by SignatureSpawner::
        // handle_request, and Responding/Total by rpc.rs. Passing any to
        // `add` must be a no-op or they would be double-counted on
        // multichain_sign_request_latency_sec.
        let mut d = PhaseDurations::default();
        d.add(SignRequestStep::Indexing, Duration::from_millis(100));
        d.add(
            SignRequestStep::AwaitingGeneration,
            Duration::from_millis(200),
        );
        d.add(SignRequestStep::Responding, Duration::from_millis(300));
        d.add(SignRequestStep::Total, Duration::from_millis(400));

        assert_eq!(d, PhaseDurations::default());
    }

    #[test]
    fn phase_durations_preserve_additivity_invariant() {
        // This represents the case where we have 2 attempts:
        // 1st one fails at posit, then starts from organizing again and finishes
        let inputs = [
            (SignRequestStep::Organizing, Duration::from_millis(40)),
            (SignRequestStep::Posit, Duration::from_millis(120)),
            (SignRequestStep::Organizing, Duration::from_millis(35)),
            (SignRequestStep::Posit, Duration::from_millis(95)),
            (SignRequestStep::Generating, Duration::from_millis(710)),
        ];
        let expected: Duration = inputs.iter().map(|(_, d)| *d).sum();

        let mut d = PhaseDurations::default();
        for (step, elapsed) in inputs {
            d.add(step, elapsed);
        }

        assert_eq!(d.organizing + d.posit + d.generating, expected);
    }

    #[tokio::test]
    async fn sign_limiter_times_out_at_limit() {
        let semaphore = SignLimiter::new(1);
        let permit = semaphore
            .acquire(Duration::from_millis(10))
            .await
            .expect("first acquire should succeed");

        let second = semaphore.acquire(Duration::from_millis(10)).await;
        assert!(matches!(second, Err(SignLimitError::Timeout)));

        drop(permit);

        let third = semaphore.acquire(Duration::from_millis(10)).await;
        assert!(third.is_ok());
    }

    #[tokio::test]
    async fn sign_limiter_applies_reduced_limit_on_release() {
        let semaphore = SignLimiter::new(2);
        let first = semaphore
            .acquire(Duration::from_millis(10))
            .await
            .expect("first acquire should succeed");
        let second = semaphore
            .acquire(Duration::from_millis(10))
            .await
            .expect("second acquire should succeed");

        semaphore.update(1);

        drop(first);

        let third = semaphore.acquire(Duration::from_millis(10)).await;
        assert!(matches!(third, Err(SignLimitError::Timeout)));

        drop(second);

        let fourth = semaphore.acquire(Duration::from_millis(10)).await;
        assert!(fourth.is_ok());
    }
}
