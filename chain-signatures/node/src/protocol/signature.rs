use super::MpcSignProtocol;
use crate::backlog::Backlog;
use crate::config::Config;
use crate::kdf::derive_delta;
use crate::mesh::MeshState;
use crate::protocol::contract::primitives::intersect_vec;
use crate::protocol::message::{
    MessageChannel, PositMessage, PositProtocolId, SignatureMessage, Subscriber,
};
use crate::protocol::posit::{PositAction, SinglePositCounter};
use crate::protocol::presignature::PresignatureId;
use crate::protocol::Chain;
use crate::rpc::{ContractStateWatcher, RpcChannel};
use crate::storage::presignature_storage::{PresignatureTaken, PresignatureTakenDropper};
use crate::storage::PresignatureStorage;
use crate::types::SignatureProtocol;
use crate::util::{AffinePointExt, JoinMap, TimeoutBudget};

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
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch, RwLock};
use tokio::task::JoinHandle;

use near_account_id::AccountId;

/// The round interval to search for a proposer in the organizing phase.
const ROUND_INTERVAL: usize = 512;

/// The default timeout budget for organizing and posit phases.
const ORGANIZE_POSIT_TIMEOUT: Duration = Duration::from_secs(60);

/// All relevant info pertaining to an Indexed sign request from an indexer.
#[derive(Debug, Clone, PartialEq)]
pub struct IndexedSignRequest {
    pub id: SignId,
    pub args: SignArgs,
    pub chain: Chain,
    pub unix_timestamp_indexed: u64,
    pub timestamp_sign_queue: Instant,
    pub total_timeout: Duration,
    pub sign_request_type: SignRequestType,
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

struct SignState {
    round: usize,
    indexed: IndexedSignRequest,
    mesh_state: watch::Receiver<MeshState>,
    /// Budget for the current organizing+posit attempt.
    budget: TimeoutBudget,
}

impl SignState {
    fn new(indexed: IndexedSignRequest, mesh_state: watch::Receiver<MeshState>) -> Self {
        Self {
            round: 0,
            indexed,
            mesh_state,
            budget: TimeoutBudget::new(ORGANIZE_POSIT_TIMEOUT),
        }
    }

    fn indexed(&self) -> &IndexedSignRequest {
        &self.indexed
    }

    fn bump_round(&mut self) {
        self.round += 1;
        // Reset the budget for the new attempt
        self.budget.reset(ORGANIZE_POSIT_TIMEOUT);
    }
}

struct SignPositor {
    proposer: Participant,
    stable: BTreeSet<Participant>,
    presignature_id: PresignatureId,
    presignature: Option<PresignatureTaken>,
}

struct SignGenerating {
    proposer: Participant,
    presignature_id: PresignatureId,
    presignature: Option<PresignatureTaken>,
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
        self,
        ctx: &SignTask,
        state: &mut SignState,
        task_rx: &mut mpsc::Receiver<SignTaskMessage>,
    ) -> SignPhase {
        match self {
            SignPhase::Organizing(phase) => phase.advance(ctx, state).await,
            SignPhase::Posit(phase) => phase.advance(ctx, state, task_rx).await,
            SignPhase::Generating(phase) => phase.advance(ctx, state).await,
            SignPhase::Complete(result) => SignPhase::Complete(result),
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

    /// Waits for threshold stable participants to be present.
    async fn wait_stable(
        &self,
        ctx: &SignTask,
        state: &mut SignState,
        threshold: usize,
    ) -> Option<BTreeSet<Participant>> {
        let sign_id = ctx.sign_id;
        let mut once = true;

        loop {
            let stable_count = {
                let stable = &state.mesh_state.borrow().stable;
                if stable.len() >= threshold {
                    return Some(stable.clone());
                }
                stable.len()
            };

            if once {
                tracing::info!(
                    ?sign_id,
                    stable_count,
                    ?threshold,
                    "waiting for enough stable participants"
                );
                once = false;
            }

            if state.mesh_state.changed().await.is_err() {
                return None;
            }
        }
    }

    async fn advance(self, ctx: &SignTask, state: &mut SignState) -> SignPhase {
        let sign_id = ctx.sign_id;
        let threshold = ctx.threshold;
        let me = ctx.me;
        let entropy = state.indexed.args.entropy;
        let participants = ctx.participants.iter().copied().collect::<Vec<_>>();

        tracing::info!(?sign_id, round = ?state.round, "entering organizing phase");
        let (stable, proposer) = {
            let Some(stable) = self.wait_stable(ctx, state, threshold).await else {
                tracing::warn!(?sign_id, round = ?state.round, "no stable participants, reorganizing");
                state.bump_round();
                return SignPhase::Organizing(self);
            };

            let max_rounds = state.round + ROUND_INTERVAL;
            let (selected_round, proposer) = (state.round..max_rounds)
                .map(|r| (r, Self::proposer_per_round(r, &participants, &entropy)))
                .find(|(_, potential_proposer)| stable.contains(potential_proposer))
                .unwrap_or_else(|| {
                    (
                        max_rounds,
                        *stable
                            .iter()
                            .choose(&mut StdRng::from_seed(entropy))
                            .unwrap(),
                    )
                });

            let is_mine = proposer == me;
            state.round = selected_round;

            tracing::info!(
                ?sign_id,
                round = selected_round,
                ?proposer,
                ?me,
                is_mine,
                stable_count = stable.len(),
                "organized: selected proposer"
            );

            if is_mine && state.round == 0 {
                crate::metrics::requests::NUM_SIGN_REQUESTS_MINE
                    .with_label_values(&[ctx.my_account_id.as_str()])
                    .inc();
            }

            (stable, proposer)
        };

        let is_proposer = proposer == ctx.me;
        let (presignature_id, presignature, stable) = if is_proposer {
            tracing::info!(?sign_id, round = ?state.round, "proposer waiting for presignature");
            let stable = stable.iter().copied().collect::<Vec<_>>();
            let mut recycle = Vec::new();
            let remaining = state.budget.remaining();
            let fetch = tokio::time::timeout(remaining, async {
                loop {
                    if let Some(taken) = ctx.presignatures.take_mine(ctx.me).await {
                        let participants = intersect_vec(&[&taken.artifact.participants, &stable]);
                        if participants.len() < ctx.threshold {
                            recycle.push(taken);
                            continue;
                        }

                        break (taken, participants);
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            })
            .await;

            let presignatures = ctx.presignatures.clone();
            tokio::spawn(async move {
                for taken in recycle {
                    presignatures.recycle_mine(me, taken).await;
                }
            });

            let (taken, participants) = match fetch {
                Ok(value) => value,
                Err(_) => {
                    tracing::warn!(
                        ?sign_id,
                        round = ?state.round,
                        "proposer timeout waiting for presignature, reorganizing"
                    );
                    state.bump_round();
                    return SignPhase::Organizing(self);
                }
            };

            let presignature_id = taken.artifact.id;

            tracing::info!(?sign_id, presignature_id, "proposer got presignature");

            // broadcast to participants and let them reject if they don't have the presignature.
            for &p in &participants {
                if p == ctx.me {
                    continue;
                }
                ctx.msg
                    .send(
                        ctx.me,
                        p,
                        PositMessage {
                            id: PositProtocolId::Signature(sign_id, presignature_id),
                            from: ctx.me,
                            action: PositAction::Propose,
                        },
                    )
                    .await;
            }

            // Update stable to only include participants that are in both the presignature and stable set
            let stable = participants.into_iter().collect::<BTreeSet<_>>();
            (presignature_id, Some(taken), stable)
        } else {
            (PresignatureId::default(), None, stable)
        };

        SignPhase::Posit(SignPositor {
            proposer,
            stable,
            presignature_id,
            presignature,
        })
    }
}

impl SignPositor {
    /// Deliberator waits for the proposer to send a Propose message with a presignature_id.
    async fn wait_propose(
        ctx: &SignTask,
        state: &mut SignState,
        task_rx: &mut mpsc::Receiver<SignTaskMessage>,
        proposer: Participant,
    ) -> Result<PresignatureId, SignPhase> {
        let sign_id = ctx.sign_id;
        let round = state.round;
        let remaining = state.budget.remaining();
        let outcome = tokio::time::timeout(remaining, async {
            loop {
                let Some(task_msg) = task_rx.recv().await else {
                    continue;
                };
                let SignTaskMessage::PositMessage {
                    presignature_id,
                    from,
                    action,
                } = &task_msg;

                if !matches!(action, PositAction::Propose) {
                    continue;
                }

                if from == &proposer {
                    tracing::info!(
                        ?sign_id,
                        presignature_id,
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
                                ctx.me,
                                proposer,
                                PositMessage {
                                    id: PositProtocolId::Signature(sign_id, *presignature_id),
                                    from: ctx.me,
                                    action: PositAction::Reject,
                                },
                            )
                            .await;
                        continue;
                    }

                    break *presignature_id;
                } else {
                    tracing::warn!(
                        ?sign_id,
                        ?from,
                        ?proposer,
                        "received Propose from non-proposer, rejecting"
                    );

                    ctx.msg
                        .send(
                            ctx.me,
                            *from,
                            PositMessage {
                                id: PositProtocolId::Signature(sign_id, *presignature_id),
                                from: ctx.me,
                                action: PositAction::Reject,
                            },
                        )
                        .await;
                }
            }
        })
        .await;

        let presignature_id = match outcome {
            Ok(id) => id,
            Err(_) => {
                tracing::warn!(
                    ?sign_id,
                    ?round,
                    ?proposer,
                    "deliberator timeout waiting for Propose, reorganizing"
                );
                state.bump_round();
                return Err(SignPhase::Organizing(SignOrganizer));
            }
        };

        // received propose, send Accept
        ctx.msg
            .send(
                ctx.me,
                proposer,
                PositMessage {
                    id: PositProtocolId::Signature(sign_id, presignature_id),
                    from: ctx.me,
                    action: PositAction::Accept,
                },
            )
            .await;

        Ok(presignature_id)
    }

    async fn advance(
        self,
        ctx: &SignTask,
        state: &mut SignState,
        task_rx: &mut mpsc::Receiver<SignTaskMessage>,
    ) -> SignPhase {
        let SignPositor {
            proposer,
            stable,
            mut presignature_id,
            presignature,
        } = self;

        let sign_id = ctx.sign_id;
        let round = state.round;
        let is_proposer = proposer == ctx.me;
        let is_deliberator = !is_proposer;

        // Get the presignature participants - only these nodes participated in generating it
        let presignature_participants = if let Some(ref taken) = presignature {
            taken.artifact.participants.clone()
        } else {
            // Deliberators don't have the presignature yet, will verify when they receive Propose
            Vec::new()
        };

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
        let posit_participants = stable.iter().copied().collect::<Vec<_>>();
        let mut counter = SinglePositCounter::new(ctx.me, &posit_participants);

        let remaining = state.budget.remaining();
        let posit_deadline = tokio::time::sleep(remaining);
        tokio::pin!(posit_deadline);

        let accepted_participants = loop {
            tokio::select! {
                Some(task_msg) = task_rx.recv() => {
                    let SignTaskMessage::PositMessage { presignature_id: _, from, action } = task_msg;
                    if is_deliberator {
                        if let PositAction::Start(participants) = action {
                            if from != proposer {
                                tracing::warn!(?sign_id, ?from, ?proposer, "received Start from non-proposer, ignoring");
                                continue;
                            }

                            if participants.len() < ctx.threshold {
                                tracing::warn!(
                                    ?sign_id,
                                    ?round,
                                    "not enough start participants"
                                );
                                state.bump_round();
                                return SignPhase::Organizing(SignOrganizer);
                            }

                            tracing::info!(?sign_id, participant = ?ctx.me, ?participants, "deliberator received Start");
                            break participants;
                        }
                    } else {
                        if !counter.process_action(from, &action) {
                            continue;
                        }

                        if counter.enough_rejects(ctx.threshold) {
                            tracing::warn!(?sign_id, ?from, "received enough REJECTs, reorganizing");
                            if let Some(taken) = presignature {
                                tracing::warn!(?sign_id, "recycling presignature due to REJECTs");
                                ctx.presignatures.recycle_mine(ctx.me, taken).await;
                            }
                            state.bump_round();
                            return SignPhase::Organizing(SignOrganizer);
                        }

                        if counter.meets_totality() {
                            // Only include participants who both accepted AND were part of the presignature generation
                            let mut participants = counter.accepts.iter().copied().collect::<Vec<_>>();
                            if !presignature_participants.is_empty() {
                                participants.retain(|p| presignature_participants.contains(p));
                            }

                            if participants.len() < ctx.threshold {
                                tracing::warn!(
                                    ?sign_id,
                                    presig_participants = ?presignature_participants,
                                    accepts = ?counter.accepts,
                                    filtered_participants = ?participants,
                                    threshold = ctx.threshold,
                                    "not enough presignature participants accepted, reorganizing"
                                );
                                if let Some(taken) = presignature {
                                    tracing::warn!(?sign_id, "recycling presignature due to insufficient participants");
                                    ctx.presignatures.recycle_mine(ctx.me, taken).await;
                                }
                                state.bump_round();
                                return SignPhase::Organizing(SignOrganizer);
                            }

                            tracing::info!(?sign_id, me = ?ctx.me, ?participants, "proposer broadcasting Start");
                            for &p in &participants {
                                if p == ctx.me {
                                    continue;
                                }
                                ctx.msg
                                    .send(
                                        ctx.me,
                                        p,
                                        PositMessage {
                                            id: PositProtocolId::Signature(sign_id, presignature_id),
                                            from: ctx.me,
                                            action: PositAction::Start(participants.clone()),
                                        },
                                    )
                                    .await;
                            }
                            break participants;
                        }
                    }
                }
                _ = &mut posit_deadline => {
                    if is_proposer {
                        if counter.enough_accepts(ctx.threshold) {
                            // Only include participants who both accepted AND were part of the presignature generation
                            let mut participants = counter.accepts.iter().copied().collect::<Vec<_>>();
                            if !presignature_participants.is_empty() {
                                participants.retain(|p| presignature_participants.contains(p));
                            }

                            if participants.len() < ctx.threshold {
                                tracing::warn!(
                                    ?sign_id,
                                    presig_participants = ?presignature_participants,
                                    accepts = ?counter.accepts,
                                    filtered_participants = ?participants,
                                    threshold = ctx.threshold,
                                    "posit timeout: not enough presignature participants accepted, reorganizing"
                                );
                                if let Some(taken) = presignature {
                                    tracing::warn!(?sign_id, "recycling presignature due to posit timeout");
                                    ctx.presignatures.recycle_mine(ctx.me, taken).await;
                                }
                                state.bump_round();
                                return SignPhase::Organizing(SignOrganizer);
                            }

                            tracing::info!(?sign_id, "posit timeout with enough accepts, broadcasting Start");
                            for &p in &participants {
                                if p == ctx.me {
                                    continue;
                                }
                                ctx.msg
                                    .send(
                                        ctx.me,
                                        p,
                                        PositMessage {
                                            id: PositProtocolId::Signature(sign_id, presignature_id),
                                            from: ctx.me,
                                            action: PositAction::Start(participants.clone()),
                                        },
                                    )
                                    .await;
                            }
                            break participants;
                        } else {
                            tracing::warn!(?sign_id, "posit timeout without enough accepts, reorganizing");
                            if let Some(taken) = presignature {
                                tracing::warn!(?sign_id, "recycling presignature due to posit timeout (no accepts)");
                                ctx.presignatures.recycle_mine(ctx.me, taken).await;
                            }
                            state.bump_round();
                            return SignPhase::Organizing(SignOrganizer);
                        }
                    } else {
                        tracing::warn!(?sign_id, "deliberator posit timeout waiting for Start, reorganizing");
                        state.bump_round();
                        return SignPhase::Organizing(SignOrganizer);
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
}

impl SignGenerating {
    async fn advance(mut self, ctx: &SignTask, state: &mut SignState) -> SignPhase {
        let sign_id = ctx.sign_id;
        let round = state.round;

        tracing::info!(
            ?sign_id,
            presignature_id = ?self.presignature_id,
            participants = ?self.accepted_participants,
            "posit complete, starting generation"
        );

        let presignature_pending = if let Some(taken) = self.presignature.take() {
            PendingPresignature::Available(taken)
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
        crate::metrics::protocols::NUM_TOTAL_HISTORICAL_SIGNATURE_GENERATORS
            .with_label_values(&[ctx.my_account_id.as_str()])
            .inc();

        match generator.run(ctx).await {
            Ok(()) => SignPhase::Complete(Ok(())),
            Err(err) => {
                tracing::warn!(
                    ?sign_id,
                    ?round,
                    ?err,
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
    ) -> Result<Self, InitializationError> {
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
            me = ?ctx.me,
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
            ctx.me,
            derive_key(ctx.public_key, indexed.args.epsilon),
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
                ctx.my_account_id.to_string(),
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
                tracing::warn!(?sign_id, presignature_id, "signature generation aborted");
                Err(SignError::Aborted)
            }
            Err(_err) => {
                tracing::warn!(?sign_id, presignature_id, "signature generation timeout");
                Err(SignError::Aborted)
            }
        }
    }

    async fn run(mut self, ctx: &SignTask) -> Result<(), SignError> {
        let my_account_id = &ctx.my_account_id;
        let me = ctx.me;
        let epoch = ctx.epoch;

        let accrued_wait_delay = crate::metrics::protocols::SIGNATURE_ACCRUED_WAIT_DELAY
            .with_label_values(&[my_account_id.as_str()]);
        let poke_counts = crate::metrics::protocols::SIGNATURE_POKES_CNT
            .with_label_values(&[my_account_id.as_str()]);
        let signature_generator_failures_metric =
            crate::metrics::protocols::SIGNATURE_GENERATOR_FAILURES
                .with_label_values(&[my_account_id.as_str()]);
        let signature_generator_success_metric =
            crate::metrics::protocols::SIGNATURE_GENERATOR_SUCCESS
                .with_label_values(&[my_account_id.as_str()]);
        let poke_latency = crate::metrics::protocols::SIGNATURE_POKE_CPU_TIME
            .with_label_values(&[my_account_id.as_str()]);

        let sign_id = self.indexed.id;
        let presignature_id = self.dropper.id;

        let mut total_wait = Duration::from_millis(0);
        let mut total_pokes = 0;
        let mut poke_last_time = self.created;
        crate::metrics::protocols::SIGNATURE_BEFORE_POKE_DELAY
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
                    break Err(SignError::Aborted);
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
                        if self.proposer == me {
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
                        presignature_id,
                        big_r = ?big_r.to_base58(),
                        ?s,
                        elapsed = ?self.created.elapsed(),
                        "completed signature generation"
                    );

                    accrued_wait_delay.observe(total_wait.as_millis() as f64);
                    poke_counts.observe(total_pokes as f64);
                    crate::metrics::protocols::SIGN_GENERATION_LATENCY
                        .with_label_values(&[my_account_id.as_str()])
                        .observe(self.created.elapsed().as_secs_f64());
                    signature_generator_success_metric.inc();

                    if self.proposer == me {
                        ctx.rpc.publish(
                            ctx.public_key,
                            self.indexed.clone(),
                            output,
                            self.participants.clone(),
                        );
                    }

                    if let SignRequestType::SignBidirectional(event) =
                        &self.indexed.sign_request_type
                    {
                        // Note: The promotion to Bidirectional will happen when we receive the
                        // SignatureRespondedEvent in the Solana indexer, which has the signature data.
                        // For now, we just complete the signature generation. The indexer will handle the promotion.
                        tracing::info!(
                            ?sign_id,
                            source_chain = ?self.indexed.chain,
                            target_chain = ?event.dest,
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

struct SignTask {
    me: Participant,
    participants: BTreeSet<Participant>,
    sign_id: SignId,
    threshold: usize,
    public_key: PublicKey,
    epoch: u64,
    my_account_id: AccountId,
    presignatures: PresignatureStorage,
    msg: MessageChannel,
    rpc: RpcChannel,

    // TODO: will be used in the future when we move requests channels
    // into the backlog.
    #[allow(dead_code)]
    backlog: Backlog,

    cfg: ProtocolConfig,
    contract: ContractStateWatcher,
}

impl SignTask {
    async fn run(
        self,
        indexed: IndexedSignRequest,
        mesh_state: watch::Receiver<MeshState>,
        mut task_rx: mpsc::Receiver<SignTaskMessage>,
    ) -> Result<(), SignError> {
        let sign_id = self.sign_id;
        let task_epoch = self.epoch;
        tracing::info!(
            ?sign_id,
            me = ?self.me,
            epoch = task_epoch,
            "signature task starting with organizing loop"
        );

        let mut state = SignState::new(indexed, mesh_state);
        let mut phase = SignPhase::Organizing(SignOrganizer);

        loop {
            // Check if we should abort due to resharing or epoch change
            if let Some(contract_state) = self.contract.state() {
                match contract_state {
                    crate::protocol::ProtocolState::Resharing(_) => {
                        tracing::info!(
                            ?sign_id,
                            epoch = task_epoch,
                            "signature task interrupted: contract is resharing"
                        );
                        return Err(SignError::Aborted);
                    }
                    crate::protocol::ProtocolState::Running(running)
                        if running.epoch != task_epoch =>
                    {
                        tracing::info!(
                            ?sign_id,
                            old_epoch = task_epoch,
                            new_epoch = running.epoch,
                            "signature task interrupted: epoch changed"
                        );
                        return Err(SignError::Aborted);
                    }
                    _ => {}
                }
            }

            phase = match phase.advance(&self, &mut state, &mut task_rx).await {
                SignPhase::Complete(result) => return result,
                other => other,
            }
        }
    }
}

/// Message types that can be sent to a running signature task
enum SignTaskMessage {
    PositMessage {
        presignature_id: PresignatureId,
        from: Participant,
        action: PositAction,
    },
}

pub struct SignatureSpawner {
    /// Presignature storage that maintains all presignatures.
    presignatures: PresignatureStorage,
    /// Consolidated signature tasks - one per sign_id, each task is an async task handling complete lifecycle
    tasks: JoinMap<SignId, Result<(), SignError>>,
    /// Buffered inboxes for posit messages, allowing us to queue before tasks spawn
    inboxes: HashMap<SignId, Subscriber<SignTaskMessage>>,
    mesh_state: watch::Receiver<MeshState>,

    me: Participant,
    my_account_id: AccountId,
    threshold: usize,
    public_key: PublicKey,
    epoch: u64,
    msg: MessageChannel,
    rpc: RpcChannel,
    backlog: Backlog,
}

impl SignatureSpawner {
    /// Creates a signature task for a new sign request
    /// The task will handle organizing, posit, and generation internally
    fn spawn_task(
        &mut self,
        indexed: IndexedSignRequest,
        participants: BTreeSet<Participant>,
        contract: ContractStateWatcher,
        cfg: ProtocolConfig,
    ) {
        let sign_id = indexed.id;
        tracing::info!(?sign_id, "spawning signature task");

        // Subscribe to (or create) the posit inbox for this sign request
        let rx = self.inboxes.entry(sign_id).or_default().subscribe();
        let task = SignTask {
            me: self.me,
            participants,
            sign_id,
            threshold: self.threshold,
            public_key: self.public_key,
            epoch: self.epoch,
            my_account_id: self.my_account_id.clone(),
            presignatures: self.presignatures.clone(),
            msg: self.msg.clone(),
            rpc: self.rpc.clone(),
            backlog: self.backlog.clone(),
            cfg,
            contract,
        };

        // Spawn the async task with organizing loop
        self.tasks
            .spawn(sign_id, task.run(indexed, self.mesh_state.clone(), rx));
    }

    /// Handle a posit message - routes to existing task or buffers if task not yet created
    async fn handle_posit(
        &mut self,
        sign_id: SignId,
        presignature_id: PresignatureId,
        from: Participant,
        action: PositAction,
    ) {
        // Ignore messages from ourselves
        if from == self.me {
            return;
        }
        let _ = self
            .inboxes
            .entry(sign_id)
            .or_default()
            .send(SignTaskMessage::PositMessage {
                presignature_id,
                from,
                action,
            })
            .await;
    }

    fn handle_completion(&mut self, sign_id: SignId) {
        self.inboxes.remove(&sign_id);
        if self.tasks.abort(sign_id) {
            tracing::info!(?sign_id, "aborting signature task due to completion event");
        } else {
            tracing::info!(?sign_id, "task already completed or unable to be aborted");
        }
    }

    fn handle_request(
        &mut self,
        sign: Sign,
        cfg: &ProtocolConfig,
        participants: &BTreeSet<Participant>,
        contract: &ContractStateWatcher,
    ) {
        match sign {
            Sign::Completion(sign_id) => {
                self.handle_completion(sign_id);
            }
            Sign::Request(indexed) => {
                let sign_id = indexed.id;

                // Skip if we already have a task handling this request.
                // Use tasks instead of inbox map since it may already contain buffered messages
                // (e.g. a Propose arriving before the indexer notifies us), so we must only look
                // at the task map to decide whether the request is truly a duplicate.
                if self.tasks.contains_key(&sign_id) {
                    tracing::info!(?sign_id, "skipping duplicate sign request");
                    return;
                }

                crate::metrics::requests::NUM_UNIQUE_SIGN_REQUESTS
                    .with_label_values(&[indexed.chain.as_str(), self.my_account_id.as_str()])
                    .inc();

                self.spawn_task(indexed, participants.clone(), contract.clone(), cfg.clone());
            }
        }

        // Update metrics
        crate::metrics::requests::SIGN_QUEUE_SIZE
            .with_label_values(&[self.my_account_id.as_str()])
            .set(self.tasks.len() as i64);
    }

    async fn run(
        mut self,
        sign_rx: Arc<RwLock<mpsc::Receiver<Sign>>>,
        mut contract: ContractStateWatcher,
        mut cfg: watch::Receiver<Config>,
    ) {
        let mut posits = self.msg.subscribe_signature_posit().await;

        let running = contract.wait_running().await;
        let all_participants = running.participants.keys().copied().collect();
        let mut protocol = cfg.borrow().protocol.clone();

        // we acquire the lock but since this is a tokio lock, aborting the task while holding
        // the lock is safe and will not deadlock other tasks trying to acquire the lock
        let mut sign_rx = sign_rx.write().await;

        loop {
            tokio::select! {
                sign = sign_rx.recv() => {
                    let Some(sign) = sign else {
                        tracing::warn!("signature spawner sign_rx closed, terminating");
                        break;
                    };
                    self.handle_request(sign, &protocol, &all_participants, &contract);
                }
                Some((sign_id, presignature_id, from, action)) = posits.recv() => {
                    self.handle_posit(sign_id, presignature_id, from, action).await;
                }
                Some(result) = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    let (sign_id, result) = match result {
                        Ok(outcome) => outcome,
                        Err(sign_id) => {
                            tracing::warn!(?sign_id, "signature task interrupted");
                            self.inboxes.remove(&sign_id);
                            continue;
                        }
                    };

                    self.inboxes.remove(&sign_id);
                    match result {
                        Ok(()) => {
                            tracing::info!(?sign_id, "signature task completed successfully");
                        }
                        Err(SignError::Aborted) => {
                            tracing::warn!(?sign_id, "signature task terminated");
                        }
                    }
                }
                Ok(()) = cfg.changed() => {
                    protocol = cfg.borrow().protocol.clone();
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
        let spawner = SignatureSpawner {
            me,
            tasks: JoinMap::new(),
            inboxes: HashMap::new(),
            my_account_id: ctx.my_account_id.clone(),
            threshold,
            public_key,
            epoch,
            presignatures: ctx.presignature_storage.clone(),
            mesh_state: ctx.mesh_state.clone(),
            msg: ctx.msg_channel.clone(),
            rpc: ctx.rpc_channel.clone(),
            backlog: ctx.backlog.clone(),
        };

        Self {
            handle: tokio::spawn(spawner.run(
                ctx.sign_rx.clone(),
                ctx.contract.clone(),
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
            PendingPresignature::Available(taken) => taken.artifact.id,
            PendingPresignature::InStorage(id, _, _) => *id,
        }
    }

    pub async fn fetch(self, timeout: Duration) -> Option<PresignatureTaken> {
        let (id, storage, owner) = match self {
            PendingPresignature::Available(taken) => return Some(taken),
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
