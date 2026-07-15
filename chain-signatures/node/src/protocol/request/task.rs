//! Per-request driver: the `SignPhase` state machine and the `SignTask` that owns it.

use super::metrics::PhaseDurations;
use super::organize::OrganizingPhase;
use super::posit::PositPhase;
use super::state::SignState;
use super::work_queue::SignPositWorkQueue;
use super::*;

/// Generating phase — see [`SignPhase::Generating`].
pub struct GeneratingPhase {
    pub proposer: Participant,
    pub presignature_id: PresignatureId,
    pub presignature: Option<PresignatureReservation>,
    pub accepted_participants: Vec<Participant>,
}

/// State machine for one sign request. Each phase advances to the next or loops
/// back to `Organizing` (a new round) on any recoverable failure.
pub enum SignPhase {
    /// Wait for threshold active peers and elect the round's proposer; if that's
    /// us, take a concurrency slot, reserve a presignature, and broadcast Propose.
    Organizing(OrganizingPhase),
    /// Agree on the presignature and participant set: the proposer collects
    /// Accepts and broadcasts Start; each deliberator does Propose -> Accept -> Start.
    Posit(PositPhase),
    /// Commit the reserved presignature and run the signing protocol to completion.
    Generating(GeneratingPhase),
    /// Terminal: the request finished (`Ok`) or aborted (`Err`).
    Complete(Result<(), SignError>),
}

impl SignPhase {
    async fn advance(
        &mut self,
        ctx: &mut SignTask,
        state: &mut SignState,
        posit_queue: &SignPositWorkQueue,
    ) -> SignPhase {
        match self {
            SignPhase::Organizing(phase) => phase.advance(ctx, state).await,
            SignPhase::Posit(phase) => phase.advance(ctx, state, posit_queue).await,
            SignPhase::Generating(phase) => phase.advance(ctx, state, posit_queue).await,
            SignPhase::Complete(result) => SignPhase::Complete(*result),
        }
    }
}

impl GeneratingPhase {
    async fn advance(
        &mut self,
        ctx: &SignTask,
        state: &mut SignState,
        posit_queue: &SignPositWorkQueue,
    ) -> SignPhase {
        // We successfully committed to generating; future rounds should be unrestricted.
        state.pause_proposing_until = None;

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
                    return state.reorganize();
                }
            }
        } else {
            PendingPresignature::InStorage(
                self.presignature_id,
                self.proposer,
                ctx.presignatures.clone(),
            )
        };

        // Create and run signature generator, which will drive the protocol to completion.
        let gen_ctx = ctx.generate_ctx();
        let generator = match SignGenerator::new(
            &gen_ctx,
            self.proposer,
            state.request().clone(),
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
                return state.reorganize();
            }
        };

        crate::metrics::protocols::NUM_TOTAL_HISTORICAL_SIGNATURE_GENERATORS.inc();

        // Drive generation while answering posit traffic: peers proposing this
        // signature get a Reject so they don't wait for us. The generator itself
        // knows nothing about posits.
        let generation = generator.run(&gen_ctx);
        tokio::pin!(generation);
        let result = loop {
            tokio::select! {
                result = &mut generation => break result,
                task_msg = posit_queue.recv() => {
                    Self::reject_late_propose(ctx, task_msg).await;
                }
            }
        };

        match result {
            Ok(()) => SignPhase::Complete(Ok(())),
            Err(err) => {
                tracing::warn!(
                    ?sign_id,
                    ?round,
                    ?err,
                    me=?ctx.governance.me,
                    "signature generation failed, reorganizing"
                );
                state.reorganize()
            }
        }
    }

    /// Reject a `Propose` that arrives while we are already generating; drop
    /// stale Accept/Reject/Start messages.
    async fn reject_late_propose(ctx: &SignTask, task_msg: SignTaskMessage) {
        let SignTaskMessage::PositMessage {
            presignature_id,
            round,
            from,
            action,
        } = task_msg;
        if !matches!(action, PositAction::Propose) {
            return;
        }
        let me = ctx.governance.me;
        tracing::info!(
            sign_id = ?ctx.sign_id,
            ?from,
            round,
            "received Propose while already generating, rejecting"
        );
        ctx.msg
            .send(
                me,
                from,
                PositMessage {
                    id: PositProtocolId::Signature(ctx.sign_id, presignature_id, round),
                    from: me,
                    action: PositAction::RejectWithReason(PositRejectReason::AlreadyGenerating),
                },
            )
            .await;
    }
}

/// Owns everything needed to fulfil one sign request; the context passed between phases of the state machine.
pub struct SignTask {
    pub governance: GovernanceInfo,
    pub sign_id: SignId,
    pub presignatures: PresignatureStorage,
    pub msg: MessageChannel,
    pub rpc: RpcChannel,
    pub backlog: Backlog,
    pub cfg: ProtocolConfig,
    pub contract: ContractStateWatcher,
    pub is_proposer: Arc<AtomicBool>,
    pub limiter: SignLimiter,
    pub node_account_id: near_account_id::AccountId,
}

impl SignTask {
    /// Drive the signature generation state machine to completion
    pub async fn run(
        mut self,
        request: IndexedSignRequest,
        mesh_state: watch::Receiver<MeshState>,
        posit_queue: Arc<SignPositWorkQueue>,
    ) -> Result<(), SignError> {
        let sign_id = self.sign_id;
        tracing::info!(?sign_id, governance = ?self.governance, "signature task starting...");

        let mut state = SignState::new(request, mesh_state);
        let mut phase = SignPhase::Organizing(OrganizingPhase);
        let mut contract_watcher = self.contract.clone();

        // If started during resharing, we won't advance until back in running state.
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
                        // Back in running; the interrupted attempt is abandoned and we
                        // retry with a fresh round, like any other failed attempt.
                        phase = state.reorganize();
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
                new_phase = phase.advance(&mut self, &mut state, &posit_queue), if is_running => {
                    if let Some(step) = current_phase_step {
                        durations.add(step, phase_start.elapsed());
                        if matches!(&new_phase, SignPhase::Organizing(_)) {
                            SIGN_REQUEST_LOOPS
                                .with_label_values(&[
                                    state.request().chain.as_str(),
                                    step.as_str(),
                                ])
                                .inc();
                        }
                    }

                    match new_phase {
                        SignPhase::Complete(result) => {
                            if result.is_ok() {
                                durations.emit(state.request().chain);
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

    /// Snapshot the fields the generation protocol needs.
    fn generate_ctx(&self) -> GenerateCtx {
        GenerateCtx {
            governance: self.governance.clone(),
            msg: self.msg.clone(),
            rpc: self.rpc.clone(),
            backlog: self.backlog.clone(),
            cfg: self.cfg.clone(),
            node_account_id: self.node_account_id.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::contract::primitives::{ParticipantInfo, Participants};
    use crate::protocol::contract::{ResharingContractState, RunningContractState};
    use crate::protocol::presignature::Presignature;
    use crate::protocol::ProtocolState;
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
            new_threshold: 1,
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
}
