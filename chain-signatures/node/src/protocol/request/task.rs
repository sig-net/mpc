//! Per-request driver: the `SignPhase` state machine and the `SignTask` that owns it.

use super::mailbox::PositMailbox;
use super::metrics::PhaseDurations;
use super::organize::OrganizingPhase;
use super::posit::PositPhase;
use super::state::SignState;
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
        mailbox: &PositMailbox,
    ) -> SignPhase {
        match self {
            SignPhase::Organizing(phase) => phase.advance(ctx, state).await,
            SignPhase::Posit(phase) => phase.advance(ctx, state, mailbox).await,
            SignPhase::Generating(phase) => phase.advance(ctx, state, mailbox).await,
            SignPhase::Complete(result) => SignPhase::Complete(*result),
        }
    }
}

impl GeneratingPhase {
    async fn advance(
        &mut self,
        ctx: &SignTask,
        state: &mut SignState,
        mailbox: &PositMailbox,
    ) -> SignPhase {
        let sign_id = ctx.sign_id;

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
                    return state.reorganize("failed to commit presignature reservation");
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
            Arc::clone(&state.request),
            presignature_pending,
            self.accepted_participants.clone(),
        )
        .await
        {
            Ok(gen) => gen,
            Err(err) => {
                return state.reorganize(&format!("failed to create generator: {err}"));
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
                task_msg = mailbox.recv() => {
                    Self::reject_late_propose(ctx, state, task_msg).await;
                }
            }
        };

        match result {
            Ok(()) => SignPhase::Complete(Ok(())),
            Err(err) => state.reorganize(&format!("signature generation failed: {err:?}")),
        }
    }

    /// Reject a `Propose` that arrives while we are already generating; drop
    /// stale Accept/Reject/Start messages.
    async fn reject_late_propose(
        ctx: &SignTask,
        state: &mut SignState,
        task_msg: SignPositMessage,
    ) {
        let SignPositMessage {
            presignature_id,
            round,
            from,
            action,
            ..
        } = task_msg;
        if !matches!(action, PositAction::Propose) {
            return;
        }
        let me = ctx.governance.me;
        let reason = if state.round() > round {
            PositRejectReason::StaleRound(state.round())
        } else {
            state.record_peer_round(round);
            PositRejectReason::AlreadyGenerating
        };
        tracing::info!(
            sign_id = ?ctx.sign_id,
            ?from,
            round,
            my_round = state.round(),
            ?reason,
            "received Propose while already generating, rejecting"
        );
        ctx.msg
            .send(
                me,
                from,
                PositMessage {
                    id: PositProtocolId::Signature(ctx.sign_id, presignature_id, round),
                    from: me,
                    action: PositAction::RejectWithReason(reason),
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
    pub is_proposer: Arc<AtomicBool>,
    /// Posit round, shared with `SignEntry` so it survives a respawn.
    pub round: Arc<AtomicUsize>,
    pub limiter: SignLimiter,
    pub node_account_id: near_account_id::AccountId,
}

impl SignTask {
    /// Drive the signature generation state machine to completion
    pub async fn run(
        mut self,
        request: Arc<IndexedSignRequest>,
        mesh_state: watch::Receiver<MeshState>,
        mailbox: Arc<PositMailbox>,
    ) -> Result<(), SignError> {
        let sign_id = self.sign_id;
        tracing::info!(?sign_id, governance = ?self.governance, "signature task starting...");

        let mut state = SignState::new(request, mesh_state, Arc::clone(&self.round));
        let mut phase = SignPhase::Organizing(OrganizingPhase);

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

            let new_phase = phase.advance(&mut self, &mut state, &mailbox).await;
            if let Some(step) = current_phase_step {
                durations.add(step, phase_start.elapsed());
                if matches!(&new_phase, SignPhase::Organizing(_)) {
                    SIGN_REQUEST_LOOPS
                        .with_label_values(&[state.request().chain.as_str(), step.as_str()])
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
    use super::super::posit::tests::{sent_posit, setup};
    use super::*;

    fn propose(from: Participant, round: usize) -> SignPositMessage {
        SignPositMessage {
            presignature_id: 42,
            round,
            from,
            action: PositAction::Propose,
        }
    }

    /// A behind peer is answered the way every other phase answers one, with
    /// StaleRound carrying our round, so it catches up in a single bump.
    #[tokio::test]
    async fn late_propose_from_behind_peer_carries_our_round() {
        let me = Participant::from(0);
        let behind = Participant::from(1);
        let mut t = setup(me, behind, 2);
        t.state.set_round(5);

        GeneratingPhase::reject_late_propose(&t.ctx, &mut t.state, propose(behind, 2)).await;

        let (round, action) = sent_posit(&mut t.outbox, me, behind);
        // The id echoes the rejected round; ours rides in the reject.
        assert_eq!(round, 2);
        assert_eq!(
            action,
            PositAction::RejectWithReason(PositRejectReason::StaleRound(5))
        );
        assert_eq!(t.state.round(), 5);
    }

    /// An ahead peer's round is recorded, so the reorganize after a failed
    /// generation lands on it instead of climbing one round at a time.
    #[tokio::test]
    async fn late_propose_from_ahead_peer_is_recorded() {
        let me = Participant::from(0);
        let ahead = Participant::from(1);
        let mut t = setup(me, ahead, 2);
        t.state.set_round(3);

        GeneratingPhase::reject_late_propose(&t.ctx, &mut t.state, propose(ahead, 12)).await;

        let (_, action) = sent_posit(&mut t.outbox, me, ahead);
        assert!(matches!(
            action,
            PositAction::RejectWithReason(PositRejectReason::AlreadyGenerating)
        ));

        // Caught up in one bump: max(3 + 1, 12) = 12.
        t.state.reorganize("generation failed");
        assert_eq!(t.state.round(), 12);
    }
}
