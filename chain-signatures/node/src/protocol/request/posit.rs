use super::mailbox::PositMailbox;
use super::state::SignState;
use super::task::{GeneratingPhase, SignPhase};
use super::*;

/// Posit phase — see [`super::task::SignPhase::Posit`].
pub struct PositPhase {
    pub proposer: Participant,
    pub active: BTreeSet<Participant>,
    pub presignature_id: PresignatureId,
    pub presignature: Option<PresignatureReservation>,
}

#[derive(Clone, Copy)]
enum RoundStatus {
    Current,
    Older,
    Future,
}

impl PositPhase {
    fn classify_round(state: &mut SignState, msg: &SignPositMessage) -> RoundStatus {
        if let (PositAction::RejectWithReason(PositRejectReason::StaleRound), Some(peer_current)) =
            (&msg.action, msg.stale_round)
        {
            state.record_peer_round(peer_current);
        }

        match state.round().cmp(&msg.round) {
            std::cmp::Ordering::Less => RoundStatus::Future,
            std::cmp::Ordering::Equal => RoundStatus::Current,
            std::cmp::Ordering::Greater => RoundStatus::Older,
        }
    }

    async fn send_stale_round(ctx: &SignTask, state: &SignState, msg: &SignPositMessage) {
        ctx.msg
            .send(
                ctx.governance.me,
                msg.from,
                PositMessage {
                    id: PositProtocolId::Signature(ctx.sign_id, msg.presignature_id, msg.round),
                    from: ctx.governance.me,
                    action: PositAction::RejectWithReason(PositRejectReason::StaleRound),
                    stale_round: Some(state.round()),
                },
            )
            .await;
    }

    /// Deliberator: wait for the proposer's Propose, reply Accept.
    async fn wait_for_propose(
        ctx: &mut SignTask,
        state: &mut SignState,
        mailbox: &PositMailbox,
        proposer: Participant,
    ) -> Result<PresignatureId, SignPhase> {
        let sign_id = ctx.sign_id;
        let remaining = state.budget.remaining();
        let outcome = tokio::time::timeout(remaining, async {
            loop {
                // Prioritize buffered messages for the current round.
                let task_msg = match state.take_buffered_posit_message() {
                    Some(buffered) => buffered,
                    None => mailbox.recv().await,
                };

                let SignPositMessage {
                    presignature_id,
                    from,
                    action,
                    round: peer_round,
                    stale_round: _,
                } = &task_msg;

                let round_status = Self::classify_round(state, &task_msg);

                // Nothing else to do with a Reject: a deliberator has sent
                // nothing that could be rejected, and answering one would
                // ping-pong rejects between two nodes.
                if matches!(action, PositAction::RejectWithReason(_)) {
                    continue;
                }

                // reject any messages with a different round than ours
                //
                // note: Rejecting messages of older rounds is always the right
                // choice. But for newer messages, we could buffer them and try
                // that round later. What we must not do is immediately jump to
                // that higher round, or else any peer could force themselves to
                // be the proposer every time.
                if matches!(round_status, RoundStatus::Older) {
                    tracing::info!(
                        ?from,
                        peer_round,
                        my_round = state.round(),
                        "Rejecting message from older round, as deliberator",
                    );
                    Self::send_stale_round(ctx, state, &task_msg).await;
                    continue;
                }

                // Message can't be processed now but is crucial to make progress later.
                // Note that we must first try and finish the current round and
                // not immediately jump to that higher round. Otherwise, any peer
                // could force themselves to be the proposer every time.
                if matches!(round_status, RoundStatus::Future) {
                    tracing::info!(
                        peer_round,
                        my_round = state.round(),
                        "Storing message for future round, as deliberator",
                    );
                    state.buffer_future_posit_message(task_msg);
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
                                        state.round(),
                                    ),
                                    from: ctx.governance.me,
                                    action: PositAction::RejectWithReason(
                                        PositRejectReason::MissingArtifact,
                                    ),
                                    stale_round: None,
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
                                    state.round(),
                                ),
                                from: ctx.governance.me,
                                action: PositAction::RejectWithReason(
                                    PositRejectReason::InvalidRequest,
                                ),
                                stale_round: None,
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
                return Err(state.reorganize(&format!(
                    "deliberator timeout waiting for Propose from {proposer:?}"
                )));
            }
        };

        // received propose, send Accept
        ctx.msg
            .send(
                ctx.governance.me,
                proposer,
                PositMessage {
                    id: PositProtocolId::Signature(sign_id, presignature_id, state.round()),
                    from: ctx.governance.me,
                    action: PositAction::Accept,
                    stale_round: None,
                },
            )
            .await;

        Ok(presignature_id)
    }

    /// Return the next response relevant to the proposer barrier, handling
    /// stale and future rounds before they reach the collector.
    async fn next_proposer_action(
        ctx: &SignTask,
        state: &mut SignState,
        mailbox: &PositMailbox,
    ) -> (Participant, PositAction) {
        loop {
            let task_msg = mailbox.recv().await;
            let peer_round = task_msg.round;

            let round_status = Self::classify_round(state, &task_msg);

            if matches!(round_status, RoundStatus::Older) {
                if matches!(&task_msg.action, PositAction::RejectWithReason(_)) {
                    continue;
                }
                Self::send_stale_round(ctx, state, &task_msg).await;
                continue;
            }

            if matches!(round_status, RoundStatus::Future) {
                tracing::info!(
                    peer_round,
                    my_round = state.round(),
                    "Storing message for future round"
                );
                state.buffer_future_posit_message(task_msg);
                continue;
            }

            let SignPositMessage { from, action, .. } = task_msg;
            return (from, action);
        }
    }

    async fn wait_for_accepts(
        ctx: &SignTask,
        state: &mut SignState,
        mailbox: &PositMailbox,
        barrier: &mut PositBarrier,
        timeout: Duration,
    ) -> PositBarrierResult {
        let started_at = tokio::time::Instant::now();
        let timeout_at = started_at + timeout;
        let accept_deadline_at = started_at + ACCEPT_POSIT_TIMEOUT;
        let timeout_sleep = tokio::time::sleep(timeout);
        tokio::pin!(timeout_sleep);
        let accept_sleep = tokio::time::sleep(ACCEPT_POSIT_TIMEOUT);
        tokio::pin!(accept_sleep);
        let mut accept_deadline_reached = false;

        loop {
            // A busy mailbox can be ready on every poll. Check wall-clock
            // deadlines explicitly so it cannot starve the timers.
            let now = tokio::time::Instant::now();
            if now >= timeout_at {
                return barrier.timeout();
            }
            if !accept_deadline_reached && now >= accept_deadline_at {
                accept_deadline_reached = true;
                if let Some(result) = barrier.terminal_result(true) {
                    return result;
                }
            }

            tokio::select! {
                biased;
                _ = &mut timeout_sleep => {
                    return barrier.timeout();
                }
                _ = &mut accept_sleep, if !accept_deadline_reached => {
                    accept_deadline_reached = true;
                    if let Some(result) = barrier.terminal_result(true) {
                        return result;
                    }
                }
                (from, action) = Self::next_proposer_action(ctx, state, mailbox) => {
                    barrier.process_action(from, &action);
                    if let Some(result) = barrier.terminal_result(accept_deadline_reached) {
                        return result;
                    }
                }
            }
        }
    }

    async fn wait_for_start(
        ctx: &SignTask,
        state: &mut SignState,
        mailbox: &PositMailbox,
        proposer: Participant,
    ) -> Result<Vec<Participant>, ()> {
        loop {
            let task_msg = match state.take_buffered_posit_message() {
                Some(buffered) => buffered,
                None => mailbox.recv().await,
            };
            let round_status = Self::classify_round(state, &task_msg);

            if matches!(&task_msg.action, PositAction::RejectWithReason(_)) {
                continue;
            }

            if matches!(round_status, RoundStatus::Older) {
                Self::send_stale_round(ctx, state, &task_msg).await;
                continue;
            }

            if matches!(round_status, RoundStatus::Future) {
                state.buffer_future_posit_message(task_msg);
                continue;
            }

            let SignPositMessage { from, action, .. } = task_msg;
            let PositAction::Start(participants) = action else {
                continue;
            };
            if from != proposer {
                tracing::warn!(?from, ?proposer, "received Start from non-proposer");
                continue;
            }
            if participants.len() < ctx.governance.threshold {
                return Err(());
            }
            return Ok(participants);
        }
    }

    /// Run the posit round. Returns `Generating` with the accepted participants,
    /// or `Organizing` on rejection/timeout.
    pub async fn advance(
        &mut self,
        ctx: &mut SignTask,
        state: &mut SignState,
        mailbox: &PositMailbox,
    ) -> SignPhase {
        let proposer = self.proposer;
        let active = self.active.clone();
        let mut presignature_id = self.presignature_id;
        let presignature = self.presignature.take();

        let sign_id = ctx.sign_id;
        let round = state.round();
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

            presignature_id = match Self::wait_for_propose(ctx, state, mailbox, proposer).await {
                Ok(id) => id,
                Err(phase) => return phase,
            }
        }

        // GUARANTEE: at least threshold participants from organizing phase.
        let posit_participants = active.iter().copied().collect::<Vec<_>>();

        let accepted_participants = if is_proposer {
            let mut barrier = match PositBarrier::new(
                ctx.governance.me,
                &posit_participants,
                ctx.governance.threshold,
            ) {
                Ok(barrier) => barrier,
                Err(error) => {
                    tracing::error!(?sign_id, ?error, "invalid posit barrier configuration");
                    return state
                        .reorganize(&format!("invalid posit barrier configuration: {error}"));
                }
            };
            let remaining = state.budget.remaining();
            let result = Self::wait_for_accepts(ctx, state, mailbox, &mut barrier, remaining).await;

            match result {
                PositBarrierResult::EnoughAccepts(result) => {
                    Self::start_with_current_accepts(
                        ctx,
                        state,
                        result.accepted.into_iter().collect(),
                        sign_id,
                        presignature_id,
                    )
                    .await
                }
                PositBarrierResult::TooManyRejects(result) => {
                    let peers_already_generating = result
                        .rejected
                        .values()
                        .filter(|reason| matches!(reason, PositRejectReason::AlreadyGenerating))
                        .count();
                    let too_few_available = ctx
                        .governance
                        .participants
                        .len()
                        .saturating_sub(peers_already_generating)
                        < ctx.governance.threshold;
                    let reason = if too_few_available {
                        state.pause_proposing_until = Some(
                            Instant::now()
                                + Duration::from_millis(ctx.cfg.signature.generation_timeout),
                        );
                        "peers already generating this signature"
                    } else {
                        "received enough rejects"
                    };
                    if presignature.is_some() {
                        tracing::warn!(?sign_id, "returning presignature to pool due to REJECTs");
                    }
                    return state.reorganize(reason);
                }
                PositBarrierResult::Timeout(result) => {
                    if presignature.is_some() {
                        tracing::warn!(
                            ?sign_id,
                            accepts = result.accepted.len(),
                            threshold = ctx.governance.threshold,
                            "returning presignature to pool due to proposer timeout"
                        );
                    }
                    return state.reorganize(&format!(
                        "proposer posit deadline reached ({} accepts, threshold {})",
                        result.accepted.len(),
                        ctx.governance.threshold
                    ));
                }
            }
        } else {
            // We just sent an Accept to the proposer. The proposer might wait up to
            // ACCEPT_POSIT_TIMEOUT to gather more accepts before sending Start.
            // We must wait at least that long so we don't abandon the round after
            // promising to participate, which would cause the proposer's generation
            // phase to hang.
            let remaining = state.budget.remaining().max(2 * ACCEPT_POSIT_TIMEOUT);
            let result = tokio::time::timeout(
                remaining,
                Self::wait_for_start(ctx, state, mailbox, proposer),
            )
            .await;

            match result {
                Ok(Ok(participants)) => participants,
                Ok(Err(())) => return state.reorganize("not enough Start participants"),
                Err(_) => {
                    return state.reorganize(&format!(
                        "deliberator posit timeout waiting for Start from {proposer:?}"
                    ));
                }
            }
        };

        SignPhase::Generating(GeneratingPhase {
            proposer,
            presignature_id,
            presignature,
            accepted_participants,
        })
    }

    /// Proposer-only: broadcast Start to all Accepters and return that set.
    async fn start_with_current_accepts(
        ctx: &SignTask,
        state: &mut SignState,
        participants: Vec<Participant>,
        sign_id: SignId,
        presignature_id: PresignatureId,
    ) -> Vec<Participant> {
        tracing::info!(?sign_id, round=?state.round(), me = ?ctx.governance.me, ?participants, "proposer broadcasting Start");

        for &p in &participants {
            if p == ctx.governance.me {
                continue;
            }
            ctx.msg
                .send(
                    ctx.governance.me,
                    p,
                    PositMessage {
                        id: PositProtocolId::Signature(sign_id, presignature_id, state.round()),
                        from: ctx.governance.me,
                        action: PositAction::Start(participants.clone()),
                        stale_round: None,
                    },
                )
                .await;
        }
        participants
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::message::{Message, MessageInbox, MessageOutbox};
    use crate::protocol::presignature::Presignature;
    use crate::rpc::RpcAction;
    use deadpool_redis::Runtime;
    use mpc_primitives::SignKind;

    /// A posit-phase harness; the unused channel ends are held alive so sends
    /// keep working. The redis pool is lazy and never actually connected.
    struct TestSetup {
        ctx: SignTask,
        state: SignState,
        outbox: MessageOutbox,
        _inbox: MessageInbox,
        _rpc_rx: mpsc::Receiver<RpcAction>,
        _mesh_tx: watch::Sender<MeshState>,
    }

    fn setup(me: Participant, other: Participant, threshold: usize) -> TestSetup {
        let account_id: near_account_id::AccountId = "p-1".parse().unwrap();
        let governance = GovernanceInfo {
            me,
            threshold,
            epoch: 0,
            public_key: k256::AffinePoint::default(),
            participants: [other, me].into_iter().collect(),
            is_running: true,
        };

        let redis_cfg = deadpool_redis::Config::from_url("redis://127.0.0.1/");
        let pool = redis_cfg.create_pool(Some(Runtime::Tokio1)).unwrap();
        let presignatures = Presignature::storage(&pool, &account_id);
        let (_inbox, outbox, msg_channel) = MessageChannel::new();
        let (rpc_tx, _rpc_rx) = mpsc::channel(1);

        let ctx = SignTask {
            governance,
            sign_id: SignId::new([0u8; 32]),
            presignatures,
            msg: msg_channel,
            rpc: RpcChannel { tx: rpc_tx },
            backlog: Backlog::new(),
            cfg: ProtocolConfig::default(),
            is_proposer: Arc::new(AtomicBool::new(false)),
            round: Arc::new(AtomicUsize::new(0)),
            limiter: SignLimiter::new(1),
            node_account_id: account_id,
        };

        let request = IndexedSignRequest::new(
            ctx.sign_id,
            mpc_primitives::SignArgs {
                entropy: [0u8; 32],
                epsilon: k256::Scalar::from(1u64),
                payload: k256::Scalar::from(2u64),
                path: "test".to_string(),
                key_version: 0,
            },
            Chain::Ethereum,
            0,
            SignKind::Sign,
        );
        let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());
        let state = SignState::new(request, mesh_rx, Arc::clone(&ctx.round));

        TestSetup {
            ctx,
            state,
            outbox,
            _inbox,
            _rpc_rx,
            _mesh_tx,
        }
    }

    /// The single message sitting in the outbox, which must be a posit from
    /// `from` to `to`; returns its stamped round, action, and stale_round.
    fn sent_posit(
        outbox: &mut MessageOutbox,
        from: Participant,
        to: Participant,
    ) -> (usize, PositAction, Option<usize>) {
        let sent = outbox
            .intercept_outgoing_messages()
            .try_recv()
            .expect("a posit message should have been sent");
        assert_eq!(sent.from, from);
        assert_eq!(sent.to, to);
        let Message::Posit(posit) = sent.message else {
            panic!("expected a posit message");
        };
        let PositProtocolId::Signature(_, _, round) = posit.id else {
            panic!("expected a signature posit id");
        };
        (round, posit.action, posit.stale_round)
    }

    /// A deliberator that rejects a Propose from a *behind* proposer echoes the
    /// rejected round in the id (so the reject reaches the sender's current
    /// conversation) and carries its own round in `stale_round`. Otherwise the
    /// behind proposer never learns it is behind and climbs one round per
    /// attempt instead of catching up in a single `bump_round`.
    #[tokio::test]
    async fn reject_of_older_round_carries_rejectors_round() {
        let me = Participant::from(1);
        let proposer = Participant::from(0);
        let mut t = setup(me, proposer, 1);

        // We are ahead of the proposer. Give the round a short budget so
        // `wait_for_propose` times out and returns shortly after emitting the
        // reject.
        let our_round = 5;
        let propose_round = 2;
        t.state.set_round(our_round);
        t.state.budget.reset(Duration::from_millis(200));

        let mailbox = PositMailbox::new();
        mailbox.push(SignPositMessage {
            presignature_id: 42,
            round: propose_round,
            from: proposer,
            action: PositAction::Propose,
            stale_round: None,
        });

        // Behind-proposer Propose is rejected; the call then times out waiting
        // for a valid one and reorganizes.
        let phase =
            PositPhase::wait_for_propose(&mut t.ctx, &mut t.state, &mailbox, proposer).await;
        assert!(matches!(phase, Err(SignPhase::Organizing(_))));

        let (round, action, stale_round) = sent_posit(&mut t.outbox, me, proposer);
        // The id echoes the round of the message being rejected.
        assert_eq!(round, propose_round);
        assert!(matches!(
            action,
            PositAction::RejectWithReason(PositRejectReason::StaleRound)
        ));
        // Our round rides in `stale_round` so the sender can catch up in one bump.
        assert_eq!(stale_round, Some(our_round));
    }

    /// Receiving side of the same contract in `wait_for_propose`: the
    /// rejector's round carried in `stale_round` is recorded and the reject
    /// itself never answered, so the next bump jumps straight to that round
    /// instead of climbing one round per attempt.
    #[tokio::test]
    async fn received_stale_round_reject_catches_up_in_one_bump() {
        let me = Participant::from(1);
        let peer = Participant::from(0);
        let mut t = setup(me, peer, 1);

        // We are behind at round 2; a peer at round 5 rejected our message,
        // echoing our round in the id and carrying its own in the payload.
        t.state.set_round(2);
        t.state.budget.reset(Duration::from_millis(200));

        let mailbox = PositMailbox::new();
        mailbox.push(SignPositMessage {
            presignature_id: 42,
            round: 2,
            from: peer,
            action: PositAction::RejectWithReason(PositRejectReason::StaleRound),
            stale_round: Some(5),
        });

        // No Propose ever arrives, so the wait times out and reorganizes,
        // bumping the round with the recorded rejector's round.
        let phase = PositPhase::wait_for_propose(&mut t.ctx, &mut t.state, &mailbox, peer).await;
        assert!(matches!(phase, Err(SignPhase::Organizing(_))));

        // Caught up in one bump: max(2 + 1, 5) = 5.
        assert_eq!(t.state.round(), 5);
        // A reject is never answered — replying would ping-pong rejects.
        assert!(t.outbox.intercept_outgoing_messages().try_recv().is_err());
    }

    #[tokio::test]
    async fn proposer_deadline_wins_over_busy_mailbox() {
        let proposer = Participant::from(0);
        let other = Participant::from(1);
        let mut t = setup(proposer, other, 2);
        let mailbox = PositMailbox::new();
        let producer_mailbox = Arc::clone(&mailbox);
        let producer = tokio::spawn(async move {
            loop {
                producer_mailbox.push(SignPositMessage {
                    presignature_id: 42,
                    round: 0,
                    from: other,
                    action: PositAction::Propose,
                    stale_round: None,
                });
                tokio::task::yield_now().await;
            }
        });

        let mut barrier =
            PositBarrier::new(proposer, &[proposer, other], 2).expect("valid posit barrier");
        let result = PositPhase::wait_for_accepts(
            &t.ctx,
            &mut t.state,
            &mailbox,
            &mut barrier,
            Duration::from_millis(1),
        )
        .await;
        producer.abort();

        assert!(matches!(result, PositBarrierResult::Timeout(_)));
    }

    /// The posit loop must answer stale-round messages the same way instead of
    /// dropping them silently; a behind peer would otherwise burn its full
    /// timeout without learning it is behind.
    #[tokio::test]
    async fn advance_rejects_older_round_with_stale_round() {
        let proposer = Participant::from(0);
        let behind = Participant::from(1);
        // Threshold 2 keeps the proposer's own accept from starting generation.
        let mut t = setup(proposer, behind, 2);

        // We propose at round 5; a straggler Accept for round 2 sits in the
        // mailbox. Short budget so the loop exits via its deadline.
        t.state.set_round(5);
        t.state.budget.reset(Duration::from_millis(200));

        let mailbox = PositMailbox::new();
        mailbox.push(SignPositMessage {
            presignature_id: 42,
            round: 2,
            from: behind,
            action: PositAction::Accept,
            stale_round: None,
        });

        let mut phase = PositPhase {
            proposer,
            active: [proposer, behind].into_iter().collect(),
            presignature_id: 42,
            presignature: None,
        };
        let next = phase.advance(&mut t.ctx, &mut t.state, &mailbox).await;
        assert!(matches!(next, SignPhase::Organizing(_)));

        let (round, action, stale_round) = sent_posit(&mut t.outbox, proposer, behind);
        // The id echoes the rejected round; ours rides in `stale_round`.
        assert_eq!(round, 2);
        assert!(matches!(
            action,
            PositAction::RejectWithReason(PositRejectReason::StaleRound)
        ));
        assert_eq!(stale_round, Some(5));
    }

    /// The receive side inside `advance()`: a behind proposer harvests the
    /// round carried by a StaleRound reject without answering it (even one
    /// echoing an older round), then reorganizes straight to that round on
    /// its deadline.
    #[tokio::test]
    async fn advance_harvests_rejectors_round() {
        let proposer = Participant::from(0);
        let rejector = Participant::from(1);
        // Threshold 2 keeps the proposer's own accept from starting generation.
        let mut t = setup(proposer, rejector, 2);

        // We propose at round 3; a reject echoing our earlier round 2 arrives,
        // carrying the rejector's round 5. Short budget so the loop exits via
        // its deadline.
        t.state.set_round(3);
        t.state.budget.reset(Duration::from_millis(200));

        let mailbox = PositMailbox::new();
        mailbox.push(SignPositMessage {
            presignature_id: 42,
            round: 2,
            from: rejector,
            action: PositAction::RejectWithReason(PositRejectReason::StaleRound),
            stale_round: Some(5),
        });

        let mut phase = PositPhase {
            proposer,
            active: [proposer, rejector].into_iter().collect(),
            presignature_id: 42,
            presignature: None,
        };
        let next = phase.advance(&mut t.ctx, &mut t.state, &mailbox).await;
        assert!(matches!(next, SignPhase::Organizing(_)));

        assert_eq!(t.state.round(), 5, "must catch up in one bump");
        assert!(
            t.outbox.intercept_outgoing_messages().try_recv().is_err(),
            "a reject must never be answered"
        );
    }
}
