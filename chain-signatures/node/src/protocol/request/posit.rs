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

impl PositPhase {
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
                    stale_round,
                } = &task_msg;

                // A StaleRound reject carries the rejector's current round;
                // remember it so our next bump catches up in one step.
                if let (
                    PositAction::RejectWithReason(PositRejectReason::StaleRound),
                    Some(peer_current),
                ) = (action, stale_round)
                {
                    state.highest_seen_round = state.highest_seen_round.max(*peer_current);
                }

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
                if state.round() > *peer_round {
                    tracing::info!(
                        ?from,
                        peer_round,
                        my_round = state.round(),
                        "Rejecting message from older round, as deliberator",
                    );
                    ctx.msg
                        .send(
                            ctx.governance.me,
                            *from,
                            PositMessage {
                                // The id echoes the rejected message so the
                                // sender knows which attempt we are answering.
                                id: PositProtocolId::Signature(
                                    sign_id,
                                    *presignature_id,
                                    *peer_round,
                                ),
                                from: ctx.governance.me,
                                action: PositAction::RejectWithReason(
                                    PositRejectReason::StaleRound,
                                ),
                                stale_round: Some(state.round()),
                            },
                        )
                        .await;
                    continue;
                }

                // Message can't be processed now but is crucial to make progress later.
                // Note that we must first try and finish the current round and
                // not immediately jump to that higher round. Otherwise, any peer
                // could force themselves to be the proposer every time.
                if state.round() < *peer_round {
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
        let mut counter = SinglePositCounter::new(ctx.governance.me, &posit_participants);

        let mut remaining = state.budget.remaining();
        if is_deliberator {
            // We just sent an Accept to the proposer. The proposer might wait up to ACCEPT_POSIT_TIMEOUT
            // to gather more accepts before sending Start.
            // We must wait at least that long so we don't abandon the round after promising to participate,
            // which would cause the proposer's generation phase to hang.
            let min_wait = 2 * ACCEPT_POSIT_TIMEOUT;
            if remaining < min_wait {
                remaining = min_wait;
            }
        }
        let posit_deadline = tokio::time::sleep(remaining);
        tokio::pin!(posit_deadline);
        let accept_deadline = tokio::time::sleep(ACCEPT_POSIT_TIMEOUT);
        tokio::pin!(accept_deadline);
        let mut accept_deadline_reached = false;

        let accepted_participants = loop {
            tokio::select! {
                task_msg = mailbox.recv() => {
                    let SignPositMessage { round: peer_round , ..} = task_msg;

                    // A StaleRound reject carries the rejector's current round;
                    // remember it so our next bump catches up in one step.
                    if let (PositAction::RejectWithReason(PositRejectReason::StaleRound), Some(peer_current)) = (&task_msg.action, task_msg.stale_round) {
                        state.highest_seen_round = state.highest_seen_round.max(peer_current);
                    }

                    // Ignore messages for older rounds
                    if state.round() > peer_round {
                        continue;
                    }

                    // Message can't be processed now but is crucial to make progress later.
                    // Note that we must first try and finish the current round and
                    // not immediately jump to that higher round. Otherwise, any peer
                    // could force themselves to be the proposer every time.
                    if state.round() < peer_round {
                        tracing::info!(
                            peer_round,
                            my_round = state.round(),
                            "Storing message for future round",
                        );
                        state.buffer_future_posit_message(task_msg);
                        continue;
                    }

                    let SignPositMessage { presignature_id: _, round: _peer_round, from, action, stale_round: _ } = task_msg;

                    if is_deliberator {
                        if let PositAction::Start(participants) = action {
                            if from != proposer {
                                tracing::warn!(?sign_id, ?round, ?from, ?proposer, "received Start from non-proposer, ignoring");
                                continue;
                            }

                            if participants.len() < ctx.governance.threshold {
                                return state.reorganize("not enough Start participants");
                            }

                            tracing::info!(?sign_id, participant = ?ctx.governance.me, ?participants, "deliberator received Start");
                            break participants;
                        }
                    } else {
                        if !counter.process_action(from, &action) {
                            continue;
                        }

                        if counter.enough_rejects(ctx.governance.threshold) {
                            let peers_already_generating = counter.num_peers_already_generating();
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
                            if let Some(_reservation) = presignature {
                                tracing::warn!(?sign_id, "returning presignature to pool due to REJECTs");
                            }
                            return state.reorganize(reason);
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
                    let reason = if is_proposer {
                        if presignature.is_some() {
                            tracing::warn!(?sign_id, "returning presignature to pool due to proposer timeout");
                        }
                        format!(
                            "proposer posit deadline reached ({} accepts, threshold {})",
                            counter.accepts.len(),
                            ctx.governance.threshold
                        )
                    } else {
                        format!("deliberator posit timeout waiting for Start from {proposer:?}")
                    };

                    return state.reorganize(&reason);
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
        counter: SinglePositCounter,
        sign_id: SignId,
        presignature_id: PresignatureId,
    ) -> Vec<Participant> {
        let participants = counter.accepts.into_iter().collect::<Vec<_>>();
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

    /// A `wait_for_propose` harness; the unused channel ends are held alive so
    /// sends keep working.
    struct TestSetup {
        ctx: SignTask,
        state: SignState,
        outbox: MessageOutbox,
        _inbox: MessageInbox,
        _rpc_rx: mpsc::Receiver<RpcAction>,
        _mesh_tx: watch::Sender<MeshState>,
    }

    fn setup(me: Participant, other: Participant) -> TestSetup {
        let account_id: near_account_id::AccountId = "p-1".parse().unwrap();
        let governance = GovernanceInfo {
            me,
            threshold: 1,
            epoch: 0,
            public_key: k256::AffinePoint::default(),
            participants: [other, me].into_iter().collect(),
            is_running: true,
        };

        let redis_cfg = deadpool_redis::Config::from_url("redis://127.0.0.1/");
        let pool = redis_cfg.create_pool(Some(Runtime::Tokio1)).unwrap();
        // These tests never touch presignatures, so the lazy pool is never
        // actually connected.
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

    /// A deliberator that rejects a Propose from a *behind* proposer echoes the
    /// rejected round in the id (so the reject reaches the sender's current
    /// conversation) and carries its own round inside `StaleRound` — otherwise
    /// the behind proposer never learns it is behind and climbs one round per
    /// attempt instead of catching up in a single `bump_round`.
    #[tokio::test]
    async fn reject_of_older_round_carries_rejectors_round() {
        let me = Participant::from(1);
        let proposer = Participant::from(0);
        let mut t = setup(me, proposer);

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

        let sent = t
            .outbox
            .intercept_outgoing_messages()
            .try_recv()
            .expect("a reject should have been sent to the behind proposer");
        assert_eq!(sent.from, me);
        assert_eq!(sent.to, proposer);

        let Message::Posit(posit) = sent.message else {
            panic!("expected a posit message");
        };
        let PositProtocolId::Signature(_, _, reject_round) = posit.id else {
            panic!("expected a signature posit id");
        };
        // The id echoes the round of the message being rejected.
        assert_eq!(reject_round, propose_round);
        assert!(matches!(
            posit.action,
            PositAction::RejectWithReason(PositRejectReason::StaleRound)
        ));
        // Our round rides in `stale_round` so the sender can catch up in one bump.
        assert_eq!(posit.stale_round, Some(our_round));
    }

    /// Receiving side of the same contract: the rejector's round carried in
    /// `StaleRound` is recorded and the reject itself never answered, so the
    /// next bump jumps straight to that round instead of climbing one round
    /// per attempt.
    #[tokio::test]
    async fn received_stale_round_reject_catches_up_in_one_bump() {
        let me = Participant::from(1);
        let peer = Participant::from(0);
        let mut t = setup(me, peer);

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
}
