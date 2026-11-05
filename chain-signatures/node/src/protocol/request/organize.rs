use super::limiter::SignLimitError;
use super::posit::PositPhase;
use super::state::SignState;
use super::task::SignPhase;
use super::*;

/// Organizing phase — see [`super::task::SignPhase::Organizing`].
pub struct OrganizingPhase;

/// Leaves the round when its deliberators do, without holding a slot, so this
/// node's next round does not start ahead of theirs.
async fn wait_out_round(state: &mut SignState, reason: &str) -> SignPhase {
    state.permit = None;
    tokio::time::sleep(state.budget.remaining()).await;
    state.reorganize(reason)
}

impl OrganizingPhase {
    /// Seeded by request entropy so all nodes pick the same proposer.
    ///
    /// Both operands are reduced before adding: `round` comes from
    /// `highest_seen_round`, which a peer sets, so it can be arbitrarily large.
    fn proposer_per_round(
        round: usize,
        participants: &[Participant],
        entropy: &[u8; 32],
    ) -> Participant {
        let n = participants.len();
        let index = (entropy[0] as usize % n + round % n) % n;
        participants[index]
    }

    /// Waits for threshold active participants to be present.
    async fn wait_for_active_participants(
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

    /// Returns `Posit` once a proposer is chosen, else loops back to
    /// `Organizing` on timeout / missing presignature / no slot.
    pub async fn advance(&mut self, ctx: &mut SignTask, state: &mut SignState) -> SignPhase {
        let sign_id = ctx.sign_id;
        let threshold = ctx.governance.threshold;
        let me = ctx.governance.me;
        let entropy = state.request().args.entropy;
        let participants = ctx
            .governance
            .participants
            .iter()
            .copied()
            .collect::<Vec<_>>();

        ctx.is_proposer.store(false, Ordering::Relaxed);

        tracing::info!(?sign_id, round = ?state.round(), "entering organizing phase");
        let (active, proposer, is_proposer) = {
            let Some(active) = self
                .wait_for_active_participants(ctx, state, threshold)
                .await
            else {
                return state.reorganize("no active participants");
            };

            // Elect from inputs every node shares (round, membership, entropy), no
            // local-only information: filtering by the local active set makes nodes
            // elect different proposers and diverge permanently (#907).
            let proposer = Self::proposer_per_round(state.round(), &participants, &entropy);

            let is_proposer = proposer == me;
            ctx.is_proposer.store(is_proposer, Ordering::Relaxed);

            tracing::info!(
                ?sign_id,
                round = ?state.round(),
                ?proposer,
                ?me,
                is_proposer,
                active_count = active.len(),
                "organized: selected proposer"
            );

            (active, proposer, is_proposer)
        };

        // Past this the proposer stops waiting for a slot or a presignature: the
        // posit needs a round's minimum time, or the deliberators give up first.
        // A round no longer than that minimum splits its budget instead.
        let remaining = state.budget.remaining();
        let reserve = if remaining > ROUND_TIMEOUT_FLOOR {
            ROUND_TIMEOUT_FLOOR
        } else {
            remaining / 2
        };
        let prepare_deadline = Instant::now() + remaining.saturating_sub(reserve);

        if is_proposer {
            let slot_wait = prepare_deadline.saturating_duration_since(Instant::now());
            tracing::info!(
                ?sign_id,
                round = ?state.round(),
                ?remaining,
                timeout = ?slot_wait,
                limit = ctx.limiter.limit(),
                "proposer waiting for concurrency slot"
            );

            let permit = match ctx.limiter.acquire(slot_wait).await {
                Ok(permit) => permit,
                Err(SignLimitError::Timeout) => {
                    return wait_out_round(state, "proposer timeout waiting for concurrency slot")
                        .await;
                }
                Err(SignLimitError::Closed) => {
                    tracing::error!(?sign_id, "proposer semaphore closed");
                    return SignPhase::Complete(Err(SignError::Aborted(
                        "proposer semaphore closed".to_string(),
                    )));
                }
            };

            state.permit = Some(permit);
        } else {
            state.permit = None;
        }

        let (presignature_id, presignature, active) = if is_proposer {
            tracing::info!(?sign_id, round = ?state.round(), "proposer waiting for presignature");
            let active = active.iter().copied().collect::<Vec<_>>();
            let fetch_wait = prepare_deadline.saturating_duration_since(Instant::now());
            let fetch = tokio::time::timeout(fetch_wait, async {
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
                    return wait_out_round(state, "proposer timeout waiting for presignature")
                        .await;
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
                            id: PositProtocolId::signature(
                                sign_id,
                                ctx.kind,
                                presignature_id,
                                state.round(),
                            ),
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

        SignPhase::Posit(PositPhase {
            proposer,
            active,
            presignature_id,
            presignature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Some integrations tests rely on this. If this changes, you probably also
    /// have to update the tests.
    #[test]
    fn proposer_order_for_seed_0() {
        // SHA256([0,0,0,0])[0] = 223.
        // With 3 participants:
        //   round 0: (223 + 0) % 3 = 1 -> participant 1
        //   round 1: (223 + 1) % 3 = 2 -> participant 2
        //   round 2: (223 + 2) % 3 = 0 -> participant 0
        let participants: Vec<Participant> = (0u32..3).map(Participant::from).collect();
        // entropy[0] = SHA256([0,0,0,0])[0] = 0xdf = 223; only the first byte matters.
        let mut entropy = [0u8; 32];
        entropy[0] = 0xdf;
        assert_eq!(
            OrganizingPhase::proposer_per_round(0, &participants, &entropy),
            Participant::from(1)
        );
        assert_eq!(
            OrganizingPhase::proposer_per_round(1, &participants, &entropy),
            Participant::from(2)
        );
        assert_eq!(
            OrganizingPhase::proposer_per_round(2, &participants, &entropy),
            Participant::from(0)
        );
    }

    /// From any starting round, with any `f < n` participants down, rotation must
    /// reach a live proposer within `f + 1` rounds — the bound that lets a request
    /// make progress past dead proposers. A rotation that revisited a participant
    /// before covering the rest (say a hash of the round, or a stride sharing a
    /// factor with `n`) would silently lose it.
    #[test]
    fn rotation_reaches_live_proposer_within_f_plus_1_rounds() {
        // Only `entropy[0]` selects the offset, so varying the seed is the same
        // as varying the starting round, which the loop below already sweeps.
        let entropy = [0u8; 32];
        for n in [4usize, 5] {
            let participants: Vec<Participant> = (0..n as u32).map(Participant::from).collect();
            // Every down-set except "all down", which has no live proposer.
            for down_mask in 0..((1u32 << n) - 1) {
                let down: BTreeSet<Participant> = (0..n)
                    .filter(|&i| down_mask & (1 << i) != 0)
                    .map(|i| participants[i])
                    .collect();
                let budget = down.len() + 1;
                for start in 0..n {
                    let reached_live = (start..start + budget).any(|r| {
                        let p = OrganizingPhase::proposer_per_round(r, &participants, &entropy);
                        !down.contains(&p)
                    });
                    assert!(
                        reached_live,
                        "n {n}, down {down:?}, start {start}: no live proposer within {budget} rounds"
                    );
                }
            }
        }
    }

    /// Time the test proposer gets on top of the posit floor to find a slot
    /// and a presignature.
    const PREPARE: Duration = Duration::from_millis(300);

    /// A lone proposer with a round budget of the floor plus [`PREPARE`]. Its
    /// storage has no owner set, so every presignature peek finds nothing.
    fn sole_proposer() -> super::super::posit::tests::TestSetup {
        use crate::mesh::connection::NodeStatus;
        use crate::protocol::ParticipantInfo;

        let me = Participant::from(0);
        let mut t = super::super::posit::tests::setup(me, me, 1);
        let mut mesh = MeshState::default();
        mesh.update(me, NodeStatus::Active, ParticipantInfo::new(0));
        let (_mesh_tx, mesh_rx) = watch::channel(mesh);
        t.state.mesh_state = mesh_rx;
        t.state.budget.reset(ROUND_TIMEOUT_FLOOR + PREPARE);
        t
    }

    /// Whether `limiter` has a free slot `after` from now; released at once.
    fn probe_slot(limiter: SignLimiter, after: Duration) -> tokio::task::JoinHandle<bool> {
        tokio::spawn(async move {
            tokio::time::sleep(after).await;
            limiter.acquire(Duration::ZERO).await.is_ok()
        })
    }

    /// A slot freed after the proposer's deadline stays free: taking it then
    /// would start a posit the deliberators leave before it can finish.
    #[tokio::test]
    async fn proposer_leaves_a_slot_freed_after_its_deadline() {
        let mut t = sole_proposer();
        let held = t.ctx.limiter.acquire(Duration::ZERO).await.unwrap();
        tokio::spawn(async move {
            tokio::time::sleep(PREPARE + Duration::from_millis(100)).await;
            drop(held);
        });
        let probe = probe_slot(t.ctx.limiter.clone(), PREPARE + Duration::from_millis(300));

        let phase = OrganizingPhase.advance(&mut t.ctx, &mut t.state).await;

        assert!(matches!(phase, SignPhase::Organizing(_)));
        assert!(
            probe.await.unwrap(),
            "the proposer took a slot it could no longer use"
        );
    }

    /// A proposer that found no slot still leaves the round when the
    /// deliberators do, so its next round starts in step with theirs.
    #[tokio::test]
    async fn proposer_sits_out_the_round_after_a_slot_timeout() {
        let mut t = sole_proposer();
        let _held = t.ctx.limiter.acquire(Duration::ZERO).await.unwrap();

        let started = Instant::now();
        let phase = OrganizingPhase.advance(&mut t.ctx, &mut t.state).await;
        let waited = started.elapsed();

        assert!(matches!(phase, SignPhase::Organizing(_)));
        assert_eq!(t.state.round(), 1);
        assert!(
            waited >= ROUND_TIMEOUT_FLOOR,
            "left the round after {waited:?}, ahead of its deliberators"
        );
    }

    /// A proposer that got a slot but no presignature by its deadline gives
    /// the slot back then, instead of holding it until the round ends.
    #[tokio::test]
    async fn proposer_releases_its_slot_when_no_presignature_comes_in_time() {
        let mut t = sole_proposer();
        let probe = probe_slot(t.ctx.limiter.clone(), PREPARE + Duration::from_millis(500));

        let started = Instant::now();
        let phase = OrganizingPhase.advance(&mut t.ctx, &mut t.state).await;
        let waited = started.elapsed();

        assert!(matches!(phase, SignPhase::Organizing(_)));
        assert!(
            probe.await.unwrap(),
            "the proposer kept its slot past the deadline"
        );
        assert!(
            waited >= ROUND_TIMEOUT_FLOOR,
            "left the round after {waited:?}, ahead of its deliberators"
        );
    }

    /// A round as short as the floor still leaves the proposer time to take a
    /// slot that frees early in the round.
    #[tokio::test]
    async fn proposer_keeps_a_prepare_window_in_a_floor_length_round() {
        let mut t = sole_proposer();
        t.state.budget.reset(ROUND_TIMEOUT_FLOOR);
        let held = t.ctx.limiter.acquire(Duration::ZERO).await.unwrap();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            drop(held);
        });
        let probe = probe_slot(t.ctx.limiter.clone(), Duration::from_millis(500));

        let phase = OrganizingPhase.advance(&mut t.ctx, &mut t.state).await;

        assert!(matches!(phase, SignPhase::Organizing(_)));
        assert!(
            !probe.await.unwrap(),
            "the proposer gave up before the slot freed"
        );
    }
}
