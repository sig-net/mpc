use super::limiter::SignLimitError;
use super::posit::PositPhase;
use super::state::SignState;
use super::task::SignPhase;
use super::*;

/// Organizing phase — see [`super::task::SignPhase::Organizing`].
pub struct OrganizingPhase;

impl OrganizingPhase {
    /// Seeded by request entropy so all nodes pick the same proposer.
    fn proposer_per_round(
        round: usize,
        participants: &[Participant],
        entropy: &[u8; 32],
    ) -> Participant {
        let index = entropy[0] as usize + round;
        participants[index % participants.len()]
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
        let entropy = state.request.args.entropy;
        let participants = ctx
            .governance
            .participants
            .iter()
            .copied()
            .collect::<Vec<_>>();

        ctx.is_proposer.store(false, Ordering::Relaxed);

        tracing::info!(?sign_id, round = ?state.round, "entering organizing phase");
        let (active, proposer, is_proposer) = {
            let Some(active) = self
                .wait_for_active_participants(ctx, state, threshold)
                .await
            else {
                tracing::warn!(?sign_id, round = ?state.round, "no active participants, reorganizing");
                return state.reorganize();
            };

            // No liveness filter: `state.round` advances only via `bump_round`,
            // and a dead proposer costs one silent round bounded by `T(r)`.
            let proposer = Self::proposer_per_round(state.round, &participants, &entropy);

            // If proposing is paused (generating already ongoing), we act as if we weren't a proposer.
            let skip_proposing = state
                .pause_proposing_until
                .is_some_and(|until| until > std::time::Instant::now());
            let is_proposer = proposer == me && !skip_proposing;
            ctx.is_proposer.store(is_proposer, Ordering::Relaxed);

            tracing::info!(
                ?sign_id,
                round = ?state.round,
                ?proposer,
                ?me,
                is_proposer,
                skip_proposing,
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
                limit = ctx.limiter.limit(),
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
                    return state.reorganize();
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
                    return state.reorganize();
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

    /// The liveness guarantee deterministic rotation exists to provide: from any
    /// starting round, with any set of `f < n` participants down, a live proposer
    /// is elected within `f + 1` rounds. This is the bound that lets a request
    /// make progress past dead proposers; a rotation that clustered or skipped
    /// participants (e.g. a hash-based seed) would silently break it. Checked
    /// exhaustively over every down-set and start round, across seeds.
    #[test]
    fn rotation_reaches_live_proposer_within_f_plus_1_rounds() {
        let participants: Vec<Participant> = (0u32..5).map(Participant::from).collect();
        let n = participants.len();
        for seed in [0u8, 1, 7, 128, 255] {
            let mut entropy = [0u8; 32];
            entropy[0] = seed;
            // Every down-set except "all down" (which has no live proposer).
            for down_mask in 0..((1u32 << n) - 1) {
                let down: BTreeSet<Participant> = (0..n)
                    .filter(|&i| down_mask & (1 << i) != 0)
                    .map(|i| participants[i])
                    .collect();
                let budget = down.len() + 1; // f + 1 rounds
                for start in 0..n {
                    let reached_live = (start..start + budget).any(|r| {
                        let p = OrganizingPhase::proposer_per_round(r, &participants, &entropy);
                        !down.contains(&p)
                    });
                    assert!(
                        reached_live,
                        "seed {seed}, down {down:?}, start {start}: no live proposer within {budget} rounds"
                    );
                }
            }
        }
    }
}
