use super::limiter::SignPermit;
use super::mailbox::PositMailbox;
use super::organize::OrganizingPhase;
use super::task::{SignPhase, SignTask};
use super::*;

pub struct SignState {
    round: usize,
    pub request: Arc<IndexedSignRequest>,
    pub mesh_state: watch::Receiver<MeshState>,
    /// Budget for the current organizing+posit attempt.
    pub budget: TimeoutBudget,
    pub permit: Option<SignPermit>,
    /// Posits for this request. Shared with the spawner, which buffers messages
    /// that arrive before the task, and kept across respawns. Messages for
    /// rounds we have not reached wait in it, and it remembers the highest
    /// round peers have shown us.
    pub mailbox: Arc<PositMailbox>,
    /// Shared with `SignEntry` so a respawn resumes at the round it left off;
    /// peers rely on our rounds never going down.
    carried_round: Arc<AtomicUsize>,
}

/// Where a posit stands against our round; see [`SignState::gate`].
pub enum Gate {
    /// Our round, or one we have not reached: for the caller to handle.
    Live(SignPositMessage),
    /// From a round we have left: the sender should learn our round.
    Stale(SignPositMessage),
}

impl SignState {
    pub fn new(
        request: Arc<IndexedSignRequest>,
        mesh_state: watch::Receiver<MeshState>,
        carried_round: Arc<AtomicUsize>,
        mailbox: Arc<PositMailbox>,
    ) -> Self {
        Self {
            round: carried_round.load(Ordering::Relaxed),
            request,
            mesh_state,
            budget: TimeoutBudget::new(round_timeout(0)),
            permit: None,
            mailbox,
            carried_round,
        }
    }

    pub fn round(&self) -> usize {
        self.round
    }

    /// Sole write path for `round`; keeps the carried value in step.
    pub fn set_round(&mut self, round: usize) {
        self.round = round;
        self.carried_round.store(round, Ordering::Relaxed);
    }

    pub fn request(&self) -> &IndexedSignRequest {
        &self.request
    }

    /// Abandon the current attempt: advance to the next round (releasing the
    /// held permit and resetting the timeout budget) and restart the state
    /// machine from the Organizing phase. The single back-edge of the sign
    /// state machine.
    pub fn reorganize(&mut self, reason: &str) -> SignPhase {
        tracing::warn!(
            sign_id = ?self.request.id,
            round = self.round,
            reason,
            "reorganizing sign request"
        );
        self.bump_round();
        SignPhase::Organizing(OrganizingPhase)
    }

    /// Next round: one past ours, or straight to the highest round peers have
    /// shown us, whichever is further. We never jump on sight: if we did, any
    /// peer could name a round that makes itself proposer, every time.
    fn bump_round(&mut self) {
        let prev_round = self.round;
        self.set_round(std::cmp::max(
            self.round.saturating_add(1),
            self.mailbox.highest_round(),
        ));
        self.budget.reset(round_timeout(self.round));
        self.permit = None;
        tracing::debug!(prev_round, new_round = self.round, "bumped round");
    }

    /// Record a peer's round learned from a `StaleRound` reject so the next
    /// bump catches up in one step.
    pub fn record_peer_round(&self, peer_round: usize) {
        self.mailbox.record_round(peer_round);
    }

    /// Place a posit against our round, recording whatever it tells us about
    /// the sender's round on the way. `None` is a reject from a round we have
    /// left: there is nothing to answer (a reject is never answered with a
    /// reject, or two nodes ping-pong) and any `StaleRound` payload has been
    /// recorded.
    pub fn gate(&self, msg: SignPositMessage) -> Option<Gate> {
        self.mailbox.record_round(msg.round);
        if let PositAction::RejectWithReason(PositRejectReason::StaleRound(peer_round)) = msg.action
        {
            self.record_peer_round(peer_round);
        }

        if msg.round >= self.round {
            return Some(Gate::Live(msg));
        }
        if matches!(msg.action, PositAction::RejectWithReason(_)) {
            return None;
        }
        Some(Gate::Stale(msg))
    }

    /// Next posit for the current round. A message from a round we have left
    /// is answered with `StaleRound`, carrying our round so the sender catches
    /// up in one bump. Messages for rounds we have not reached wait in the
    /// mailbox until we get there.
    pub async fn recv_current(&self, ctx: &SignTask) -> SignPositMessage {
        loop {
            let msg = self.mailbox.recv_up_to(self.round).await;
            match self.gate(msg) {
                Some(Gate::Live(msg)) => return msg,
                Some(Gate::Stale(msg)) => {
                    tracing::info!(
                        sign_id = ?ctx.sign_id,
                        from = ?msg.from,
                        peer_round = msg.round,
                        my_round = self.round,
                        "rejecting posit from an older round"
                    );
                    ctx.reject(
                        msg.from,
                        msg.presignature_id,
                        msg.round,
                        PositRejectReason::StaleRound(self.round),
                    )
                    .await;
                }
                None => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> IndexedSignRequest {
        IndexedSignRequest::sign(
            SignId::new([0u8; 32]),
            mpc_primitives::SignArgs {
                entropy: [0u8; 32],
                epsilon: k256::Scalar::from(1u64),
                payload: k256::Scalar::from(2u64),
                path: "test".to_string(),
                key_version: 0,
            },
            Chain::Ethereum,
            0,
        )
    }

    fn posit(from: u32, round: usize, action: PositAction) -> SignPositMessage {
        SignPositMessage {
            presignature_id: 0,
            round,
            from: Participant::from(from),
            action,
        }
    }

    fn state(round: usize) -> SignState {
        let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());
        let mut state = SignState::new(
            Arc::new(request()),
            mesh_rx,
            Arc::new(AtomicUsize::new(0)),
            PositMailbox::new(),
        );
        state.set_round(round);
        state
    }

    /// A respawn rebuilds `SignState`; the round must resume from the carried
    /// value, not restart at 0 — peers read a round reset as time travel.
    #[test]
    fn round_survives_a_respawn() {
        let carried = Arc::new(AtomicUsize::new(0));
        let mailbox = PositMailbox::new();
        let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());

        let mut state = SignState::new(
            Arc::new(request()),
            mesh_rx.clone(),
            Arc::clone(&carried),
            Arc::clone(&mailbox),
        );
        state.reorganize("test");
        state.record_peer_round(9);
        state.reorganize("test");
        assert_eq!(state.round(), 9);

        // The task is aborted and a new incarnation takes over.
        drop(state);
        let respawned = SignState::new(Arc::new(request()), mesh_rx, carried, mailbox);
        assert_eq!(respawned.round(), 9);
    }

    /// The gate sorts messages by round: ours or later pass through, older
    /// ones come back as stale unless they are rejects, which have nothing to
    /// answer. Every message leaves its round behind for the next bump.
    #[test]
    fn gate_sorts_by_round_and_drops_stale_rejects() {
        let state = state(5);

        assert!(matches!(
            state.gate(posit(1, 5, PositAction::Accept)),
            Some(Gate::Live(_))
        ));
        assert!(matches!(
            state.gate(posit(1, 7, PositAction::Propose)),
            Some(Gate::Live(_))
        ));
        assert!(matches!(
            state.gate(posit(1, 2, PositAction::Propose)),
            Some(Gate::Stale(_))
        ));
        assert!(state
            .gate(posit(
                1,
                2,
                PositAction::RejectWithReason(PositRejectReason::InvalidRequest)
            ))
            .is_none());

        // The round-7 Propose was recorded on the way through.
        assert_eq!(state.mailbox.highest_round(), 7);
    }

    /// A StaleRound reject names the rejector's round; that is recorded even
    /// when the reject itself is dropped as stale.
    #[test]
    fn gate_records_the_round_inside_a_stale_round_reject() {
        let mut state = state(3);

        let gated = state.gate(posit(
            1,
            2,
            PositAction::RejectWithReason(PositRejectReason::StaleRound(12)),
        ));
        assert!(gated.is_none());

        state.reorganize("test");
        assert_eq!(state.round(), 12, "must catch up in one bump");
    }
}
