use super::limiter::SignPermit;
use super::organize::OrganizingPhase;
use super::task::SignPhase;
use super::*;
use crate::backlog::{Generating, SignEntry};

pub struct SignState {
    round: usize,
    /// Round of the last reorganize warn; reorganizations are sampled against
    /// it so `bump_round` jumps can't skip the sampling points.
    last_warned_round: usize,
    pub entry: SignEntry<Generating>,
    pub mesh_state: watch::Receiver<MeshState>,
    /// Budget for the current organizing+posit attempt.
    pub budget: TimeoutBudget,
    pub permit: Option<SignPermit>,
    /// The highest round sent by a peer
    pub highest_seen_round: usize,
    /// Posit message for `highest_seen_round` round.
    ///
    /// These are later processed, if the task reaches the `highest_seen_round`
    /// as a deliberator. Proposers do not reprocess old messages. A valid peer
    /// would not have sent a posit message before the proposer proposes.
    ///
    /// INVARIANT: All messages stored here are for `highest_seen_round`. Must
    /// be cleared when `highest_seen_round` changes. One slot per sender.
    pub buffered_messages: HashMap<Participant, SignPositMessage>,
    /// Shared with `SignEntry` so a respawn resumes at the round it left off;
    /// peers rely on our rounds never going down.
    carried_round: Arc<AtomicUsize>,
}

impl SignState {
    pub fn new(
        entry: SignEntry<Generating>,
        mesh_state: watch::Receiver<MeshState>,
        carried_round: Arc<AtomicUsize>,
    ) -> Self {
        let round = carried_round.load(Ordering::Relaxed);
        Self {
            round,
            last_warned_round: 0,
            entry,
            mesh_state,
            // A respawn restarts the round clock, and the skew it injects does
            // not shrink with the round, so floor the budget at round 0's.
            budget: TimeoutBudget::new(round_timeout(round).max(ORGANIZE_POSIT_TIMEOUT)),
            permit: None,
            highest_seen_round: 0,
            buffered_messages: HashMap::new(),
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
        self.entry.request()
    }

    /// Abandon the current attempt: advance to the next round (releasing the
    /// held permit and resetting the timeout budget) and restart the state
    /// machine from the Organizing phase. The single back-edge of the sign
    /// state machine.
    pub fn reorganize(&mut self, reason: &str) -> SignPhase {
        // Wedged requests rotate forever; a watermark on the last warned round
        // keeps the warn rate at ~1 per 10 rounds even when StaleRound jumps
        // `bump_round` past whole decades.
        if self.round == 0 || self.round >= self.last_warned_round + 10 {
            tracing::warn!(
                sign_id = ?self.entry.sign_id(),
                round = self.round,
                reason,
                "reorganizing sign request"
            );
            self.last_warned_round = self.round;
        } else {
            tracing::info!(
                sign_id = ?self.entry.sign_id(),
                round = self.round,
                reason,
                "reorganizing sign request"
            );
        }
        self.bump_round();
        SignPhase::Organizing(OrganizingPhase)
    }

    fn bump_round(&mut self) {
        let prev_round = self.round;
        self.set_round(std::cmp::max(
            self.round.saturating_add(1),
            self.highest_seen_round,
        ));
        self.budget.reset(round_timeout(self.round));
        self.permit = None;
        tracing::debug!(prev_round, new_round = self.round, "bumped round");
    }

    /// Record a peer's round learned from a `StaleRound` reject so the next
    /// bump catches up in one step.
    pub fn record_peer_round(&mut self, peer_round: usize) {
        if peer_round > self.highest_seen_round {
            self.highest_seen_round = peer_round;
            self.buffered_messages.clear();
        }
    }

    /// Buffer a posit message for a future round until that round is reached.
    pub fn buffer_future_posit_message(&mut self, msg: SignPositMessage) {
        let SignPositMessage {
            round: peer_round,
            from,
            ..
        } = msg;

        if peer_round < self.highest_seen_round {
            return;
        }
        if peer_round > self.highest_seen_round {
            self.highest_seen_round = peer_round;
            self.buffered_messages.clear();
        }
        // One slot per sender, keep only the latest round.
        self.buffered_messages.insert(from, msg);
    }

    /// Take a buffered message to process, if one exists for the current round.
    pub fn take_buffered_posit_message(&mut self) -> Option<SignPositMessage> {
        if self.highest_seen_round == self.round {
            let key = self.buffered_messages.keys().next().copied()?;
            self.buffered_messages.remove(&key)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backlog::mock::mock_sign_request;
    use crate::backlog::Backlog;

    /// A respawn rebuilds `SignState`; the round must resume from the carried
    /// value, not restart at 0 — peers read a round reset as time travel.
    #[test]
    fn round_survives_a_respawn() {
        let carried = Arc::new(AtomicUsize::new(0));
        let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());
        let backlog = Backlog::new();
        let entry = SignEntry::generating(
            mock_sign_request(SignId::new([0u8; 32]), Chain::Ethereum),
            &backlog,
        );

        let mut state = SignState::new(entry.clone(), mesh_rx.clone(), Arc::clone(&carried));
        state.reorganize("test");
        state.highest_seen_round = 9;
        state.reorganize("test");
        assert_eq!(state.round(), 9);
    }

    #[test]
    fn warn_watermark_survives_round_jumps() {
        let carried = Arc::new(AtomicUsize::new(0));
        let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());
        let backlog = Backlog::new();
        let entry = SignEntry::generating(
            mock_sign_request(SignId::new([0u8; 32]), Chain::Ethereum),
            &backlog,
        );
        let mut state = SignState::new(entry.clone(), mesh_rx.clone(), Arc::clone(&carried));

        state.reorganize("test");
        assert_eq!(state.last_warned_round, 0);

        state.highest_seen_round = 9;
        state.reorganize("test");
        assert_eq!(state.round(), 9);
        assert_eq!(state.last_warned_round, 0);

        state.highest_seen_round = 20;
        state.reorganize("test");
        assert_eq!(state.round(), 20);
        assert_eq!(state.last_warned_round, 0);

        state.reorganize("test");
        assert_eq!(state.last_warned_round, 20);

        // A respawned incarnation resumes at the carried round; its watermark
        // starts fresh, but the high carried round re-arms the next warn.
        drop(state);
        let respawned = SignState::new(entry, mesh_rx, carried);
        assert_eq!(respawned.round(), 21);
        assert_eq!(respawned.last_warned_round, 0);
    }

    /// A respawn rebuilds `SignState` at the carried round, so it has to take
    /// that round's budget -- but never less than round 0's, because the skew a
    /// respawn injects does not shrink with the round.
    #[test]
    fn respawn_budget_is_the_carried_round_floored_at_round_zero() {
        let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());
        let backlog = Backlog::new();
        let entry = SignEntry::generating(
            mock_sign_request(SignId::new([0u8; 32]), Chain::Ethereum),
            &backlog,
        );

        // 0 and 3 sit below the floor and 18 and 40 above it, in both the
        // production and `test-feature` constants.
        for round in [0, 3, 18, 40] {
            let carried = Arc::new(AtomicUsize::new(round));
            let first = SignState::new(entry.clone(), mesh_rx.clone(), Arc::clone(&carried));
            drop(first);
            let respawned = SignState::new(entry.clone(), mesh_rx.clone(), carried);

            assert_eq!(respawned.round(), round);
            let expected = round_timeout(round).max(ORGANIZE_POSIT_TIMEOUT);
            let remaining = respawned.budget.remaining();
            assert!(
                remaining <= expected && expected - remaining < Duration::from_millis(100),
                "round {round}: budget {remaining:?} should be {expected:?}"
            );
        }

        // Non-vacuous only if the set spans both sides of the floor.
        assert_eq!(
            round_timeout(3).max(ORGANIZE_POSIT_TIMEOUT),
            ORGANIZE_POSIT_TIMEOUT
        );
        assert!(round_timeout(18) > ORGANIZE_POSIT_TIMEOUT);
    }
}
