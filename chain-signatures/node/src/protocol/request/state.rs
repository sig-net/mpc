use super::limiter::SignPermit;
use super::organize::OrganizingPhase;
use super::task::SignPhase;
use super::*;
use crate::backlog::{Generating, SignEntry};

pub struct SignState {
    round: usize,
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
        Self {
            round: carried_round.load(Ordering::Relaxed),
            entry,
            mesh_state,
            budget: TimeoutBudget::new(round_timeout(0)),
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
        tracing::warn!(
            sign_id = ?self.entry.sign_id(),
            round = self.round,
            reason,
            "reorganizing sign request"
        );
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

    /// A respawn rebuilds `SignState`; the round must resume from the carried
    /// value, not restart at 0 — peers read a round reset as time travel.
    #[test]
    fn round_survives_a_respawn() {
        let carried = Arc::new(AtomicUsize::new(0));
        let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());
        let backlog = Backlog::new();
        let entry = SignEntry::generating(Arc::new(request()), &backlog);

        let mut state = SignState::new(entry.clone(), mesh_rx.clone(), Arc::clone(&carried));
        state.reorganize("test");
        state.highest_seen_round = 9;
        state.reorganize("test");
        assert_eq!(state.round(), 9);

        // The task is aborted and a new incarnation takes over.
        drop(state);
        let respawned = SignState::new(entry, mesh_rx, carried);
        assert_eq!(respawned.round(), 9);
    }
}
