use super::limiter::SignPermit;
use super::organize::OrganizingPhase;
use super::task::SignPhase;
use super::*;

pub struct SignState {
    pub round: usize,
    pub request: IndexedSignRequest,
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
    pub buffered_messages: HashMap<Participant, SignTaskMessage>,
    /// When Some, another group is already generating this signature.
    /// The timestamp is when proposing can be resumed.
    pub pause_proposing_until: Option<std::time::Instant>,
}

impl SignState {
    pub fn new(request: IndexedSignRequest, mesh_state: watch::Receiver<MeshState>) -> Self {
        Self {
            round: 0,
            request,
            mesh_state,
            budget: TimeoutBudget::new(ORGANIZE_POSIT_TIMEOUT),
            permit: None,
            highest_seen_round: 0,
            buffered_messages: HashMap::new(),
            pause_proposing_until: None,
        }
    }

    pub fn request(&self) -> &IndexedSignRequest {
        &self.request
    }

    /// Abandon the current attempt: advance to the next round (releasing the
    /// held permit and resetting the timeout budget) and restart the state
    /// machine from the Organizing phase. The single back-edge of the sign
    /// state machine.
    pub fn reorganize(&mut self) -> SignPhase {
        self.bump_round();
        SignPhase::Organizing(OrganizingPhase)
    }

    fn bump_round(&mut self) {
        let prev_round = self.round;
        self.round = std::cmp::max(self.round + 1, self.highest_seen_round);
        self.budget.reset(ORGANIZE_POSIT_TIMEOUT);
        self.permit = None;
        tracing::debug!(prev_round, new_round = self.round, "bumped round");
    }

    /// Buffer a posit message for a future round until that round is reached.
    pub fn buffer_future_posit_message(&mut self, msg: SignTaskMessage) {
        let SignTaskMessage::PositMessage {
            round: peer_round,
            from,
            ..
        } = msg;

        if peer_round < self.highest_seen_round
            || peer_round > self.round.saturating_add(MAX_ROUND_LOOKAHEAD)
        {
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
    pub fn take_buffered_posit_message(&mut self) -> Option<SignTaskMessage> {
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
    use mpc_primitives::{Chain, SignArgs, SignId, SignKind};

    fn state() -> SignState {
        let request = IndexedSignRequest::new(
            SignId {
                request_id: [0u8; 32],
            },
            SignArgs {
                entropy: [0u8; 32],
                epsilon: Default::default(),
                payload: Default::default(),
                path: String::new(),
                key_version: 0,
            },
            Chain::Ethereum,
            0,
            SignKind::Sign,
        );
        let (_tx, rx) = watch::channel(MeshState::default());
        SignState::new(request, rx)
    }

    fn posit(round: usize) -> SignTaskMessage {
        SignTaskMessage::PositMessage {
            presignature_id: 0,
            round,
            from: Participant::from(0),
            action: PositAction::Propose,
        }
    }

    #[test]
    fn peer_round_within_lookahead_is_adopted() {
        let mut state = state();
        state.buffer_future_posit_message(posit(MAX_ROUND_LOOKAHEAD));

        assert_eq!(state.highest_seen_round, MAX_ROUND_LOOKAHEAD);
        assert_eq!(state.buffered_messages.len(), 1);
    }

    #[test]
    fn peer_round_beyond_lookahead_is_ignored() {
        let mut state = state();
        state.buffer_future_posit_message(posit(usize::MAX));

        assert_eq!(state.highest_seen_round, 0);
        assert!(state.buffered_messages.is_empty());
    }

    #[test]
    fn peer_cannot_stall_rotation_with_an_implausible_round() {
        let mut state = state();
        for _ in 0..8 {
            state.buffer_future_posit_message(posit(usize::MAX));
            let prev = state.round;
            state.reorganize();
            assert!(
                state.round > prev,
                "round must keep advancing so the proposer keeps rotating"
            );
        }
    }
}
