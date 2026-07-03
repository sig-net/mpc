use super::limiter::SignPermit;
use super::*;

pub struct SignState {
    pub round: usize,
    pub indexed: IndexedSignRequest,
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
    pub pause_proposing: Option<std::time::Instant>,
}

impl SignState {
    pub fn new(indexed: IndexedSignRequest, mesh_state: watch::Receiver<MeshState>) -> Self {
        Self {
            round: 0,
            indexed,
            mesh_state,
            budget: TimeoutBudget::new(ORGANIZE_POSIT_TIMEOUT),
            permit: None,
            highest_seen_round: 0,
            buffered_messages: HashMap::new(),
            pause_proposing: None,
        }
    }

    pub fn indexed(&self) -> &IndexedSignRequest {
        &self.indexed
    }

    pub fn bump_round(&mut self) {
        let prev_round = self.round;
        self.round = std::cmp::max(self.round + 1, self.highest_seen_round);
        // Reset the budget for the new attempt
        self.budget.reset(ORGANIZE_POSIT_TIMEOUT);
        self.permit = None;
        tracing::debug!(prev_round, new_round = self.round, "bumped round");
    }

    /// When receiving posit message for future rounds, store them away until
    /// that round is reached.
    pub fn store_future_posit_message(&mut self, msg: SignTaskMessage) {
        let SignTaskMessage::PositMessage {
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

    /// Remove a buffered message for processing, if there is one for the
    /// current round.
    pub fn take_buffered_posit_message(&mut self) -> Option<SignTaskMessage> {
        if self.highest_seen_round == self.round {
            let key = self.buffered_messages.keys().next().copied()?;
            self.buffered_messages.remove(&key)
        } else {
            None
        }
    }
}
