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
    /// Highest round seen from peers — via future-round messages or the round
    /// carried in `StaleRound` rejects. `bump_round` jumps straight here so a
    /// behind node catches up in one bump.
    pub highest_seen_round: usize,
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

    fn bump_round(&mut self) {
        let prev_round = self.round;
        self.round = std::cmp::max(self.round + 1, self.highest_seen_round);
        self.budget.reset(ORGANIZE_POSIT_TIMEOUT);
        self.permit = None;
        tracing::debug!(prev_round, new_round = self.round, "bumped round");
    }
}
