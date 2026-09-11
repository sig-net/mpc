use super::{PositAction, PositRejectReason};
use cait_sith::protocol::Participant;
use std::collections::{BTreeMap, BTreeSet};

/// The participants observed by a [`PositBarrier`] when it reaches a terminal
/// state. `pending` contains participants that have not sent a usable response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PositBarrierState {
    pub(crate) accepted: BTreeSet<Participant>,
    pub(crate) rejected: BTreeMap<Participant, PositRejectReason>,
    pub(crate) pending: BTreeSet<Participant>,
}

/// Errors returned when constructing a [`PositBarrier`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum PositBarrierError {
    #[error("local participant {participant:?} is not in posit participants")]
    MissingLocalParticipant { participant: Participant },
    #[error(
        "posit threshold {threshold} must be between 1 and {participant_count} unique participants"
    )]
    InvalidThreshold {
        threshold: usize,
        participant_count: usize,
    },
}

/// The terminal state of a [`PositBarrier`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PositBarrierResult {
    Timeout(PositBarrierState),
    TooManyRejects(PositBarrierState),
    EnoughAccepts(PositBarrierState),
}

/// Collects responses to one posit and reports when the posit can be decided.
///
/// Unlike [`tokio::sync::Barrier`], this barrier does not require every
/// participant to respond. The caller owns async I/O and deadlines; this type
/// only tracks votes and computes the current terminal result.
#[derive(Debug)]
pub(crate) struct PositBarrier {
    participants: BTreeSet<Participant>,
    threshold: usize,
    accepted: BTreeSet<Participant>,
    rejected: BTreeMap<Participant, PositRejectReason>,
}

impl PositBarrier {
    /// Create a barrier with the local participant's implicit accept vote.
    ///
    /// Each participant contributes at most one vote: later duplicate or
    /// contradictory responses are ignored.
    ///
    pub(crate) fn new(
        me: Participant,
        participants: &[Participant],
        threshold: usize,
    ) -> Result<Self, PositBarrierError> {
        let participants: BTreeSet<_> = participants.iter().copied().collect();
        if !participants.contains(&me) {
            return Err(PositBarrierError::MissingLocalParticipant { participant: me });
        }
        if threshold == 0 || threshold > participants.len() {
            return Err(PositBarrierError::InvalidThreshold {
                threshold,
                participant_count: participants.len(),
            });
        }

        let accepted = BTreeSet::from([me]);

        Ok(Self {
            participants,
            threshold,
            accepted,
            rejected: BTreeMap::new(),
        })
    }

    /// Record one participant's response, ignoring non-voting actions and
    /// senders outside the participant set.
    ///
    /// Each participant has one vote: the first response wins, and later
    /// duplicate or contradictory responses are accepted as handled but do not
    /// change the recorded result.
    pub(crate) fn process_action(&mut self, from: Participant, action: &PositAction) {
        if !self.participants.contains(&from) {
            return;
        }

        let response_recorded = self.accepted.contains(&from) || self.rejected.contains_key(&from);
        match action {
            PositAction::Accept | PositAction::RejectWithReason(_) if response_recorded => {}
            PositAction::Accept => {
                self.accepted.insert(from);
            }
            PositAction::RejectWithReason(reason) => {
                self.rejected.insert(from, *reason);
            }
            PositAction::Propose | PositAction::Start(_) => {}
        }
    }

    fn enough_accepts(&self) -> bool {
        self.accepted.len() >= self.threshold
    }

    fn enough_rejects(&self) -> bool {
        self.rejected.len() > self.participants.len().saturating_sub(self.threshold)
    }

    fn meets_totality(&self) -> bool {
        self.accepted.len() + self.rejected.len() == self.participants.len()
    }

    pub(crate) fn terminal_result(
        &self,
        accept_deadline_reached: bool,
    ) -> Option<PositBarrierResult> {
        if self.enough_rejects() {
            return Some(PositBarrierResult::TooManyRejects(self.state()));
        }

        if self.enough_accepts() && (accept_deadline_reached || self.meets_totality()) {
            return Some(PositBarrierResult::EnoughAccepts(self.state()));
        }

        None
    }

    pub(crate) fn timeout(&self) -> PositBarrierResult {
        PositBarrierResult::Timeout(self.state())
    }

    fn state(&self) -> PositBarrierState {
        let responded = self
            .accepted
            .iter()
            .copied()
            .chain(self.rejected.keys().copied())
            .collect::<BTreeSet<_>>();
        let pending = self.participants.difference(&responded).copied().collect();

        PositBarrierState {
            accepted: self.accepted.clone(),
            rejected: self.rejected.clone(),
            pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn test_posit_barrier_keeps_first_vote() {
        let me = Participant::from(0);
        let participants = vec![
            me,
            Participant::from(1),
            Participant::from(2),
            Participant::from(3),
        ];
        let mut barrier = PositBarrier::new(me, &participants, 2).expect("valid posit barrier");

        barrier.process_action(
            Participant::from(1),
            &PositAction::RejectWithReason(PositRejectReason::AlreadyGenerating),
        );
        barrier.process_action(
            Participant::from(3),
            &PositAction::RejectWithReason(PositRejectReason::AlreadyGenerating),
        );
        assert_eq!(barrier.state().rejected.len(), 2);

        // A participant has one vote. Contradictory or duplicate responses are
        // ignored once that participant has responded.
        barrier.process_action(Participant::from(3), &PositAction::Accept);
        assert!(!barrier.enough_accepts());
        barrier.process_action(
            Participant::from(1),
            &PositAction::RejectWithReason(PositRejectReason::MissingArtifact),
        );
        assert_eq!(barrier.state().rejected.len(), 2);
        assert_eq!(
            barrier.state().rejected[&Participant::from(1)],
            PositRejectReason::AlreadyGenerating
        );

        barrier.process_action(Participant::from(99), &PositAction::Accept);
        barrier.process_action(Participant::from(1), &PositAction::Propose);
    }

    #[test]
    fn posit_barrier_requires_local_participant() {
        let error = PositBarrier::new(Participant::from(0), &[Participant::from(1)], 1)
            .expect_err("missing local participant should be rejected");
        assert_eq!(
            error,
            PositBarrierError::MissingLocalParticipant {
                participant: Participant::from(0)
            }
        );
    }

    #[test]
    fn posit_barrier_requires_positive_threshold() {
        let error = PositBarrier::new(Participant::from(0), &[Participant::from(0)], 0)
            .expect_err("zero threshold should be rejected");
        assert_eq!(
            error,
            PositBarrierError::InvalidThreshold {
                threshold: 0,
                participant_count: 1
            }
        );
    }

    #[test]
    fn posit_barrier_rejects_threshold_above_participants() {
        let error = PositBarrier::new(Participant::from(0), &[Participant::from(0)], 2)
            .expect_err("threshold above participant count should be rejected");
        assert_eq!(
            error,
            PositBarrierError::InvalidThreshold {
                threshold: 2,
                participant_count: 1
            }
        );
    }

    #[test]
    fn posit_barrier_orders_participants_deterministically() {
        let me = Participant::from(0);
        let participants = [
            Participant::from(3),
            me,
            Participant::from(2),
            Participant::from(1),
            Participant::from(3),
        ];
        let mut barrier = PositBarrier::new(me, &participants, 4).expect("valid posit barrier");
        for participant in [
            Participant::from(3),
            Participant::from(1),
            Participant::from(2),
        ] {
            barrier.process_action(participant, &PositAction::Accept);
        }

        let Some(PositBarrierResult::EnoughAccepts(state)) = barrier.terminal_result(false) else {
            panic!("expected enough accepts");
        };
        assert_eq!(
            state.accepted.into_iter().collect::<Vec<_>>(),
            vec![
                Participant::from(0),
                Participant::from(1),
                Participant::from(2),
                Participant::from(3),
            ]
        );
        assert!(state.rejected.is_empty());
        assert!(state.pending.is_empty());
    }

    #[test]
    fn test_posit_barrier_returns_enough_accepts_with_pending() {
        let me = Participant::from(0);
        let participants = vec![
            me,
            Participant::from(1),
            Participant::from(2),
            Participant::from(3),
        ];
        let mut barrier = PositBarrier::new(me, &participants, 2).expect("valid posit barrier");
        barrier.process_action(Participant::from(1), &PositAction::Accept);

        let Some(PositBarrierResult::EnoughAccepts(state)) = barrier.terminal_result(true) else {
            panic!("expected enough accepts");
        };
        assert_eq!(state.accepted.len(), 2);
        assert!(state.rejected.is_empty());
        assert_eq!(state.pending.len(), 2);
    }

    #[test]
    fn test_posit_barrier_returns_too_many_rejects() {
        let me = Participant::from(0);
        let participants = vec![me, Participant::from(1), Participant::from(2)];
        let mut barrier = PositBarrier::new(me, &participants, 2).expect("valid posit barrier");
        barrier.process_action(
            Participant::from(1),
            &PositAction::RejectWithReason(PositRejectReason::MissingArtifact),
        );
        barrier.process_action(
            Participant::from(2),
            &PositAction::RejectWithReason(PositRejectReason::AlreadyGenerating),
        );

        let Some(PositBarrierResult::TooManyRejects(state)) = barrier.terminal_result(false) else {
            panic!("expected too many rejects");
        };
        assert_eq!(state.accepted, BTreeSet::from([me]));
        assert_eq!(state.rejected.len(), 2);
        assert!(state.pending.is_empty());
    }

    #[test]
    fn test_posit_barrier_returns_timeout() {
        let me = Participant::from(0);
        let participants = vec![me, Participant::from(1)];
        let barrier = PositBarrier::new(me, &participants, 2).expect("valid posit barrier");
        let PositBarrierResult::Timeout(state) = barrier.timeout() else {
            panic!("expected timeout");
        };
        assert_eq!(state.accepted, BTreeSet::from([me]));
        assert!(state.rejected.is_empty());
        assert_eq!(state.pending, BTreeSet::from([Participant::from(1)]));
    }
}
