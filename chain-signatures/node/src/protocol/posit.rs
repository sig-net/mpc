use cait_sith::protocol::Participant;
use serde::{Deserialize, Serialize};

use std::collections::HashSet;
use std::fmt;
use std::time::{Duration, Instant};

pub type ProposerId = Participant;

#[derive(Debug)]
pub enum Positor<T> {
    Proposer(ProposerId, T),
    Deliberator(ProposerId),
}

impl<T> Positor<T> {
    pub fn is_proposer(&self) -> bool {
        matches!(self, Positor::Proposer(_, _))
    }

    pub fn id(&self) -> ProposerId {
        match self {
            Positor::Proposer(id, _) => *id,
            Positor::Deliberator(id) => *id,
        }
    }
}

/// All actions that can be taken when a new posit is introduced for a protocol.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum PositAction {
    Propose,
    Start(Vec<Participant>),
    Accept,
    // TODO: Reject can also have a reason
    Reject,
}

impl PositAction {
    pub fn is_accept(&self) -> bool {
        matches!(self, PositAction::Accept)
    }
}

#[derive(Debug)]
pub enum PositInternalAction<S> {
    StartProtocol(Vec<Participant>, Positor<S>),
    Reply(PositAction),
    Abort,
    None,
}

/// A counter for a posit. This is used to track the participants that have
/// accepted the posit alongside storing an intermediary state for the protocol
/// that the proposer needs to keep track of.
#[derive(Debug)]
pub struct PositCounter<S> {
    pub participants: HashSet<Participant>,
    accepts: HashSet<Participant>,
    rejects: HashSet<Participant>,
    store: S,
}

impl<T> PositCounter<T> {
    pub fn enough_accepts(&self, threshold: usize) -> bool {
        self.accepts.len() >= threshold
    }

    pub fn enough_rejects(&self, threshold: usize) -> bool {
        self.rejects.len() > self.participants.len() - threshold
    }

    pub fn meets_totality(&self) -> bool {
        self.accepts.len() + self.rejects.len() == self.participants.len()
    }
}

#[derive(Debug)]
struct ActivePosit<Id, S> {
    id: Id,
    positor: Positor<PositCounter<S>>,
    timestamp: Instant,
}

/// Tracks a single posit that is being deliberated for a protocol.
pub struct Posit<Id, S> {
    me: Participant,
    active: Option<ActivePosit<Id, S>>,
}

impl<Id: Copy + Eq + fmt::Debug, S> Posit<Id, S> {
    pub fn new(me: Participant) -> Self {
        Self { me, active: None }
    }

    pub fn propose(&mut self, id: Id, store: S, participants: &[Participant]) -> PositAction {
        if let Some(active) = &self.active {
            tracing::warn!(
                ?id,
                ?active.id,
                is_proposer = active.positor.is_proposer(),
                "PROPOSE protocol already in progress",
            );
            return PositAction::Reject;
        }

        let mut accepts = HashSet::new();
        accepts.insert(self.me);
        let positor = Positor::Proposer(
            self.me,
            PositCounter {
                participants: participants.iter().copied().collect(),
                accepts,
                rejects: HashSet::new(),
                store,
            },
        );
        self.active = Some(ActivePosit {
            id,
            positor,
            timestamp: Instant::now(),
        });

        PositAction::Propose
    }

    /// Act on the posit action. This maps the action received to the internal action the node
    /// should take while maintaining the posit state.
    pub fn act(
        &mut self,
        id: Id,
        from: Participant,
        threshold: usize,
        action: &PositAction,
    ) -> PositInternalAction<S> {
        // Before getting to this point, we should have already checked storage for the related protocols.
        // All information passed to this function should be valid. The only information that still needs
        // to be checked is the information about the posit itself and whether we're in the right state for
        // it to proceed and be acted upon.

        match action {
            PositAction::Propose => {
                // Checks:
                // 1. We are not the proposer.
                // 2. Somebody else hasn't also proposed the protocol.
                let Some(active) = &self.active else {
                    // We have no information about this posit, so accept it and create the state.
                    self.active = Some(ActivePosit {
                        id,
                        positor: Positor::Deliberator(from),
                        timestamp: Instant::now(),
                    });
                    return PositInternalAction::Reply(PositAction::Accept);
                };

                if active.id != id {
                    tracing::warn!(
                        ?id,
                        existing = ?active.id,
                        ?from,
                        "received INIT on unexpected protocol",
                    );
                    return PositInternalAction::Reply(PositAction::Reject);
                }
                let proposer = active.positor.id();
                if active.positor.is_proposer() {
                    tracing::warn!(?id, ?from, "received INIT on protocol we already proposed");
                    PositInternalAction::Reply(PositAction::Reject)
                } else if proposer != from {
                    tracing::warn!(
                        ?id,
                        ?from,
                        ?proposer,
                        "received INIT on conflicting proposer",
                    );
                    PositInternalAction::Reply(PositAction::Reject)
                } else {
                    PositInternalAction::Reply(PositAction::Accept)
                }
            }
            PositAction::Start(participants) => {
                // Checks:
                // 1. We are a participant in the protocol.
                // 2. We are not the proposer.
                // 3. The proposer is the one that started the protocol.

                if !participants.contains(&self.me) {
                    tracing::warn!(
                        ?id,
                        ?from,
                        "received START on protocol we are not a part of",
                    );
                    return PositInternalAction::Reply(PositAction::Reject);
                }

                let Some(active) = self.active.take() else {
                    tracing::warn!(?id, ?from, "received START on protocol we have no info for");
                    return PositInternalAction::Reply(PositAction::Reject);
                };

                if active.id != id {
                    tracing::warn!(?id, ?active.id, ?from, "received START on mismatch posit id");
                    self.active = Some(active);
                    return PositInternalAction::Reply(PositAction::Reject);
                }

                let proposer = active.positor.id();
                if active.positor.is_proposer() {
                    tracing::warn!(?id, ?from, "received START on protocol we already proposed");
                    self.active = Some(active);
                    return PositInternalAction::Reply(PositAction::Reject);
                }

                if proposer != from {
                    tracing::warn!(
                        ?id,
                        ?from,
                        ?proposer,
                        "received START on conflicting proposer",
                    );
                    self.active = Some(active);
                    return PositInternalAction::Reply(PositAction::Reject);
                }

                PositInternalAction::StartProtocol(
                    participants.to_vec(),
                    Positor::Deliberator(from),
                )
            }
            PositAction::Accept | PositAction::Reject => {
                let Some(active) = self.active.as_mut() else {
                    tracing::warn!(
                        ?id,
                        ?from,
                        ?action,
                        "received ACCEPT/REJECT on protocol we have no info for",
                    );
                    return PositInternalAction::None;
                };

                if active.id != id {
                    tracing::warn!(
                        ?id,
                        ?active.id,
                        ?from,
                        ?action,
                        "received ACCEPT/REJECT on mistmatch posit id",
                    );
                    return PositInternalAction::None;
                }

                let Positor::Proposer(_, counter) = &mut active.positor else {
                    tracing::warn!(
                        ?id,
                        ?from,
                        ?action,
                        "received ACCEPT/REJECT on protocol we are not proposer for",
                    );
                    return PositInternalAction::None;
                };

                if !counter.participants.contains(&from) {
                    tracing::warn!(
                        ?id,
                        ?from,
                        ?action,
                        "received ACCEPT/REJECT from participant not in protocol",
                    );
                    return PositInternalAction::None;
                }

                if action.is_accept() {
                    if counter.accepts.insert(from) {
                        tracing::info!(?id, ?from, "posit ACCEPT processed");
                    } else {
                        tracing::warn!(?id, ?from, "posit ACCEPT duplicate ignored");
                    }
                } else if counter.rejects.insert(from) {
                    tracing::info!(?id, ?from, "posit REJECT processed");
                } else {
                    tracing::warn!(?id, ?from, "posit REJECT duplicate ignored");
                }

                if counter.enough_rejects(threshold) {
                    tracing::info!(
                        ?id,
                        accepted = ?counter.accepts,
                        rejected = ?counter.rejects,
                        "received enough REJECTs, aborting protocol",
                    );
                    return PositInternalAction::Abort;
                }

                if !counter.meets_totality() {
                    return PositInternalAction::None;
                }

                tracing::info!(
                    ?id,
                    accepted = ?counter.accepts,
                    rejected = ?counter.rejects,
                    "received enough ACCEPTs, starting protocol"
                );

                let Positor::Proposer(_, counter) = self.active.take().unwrap().positor else {
                    unreachable!("we already checked that we are the proposer");
                };

                let participants = counter.accepts.iter().copied().collect();
                PositInternalAction::StartProtocol(
                    participants,
                    Positor::Proposer(self.me, counter.store),
                )
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.active.is_none()
    }

    /// Expire and start the protocol if enough accepts have been gathered. Returns the action to
    /// take when the current posit times out.
    pub fn expire_and_start(
        &mut self,
        threshold: usize,
        timeout: Duration,
    ) -> Option<(Id, PositInternalAction<S>)> {
        let Some(active) = &self.active else {
            return None;
        };

        if active.timestamp.elapsed() <= timeout {
            return None;
        }

        let ActivePosit { id, positor, .. } = self
            .active
            .take()
            .expect("active posit should still be present");

        match positor {
            Positor::Deliberator(_) => {
                tracing::info!(?id, "expiring deliberator posit");
                None
            }
            Positor::Proposer(_, counter) => {
                if counter.enough_accepts(threshold) {
                    tracing::info!(
                        ?id,
                        accepted = ?counter.accepts,
                        rejected = ?counter.rejects,
                        "expiring posit with enough ACCEPTs",
                    );
                    Some((
                        id,
                        PositInternalAction::StartProtocol(
                            counter.accepts.into_iter().collect(),
                            Positor::Proposer(self.me, counter.store),
                        ),
                    ))
                } else {
                    tracing::info!(
                        ?id,
                        accepted = ?counter.accepts,
                        rejected = ?counter.rejects,
                        "expiring posit without enough ACCEPTs",
                    );
                    Some((id, PositInternalAction::Abort))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cait_sith::protocol::Participant;

    type Id = u64;

    #[test]
    fn test_posit_non_proposer() {
        let threshold = 2;
        let participants = vec![
            Participant::from(0),
            Participant::from(1),
            Participant::from(2),
        ];
        let mut posit0 = Posit::<Id, ()>::new(Participant::from(0));
        let mut posit1 = Posit::<Id, ()>::new(Participant::from(1));
        let mut posit3 = Posit::<Id, ()>::new(Participant::from(3));

        // Node0 propose a new posit 101
        let id = 101;
        let correct_proposer = Participant::from(0);
        let incorrect_proposer = Participant::from(1);
        let action = posit0.propose(id, (), &participants);
        assert!(matches!(action, PositAction::Propose));

        // propose: act on posit with correct proposer should be accepted
        let action = posit1.act(id, correct_proposer, threshold, &PositAction::Propose);
        assert!(matches!(
            action,
            PositInternalAction::Reply(PositAction::Accept)
        ));
        // propose(conflict): a second node claims this posit, but only the first is accepted. reject this one
        let action = posit1.act(id, incorrect_proposer, threshold, &PositAction::Propose);
        assert!(matches!(
            action,
            PositInternalAction::Reply(PositAction::Reject)
        ));
        // propose: act on posit again should be idempotent
        let action = posit1.act(id, correct_proposer, threshold, &PositAction::Propose);
        assert!(matches!(
            action,
            PositInternalAction::Reply(PositAction::Accept)
        ));

        // propose(conflict): proposing a posit that is already in progress should be rejected
        let action = posit1.propose(id, (), &participants);
        assert!(matches!(action, PositAction::Reject));

        // start: incorrect proposer should reject
        let start = PositAction::Start(participants);
        let action = posit1.act(id, incorrect_proposer, threshold, &start);
        assert!(matches!(
            action,
            PositInternalAction::Reply(PositAction::Reject)
        ));
        // start: correct proposer should start the protocol
        let action = posit1.act(id, correct_proposer, threshold, &start);
        assert!(matches!(
            action,
            PositInternalAction::StartProtocol(_, Positor::Deliberator(_))
        ));

        // start: the node is not a part of the participants so reject
        let proposer = Participant::from(0);
        let action = posit3.act(id, proposer, threshold, &start);
        assert!(matches!(
            action,
            PositInternalAction::Reply(PositAction::Reject)
        ));
    }

    #[test]
    fn test_posit_proposer() {
        let threshold = 2;
        let participants = vec![
            Participant::from(0),
            Participant::from(1),
            Participant::from(2),
        ];
        let mut posit0 = Posit::<Id, ()>::new(Participant::from(0));

        let id = 101;

        // start: on all accept, start the protocol
        posit0.propose(id, (), &participants);
        let action = posit0.act(id, Participant::from(1), threshold, &PositAction::Accept);
        assert!(matches!(action, PositInternalAction::None));
        // receiving an accept from the same participant will do nothing
        let action = posit0.act(id, Participant::from(1), threshold, &PositAction::Accept);
        assert!(matches!(action, PositInternalAction::None));
        // everyone has voted, so we can start the protocol
        let action = posit0.act(id, Participant::from(2), threshold, &PositAction::Accept);
        assert!(matches!(action, PositInternalAction::StartProtocol(_, _)));
        // receiving an accept after the protocol has started will do nothing
        let action = posit0.act(id, Participant::from(1), threshold, &PositAction::Accept);
        assert!(matches!(action, PositInternalAction::None));

        // start: on threshold amount accept, start the protocol
        posit0.propose(id, (), &participants);
        let action = posit0.act(id, Participant::from(1), threshold, &PositAction::Accept);
        assert!(matches!(action, PositInternalAction::None));
        let action = posit0.act(id, Participant::from(2), threshold, &PositAction::Reject);
        assert!(matches!(action, PositInternalAction::StartProtocol(_, _)));

        // start: on threshold amount reject, abort the protocol
        posit0.propose(id, (), &participants);
        let action = posit0.act(id, Participant::from(1), threshold, &PositAction::Reject);
        assert!(matches!(action, PositInternalAction::None));
        let action = posit0.act(id, Participant::from(2), threshold, &PositAction::Reject);
        assert!(matches!(action, PositInternalAction::Abort));
    }

    #[test]
    fn test_posit_expiration() {
        let threshold = 2;
        let participants = vec![
            Participant::from(0),
            Participant::from(1),
            Participant::from(2),
            Participant::from(3),
        ];
        let mut posit0 = Posit::<Id, ()>::new(Participant::from(0));

        // have proposer accept and participants 1 and 2 accept. participant 3 will neither accept or reject.
        let id101 = 101;
        posit0.propose(id101, (), &participants);
        for from in &participants[1..=2] {
            posit0.act(id101, *from, threshold, &PositAction::Accept);
        }

        std::thread::sleep(Duration::from_millis(1100));
        let action = posit0.expire_and_start(threshold, Duration::from_secs(1));
        match action {
            Some((id, PositInternalAction::StartProtocol(_, Positor::Proposer(_, _)))) => {
                assert_eq!(id, id101)
            }
            other => panic!("unexpected expiration result: {:?}", other),
        }
        assert!(posit0.is_empty());

        // have proposer accept, and everyone else not reply at all.
        let id202 = 202;
        posit0.propose(id202, (), &participants);
        std::thread::sleep(Duration::from_millis(1100));
        let action = posit0.expire_and_start(threshold, Duration::from_secs(1));
        match action {
            Some((id, PositInternalAction::Abort)) => assert_eq!(id, id202),
            other => panic!("unexpected expiration result: {:?}", other),
        }
        assert!(posit0.is_empty());

        // the posit for id101 should have expired after not receiving a start action on a deliberator.
        let mut posit1 = Posit::<Id, ()>::new(Participant::from(1));
        posit1.act(
            id101,
            Participant::from(0),
            threshold,
            &PositAction::Propose,
        );
        std::thread::sleep(Duration::from_millis(1100));
        let action = posit1.expire_and_start(threshold, Duration::from_secs(1));
        assert!(action.is_none());
        assert!(posit1.is_empty());
    }
}
