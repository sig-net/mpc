use cait_sith::protocol::Participant;
use serde::{Deserialize, Serialize};

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::Hash;

pub type ProposerId = Participant;

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
#[derive(Debug, PartialEq, Serialize, Deserialize)]
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

pub enum PositInternalAction<S> {
    StartProtocol(Vec<Participant>, Positor<S>),
    Reply(PositAction),
    None,
}

/// A counter for a posit. This is used to track the participants that have
/// accepted the posit alongside storing an intermediary state for the protocol
/// that the proposer needs to keep track of.
pub struct PositCounter<S> {
    pub participants: HashSet<Participant>,
    accepts: HashSet<Participant>,
    rejects: HashSet<Participant>,
    store: S,
}

/// A collection of posits that are being proposed. This is used to track
/// the posits that are being proposed and the participants that have
/// accepted them.
pub struct Posits<Id, S> {
    me: Participant,

    /// The posits that either our node proposed or that we are a part of.
    posits: HashMap<Id, Positor<PositCounter<S>>>,
}

impl<T: Copy + Hash + Eq + fmt::Debug, S> Posits<T, S> {
    pub fn new(me: Participant) -> Self {
        Self {
            me,
            posits: HashMap::new(),
        }
    }

    pub fn propose(&mut self, id: T, store: S, participants: &[Participant]) -> PositAction {
        let entry = match self.posits.entry(id) {
            Entry::Vacant(entry) => entry,
            Entry::Occupied(_) => {
                tracing::warn!(?id, "PROPOSE protocol already in progress");
                return PositAction::Reject;
            }
        };

        let mut accepts = HashSet::new();
        accepts.insert(self.me);
        entry.insert(Positor::Proposer(
            self.me,
            PositCounter {
                participants: participants.iter().copied().collect(),
                accepts,
                rejects: HashSet::new(),
                store,
            },
        ));

        PositAction::Propose
    }

    /// Act on the posit action. This will map the action received to a corresponding
    /// action to be sent back to the proposer. This will return a series of internal
    /// actions the node should take.
    pub fn act(
        &mut self,
        id: T,
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

                if let Some(positor) = self.posits.get(&id) {
                    let proposer = positor.id();
                    if positor.is_proposer() {
                        tracing::warn!(?id, ?from, "received INIT on protocol we already proposed");
                        return PositInternalAction::Reply(PositAction::Reject);
                    } else if proposer != from {
                        tracing::warn!(
                            ?id,
                            ?from,
                            ?proposer,
                            "received INIT on conflicting proposer"
                        );
                        return PositInternalAction::Reply(PositAction::Reject);
                    }
                } else {
                    self.posits.insert(id, Positor::Deliberator(from));
                }

                // No further checks necessary, we can just accept the posit.
                PositInternalAction::Reply(PositAction::Accept)
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
                        "received START on protocol we are not a part of"
                    );
                    return PositInternalAction::Reply(PositAction::Reject);
                }

                if let Some(positor) = self.posits.remove(&id) {
                    let proposer = positor.id();
                    if positor.is_proposer() {
                        tracing::warn!(
                            ?id,
                            ?from,
                            "received START on protocol we already proposed"
                        );
                        self.posits.insert(id, positor);
                        return PositInternalAction::Reply(PositAction::Reject);
                    } else if proposer != from {
                        tracing::warn!(
                            ?id,
                            ?from,
                            ?proposer,
                            "received START on conflicting proposer"
                        );
                        self.posits.insert(id, positor);
                        return PositInternalAction::Reply(PositAction::Reject);
                    }
                } else {
                    tracing::warn!(?id, ?from, "received START on protocol we have no info for");
                    return PositInternalAction::Reply(PositAction::Reject);
                }

                PositInternalAction::StartProtocol(
                    participants.to_vec(),
                    Positor::Deliberator(from),
                )
            }
            PositAction::Accept | PositAction::Reject => {
                let mut entry = match self.posits.entry(id) {
                    Entry::Occupied(entry) => entry,
                    Entry::Vacant(_) => {
                        tracing::warn!(
                            ?id,
                            ?from,
                            ?action,
                            "received ACCEPT/REJECT on protocol we have no info for",
                        );
                        return PositInternalAction::None;
                    }
                };

                let Positor::Proposer(_, counter) = entry.get_mut() else {
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
                    counter.accepts.insert(from);
                } else {
                    counter.rejects.insert(from);
                }

                // TODO: broadcast aborting the protocol if we have enough rejections
                let enough_rejections =
                    counter.rejects.len() > counter.participants.len() - threshold;
                if enough_rejections {
                    tracing::info!(?id, rejects = ?counter.rejects, "received enough REJECTs, aborting protocol");
                    entry.remove();
                    return PositInternalAction::None;
                }

                // TODO: have a timeout on waiting for votes. The moment we have enough threshold accepts,
                // we can start the protocol after a timeout, such that we don't wait for slow responders.
                // This will be our way to cleanup the posits that are nowhere to be found.
                let enough_votes = counter.accepts.len() >= threshold
                    && counter.accepts.len() + counter.rejects.len() == counter.participants.len();
                if !enough_votes {
                    return PositInternalAction::None;
                }

                tracing::info!(?id, "received enough ACCEPTs, starting protocol");
                let Positor::Proposer(_, counter) = entry.remove() else {
                    unreachable!("we already checked that we are the proposer");
                };
                let participants = counter.accepts.into_iter().collect();
                PositInternalAction::StartProtocol(
                    participants,
                    Positor::Proposer(self.me, counter.store),
                )
            }
        }
    }

    pub fn len(&self) -> usize {
        self.posits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.posits.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cait_sith::protocol::Participant;

    type Id = u64;

    #[test]
    fn test_posits_non_proposer() {
        let threshold = 2;
        let participants = vec![
            Participant::from(0),
            Participant::from(1),
            Participant::from(2),
        ];
        let mut posits0 = Posits::<Id, ()>::new(Participant::from(0));
        let mut posits1 = Posits::<Id, ()>::new(Participant::from(1));
        let mut posits3 = Posits::<Id, ()>::new(Participant::from(3));

        // Node0 propose a new posit 101
        let id = 101;
        let correct_proposer = Participant::from(0);
        let incorrect_proposer = Participant::from(1);
        let action = posits0.propose(id, (), &participants);
        assert!(matches!(action, PositAction::Propose));

        // propose: act on posit with correct proposer should be accepted
        let action = posits1.act(id, correct_proposer, threshold, &PositAction::Propose);
        assert!(matches!(
            action,
            PositInternalAction::Reply(PositAction::Accept)
        ));
        // propose(conflict): a second node claims this posit, but only the first is accepted. reject this one
        let action = posits1.act(id, incorrect_proposer, threshold, &PositAction::Propose);
        assert!(matches!(
            action,
            PositInternalAction::Reply(PositAction::Reject)
        ));
        // propose: act on posit again should be idempotent
        let action = posits1.act(id, correct_proposer, threshold, &PositAction::Propose);
        assert!(matches!(
            action,
            PositInternalAction::Reply(PositAction::Accept)
        ));

        // propose(conflict): proposing a posit that is already in progress should be rejected
        let action = posits1.propose(id, (), &participants);
        assert!(matches!(action, PositAction::Reject));

        // start: incorrect proposer should reject
        let start = PositAction::Start(participants);
        let action = posits1.act(id, incorrect_proposer, threshold, &start);
        assert!(matches!(
            action,
            PositInternalAction::Reply(PositAction::Reject)
        ));
        // start: correct proposer should start the protocol
        let action = posits1.act(id, correct_proposer, threshold, &start);
        assert!(matches!(
            action,
            PositInternalAction::StartProtocol(_, Positor::Deliberator(_))
        ));

        // start: the node is not a part of the participants so reject
        let proposer = Participant::from(0);
        let action = posits3.act(id, proposer, threshold, &start);
        assert!(matches!(
            action,
            PositInternalAction::Reply(PositAction::Reject)
        ));
    }

    #[test]
    fn test_posits_proposer() {
        let threshold = 2;
        let participants = vec![
            Participant::from(0),
            Participant::from(1),
            Participant::from(2),
        ];
        let mut posits0 = Posits::<Id, ()>::new(Participant::from(0));

        let id = 101;

        // start: on all accept, start the protocol
        posits0.propose(id, (), &participants);
        let action = posits0.act(id, Participant::from(1), threshold, &PositAction::Accept);
        assert!(matches!(action, PositInternalAction::None));
        // receiving an accept from the same participant will do nothing
        let action = posits0.act(id, Participant::from(1), threshold, &PositAction::Accept);
        assert!(matches!(action, PositInternalAction::None));
        // everyone has voted, so we can start the protocol
        let action = posits0.act(id, Participant::from(2), threshold, &PositAction::Accept);
        assert!(matches!(action, PositInternalAction::StartProtocol(_, _)));
        // receiving an accept after the protocol has started will do nothing
        let action = posits0.act(id, Participant::from(1), threshold, &PositAction::Accept);
        assert!(matches!(action, PositInternalAction::None));

        // start: on threshold amount accept, start the protocol
        posits0.propose(id, (), &participants);
        let action = posits0.act(id, Participant::from(1), threshold, &PositAction::Accept);
        assert!(matches!(action, PositInternalAction::None));
        let action = posits0.act(id, Participant::from(2), threshold, &PositAction::Reject);
        assert!(matches!(action, PositInternalAction::StartProtocol(_, _)));

        // start: on threshold amount reject, abort the protocol
        posits0.propose(id, (), &participants);
        let action = posits0.act(id, Participant::from(1), threshold, &PositAction::Reject);
        assert!(matches!(action, PositInternalAction::None));
        let action = posits0.act(id, Participant::from(2), threshold, &PositAction::Reject);
        assert!(matches!(action, PositInternalAction::None));
    }
}
