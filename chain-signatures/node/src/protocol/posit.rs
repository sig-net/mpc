use cait_sith::protocol::Participant;
use lru::LruCache;
use serde::{Deserialize, Serialize};

use std::collections::HashSet;
use std::fmt;
use std::hash::Hash;
use std::num::NonZeroUsize;

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

    // TODO: probably should be a LruCache to expire items
    /// The posits that our node has proposed.
    posits: LruCache<Id, Positor<PositCounter<S>>>,
}

impl<T: Copy + Hash + Eq + fmt::Debug, S> Posits<T, S> {
    pub fn new(me: Participant) -> Self {
        Self {
            me,
            // 1024 is a good default size for the cache since we don't expect to be have more
            // than 1024 concurring posits at any time. This should however be configurable in
            // the future.
            posits: LruCache::new(NonZeroUsize::new(1024).unwrap()),
        }
    }

    pub fn propose(
        &mut self,
        me: Participant,
        id: T,
        store: S,
        participants: &[Participant],
    ) -> PositAction {
        let mut accepts = HashSet::new();
        accepts.insert(me);
        self.posits.put(
            id,
            Positor::Proposer(
                me,
                PositCounter {
                    participants: participants.iter().copied().collect(),
                    accepts,
                    rejects: HashSet::new(),
                    store,
                },
            ),
        );

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
                    self.posits.put(id, Positor::Deliberator(from));
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

                if let Some(positor) = self.posits.pop(&id) {
                    let proposer = positor.id();
                    if positor.is_proposer() {
                        tracing::warn!(
                            ?id,
                            ?from,
                            "received START on protocol we already proposed"
                        );
                        self.posits.put(id, positor);
                        return PositInternalAction::Reply(PositAction::Reject);
                    } else if proposer != from {
                        tracing::warn!(
                            ?id,
                            ?from,
                            ?proposer,
                            "received START on conflicting proposer"
                        );
                        self.posits.put(id, positor);
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
                let Some(positor) = self.posits.get_mut(&id) else {
                    tracing::warn!(
                        ?id,
                        ?from,
                        ?action,
                        "received ACCEPT/REJECT on protocol we have no info for",
                    );
                    return PositInternalAction::None;
                };

                let Positor::Proposer(_, counter) = positor else {
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
                    self.posits.pop(&id);
                    return PositInternalAction::None;
                }

                // TODO: have a timeout on waiting for votes. The moment we have enough threshold accepts,
                // we can start the protocol after a timeout, such that we don't wait for slow responders.
                let enough_votes = counter.accepts.len() >= threshold
                    && counter.accepts.len() + counter.rejects.len() == counter.participants.len();
                if !enough_votes {
                    return PositInternalAction::None;
                }

                tracing::info!(?id, "received enough ACCEPTs, starting protocol");
                let Some(Positor::Proposer(_, counter)) = self.posits.pop(&id) else {
                    unreachable!("removing posit should have already been checked");
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
