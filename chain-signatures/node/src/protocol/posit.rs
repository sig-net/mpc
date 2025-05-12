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

    /// The posits that our node has proposed.
    posits: HashMap<Id, PositCounter<S>>,

    /// The posits that are pending in the system. These are posits from other proposers
    /// that we have not yet started the protocol for. Useful for keeping track of who
    /// proposed what, such that other nodes cannot override or start the protocol for
    /// a posit that they did not propose.
    pending_posits: HashMap<Id, ProposerId>,
}

impl<T: Copy + Hash + Eq + fmt::Debug, S> Posits<T, S> {
    pub fn new(me: Participant) -> Self {
        Self {
            me,
            posits: HashMap::new(),
            pending_posits: HashMap::new(),
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
        self.posits.insert(
            id,
            PositCounter {
                participants: participants.iter().copied().collect(),
                accepts,
                rejects: HashSet::new(),
                store,
            },
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
        match action {
            PositAction::Propose => {
                if self.posits.contains_key(&id) {
                    tracing::warn!(?id, ?from, "received INIT on protocol we already proposed");
                    return PositInternalAction::Reply(PositAction::Reject);
                }

                if let Some(proposer) = self.pending_posits.get(&id) {
                    if *proposer != from {
                        tracing::warn!(
                            ?id,
                            ?from,
                            ?proposer,
                            "received INIT on conflicting proposer",
                        );
                        return PositInternalAction::Reply(PositAction::Reject);
                    }
                } else {
                    self.pending_posits.insert(id, from);
                }

                // No further checks necessary, we can just accept the posit.
                PositInternalAction::Reply(PositAction::Accept)
            }
            PositAction::Start(participants) => {
                if self.posits.contains_key(&id) {
                    tracing::warn!(?id, ?from, "received START on protocol we already proposed");
                    return PositInternalAction::Reply(PositAction::Reject);
                }

                if let Some(proposer) = self.pending_posits.remove(&id) {
                    if proposer != from {
                        tracing::warn!(?id, ?from, ?proposer, "received START from wrong proposer");
                        self.pending_posits.insert(id, proposer);
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
                    Entry::Occupied(counter) => counter,
                    Entry::Vacant(_) => {
                        tracing::warn!(
                            ?id,
                            ?from,
                            ?action,
                            "receive ACCEPT/REJECT on protocol we have no info for",
                        );
                        return PositInternalAction::None;
                    }
                };

                let counter = entry.get_mut();
                if action.is_accept() {
                    counter.accepts.insert(from);
                } else {
                    counter.rejects.insert(from);
                }

                let enough_votes = counter.accepts.len() >= threshold
                    && counter.accepts.len() + counter.rejects.len() == counter.participants.len();
                if !enough_votes {
                    return PositInternalAction::None;
                }

                tracing::info!(?id, "received enough ACCEPTs, starting protocol");
                let counter = entry.remove();
                let participants = counter.accepts.iter().copied().collect();
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

    pub fn remove(&mut self, id: &T) -> Option<PositCounter<S>> {
        self.posits.remove(id)
    }
}
