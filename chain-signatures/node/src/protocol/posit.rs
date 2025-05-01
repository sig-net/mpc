use cait_sith::protocol::Participant;
use serde::{Deserialize, Serialize};

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::Hash;

pub type ProposerId = Participant;

pub enum Positor<Store> {
    Proposer(ProposerId, Store),
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
    Propose(Vec<Participant>),
    Accept,
    // TODO: Reject can also have a reason
    Reject,
    /// Aborts the protocol. Only the proposer can send this.
    Abort,
}

pub enum PositInternalAction<Store> {
    StartProtocol(Vec<Participant>, Positor<Store>),
    AbortAllNodes(Vec<Participant>),
    Reply(PositAction),
}

/// A counter for a posit. This is used to track the participants that have
/// accepted the posit alongside storing an intermediary state for the protocol
/// that the proposer needs to keep track of.
pub struct PositCounter<Store> {
    pub participants: HashSet<Participant>,
    accepts: HashSet<Participant>,
    store: Store,
}

/// A collection of posits that are being proposed. This is used to track
/// the posits that are being proposed and the participants that have
/// accepted them.
pub struct Posits<Id, Store> {
    me: Participant,
    posits: HashMap<Id, PositCounter<Store>>,
}

impl<T: Hash + Eq + fmt::Debug, Store> Posits<T, Store> {
    pub fn new(me: Participant) -> Self {
        Self {
            me,
            posits: HashMap::new(),
        }
    }

    pub fn propose(
        &mut self,
        me: Participant,
        id: T,
        store: Store,
        participants: &[Participant],
    ) -> PositAction {
        let mut accepts = HashSet::new();
        accepts.insert(me);
        self.posits.insert(
            id,
            PositCounter {
                participants: participants.iter().copied().collect(),
                accepts,
                store,
            },
        );

        PositAction::Propose(participants.to_vec())
    }

    // TODO: make the resp of this synchronous when each of the protocol managers
    // are their own individual tasks such that they can respond without the need
    // of the main consensus loop.
    /// Act on the posit action. This will map the action received to a corresponding
    /// action to be sent back to the proposer. This will return a series of internal
    /// actions the node should take.
    pub fn act(
        &mut self,
        id: T,
        from: Participant,
        action: &PositAction,
        active: &[Participant],
    ) -> Vec<PositInternalAction<Store>> {
        match action {
            PositAction::Propose(participants) => {
                if self.posits.contains_key(&id) {
                    tracing::warn!(
                        ?id,
                        ?participants,
                        "received a protocol posit for an id that we already proposed"
                    );
                    return vec![PositInternalAction::Reply(PositAction::Reject)];
                }

                // Check that the participants are all active
                for p in participants.iter() {
                    if !active.contains(p) {
                        tracing::warn!(?id, ?active, ?participants, "rejecting protocol posit");
                        return vec![PositInternalAction::Reply(PositAction::Reject)];
                    }
                }

                // Automatically join the protocol if we're accepting here.
                vec![
                    PositInternalAction::StartProtocol(
                        participants.clone(),
                        Positor::Deliberator(from),
                    ),
                    PositInternalAction::Reply(PositAction::Accept),
                ]
            }
            // There's no action to be done here for Abort. Abort should be handled one level above.
            PositAction::Abort => Vec::new(),
            PositAction::Accept => {
                let Some(counter) = self.posits.get_mut(&id) else {
                    tracing::warn!(?id, "received an Accept for a protocol we did NOT propose");
                    return Vec::new();
                };

                counter.accepts.insert(from);
                let should_start = counter.accepts.len() == counter.participants.len();

                let mut actions = Vec::new();
                if should_start {
                    tracing::info!(?id, "received all Accepts, starting protocol");
                    let Some(counter) = self.posits.remove(&id) else {
                        tracing::warn!(
                            ?id,
                            "invalid state, we should have been able to remove this posit"
                        );
                        return Vec::new();
                    };
                    let participants = counter.participants.iter().copied().collect();
                    actions.push(PositInternalAction::StartProtocol(
                        participants,
                        Positor::Proposer(self.me, counter.store),
                    ));
                }
                actions
            }
            PositAction::Reject => {
                // TODO: On the first reject, we should abort the protocol for now.
                // We should be able to narrow down the list of participants eventually
                // such that we can go up until the threshold amount.
                if let Some(counter) = self.posits.remove(&id) {
                    vec![PositInternalAction::AbortAllNodes(
                        counter.participants.iter().copied().collect(),
                    )]
                } else {
                    tracing::warn!(?id, "received a Reject for a protocol we did NOT propose");
                    Vec::new()
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.posits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.posits.is_empty()
    }

    pub fn remove(&mut self, id: &T) -> Option<PositCounter<Store>> {
        self.posits.remove(id)
    }
}
