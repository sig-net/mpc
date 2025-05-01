use cait_sith::protocol::Participant;
use serde::{Deserialize, Serialize};

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::Hash;

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
#[derive(Default)]
pub struct Posits<Id, Store> {
    posits: HashMap<Id, PositCounter<Store>>,
}

impl<T: Hash + Eq + fmt::Debug, Store> Posits<T, Store> {
    pub fn new() -> Self {
        Self {
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

    // TODO: make the resp of this synchronous when each of the protocol
    // managers are their own individual tasks such that they can respond
    // without the need of the main consensus loop.
    /// Act on the posit action. This will map the action received to a corresponding
    /// action to be sent back to the proposer. This will return
    ///     (ShouldStartProtocol, TemporaryStorageItem, ReplyAction).
    pub fn act(
        &mut self,
        id: T,
        from: Participant,
        action: &PositAction,
        active: &[Participant],
    ) -> (Option<Vec<Participant>>, Option<Store>, Option<PositAction>) {
        match action {
            PositAction::Accept => {
                let Some(counter) = self.posits.get_mut(&id) else {
                    tracing::warn!(?id, "received an Accept for a protocol we did NOT propose");
                    return (None, None, None);
                };

                counter.accepts.insert(from);
                let should_start = counter.accepts.len() == counter.participants.len();
                let should_start =
                    should_start.then(|| counter.participants.iter().copied().collect());

                let store = if should_start.is_some() {
                    tracing::info!(?id, "received all Accepts, starting protocol");
                    self.posits.remove(&id).map(|counter| counter.store)
                } else {
                    None
                };

                (should_start, store, None)
            }
            PositAction::Reject => {
                // TODO: On the first reject, we should abort the protocol for now.
                // We should be able to narrow down the list of participants
                // that are rejecting the protocol up until the threshold amount.
                let reply = if self.posits.contains_key(&id) {
                    Some(PositAction::Abort)
                } else {
                    tracing::warn!(?id, "received a Reject for a protocol we did NOT propose");
                    None
                };
                (None, None, reply)
            }
            // There's no action to be done here for Abort. Abort should be handled one level above.
            PositAction::Abort => (None, None, None),
            PositAction::Propose(participants) => {
                if self.posits.contains_key(&id) {
                    tracing::warn!(
                        ?id,
                        ?participants,
                        "received a protocol posit for an id that we already proposed"
                    );
                    return (None, None, Some(PositAction::Reject));
                }

                // Check that the participants are all active
                for p in participants.iter() {
                    if !active.contains(p) {
                        tracing::warn!(?id, ?active, ?participants, "rejecting protocol posit");
                        return (None, None, Some(PositAction::Reject));
                    }
                }

                // Automatically join the protocol if we're accepting here.
                (Some(participants.to_vec()), None, Some(PositAction::Accept))
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
