use cait_sith::protocol::Participant;

use crate::mesh::connection::NodeStatus;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::ParticipantInfo;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct MeshState {
    /// Participants that are active in the network; synced and responsive to pings.
    active: Participants,

    /// Participants that are currently out-of-sync, they will become active
    /// once we finished synchronization.
    need_sync: Participants,
}

impl MeshState {
    pub fn active(&self) -> &Participants {
        &self.active
    }

    pub fn need_sync(&self) -> &Participants {
        &self.need_sync
    }

    /// `Active` or `Syncing` for a listed participant, `None` otherwise. The
    /// state does not keep unreachable or inactive peers, so it cannot tell
    /// those two apart.
    pub fn status(&self, participant: Participant) -> Option<NodeStatus> {
        if self.active.contains_key(&participant) {
            Some(NodeStatus::Active)
        } else if self.need_sync.contains_key(&participant) {
            Some(NodeStatus::Syncing)
        } else {
            None
        }
    }

    /// Returns whether the state changed.
    pub fn update(
        &mut self,
        participant: Participant,
        status: NodeStatus,
        info: ParticipantInfo,
    ) -> bool {
        let (target, other) = match status {
            NodeStatus::Active => (&mut self.active, &mut self.need_sync),
            NodeStatus::Syncing => (&mut self.need_sync, &mut self.active),
            NodeStatus::Inactive | NodeStatus::Offline => return self.remove(participant),
        };
        let moved = other.remove(&participant).is_some();
        let same = target.get(&participant) == Some(&info);
        target.insert(&participant, info);
        moved || !same
    }

    /// Returns whether the state changed.
    pub fn remove(&mut self, participant: Participant) -> bool {
        self.active.remove(&participant).is_some() | self.need_sync.remove(&participant).is_some()
    }

    pub fn clear(&mut self) {
        self.active.clear();
        self.need_sync.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syncing_moves_participant_out_of_active_until_reactivated() {
        let participant = Participant::from(7u32);
        let info = ParticipantInfo::new(7);
        let mut state = MeshState::default();

        assert!(state.update(participant, NodeStatus::Active, info.clone()));
        assert_eq!(state.status(participant), Some(NodeStatus::Active));
        assert!(!state.need_sync().contains_key(&participant));

        assert!(state.update(participant, NodeStatus::Syncing, info.clone()));
        assert_eq!(state.status(participant), Some(NodeStatus::Syncing));
        assert!(!state.active().contains_key(&participant));

        assert!(state.update(participant, NodeStatus::Active, info.clone()));
        assert_eq!(state.status(participant), Some(NodeStatus::Active));
        assert!(!state.need_sync().contains_key(&participant));

        // Same status and info again is not a change.
        assert!(!state.update(participant, NodeStatus::Active, info.clone()));
        assert!(state.update(participant, NodeStatus::Offline, info));
        assert_eq!(state.status(participant), None);
        assert!(!state.remove(participant));
    }
}
