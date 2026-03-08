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

    pub fn update(&mut self, participant: Participant, status: NodeStatus, info: ParticipantInfo) {
        match status {
            NodeStatus::Active => {
                self.active.insert(&participant, info);
                self.need_sync.remove(&participant);
            }
            NodeStatus::Syncing => {
                self.active.remove(&participant);
                self.need_sync.insert(&participant, info);
            }
            NodeStatus::Inactive | NodeStatus::Offline => {
                self.active.remove(&participant);
                self.need_sync.remove(&participant);
            }
        }
    }

    pub fn remove(&mut self, participant: Participant) {
        self.active.remove(&participant);
        self.need_sync.remove(&participant);
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

        state.update(participant, NodeStatus::Active, info.clone());
        assert!(state.active().contains_key(&participant));
        assert!(!state.need_sync().contains_key(&participant));

        state.update(participant, NodeStatus::Syncing, info.clone());
        assert!(!state.active().contains_key(&participant));
        assert!(state.need_sync().contains_key(&participant));

        state.update(participant, NodeStatus::Active, info);
        assert!(state.active().contains_key(&participant));
        assert!(!state.need_sync().contains_key(&participant));
    }
}
