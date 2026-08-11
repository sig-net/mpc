use cait_sith::protocol::Participant;

use crate::mesh::connection::NodeStatus;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::ParticipantInfo;

/// This node's view of which participants are usable right now.
///
/// A participant is in at most one of the two sets. See the [module
/// docs](crate::mesh) for the states, the transitions between them, and which
/// component drives each one.
///
/// Only [`active()`](Self::active) may be used to select peers for a protocol.
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

    /// Drop every participant failing `keep`.
    ///
    /// Membership changes are driven by the contract, but removals otherwise
    /// only reach this state as per-connection drop events. This is the
    /// reconciling path: it lets the caller assert the whole set against the
    /// contract instead of trusting that one event per departed peer arrived.
    pub fn retain(&mut self, keep: impl Fn(&Participant) -> bool) {
        self.active.participants.retain(|p, _| keep(p));
        self.need_sync.participants.retain(|p, _| keep(p));
    }

    pub fn clear(&mut self) {
        self.active.clear();
        self.need_sync.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn participant(id: u32) -> (Participant, ParticipantInfo) {
        (Participant::from(id), ParticipantInfo::new(id))
    }

    /// `retain` is the reconciling path against the contract, so it has to clear
    /// both sets. A participant left behind in `need_sync` would keep drawing
    /// sync broadcasts after the contract dropped it.
    #[test]
    fn retain_drops_participants_from_both_sets() {
        let (active, active_info) = participant(1);
        let (syncing, syncing_info) = participant(2);
        let (kept, kept_info) = participant(3);
        let mut state = MeshState::default();

        state.update(active, NodeStatus::Active, active_info);
        state.update(syncing, NodeStatus::Syncing, syncing_info);
        state.update(kept, NodeStatus::Active, kept_info);

        state.retain(|p| *p == kept);

        assert!(state.active().contains_key(&kept));
        assert!(!state.active().contains_key(&active));
        assert!(!state.need_sync().contains_key(&syncing));
        assert_eq!(state.active().len(), 1);
        assert!(state.need_sync().is_empty());
    }

    /// A participant re-added under a different index must not linger under the
    /// old one: that is what leaves a departed peer selectable for signing.
    #[test]
    fn remove_then_readd_under_new_index_leaves_no_stale_entry() {
        let (old_index, old_info) = participant(4);
        let (new_index, new_info) = participant(5);
        let mut state = MeshState::default();

        state.update(old_index, NodeStatus::Active, old_info);
        state.remove(old_index);
        state.update(new_index, NodeStatus::Active, new_info);

        assert!(!state.active().contains_key(&old_index));
        assert!(state.active().contains_key(&new_index));
        assert_eq!(state.active().len(), 1);
    }

    #[test]
    fn clear_empties_both_sets() {
        let (active, active_info) = participant(6);
        let (syncing, syncing_info) = participant(7);
        let mut state = MeshState::default();

        state.update(active, NodeStatus::Active, active_info);
        state.update(syncing, NodeStatus::Syncing, syncing_info);
        state.clear();

        assert!(state.active().is_empty());
        assert!(state.need_sync().is_empty());
    }

    /// Both offline reasons must evict from `need_sync` too, or a peer that goes
    /// down mid-sync keeps being broadcast to forever.
    #[test]
    fn offline_and_inactive_clear_pending_sync() {
        for status in [NodeStatus::Offline, NodeStatus::Inactive] {
            let (p, info) = participant(8);
            let mut state = MeshState::default();

            state.update(p, NodeStatus::Syncing, info.clone());
            assert!(state.need_sync().contains_key(&p));

            state.update(p, status, info);
            assert!(!state.need_sync().contains_key(&p), "{status:?}");
            assert!(!state.active().contains_key(&p), "{status:?}");
        }
    }

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
