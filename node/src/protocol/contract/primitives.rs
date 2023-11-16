use cait_sith::protocol::Participant;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use url::Url;

#[derive(Serialize, Deserialize, Debug)]
pub struct Participants {
    pub map: HashMap<Participant, Url>,
}

impl Participants {
    pub fn get(&self, key: &Participant) -> Option<&Url> {
        self.map.get(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &Participant> {
        self.map.keys()
    }

    pub fn contains_key(&self, key: &Participant) -> bool {
        self.map.contains_key(key)
    }
}

impl PartialEq for Participants {
    fn eq(&self, other: &Self) -> bool {
        self.map == other.map
    }
}

impl Eq for Participants {}

impl From<mpc_contract::primitives::Participants> for Participants {
    fn from(participants: mpc_contract::primitives::Participants) -> Self {
        // TODO: make sure that the ordering works as expected
        // TODO: consider refactoring this
        let participants_id_set = participants
            .keys()
            .map(|id| id.to_string())
            .collect::<BTreeSet<_>>();
        let maped_participants = participants
            .iter()
            .map(|(account_id, url_str)| {
                let participant_id = participants_id_set
                    .iter()
                    .position(|id| id == &account_id.to_string())
                    .unwrap();
                if participant_id > u32::MAX as usize {
                    panic!("participant id is too large");
                }
                (
                    Participant::from(participant_id as u32),
                    Url::try_from(url_str.as_str()).unwrap(),
                )
            })
            .collect();
        Self {
            map: maped_participants,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ParticipantSet {
    pub set: HashSet<Participant>,
}

impl ParticipantSet {
    pub fn contains(&self, participant: &Participant) -> bool {
        self.set.contains(participant)
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }
}

impl From<mpc_contract::primitives::ParticipantSet> for ParticipantSet {
    fn from(participants: mpc_contract::primitives::ParticipantSet) -> Self {
        let btree_participants_set = participants
            .iter()
            .map(|id| id.to_string())
            .collect::<BTreeSet<_>>();

        let maped_participants = participants
            .iter()
            .map(|account_id| {
                let participant_id = btree_participants_set
                    .iter()
                    .position(|id| id == &account_id.to_string())
                    .unwrap();
                if participant_id > u32::MAX as usize {
                    panic!("participant id is too large");
                }
                Participant::from(participant_id as u32)
            })
            .collect();

        Self {
            set: maped_participants,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Votes {
    map: HashMap<Participant, ParticipantSet>,
}

impl Votes {
    pub fn get(&self, participant: &Participant) -> Option<&ParticipantSet> {
        self.map.get(participant)
    }
}

impl
    From<(
        mpc_contract::primitives::Participants,
        mpc_contract::primitives::Votes,
    )> for Votes
{
    fn from(
        participants_and_votes: (
            mpc_contract::primitives::Participants,
            mpc_contract::primitives::Votes,
        ),
    ) -> Self {
        let btree_participants_set = participants_and_votes
            .0
            .keys()
            .map(|id| id.to_string())
            .collect::<BTreeSet<_>>();

        let maped_votes = participants_and_votes
            .1
            .into_iter()
            .map(|(account_id, votes)| {
                let participant_id = btree_participants_set
                    .iter()
                    .position(|id| id == &account_id.to_string()) // TODO: this needs to be fixed
                    .unwrap();
                if participant_id > u32::MAX as usize {
                    panic!("participant id is too large");
                }
                (
                    Participant::from(participant_id as u32),
                    ParticipantSet::from(votes),
                )
            })
            .collect();

        Self { map: maped_votes }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PkVotes {
    map: HashMap<near_crypto::PublicKey, ParticipantSet>,
}

impl PkVotes {
    pub fn get(&self, key: &near_crypto::PublicKey) -> Option<&ParticipantSet> {
        self.map.get(key)
    }

    pub fn into_iter(self) -> impl Iterator<Item = (near_crypto::PublicKey, ParticipantSet)> {
        self.map.into_iter()
    }
}

impl FromIterator<(near_crypto::PublicKey, ParticipantSet)> for PkVotes {
    fn from_iter<T: IntoIterator<Item = (near_crypto::PublicKey, ParticipantSet)>>(
        iter: T,
    ) -> Self {
        let map = iter.into_iter().collect();
        Self { map }
    }
}
