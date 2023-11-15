use crate::types::PublicKey;
use crate::util::NearPublicKeyExt;
use cait_sith::protocol::Participant;
use mpc_contract::ProtocolContractState;
use near_sdk::AccountId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use url::Url;

#[derive(Serialize, Deserialize, Debug)]
pub struct InitializingContractState {
    pub participants: ParticipantsInfo,
    pub threshold: usize,
    pub pk_votes: HashMap<near_crypto::PublicKey, ParticipantSet>,
}

// TODO: consider renaming
#[derive(Serialize, Deserialize, Debug)]
pub struct ParticipantsInfo {
    pub map: HashMap<Participant, Url>,
}

impl ParticipantsInfo {
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

impl PartialEq for ParticipantsInfo {
    fn eq(&self, other: &Self) -> bool {
        self.map == other.map
    }
}

impl Eq for ParticipantsInfo {}

impl From<HashMap<AccountId, String>> for ParticipantsInfo {
    fn from(participants: HashMap<AccountId, String>) -> Self {
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

impl From<HashSet<AccountId>> for ParticipantSet {
    fn from(participants: HashSet<AccountId>) -> Self {
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

impl From<mpc_contract::InitializingContractState> for InitializingContractState {
    fn from(contract_state: mpc_contract::InitializingContractState) -> Self {
        InitializingContractState {
            participants: ParticipantsInfo::from(contract_state.participants),
            threshold: contract_state.threshold,
            pk_votes: contract_state
                .pk_votes
                .into_iter()
                .map(|(pk, participants)| {
                    (
                        near_crypto::PublicKey::SECP256K1(
                            near_crypto::Secp256K1PublicKey::try_from(&pk.as_bytes()[1..]).unwrap(),
                        ),
                        ParticipantSet::from(participants),
                    )
                })
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RunningContractState {
    pub epoch: u64,
    pub participants: ParticipantsInfo,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub candidates: ParticipantsInfo,
    pub join_votes: Votes,
    pub leave_votes: Votes,
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
        HashMap<AccountId, String>,
        HashMap<AccountId, HashSet<AccountId>>,
    )> for Votes
{
    fn from(
        participants_and_votes: (
            HashMap<AccountId, String>,
            HashMap<AccountId, HashSet<AccountId>>,
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

impl From<mpc_contract::RunningContractState> for RunningContractState {
    fn from(contract_state: mpc_contract::RunningContractState) -> Self {
        RunningContractState {
            epoch: contract_state.epoch,
            participants: ParticipantsInfo::from(contract_state.participants.clone()),
            threshold: contract_state.threshold,
            public_key: contract_state.public_key.into_affine_point(),
            candidates: ParticipantsInfo::from(contract_state.candidates),
            join_votes: Votes::from((
                contract_state.participants.clone(),
                contract_state.join_votes,
            )),
            leave_votes: Votes::from((contract_state.participants, contract_state.leave_votes)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResharingContractState {
    pub old_epoch: u64,
    pub old_participants: ParticipantsInfo,
    pub new_participants: ParticipantsInfo,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub finished_votes: ParticipantSet,
}

impl From<mpc_contract::ResharingContractState> for ResharingContractState {
    fn from(contract_state: mpc_contract::ResharingContractState) -> Self {
        ResharingContractState {
            old_epoch: contract_state.old_epoch,
            old_participants: ParticipantsInfo::from(contract_state.old_participants),
            new_participants: ParticipantsInfo::from(contract_state.new_participants),
            threshold: contract_state.threshold,
            public_key: contract_state.public_key.into_affine_point(),
            finished_votes: ParticipantSet::from(contract_state.finished_votes),
        }
    }
}

#[derive(Debug)]
pub enum ProtocolState {
    Initializing(InitializingContractState),
    Running(RunningContractState),
    Resharing(ResharingContractState),
}

impl ProtocolState {
    pub fn participants(&self) -> &ParticipantsInfo {
        match self {
            ProtocolState::Initializing(InitializingContractState { participants, .. }) => {
                participants
            }
            ProtocolState::Running(RunningContractState { participants, .. }) => participants,
            ProtocolState::Resharing(ResharingContractState {
                old_participants, ..
            }) => old_participants,
        }
    }

    pub fn public_key(&self) -> Option<&PublicKey> {
        match self {
            ProtocolState::Initializing { .. } => None,
            ProtocolState::Running(RunningContractState { public_key, .. }) => Some(public_key),
            ProtocolState::Resharing(ResharingContractState { public_key, .. }) => Some(public_key),
        }
    }

    pub fn threshold(&self) -> usize {
        match self {
            ProtocolState::Initializing(InitializingContractState { threshold, .. }) => *threshold,
            ProtocolState::Running(RunningContractState { threshold, .. }) => *threshold,
            ProtocolState::Resharing(ResharingContractState { threshold, .. }) => *threshold,
        }
    }
}

impl TryFrom<ProtocolContractState> for ProtocolState {
    type Error = ();

    fn try_from(value: ProtocolContractState) -> Result<Self, Self::Error> {
        match value {
            ProtocolContractState::Initializing(state) => {
                Ok(ProtocolState::Initializing(state.into()))
            }
            ProtocolContractState::Running(state) => Ok(ProtocolState::Running(state.into())),
            ProtocolContractState::Resharing(state) => Ok(ProtocolState::Resharing(state.into())),
        }
    }
}
