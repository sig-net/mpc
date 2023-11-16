pub mod primitives;

use crate::types::PublicKey;
use crate::util::NearPublicKeyExt;
use mpc_contract::ProtocolContractState;
use serde::{Deserialize, Serialize};

use self::primitives::{ParticipantSet, Participants, PkVotes, Votes};

#[derive(Serialize, Deserialize, Debug)]
pub struct InitializingContractState {
    pub participants: Participants,
    pub threshold: usize,
    pub pk_votes: PkVotes,
}

impl From<mpc_contract::InitializingContractState> for InitializingContractState {
    fn from(contract_state: mpc_contract::InitializingContractState) -> Self {
        InitializingContractState {
            participants: Participants::from(contract_state.participants),
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
    pub participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub candidates: Participants,
    pub join_votes: Votes,
    pub leave_votes: Votes,
}

impl From<mpc_contract::RunningContractState> for RunningContractState {
    fn from(contract_state: mpc_contract::RunningContractState) -> Self {
        RunningContractState {
            epoch: contract_state.epoch,
            participants: Participants::from(contract_state.participants.clone()),
            threshold: contract_state.threshold,
            public_key: contract_state.public_key.into_affine_point(),
            candidates: Participants::from(contract_state.candidates),
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
    pub old_participants: Participants,
    pub new_participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub finished_votes: ParticipantSet,
}

impl From<mpc_contract::ResharingContractState> for ResharingContractState {
    fn from(contract_state: mpc_contract::ResharingContractState) -> Self {
        ResharingContractState {
            old_epoch: contract_state.old_epoch,
            old_participants: Participants::from(contract_state.old_participants),
            new_participants: Participants::from(contract_state.new_participants),
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
    pub fn participants(&self) -> &Participants {
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
