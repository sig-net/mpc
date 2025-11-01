use std::collections::{BTreeMap, HashSet};

use borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{AccountId, PublicKey};

use crate::primitives::{
    Candidates, Chain, Checkpoint, CheckpointVotes, Participants, PkVotes, Votes,
};

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct InitializingContractState {
    pub candidates: Candidates,
    pub threshold: usize,
    pub pk_votes: PkVotes,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct RunningContractState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub candidates: Candidates,
    pub join_votes: Votes,
    pub leave_votes: Votes,
    /// Per-chain voting on checkpoints
    pub checkpoint_votes: BTreeMap<Chain, CheckpointVotes>,
    /// The latest agreed checkpoint per chain
    pub latest_checkpoints: BTreeMap<Chain, Checkpoint>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct ResharingContractState {
    pub old_epoch: u64,
    pub old_participants: Participants,
    pub new_participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub finished_votes: HashSet<AccountId>,
    pub cancel_votes: HashSet<AccountId>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub enum ProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(RunningContractState),
    Resharing(ResharingContractState),
}

impl ProtocolContractState {
    pub fn name(&self) -> &'static str {
        match self {
            ProtocolContractState::NotInitialized => "NotInitialized",
            ProtocolContractState::Initializing(_) => "Initializing",
            ProtocolContractState::Running(_) => "Running",
            ProtocolContractState::Resharing(_) => "Resharing",
        }
    }
}
