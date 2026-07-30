use std::collections::HashSet;

use borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{AccountId, PublicKey};

use crate::primitives::{Candidates, Participants, PkVotes, ThresholdVotes, Votes};

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub struct InitializingContractState {
    pub candidates: Candidates,
    pub threshold: usize,
    pub pk_votes: PkVotes,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub struct RunningContractState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub candidates: Candidates,
    pub join_votes: Votes,
    pub leave_votes: Votes,
    /// Active votes to change the running threshold without otherwise
    /// modifying the participant set. Once one proposed threshold reaches the
    /// current `threshold`, the contract transitions into `Resharing` with the
    /// same participants but the new threshold.
    pub threshold_votes: ThresholdVotes,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub struct ResharingContractState {
    pub old_epoch: u64,
    pub old_participants: Participants,
    pub new_participants: Participants,
    /// Threshold of the current key shares held by `old_participants`. The node
    /// needs this to reconstruct the existing secret during resharing, and it is
    /// what the network reverts to if the resharing is cancelled.
    pub threshold: usize,
    /// Threshold that will be baked into the reshared key shares for
    /// `new_participants`, recomputed from the new participant count. It becomes
    /// the running threshold once the resharing finishes.
    pub new_threshold: usize,
    pub public_key: PublicKey,
    pub finished_votes: HashSet<AccountId>,
    pub cancel_votes: HashSet<AccountId>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
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

/// Previous [`RunningContractState`] shape, before the `threshold_votes` field
/// was introduced. Used only by [`crate::MpcContract::migrate`] to deserialize
/// state that was stored by an older contract version and bring it forward.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub struct OldRunningContractState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub candidates: Candidates,
    pub join_votes: Votes,
    pub leave_votes: Votes,
}

/// Previous [`ProtocolContractState`] shape, matching [`OldRunningContractState`].
/// Used only by [`crate::MpcContract::migrate`] for legacy deserialization.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub enum OldProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(OldRunningContractState),
    Resharing(ResharingContractState),
}
