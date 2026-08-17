use std::collections::HashSet;

use borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::store::IterableMap;
use near_sdk::{AccountId, PublicKey};

use crate::primitives::{CandidateInfo, Candidates, Participants, PkVotes, ThresholdVotes, Votes};

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub struct InitializingContractState {
    pub candidates: Candidates,
    pub threshold: usize,
    pub pk_votes: PkVotes,
}

#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct RunningContractState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub candidates: IterableMap<AccountId, CandidateInfo>,
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

#[derive(BorshDeserialize, BorshSerialize, Debug)]
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

/// Running state exposed to external callers. The unbounded candidate registry
/// and its join votes are available through the keyed `candidate_info` view.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub struct RunningContractStateView {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub leave_votes: Votes,
    pub threshold_votes: ThresholdVotes,
}

impl From<&RunningContractState> for RunningContractStateView {
    /// Converts from a borrow, cloning only the retained fields. This avoids
    /// copying the (potentially bloated) `candidates`/`join_votes` maps just to
    /// drop them — the whole point of the lean view.
    fn from(state: &RunningContractState) -> Self {
        RunningContractStateView {
            epoch: state.epoch,
            participants: state.participants.clone(),
            threshold: state.threshold,
            public_key: state.public_key.clone(),
            leave_votes: state.leave_votes.clone(),
            threshold_votes: state.threshold_votes.clone(),
        }
    }
}

/// Projection of stored protocol state for external reads. Only the unbounded
/// running candidate data is omitted.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub enum ProtocolContractStateView {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(RunningContractStateView),
    Resharing(ResharingContractState),
}

impl ProtocolContractStateView {
    pub fn name(&self) -> &'static str {
        match self {
            ProtocolContractStateView::NotInitialized => "NotInitialized",
            ProtocolContractStateView::Initializing(_) => "Initializing",
            ProtocolContractStateView::Running(_) => "Running",
            ProtocolContractStateView::Resharing(_) => "Resharing",
        }
    }
}
