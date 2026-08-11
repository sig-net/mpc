use std::collections::HashSet;

use borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{AccountId, PublicKey};

use crate::primitives::{Candidates, Participants, PkVotes, ThresholdVotes, Votes};

/// Stored `Initializing` state. Candidates are held in the top-level
/// `MpcContract::candidates` map, not here (see [`InitializingContractStateView`]
/// for what external callers receive).
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub struct InitializingContractState {
    pub threshold: usize,
    pub pk_votes: PkVotes,
}

/// Stored `Running` state. The candidate registry and its join votes live in the
/// top-level `MpcContract::candidates` map (see `CandidateEntry`); only the
/// bounded, participant-gated `leave_votes`/`threshold_votes` remain inline.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub struct RunningContractState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
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

/// A `Running` state as exposed to external callers: only the fields a node
/// actually consumes (`epoch`, `participants`, `threshold`, `public_key`). The
/// stored `RunningContractState` additionally holds the vote maps
/// (`candidates`, `join_votes`, `leave_votes`, `threshold_votes`); those are
/// omitted here — the attacker-writable `candidates`/`join_votes` could inflate
/// this payload past the RPC view-execution limit, and no node reads any vote
/// map from the polled state. A joining node reads its own candidacy through
/// the `candidate_status` view instead.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub struct RunningContractStateView {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
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
        }
    }
}

/// `Initializing` state as exposed to external callers. Unlike the stored
/// [`InitializingContractState`], it carries `candidates` (assembled from the
/// top-level map), because a joining node needs the founding set to bootstrap
/// key generation. The genesis candidate set is curated and `join()`-disabled,
/// so it is bounded and safe to return in full.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub struct InitializingContractStateView {
    pub candidates: Candidates,
    pub threshold: usize,
    pub pk_votes: PkVotes,
}

/// Lean projection of [`ProtocolContractState`] for external reads. `Running`
/// omits the vote maps (see [`RunningContractStateView`]); `Initializing`
/// carries candidates from the top-level map; `Resharing` (bounded participant
/// sets) is carried verbatim. Assembled by `VersionedMpcContract::view_state`,
/// which has access to the top-level candidate map.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub enum ProtocolContractStateView {
    NotInitialized,
    Initializing(InitializingContractStateView),
    Running(RunningContractStateView),
    Resharing(ResharingContractState),
}
