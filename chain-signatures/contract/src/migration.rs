use crate::config::Config;
use crate::errors::{Error, InvalidState};
use crate::primitives::{
    CandidateEntry, Candidates, CheckpointVotes, Participants, PendingRequest, PkVotes, StorageKey,
    ThresholdVotes, Votes,
};
use crate::state::{
    InitializingContractState, ProtocolContractState, ResharingContractState, RunningContractState,
};
use crate::update::ProposedUpdates;
use crate::{MpcContract, VersionedMpcContract};

use borsh::BorshDeserialize;
use mpc_primitives::{Chain, ConsensusCheckpointDigest, SignId};
use near_sdk::store::IterableMap;
use near_sdk::{AccountId, PublicKey};

/// Move an inline candidate registry (`candidates` + optional `join_votes`) into
/// the top-level [`CandidateEntry`] map, folding each candidate's votes into its
/// entry. Used by every migration path, since previous layouts stored candidates
/// inline in `ProtocolContractState`.
fn build_candidate_map(
    candidates: Candidates,
    mut join_votes: Votes,
) -> IterableMap<AccountId, CandidateEntry> {
    let mut map = IterableMap::new(StorageKey::Candidates);
    for (account_id, info) in candidates.candidates {
        let votes = join_votes.votes.remove(&account_id).unwrap_or_default();
        map.insert(
            account_id,
            CandidateEntry {
                info,
                join_votes: votes,
            },
        );
    }
    map
}

fn empty_candidate_map() -> IterableMap<AccountId, CandidateEntry> {
    IterableMap::new(StorageKey::Candidates)
}

// ---------------------------------------------------------------------------
// Inline `Initializing` state (candidates stored inline) — shared by all
// previous layouts.
// ---------------------------------------------------------------------------
#[derive(BorshDeserialize)]
pub struct InlineInitializingContractState {
    pub candidates: Candidates,
    pub threshold: usize,
    pub pk_votes: PkVotes,
}

// ---------------------------------------------------------------------------
// Older `Running` layout: inline candidates/join_votes, no `threshold_votes`.
// ---------------------------------------------------------------------------
#[derive(BorshDeserialize)]
pub struct OldRunningContractState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub candidates: Candidates,
    pub join_votes: Votes,
    pub leave_votes: Votes,
}

#[derive(BorshDeserialize)]
pub enum OldProtocolContractState {
    NotInitialized,
    Initializing(InlineInitializingContractState),
    Running(OldRunningContractState),
    Resharing(ResharingContractState),
}

fn upgrade_old_protocol_state(
    old: OldProtocolContractState,
) -> (
    ProtocolContractState,
    IterableMap<AccountId, CandidateEntry>,
) {
    match old {
        OldProtocolContractState::NotInitialized => {
            (ProtocolContractState::NotInitialized, empty_candidate_map())
        }
        OldProtocolContractState::Initializing(state) => (
            ProtocolContractState::Initializing(InitializingContractState {
                threshold: state.threshold,
                pk_votes: state.pk_votes,
            }),
            build_candidate_map(state.candidates, Votes::new()),
        ),
        OldProtocolContractState::Running(state) => (
            ProtocolContractState::Running(RunningContractState {
                epoch: state.epoch,
                participants: state.participants,
                threshold: state.threshold,
                public_key: state.public_key,
                leave_votes: state.leave_votes,
                threshold_votes: ThresholdVotes::new(),
            }),
            build_candidate_map(state.candidates, state.join_votes),
        ),
        OldProtocolContractState::Resharing(state) => (
            ProtocolContractState::Resharing(state),
            empty_candidate_map(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Current `Running` layout (immediately prior to this upgrade): inline
// candidates/join_votes, WITH `threshold_votes`.
// ---------------------------------------------------------------------------
#[derive(BorshDeserialize)]
pub struct InlineRunningContractState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub candidates: Candidates,
    pub join_votes: Votes,
    pub leave_votes: Votes,
    pub threshold_votes: ThresholdVotes,
}

#[derive(BorshDeserialize)]
pub enum InlineProtocolContractState {
    NotInitialized,
    Initializing(InlineInitializingContractState),
    Running(InlineRunningContractState),
    Resharing(ResharingContractState),
}

fn upgrade_inline_protocol_state(
    old: InlineProtocolContractState,
) -> (
    ProtocolContractState,
    IterableMap<AccountId, CandidateEntry>,
) {
    match old {
        InlineProtocolContractState::NotInitialized => {
            (ProtocolContractState::NotInitialized, empty_candidate_map())
        }
        InlineProtocolContractState::Initializing(state) => (
            ProtocolContractState::Initializing(InitializingContractState {
                threshold: state.threshold,
                pk_votes: state.pk_votes,
            }),
            build_candidate_map(state.candidates, Votes::new()),
        ),
        InlineProtocolContractState::Running(state) => (
            ProtocolContractState::Running(RunningContractState {
                epoch: state.epoch,
                participants: state.participants,
                threshold: state.threshold,
                public_key: state.public_key,
                leave_votes: state.leave_votes,
                threshold_votes: state.threshold_votes,
            }),
            build_candidate_map(state.candidates, state.join_votes),
        ),
        InlineProtocolContractState::Resharing(state) => (
            ProtocolContractState::Resharing(state),
            empty_candidate_map(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Full-contract previous layouts. None had a top-level `candidates` field;
// `upgrade` splits the inline candidates into it.
// ---------------------------------------------------------------------------

/// Layout in effect immediately before this upgrade: `threshold_votes` present,
/// checkpoints present, candidates still inline.
#[derive(BorshDeserialize)]
pub(crate) struct PreviousInline {
    protocol_state: InlineProtocolContractState,
    pending_requests: IterableMap<SignId, PendingRequest>,
    proposed_updates: ProposedUpdates,
    config: Config,
    latest_checkpoints: IterableMap<Chain, ConsensusCheckpointDigest>,
    checkpoint_votes: CheckpointVotes,
}

impl PreviousInline {
    fn upgrade(self) -> MpcContract {
        let Self {
            protocol_state,
            pending_requests,
            proposed_updates,
            config,
            latest_checkpoints,
            checkpoint_votes,
        } = self;
        let (protocol_state, candidates) = upgrade_inline_protocol_state(protocol_state);
        MpcContract {
            protocol_state,
            pending_requests,
            proposed_updates,
            config,
            latest_checkpoints,
            checkpoint_votes,
            candidates,
        }
    }
}

#[derive(BorshDeserialize)]
pub(crate) struct PreviousDevnet {
    protocol_state: OldProtocolContractState,
    pending_requests: IterableMap<SignId, PendingRequest>,
    proposed_updates: ProposedUpdates,
    config: Config,
    latest_checkpoints: IterableMap<Chain, ConsensusCheckpointDigest>,
    checkpoint_votes: CheckpointVotes,
}

impl PreviousDevnet {
    fn upgrade(self) -> MpcContract {
        let Self {
            protocol_state,
            pending_requests,
            proposed_updates,
            config,
            latest_checkpoints,
            checkpoint_votes,
        } = self;
        let (protocol_state, candidates) = upgrade_old_protocol_state(protocol_state);
        MpcContract {
            protocol_state,
            pending_requests,
            proposed_updates,
            config,
            latest_checkpoints,
            checkpoint_votes,
            candidates,
        }
    }
}

#[derive(BorshDeserialize)]
pub(crate) struct PreviousTestnet {
    protocol_state: OldProtocolContractState,
    pending_requests: IterableMap<SignId, PendingRequest>,
    proposed_updates: ProposedUpdates,
    config: Config,
}

impl PreviousTestnet {
    fn upgrade(self) -> MpcContract {
        let Self {
            protocol_state,
            pending_requests,
            proposed_updates,
            config,
        } = self;
        let (protocol_state, candidates) = upgrade_old_protocol_state(protocol_state);
        MpcContract {
            protocol_state,
            pending_requests,
            proposed_updates,
            config,
            latest_checkpoints: IterableMap::new(StorageKey::LatestCheckpointDigests),
            checkpoint_votes: CheckpointVotes::new(),
            candidates,
        }
    }
}

#[derive(BorshDeserialize)]
pub(crate) struct PreviousMainnet {
    protocol_state: OldProtocolContractState,
    pending_requests: IterableMap<SignId, PendingRequest>,
    proposed_updates: ProposedUpdates,
    config: Config,
}

impl PreviousMainnet {
    fn upgrade(self) -> MpcContract {
        let Self {
            protocol_state,
            pending_requests,
            proposed_updates,
            config,
        } = self;
        let (protocol_state, candidates) = upgrade_old_protocol_state(protocol_state);
        MpcContract {
            protocol_state,
            pending_requests,
            proposed_updates,
            config,
            latest_checkpoints: IterableMap::new(StorageKey::LatestCheckpointDigests),
            checkpoint_votes: CheckpointVotes::new(),
            candidates,
        }
    }
}

#[derive(BorshDeserialize)]
enum VersionedPreviousInline {
    V0(PreviousInline),
}

#[derive(BorshDeserialize)]
enum VersionedPreviousDevnet {
    V0(PreviousDevnet),
}

#[derive(BorshDeserialize)]
enum VersionedPreviousTestnet {
    V0(PreviousTestnet),
}

pub(crate) fn migrate(state_bytes: &[u8]) -> Result<VersionedMpcContract, Error> {
    if let Ok(current) = VersionedMpcContract::try_from_slice(state_bytes) {
        return Ok(current);
    }

    // Layout immediately prior to hoisting candidates out of the protocol state.
    if let Ok(VersionedPreviousInline::V0(previous)) =
        VersionedPreviousInline::try_from_slice(state_bytes)
    {
        return Ok(VersionedMpcContract::V0(previous.upgrade()));
    }

    if let Ok(VersionedPreviousDevnet::V0(previous)) =
        VersionedPreviousDevnet::try_from_slice(state_bytes)
    {
        return Ok(VersionedMpcContract::V0(previous.upgrade()));
    }

    if let Ok(VersionedPreviousTestnet::V0(previous)) =
        VersionedPreviousTestnet::try_from_slice(state_bytes)
    {
        return Ok(VersionedMpcContract::V0(previous.upgrade()));
    }

    if let Ok(previous) = PreviousMainnet::try_from_slice(state_bytes) {
        return Ok(VersionedMpcContract::V0(previous.upgrade()));
    }

    Err(InvalidState::ContractStateIsMissing.message("Failed to deserialize contract state"))
}
