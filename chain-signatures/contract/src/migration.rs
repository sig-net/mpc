use crate::config::Config;
use crate::errors::{Error, InvalidState};
use crate::primitives::{
    Candidates, CheckpointVotes, Participants, PendingRequest, StorageKey, ThresholdVotes, Votes,
};
use crate::state::{
    InitializingContractState, ProtocolContractState, ResharingContractState, RunningContractState,
};
use crate::update::ProposedUpdates;
use crate::{MpcContract, VersionedMpcContract};

use borsh::BorshDeserialize;
use mpc_primitives::{Chain, ConsensusCheckpointDigest, SignId};
use near_sdk::store::IterableMap;
use near_sdk::PublicKey;

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
    Initializing(InitializingContractState),
    Running(OldRunningContractState),
    Resharing(ResharingContractState),
}

fn upgrade_protocol_state(old: OldProtocolContractState) -> ProtocolContractState {
    match old {
        OldProtocolContractState::NotInitialized => ProtocolContractState::NotInitialized,
        OldProtocolContractState::Initializing(state) => ProtocolContractState::Initializing(state),
        OldProtocolContractState::Running(state) => {
            ProtocolContractState::Running(RunningContractState {
                epoch: state.epoch,
                participants: state.participants,
                threshold: state.threshold,
                public_key: state.public_key,
                candidates: state.candidates,
                join_votes: state.join_votes,
                leave_votes: state.leave_votes,
                threshold_votes: ThresholdVotes::new(),
            })
        }
        OldProtocolContractState::Resharing(state) => ProtocolContractState::Resharing(state),
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

        MpcContract {
            protocol_state: upgrade_protocol_state(protocol_state),
            pending_requests,
            proposed_updates,
            config,
            latest_checkpoints,
            checkpoint_votes,
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
        MpcContract {
            protocol_state: upgrade_protocol_state(protocol_state),
            pending_requests,
            proposed_updates,
            config,
            latest_checkpoints: IterableMap::new(StorageKey::LatestCheckpointDigests),
            checkpoint_votes: CheckpointVotes::new(),
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
        MpcContract {
            protocol_state: upgrade_protocol_state(protocol_state),
            pending_requests,
            proposed_updates,
            config,
            latest_checkpoints: IterableMap::new(StorageKey::LatestCheckpointDigests),
            checkpoint_votes: CheckpointVotes::new(),
        }
    }
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
