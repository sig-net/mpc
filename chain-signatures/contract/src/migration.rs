use crate::config::Config;
use crate::errors::{Error, InvalidState};
use crate::primitives::{CheckpointVotes, PendingRequest, StorageKey};
use crate::state::ProtocolContractState;
use crate::update::ProposedUpdates;
use crate::{MpcContract, VersionedMpcContract};

use borsh::{BorshDeserialize, BorshSerialize};
use mpc_primitives::{Chain, ConsensusCheckpointDigest, SignId, Signature};
use near_sdk::store::IterableMap;

#[derive(BorshDeserialize)]
pub(crate) struct PreviousDevnet {
    protocol_state: ProtocolContractState,
    pending_requests: IterableMap<SignId, PendingRequest>,
    proposed_updates: ProposedUpdates,
    config: Config,
    latest_checkpoints: IterableMap<Chain, PreviousSignedCheckpoint>,
}

impl PreviousDevnet {
    fn upgrade(self) -> MpcContract {
        let Self {
            protocol_state,
            pending_requests,
            proposed_updates,
            config,
            mut latest_checkpoints,
        } = self;

        for chain in Chain::iter() {
            latest_checkpoints.remove(&chain);
        }

        MpcContract {
            protocol_state,
            pending_requests,
            proposed_updates,
            config,
            latest_checkpoints: IterableMap::new(StorageKey::LatestCheckpointDigests),
            checkpoint_votes: CheckpointVotes::new(),
        }
    }
}

#[derive(BorshDeserialize)]
pub(crate) struct PreviousTestnet {
    protocol_state: ProtocolContractState,
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
            protocol_state,
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
    protocol_state: ProtocolContractState,
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
            protocol_state,
            pending_requests,
            proposed_updates,
            config,
            latest_checkpoints: IterableMap::new(StorageKey::LatestCheckpointDigests),
            checkpoint_votes: CheckpointVotes::new(),
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
struct PreviousSignedCheckpoint {
    checkpoint: ConsensusCheckpointDigest,
    signature: Signature,
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
