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
enum PreviousVersion {
    V0,
}

/// The devnet state has a version tag and signed checkpoints.
#[derive(BorshDeserialize)]
pub(crate) struct PreviousDevnet {
    version: PreviousVersion,
    protocol_state: ProtocolContractState,
    pending_requests: IterableMap<SignId, PendingRequest>,
    proposed_updates: ProposedUpdates,
    config: Config,
    latest_checkpoints: IterableMap<Chain, PreviousSignedCheckpoint>,
}

/// The testnet state has a version tag but predates checkpoint persistence.
#[derive(BorshDeserialize)]
pub(crate) struct PreviousTestnet {
    version: PreviousVersion,
    protocol_state: ProtocolContractState,
    pending_requests: IterableMap<SignId, PendingRequest>,
    proposed_updates: ProposedUpdates,
    config: Config,
}

/// The mainnet state predates the versioned contract wrapper.
#[derive(BorshDeserialize)]
pub(crate) struct PreviousMainnet {
    protocol_state: ProtocolContractState,
    pending_requests: IterableMap<SignId, PendingRequest>,
    proposed_updates: ProposedUpdates,
    config: Config,
}

#[derive(BorshDeserialize, BorshSerialize)]
struct PreviousSignedCheckpoint {
    checkpoint: ConsensusCheckpointDigest,
    signature: Signature,
}

pub(crate) fn version_contract(contract: MpcContract) -> VersionedMpcContract {
    VersionedMpcContract::V0(contract)
}

pub(crate) fn migrate(state_bytes: &[u8]) -> Result<VersionedMpcContract, Error> {
    if let Ok(current) = VersionedMpcContract::try_from_slice(state_bytes) {
        return Ok(current);
    }

    if let Ok(previous) = PreviousDevnet::try_from_slice(state_bytes) {
        return Ok(version_contract(from_devnet(previous)));
    }

    if let Ok(previous) = PreviousTestnet::try_from_slice(state_bytes) {
        let PreviousTestnet {
            version,
            protocol_state,
            pending_requests,
            proposed_updates,
            config,
        } = previous;
        let _ = version;
        return Ok(version_contract(from_empty(
            protocol_state,
            pending_requests,
            proposed_updates,
            config,
        )));
    }

    if let Ok(previous) = PreviousMainnet::try_from_slice(state_bytes) {
        return Ok(version_contract(from_empty(
            previous.protocol_state,
            previous.pending_requests,
            previous.proposed_updates,
            previous.config,
        )));
    }

    Err(InvalidState::ContractStateIsMissing.message("Failed to deserialize contract state"))
}

fn from_devnet(previous: PreviousDevnet) -> MpcContract {
    let PreviousDevnet {
        version,
        protocol_state,
        pending_requests,
        proposed_updates,
        config,
        latest_checkpoints,
    } = previous;
    let _ = version;

    let mut latest_checkpoint_digests = IterableMap::new(StorageKey::LatestCheckpointDigests);
    for chain in Chain::iter() {
        if let Some(checkpoint) = latest_checkpoints.get(&chain) {
            latest_checkpoint_digests.insert(chain, checkpoint.checkpoint);
        }
    }

    MpcContract {
        protocol_state,
        pending_requests,
        proposed_updates,
        config,
        latest_checkpoints: latest_checkpoint_digests,
        checkpoint_votes: CheckpointVotes::new(),
    }
}

fn from_empty(
    protocol_state: ProtocolContractState,
    pending_requests: IterableMap<SignId, PendingRequest>,
    proposed_updates: ProposedUpdates,
    config: Config,
) -> MpcContract {
    MpcContract {
        protocol_state,
        pending_requests,
        proposed_updates,
        config,
        latest_checkpoints: IterableMap::new(StorageKey::LatestCheckpointDigests),
        checkpoint_votes: CheckpointVotes::new(),
    }
}
