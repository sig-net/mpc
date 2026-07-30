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
    _latest_checkpoints: IterableMap<Chain, PreviousSignedCheckpoint>,
}

impl PreviousDevnet {
    fn upgrade(self) -> MpcContract {
        let Self {
            protocol_state,
            pending_requests,
            proposed_updates,
            config,
            ..
        } = self;

        clear_legacy_checkpoints_storage();

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

fn clear_legacy_checkpoints_storage() {
    let base_prefix = near_sdk::IntoStorageKey::into_storage_key(StorageKey::LatestCheckpoints);

    let mut vec_len_key = base_prefix.clone();
    vec_len_key.push(b'v');
    vec_len_key.extend_from_slice(&0u32.to_le_bytes());
    near_sdk::env::storage_remove(&vec_len_key);

    let mut map_prefix = base_prefix;
    map_prefix.push(b'm');
    for chain in Chain::iter() {
        let mut key_bytes = map_prefix.clone();
        if let Ok(chain_bytes) = near_sdk::borsh::to_vec(&chain) {
            key_bytes.extend_from_slice(&chain_bytes);
            let raw_key = near_sdk::env::sha256(&key_bytes);
            near_sdk::env::storage_remove(&raw_key);
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
