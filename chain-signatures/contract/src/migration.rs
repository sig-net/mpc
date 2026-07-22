use crate::errors::{Error, InvalidState};
use crate::primitives::{CheckpointVotes, StorageKey};
use crate::{MpcContract, VersionedMpcContract};

use borsh::{BorshDeserialize, BorshSerialize};
use mpc_primitives::{Chain, ConsensusCheckpointDigest, SignId, Signature};
use near_sdk::store::IterableMap;
use near_sdk::AccountId;

use crate::config::Config;
use crate::primitives::PendingRequest;
use crate::state::ProtocolContractState;
use crate::update::ProposedUpdates;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Deployment {
    Devnet,
    Testnet,
    Mainnet,
}

pub(crate) fn deployment_for_account(account_id: &AccountId) -> Result<Deployment, Error> {
    let account_id = account_id.as_str();
    if account_id == "dev.sig-net.testnet" {
        return Ok(Deployment::Devnet);
    }
    if account_id.ends_with(".testnet") {
        return Ok(Deployment::Testnet);
    }
    if account_id.ends_with(".near") {
        return Ok(Deployment::Mainnet);
    }

    // Local sandbox accounts do not use a network suffix. Treat them as the
    // cumulative mainnet layout so initialization remains usable in tests.
    Ok(Deployment::Mainnet)
}

pub(crate) fn version_contract(contract: MpcContract) -> VersionedMpcContract {
    VersionedMpcContract::V0(contract)
}

pub(crate) trait Migrater {
    fn migrate(&self, state_bytes: &[u8]) -> Result<VersionedMpcContract, Error>;
}

pub(crate) fn migrater_for(deployment: Deployment) -> Box<dyn Migrater> {
    match deployment {
        Deployment::Devnet => Box::new(DevnetMigrater),
        Deployment::Testnet | Deployment::Mainnet => Box::new(CumulativeMigrater),
    }
}

/// Devnet is kept as a step migrater because it is the deployment that has
/// already persisted the signed-checkpoint map.
struct DevnetMigrater;

/// Testnet and mainnet were migrated through the same historical layouts, so
/// they accept every known legacy state in one cumulative migration.
struct CumulativeMigrater;

#[derive(BorshDeserialize)]
struct LegacyMpcContract {
    protocol_state: ProtocolContractState,
    pending_requests: IterableMap<SignId, PendingRequest>,
    proposed_updates: ProposedUpdates,
    config: Config,
}

#[derive(BorshDeserialize, BorshSerialize)]
struct LegacySignedCheckpoint {
    checkpoint: ConsensusCheckpointDigest,
    signature: Signature,
}

#[derive(BorshDeserialize)]
struct LegacyCheckpointMpcContract {
    protocol_state: ProtocolContractState,
    pending_requests: IterableMap<SignId, PendingRequest>,
    proposed_updates: ProposedUpdates,
    config: Config,
    latest_checkpoints: IterableMap<Chain, LegacySignedCheckpoint>,
}

#[derive(BorshDeserialize)]
enum LegacyVersionedMpcContract {
    V0(LegacyMpcContract),
}

#[derive(BorshDeserialize)]
enum LegacyVersionedCheckpointMpcContract {
    V0(LegacyCheckpointMpcContract),
}

#[derive(BorshDeserialize)]
enum LegacyVersionedDigestMpcContract {
    V0(MpcContract),
}

impl Migrater for DevnetMigrater {
    fn migrate(&self, state_bytes: &[u8]) -> Result<VersionedMpcContract, Error> {
        if let Some(current) = current_variant(state_bytes)? {
            return Ok(current);
        }

        if let Some(contract) = deserialize_digest_state(state_bytes)? {
            return Ok(version_contract(contract));
        }

        if let Ok(LegacyVersionedCheckpointMpcContract::V0(legacy)) =
            LegacyVersionedCheckpointMpcContract::try_from_slice(state_bytes)
        {
            return Ok(version_contract(from_signed(legacy)));
        }
        if let Ok(legacy) = LegacyCheckpointMpcContract::try_from_slice(state_bytes) {
            return Ok(version_contract(from_signed(legacy)));
        }

        Err(migration_error(
            "Devnet migration requires signed checkpoint state",
        ))
    }
}

impl Migrater for CumulativeMigrater {
    fn migrate(&self, state_bytes: &[u8]) -> Result<VersionedMpcContract, Error> {
        if let Some(current) = current_variant(state_bytes)? {
            return Ok(current);
        }

        if let Some(contract) = deserialize_digest_state(state_bytes)? {
            return Ok(version_contract(contract));
        }

        if let Ok(legacy) = LegacyVersionedCheckpointMpcContract::try_from_slice(state_bytes) {
            let LegacyVersionedCheckpointMpcContract::V0(legacy) = legacy;
            return Ok(version_contract(from_signed(legacy)));
        }
        if let Ok(legacy) = LegacyCheckpointMpcContract::try_from_slice(state_bytes) {
            return Ok(version_contract(from_signed(legacy)));
        }
        if let Ok(legacy) = LegacyVersionedMpcContract::try_from_slice(state_bytes) {
            let LegacyVersionedMpcContract::V0(legacy) = legacy;
            return Ok(version_contract(from_empty(legacy)));
        }
        if let Ok(legacy) = LegacyMpcContract::try_from_slice(state_bytes) {
            return Ok(version_contract(from_empty(legacy)));
        }

        Err(migration_error("Failed to deserialize contract state"))
    }
}

fn current_variant(state_bytes: &[u8]) -> Result<Option<VersionedMpcContract>, Error> {
    let Ok(contract) = VersionedMpcContract::try_from_slice(state_bytes) else {
        return Ok(None);
    };

    Ok(Some(contract))
}

fn deserialize_digest_state(state_bytes: &[u8]) -> Result<Option<MpcContract>, Error> {
    match LegacyVersionedDigestMpcContract::try_from_slice(state_bytes) {
        Ok(LegacyVersionedDigestMpcContract::V0(contract)) => Ok(Some(contract)),
        Err(_) => match MpcContract::try_from_slice(state_bytes) {
            Ok(contract) => Ok(Some(contract)),
            Err(_) => Ok(None),
        },
    }
}

fn from_empty(legacy: LegacyMpcContract) -> MpcContract {
    MpcContract {
        protocol_state: legacy.protocol_state,
        pending_requests: legacy.pending_requests,
        proposed_updates: legacy.proposed_updates,
        config: legacy.config,
        latest_checkpoints: IterableMap::new(StorageKey::LatestCheckpointDigests),
        checkpoint_votes: CheckpointVotes::new(),
    }
}

fn from_signed(legacy: LegacyCheckpointMpcContract) -> MpcContract {
    let mut latest_checkpoints = IterableMap::new(StorageKey::LatestCheckpointDigests);
    for chain in Chain::iter() {
        if let Some(checkpoint) = legacy.latest_checkpoints.get(&chain) {
            latest_checkpoints.insert(chain, checkpoint.checkpoint);
        }
    }

    MpcContract {
        protocol_state: legacy.protocol_state,
        pending_requests: legacy.pending_requests,
        proposed_updates: legacy.proposed_updates,
        config: legacy.config,
        latest_checkpoints,
        checkpoint_votes: CheckpointVotes::new(),
    }
}

fn migration_error(message: &'static str) -> Error {
    InvalidState::ContractStateIsMissing.message(message)
}
