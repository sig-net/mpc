//! Contract state migration across deployed environments.
//!
//! We maintain the three previous network state definitions — [`PreviousDevnet`],
//! [`PreviousTestnet`], and [`PreviousMainnet`] — so future migrations can be
//! performed more easily.
//!
//! `Previous*` simply refers to the version currently deployed to each respective
//! network (`dev.sig-net.testnet`, `v1.sig-net.testnet`, and `v1.sig-net.near`).
//! Any breaking serialization changes align with `tests/network_migration.rs`, which
//! pulls actual live data from each network and validates migrations so that they
//! always pass in CI even if earlier breaking changes were introduced.
//!
//! Do not change the [`migrate`] function directly; instead, modify each of the individual
//! `Previous*` structs and their `.upgrade()` methods to reflect the actual deployed schemas.
//!
//! This module allows us to keep track of rolling updates to the underlying contract
//! state as deployments progress.

use crate::config::ProtocolConfig;
use crate::errors::{Error, InvalidState};
use crate::primitives::{
    Candidates, CheckpointDigest, CheckpointVotes, Participants, PendingRequest, ReshareVotes,
    StorageKey, ThresholdVotes, Votes,
};
use crate::state::{
    InitializingContractState, ProtocolContractState, ResharingContractState, RunningContractState,
};
use crate::update::ProposedUpdates;
use crate::MpcContract;

use borsh::{BorshDeserialize, BorshSerialize};
use mpc_primitives::{Chain, SignId};
use near_sdk::store::IterableMap;
use near_sdk::{AccountId, PublicKey};
use std::collections::{HashMap, HashSet};

/// Config as currently deployed on every network: carries the removed timeouts,
/// network-wide stockpile caps and the dynamic `other` maps (borsh: each value is
/// a JSON byte vector; every live map is empty).
#[derive(BorshDeserialize, BorshSerialize)]
pub(crate) struct PreviousConfig {
    pub protocol: PreviousProtocolConfig,
    pub other: HashMap<String, Vec<u8>>,
}

#[derive(BorshDeserialize, BorshSerialize)]
pub(crate) struct PreviousProtocolConfig {
    pub message_timeout: u64,
    pub garbage_timeout: u64,
    pub max_concurrent_introduction: u32,
    pub max_concurrent_generation: u32,
    pub triple: PreviousTripleConfig,
    pub presignature: PreviousPresignatureConfig,
    pub signature: PreviousSignatureConfig,
    pub other: HashMap<String, Vec<u8>>,
}

#[derive(BorshDeserialize, BorshSerialize)]
pub(crate) struct PreviousTripleConfig {
    pub min_triples: u32,
    pub max_triples: u32,
    pub generation_timeout: u64,
    pub other: HashMap<String, Vec<u8>>,
}

#[derive(BorshDeserialize, BorshSerialize)]
pub(crate) struct PreviousPresignatureConfig {
    pub min_presignatures: u32,
    pub max_presignatures: u32,
    pub generation_timeout: u64,
    pub other: HashMap<String, Vec<u8>>,
}

#[derive(BorshDeserialize, BorshSerialize)]
pub(crate) struct PreviousSignatureConfig {
    pub generation_timeout: u64,
    pub generation_timeout_total: u64,
    pub garbage_timeout: u64,
    pub other: HashMap<String, Vec<u8>>,
}

impl PreviousConfig {
    fn upgrade(self) -> ProtocolConfig {
        let p = self.protocol;
        ProtocolConfig::new(
            p.triple.min_triples,
            p.presignature.min_presignatures,
            p.max_concurrent_introduction,
        )
    }
}

#[cfg(test)]
impl From<ProtocolConfig> for PreviousConfig {
    fn from(p: ProtocolConfig) -> Self {
        Self {
            protocol: PreviousProtocolConfig {
                message_timeout: 0,
                garbage_timeout: 0,
                max_concurrent_introduction: p.max_mine_generations,
                max_concurrent_generation: 0,
                triple: PreviousTripleConfig {
                    min_triples: p.min_mine_triple_pairs,
                    max_triples: 0,
                    generation_timeout: 0,
                    other: HashMap::new(),
                },
                presignature: PreviousPresignatureConfig {
                    min_presignatures: p.min_mine_presignatures,
                    max_presignatures: 0,
                    generation_timeout: 0,
                    other: HashMap::new(),
                },
                signature: PreviousSignatureConfig {
                    generation_timeout: 0,
                    generation_timeout_total: 0,
                    garbage_timeout: 0,
                    other: HashMap::new(),
                },
                other: HashMap::new(),
            },
            other: HashMap::new(),
        }
    }
}

/// Checkpoints as deployed on every network: keyed by `Chain`'s Borsh
/// position, which shifts when a chain is removed.
type PreviousLatestCheckpoints = IterableMap<Chain, mpc_primitives::CheckpointDigest>;

/// Checkpoint votes as deployed on every network, keyed like
/// [`PreviousLatestCheckpoints`].
#[derive(BorshDeserialize, BorshSerialize, Default)]
pub(crate) struct PreviousCheckpointVotes {
    pub votes: HashMap<mpc_primitives::CheckpointDigest, HashSet<AccountId>>,
}

impl PreviousCheckpointVotes {
    fn upgrade(self) -> CheckpointVotes {
        CheckpointVotes {
            votes: self
                .votes
                .into_iter()
                .map(|(checkpoint, voters)| (checkpoint.into(), voters))
                .collect(),
        }
    }
}

/// Moves checkpoints stored under `Chain`'s Borsh position to the chain's name.
///
/// Decoding cannot tell the layouts apart: a map's own bytes do not depend on
/// its key type. So this probes each chain's old lookup key instead, which
/// also finds an entry whose iterable key is missing, as one deployed map's
/// were. Once every entry is keyed by name, nothing is found and nothing
/// changes. The rebuilt map reuses the storage prefix, so the old one is
/// cleared and flushed first.
pub(crate) fn rekey_latest_checkpoints(latest: &mut IterableMap<String, CheckpointDigest>) {
    let mut previous = PreviousLatestCheckpoints::try_from_slice(
        &borsh::to_vec(latest).expect("a map handle serializes"),
    )
    .expect("a map handle decodes under any key type");
    let checkpoints: Vec<_> = Chain::iter()
        .into_iter()
        .filter_map(|chain| previous.get(&chain).copied())
        .collect();
    if checkpoints.is_empty() {
        return;
    }
    previous.clear();
    previous.flush();

    *latest = IterableMap::new(StorageKey::LatestCheckpointDigests);
    for checkpoint in checkpoints {
        let checkpoint = CheckpointDigest::from(checkpoint);
        latest.insert(checkpoint.chain.clone(), checkpoint);
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
#[allow(dead_code)]
pub struct PreviousRunningContractState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub candidates: Candidates,
    pub join_votes: Votes,
    pub leave_votes: Votes,
    pub threshold_votes: ThresholdVotes,
}

#[derive(BorshDeserialize, BorshSerialize)]
pub enum PreviousProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(PreviousRunningContractState),
    Resharing(ResharingContractState),
}

impl PreviousProtocolContractState {
    fn upgrade(self) -> ProtocolContractState {
        match self {
            Self::NotInitialized => ProtocolContractState::NotInitialized,
            Self::Initializing(s) => ProtocolContractState::Initializing(s),
            Self::Running(s) => ProtocolContractState::Running(RunningContractState {
                epoch: s.epoch,
                participants: s.participants,
                threshold: s.threshold,
                public_key: s.public_key,
                candidates: s.candidates,
                threshold_votes: s.threshold_votes,
                reshare_votes: ReshareVotes::new(),
            }),
            Self::Resharing(s) => ProtocolContractState::Resharing(s),
        }
    }
}

/// The state currently deployed on devnet (`dev.sig-net.testnet`): the current
/// layout with checkpoints keyed by `Chain`.
#[derive(BorshDeserialize, BorshSerialize)]
pub(crate) struct PreviousDevnet {
    pub protocol_state: ProtocolContractState,
    pub pending_requests: IterableMap<SignId, PendingRequest>,
    pub proposed_updates: ProposedUpdates,
    pub config: ProtocolConfig,
    pub latest_checkpoints: IterableMap<String, CheckpointDigest>,
    pub checkpoint_votes: PreviousCheckpointVotes,
}

impl PreviousDevnet {
    fn upgrade(self) -> MpcContract {
        MpcContract {
            protocol_state: self.protocol_state,
            pending_requests: self.pending_requests,
            proposed_updates: self.proposed_updates,
            config: self.config,
            latest_checkpoints: self.latest_checkpoints,
            checkpoint_votes: self.checkpoint_votes.upgrade(),
        }
    }
}

/// The state currently deployed on testnet (`v1.sig-net.testnet`).
#[derive(BorshDeserialize, BorshSerialize)]
pub(crate) struct PreviousTestnet {
    pub protocol_state: PreviousProtocolContractState,
    pub pending_requests: IterableMap<SignId, PendingRequest>,
    pub proposed_updates: ProposedUpdates,
    pub config: PreviousConfig,
    pub latest_checkpoints: IterableMap<String, CheckpointDigest>,
    pub checkpoint_votes: PreviousCheckpointVotes,
}

impl PreviousTestnet {
    fn upgrade(self) -> MpcContract {
        MpcContract {
            protocol_state: self.protocol_state.upgrade(),
            pending_requests: self.pending_requests,
            proposed_updates: self.proposed_updates,
            config: self.config.upgrade(),
            latest_checkpoints: self.latest_checkpoints,
            checkpoint_votes: self.checkpoint_votes.upgrade(),
        }
    }
}

/// The state currently deployed on mainnet (`v1.sig-net.near`).
#[derive(BorshDeserialize, BorshSerialize)]
pub(crate) struct PreviousMainnet {
    pub protocol_state: PreviousProtocolContractState,
    pub pending_requests: IterableMap<SignId, PendingRequest>,
    pub proposed_updates: ProposedUpdates,
    pub config: PreviousConfig,
    pub latest_checkpoints: IterableMap<String, CheckpointDigest>,
    pub checkpoint_votes: PreviousCheckpointVotes,
}

impl PreviousMainnet {
    fn upgrade(self) -> MpcContract {
        MpcContract {
            protocol_state: self.protocol_state.upgrade(),
            pending_requests: self.pending_requests,
            proposed_updates: self.proposed_updates,
            config: self.config.upgrade(),
            latest_checkpoints: self.latest_checkpoints,
            checkpoint_votes: self.checkpoint_votes.upgrade(),
        }
    }
}

/// Deserializes and upgrades contract state from raw Borsh bytes.
///
/// NOTE: Do not change this function directly. Instead, modify each of the individual
/// `Previous*` structs ([`PreviousDevnet`], [`PreviousTestnet`], [`PreviousMainnet`])
/// and their `.upgrade()` methods to reflect the deployed state of each network.
pub(crate) fn migrate(state_bytes: &[u8]) -> Result<MpcContract, Error> {
    if let Ok(current) = MpcContract::try_from_slice(state_bytes) {
        return Ok(current);
    }

    if let Ok(previous) = PreviousDevnet::try_from_slice(state_bytes) {
        return Ok(previous.upgrade());
    }

    if let Ok(previous) = PreviousTestnet::try_from_slice(state_bytes) {
        return Ok(previous.upgrade());
    }

    if let Ok(previous) = PreviousMainnet::try_from_slice(state_bytes) {
        return Ok(previous.upgrade());
    }

    Err(InvalidState::ContractStateIsMissing.message("Failed to deserialize contract state"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{CandidateInfo, StorageKey};
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use std::str::FromStr;

    /// Runs the deployed migration on `state` and returns the migrated contract.
    fn migrate_stored(state: &impl BorshSerialize) -> MpcContract {
        near_sdk::env::storage_write(b"STATE", &borsh::to_vec(state).unwrap());
        MpcContract::migrate().expect("migration should succeed")
    }

    /// A map handle over `Chain`-keyed checkpoints, typed as the current map
    /// the way decoding deployed state types it.
    fn previous_latest_checkpoints(
        checkpoints: &[mpc_primitives::CheckpointDigest],
    ) -> IterableMap<String, CheckpointDigest> {
        let mut previous: PreviousLatestCheckpoints =
            IterableMap::new(StorageKey::LatestCheckpointDigests);
        for checkpoint in checkpoints {
            previous.insert(checkpoint.chain, *checkpoint);
        }
        previous.flush();
        borsh::from_slice(&borsh::to_vec(&previous).unwrap()).unwrap()
    }

    fn devnet(
        latest_checkpoints: IterableMap<String, CheckpointDigest>,
        checkpoint_votes: PreviousCheckpointVotes,
    ) -> PreviousDevnet {
        PreviousDevnet {
            protocol_state: ProtocolContractState::NotInitialized,
            pending_requests: IterableMap::new(StorageKey::PendingRequests),
            proposed_updates: ProposedUpdates::default(),
            config: ProtocolConfig::default(),
            latest_checkpoints,
            checkpoint_votes,
        }
    }

    /// Deployed checkpoints are keyed by `Chain`'s Borsh position; migration
    /// re-keys them by name, so a later change to the chain list cannot shift them.
    #[test]
    fn migrate_rekeys_checkpoints_by_chain_name() {
        testing_env!(VMContextBuilder::new().build());

        let canton = mpc_primitives::CheckpointDigest::new(Chain::Canton, 20, [2; 32]);
        let midnight = mpc_primitives::CheckpointDigest::new(Chain::Midnight, 30, [3; 32]);
        let vote = mpc_primitives::CheckpointDigest::new(Chain::Canton, 21, [4; 32]);
        let voter: AccountId = "alice.near".parse().unwrap();
        let state = devnet(
            previous_latest_checkpoints(&[canton, midnight]),
            PreviousCheckpointVotes {
                votes: HashMap::from([(vote, HashSet::from([voter]))]),
            },
        );

        // Votes convert when the state decodes; `MpcContract::migrate` then
        // drops these, as the voter is not a participant.
        assert_eq!(
            migrate(&borsh::to_vec(&state).unwrap())
                .unwrap()
                .checkpoint_votes("Canton".to_string()),
            vec![(vote.into(), 1)]
        );

        let mut migrated = migrate_stored(&state);
        assert_eq!(
            migrated.latest_checkpoint("Canton".to_string()),
            Some(&canton.into())
        );
        assert_eq!(
            migrated.latest_checkpoint("Midnight".to_string()),
            Some(&midnight.into())
        );

        // The re-keyed map persists under the reused prefix, iterates, and a
        // second migration leaves it as it is.
        migrated.latest_checkpoints.flush();
        let mut again = migrate_stored(&migrated);
        let chains: Vec<_> = again.latest_checkpoints.keys().cloned().collect();
        assert_eq!(chains, ["Canton", "Midnight"]);
        again.latest_checkpoints.flush();
    }

    /// With no votes, deployed devnet state decodes as current state, so the
    /// re-keying cannot depend on which layout decoded.
    #[test]
    fn migrate_rekeys_checkpoints_of_state_that_decodes_as_current() {
        testing_env!(VMContextBuilder::new().build());

        let canton = mpc_primitives::CheckpointDigest::new(Chain::Canton, 20, [2; 32]);
        let state = devnet(previous_latest_checkpoints(&[canton]), Default::default());
        assert!(MpcContract::try_from_slice(&borsh::to_vec(&state).unwrap()).is_ok());

        let migrated = migrate_stored(&state);
        assert_eq!(
            migrated.latest_checkpoint("Canton".to_string()),
            Some(&canton.into())
        );
    }

    #[derive(BorshSerialize)]
    struct IterableMapValueAndIndexForTest<V> {
        value: V,
        key_index: u32,
    }

    /// A deployed map was found whose lookups resolved while its iterable keys
    /// were missing. Re-keying probes the lookups, so it keeps those entries.
    #[test]
    fn migrate_keeps_checkpoints_missing_from_the_iterable_keys() {
        testing_env!(VMContextBuilder::new().build());

        // Only the lookup half, stored under `<prefix>m` with a hashed key.
        let checkpoint = mpc_primitives::CheckpointDigest::new(Chain::Solana, 120, [7; 32]);
        let mut key = borsh::to_vec(&StorageKey::LatestCheckpointDigests).unwrap();
        key.push(b'm');
        key.extend(borsh::to_vec(&Chain::Solana).unwrap());
        let value = IterableMapValueAndIndexForTest {
            value: checkpoint,
            key_index: 0,
        };
        near_sdk::env::storage_write(
            &near_sdk::env::sha256_array(&key),
            &borsh::to_vec(&value).unwrap(),
        );
        let latest = IterableMap::new(StorageKey::LatestCheckpointDigests);
        assert!(latest.iter().next().is_none());

        let migrated = migrate_stored(&devnet(latest, Default::default()));
        let chains: Vec<_> = migrated.latest_checkpoints.keys().cloned().collect();
        assert_eq!(chains, ["Solana"]);
        assert_eq!(
            migrated.latest_checkpoint("Solana".to_string()),
            Some(&checkpoint.into())
        );
    }

    #[test]
    fn migrating_previous_running_state_preserves_candidates_and_threshold_votes() {
        testing_env!(VMContextBuilder::new().build());

        let candidate_id: AccountId = "candidate.near".parse().unwrap();
        let candidate = CandidateInfo {
            account_id: candidate_id.clone(),
            url: "https://candidate.example".to_owned(),
            cipher_pk: [7; 32],
            sign_pk: PublicKey::from_str("ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae")
                .unwrap(),
        };
        let mut candidates = Candidates::new();
        candidates.insert(candidate_id.clone(), candidate.clone());

        let mut threshold_votes = ThresholdVotes::new();
        threshold_votes.votes.insert(candidate_id.clone(), 3);

        let previous = PreviousProtocolContractState::Running(PreviousRunningContractState {
            epoch: 5,
            participants: Participants::new(),
            threshold: 2,
            public_key: candidate.sign_pk.clone(),
            candidates,
            join_votes: Votes::new(),
            leave_votes: Votes::new(),
            threshold_votes: threshold_votes.clone(),
        });

        let upgraded = previous.upgrade();
        let ProtocolContractState::Running(running) = upgraded else {
            panic!("expected running state");
        };
        assert_eq!(running.epoch, 5);
        assert_eq!(running.threshold, 2);
        assert_eq!(running.candidates.get(&candidate_id), Some(&candidate));
        assert_eq!(running.threshold_votes, threshold_votes);
        assert!(running.reshare_votes.is_empty());
    }

    #[test]
    fn migrating_previous_testnet_config() {
        testing_env!(VMContextBuilder::new().build());

        let testnet = PreviousTestnet {
            protocol_state: PreviousProtocolContractState::NotInitialized,
            pending_requests: IterableMap::new(StorageKey::PendingRequests),
            proposed_updates: ProposedUpdates::default(),
            config: PreviousConfig {
                protocol: PreviousProtocolConfig {
                    message_timeout: 1,
                    garbage_timeout: 2,
                    max_concurrent_introduction: 3,
                    max_concurrent_generation: 4,
                    triple: PreviousTripleConfig {
                        min_triples: 5,
                        max_triples: 6,
                        generation_timeout: 7,
                        other: HashMap::new(),
                    },
                    presignature: PreviousPresignatureConfig {
                        min_presignatures: 8,
                        max_presignatures: 9,
                        generation_timeout: 10,
                        other: HashMap::new(),
                    },
                    signature: PreviousSignatureConfig {
                        generation_timeout: 11,
                        generation_timeout_total: 12,
                        garbage_timeout: 13,
                        other: HashMap::new(),
                    },
                    other: HashMap::new(),
                },
                other: HashMap::new(),
            },
            latest_checkpoints: IterableMap::new(StorageKey::LatestCheckpointDigests),
            checkpoint_votes: Default::default(),
        };

        let bytes = borsh::to_vec(&testnet).unwrap();
        let migrated = migrate(&bytes).expect("migration should succeed");
        assert!(matches!(
            migrated.protocol_state,
            ProtocolContractState::NotInitialized
        ));
        assert_eq!(migrated.config.min_mine_triple_pairs, 5);
        assert_eq!(migrated.config.min_mine_presignatures, 8);
        assert_eq!(migrated.config.max_mine_generations, 3);
    }

    #[test]
    fn migrate_is_idempotent_on_current_state() {
        testing_env!(VMContextBuilder::new().build());

        let current = MpcContract {
            protocol_state: ProtocolContractState::NotInitialized,
            pending_requests: IterableMap::new(StorageKey::PendingRequests),
            proposed_updates: ProposedUpdates::default(),
            config: ProtocolConfig::default(),
            latest_checkpoints: IterableMap::new(StorageKey::LatestCheckpointDigests),
            checkpoint_votes: CheckpointVotes::new(),
        };

        let bytes = borsh::to_vec(&current).unwrap();
        let migrated = migrate(&bytes).expect("migration should succeed");
        assert!(matches!(
            migrated.protocol_state,
            ProtocolContractState::NotInitialized
        ));
    }

    #[test]
    fn migrate_is_idempotent_on_current_running_state() {
        testing_env!(VMContextBuilder::new().build());

        let candidate_id: AccountId = "candidate.near".parse().unwrap();
        let candidate = CandidateInfo {
            account_id: candidate_id.clone(),
            url: "https://candidate.example".to_owned(),
            cipher_pk: [7; 32],
            sign_pk: PublicKey::from_str("ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae")
                .unwrap(),
        };
        let mut candidates = Candidates::new();
        candidates.insert(candidate_id.clone(), candidate.clone());

        let mut reshare_votes = ReshareVotes::new();
        reshare_votes.vote(
            crate::primitives::ReshareProposal {
                joins: [candidate_id.clone()].into(),
                kicks: std::collections::BTreeSet::new(),
            },
            candidate_id.clone(),
        );

        let current = MpcContract {
            protocol_state: ProtocolContractState::Running(RunningContractState {
                epoch: 5,
                participants: Participants::new(),
                threshold: 2,
                public_key: candidate.sign_pk.clone(),
                candidates,
                threshold_votes: ThresholdVotes::new(),
                reshare_votes: reshare_votes.clone(),
            }),
            pending_requests: IterableMap::new(StorageKey::PendingRequests),
            proposed_updates: ProposedUpdates::default(),
            config: ProtocolConfig::default(),
            latest_checkpoints: IterableMap::new(StorageKey::LatestCheckpointDigests),
            checkpoint_votes: CheckpointVotes::new(),
        };

        let bytes = borsh::to_vec(&current).unwrap();
        let migrated = migrate(&bytes).expect("migration should succeed");
        let ProtocolContractState::Running(running) = migrated.protocol_state else {
            panic!("expected running state");
        };
        assert_eq!(running.epoch, 5);
        assert_eq!(running.threshold, 2);
        assert_eq!(running.reshare_votes, reshare_votes);
    }
}
