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
    Candidates, CheckpointVotes, Participants, PendingRequest, ReshareVotes, ThresholdVotes, Votes,
};
use crate::state::{
    InitializingContractState, ProtocolContractState, ResharingContractState, RunningContractState,
};
use crate::update::ProposedUpdates;
use crate::MpcContract;

use borsh::{BorshDeserialize, BorshSerialize};
use mpc_primitives::{Chain, CheckpointDigest, SignId};
use near_sdk::store::IterableMap;
use near_sdk::PublicKey;
use std::collections::HashMap;

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
        ProtocolConfig {
            min_mine_triple_pairs: p.triple.min_triples,
            min_mine_presignatures: p.presignature.min_presignatures,
            max_mine_generations: p.max_concurrent_introduction,
        }
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
/// protocol state with the previous config layout.
#[derive(BorshDeserialize, BorshSerialize)]
pub(crate) struct PreviousDevnet {
    pub protocol_state: ProtocolContractState,
    pub pending_requests: IterableMap<SignId, PendingRequest>,
    pub proposed_updates: ProposedUpdates,
    pub config: PreviousConfig,
    pub latest_checkpoints: IterableMap<Chain, CheckpointDigest>,
    pub checkpoint_votes: CheckpointVotes,
}

impl PreviousDevnet {
    fn upgrade(self) -> MpcContract {
        MpcContract {
            protocol_state: self.protocol_state,
            pending_requests: self.pending_requests,
            proposed_updates: self.proposed_updates,
            config: self.config.upgrade(),
            latest_checkpoints: self.latest_checkpoints,
            checkpoint_votes: self.checkpoint_votes,
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
    pub latest_checkpoints: IterableMap<Chain, CheckpointDigest>,
    pub checkpoint_votes: CheckpointVotes,
}

impl PreviousTestnet {
    fn upgrade(self) -> MpcContract {
        MpcContract {
            protocol_state: self.protocol_state.upgrade(),
            pending_requests: self.pending_requests,
            proposed_updates: self.proposed_updates,
            config: self.config.upgrade(),
            latest_checkpoints: self.latest_checkpoints,
            checkpoint_votes: self.checkpoint_votes,
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
    pub latest_checkpoints: IterableMap<Chain, CheckpointDigest>,
    pub checkpoint_votes: CheckpointVotes,
}

impl PreviousMainnet {
    fn upgrade(self) -> MpcContract {
        MpcContract {
            protocol_state: self.protocol_state.upgrade(),
            pending_requests: self.pending_requests,
            proposed_updates: self.proposed_updates,
            config: self.config.upgrade(),
            latest_checkpoints: self.latest_checkpoints,
            checkpoint_votes: self.checkpoint_votes,
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
    use near_sdk::AccountId;
    use std::str::FromStr;

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
    fn migrating_previous_devnet_state() {
        testing_env!(VMContextBuilder::new().build());

        let devnet = PreviousDevnet {
            protocol_state: ProtocolContractState::NotInitialized,
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
            checkpoint_votes: CheckpointVotes::new(),
        };

        let bytes = borsh::to_vec(&devnet).unwrap();
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
