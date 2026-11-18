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
use near_sdk::env;

use borsh::{BorshDeserialize, BorshSerialize};
use mpc_primitives::{Chain, CheckpointDigest, SignId};
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

/// Checkpoint votes as stored before the one-vote-per-node-per-height layout:
/// keyed by digest, with the set of voters that backed it. A voter could appear
/// under several digests at the same `(chain, height)` — either because it
/// changed its mind (old storage kept both) or because it was byzantine.
#[derive(BorshDeserialize, BorshSerialize)]
pub(crate) struct PreviousCheckpointVotes {
    pub votes: HashMap<CheckpointDigest, HashSet<AccountId>>,
}

impl PreviousCheckpointVotes {
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self {
            votes: HashMap::new(),
        }
    }

    /// Convert to the current layout, keeping at most one vote per
    /// `(chain, height, voter)`.
    ///
    /// The old layout has no notion of "latest" vote, so a voter with several
    /// digests at one height cannot be migrated faithfully. We keep the
    /// lexicographically smallest digest: deterministic on every node, and
    /// still exactly one vote for that voter (no tally inflation). Such
    /// conflicts are logged rather than silently dropped. Honest votes — the
    /// overwhelming majority — carry over unchanged. `latest_checkpoints` is
    /// not touched.
    fn upgrade(self) -> CheckpointVotes {
        let mut by_voter: HashMap<(Chain, u64, AccountId), Vec<[u8; 32]>> = HashMap::new();
        for (checkpoint, voters) in self.votes {
            for voter in voters {
                by_voter
                    .entry((checkpoint.chain, checkpoint.height, voter))
                    .or_default()
                    .push(checkpoint.digest);
            }
        }

        let mut upgraded = CheckpointVotes::new();
        for ((chain, height, voter), mut digests) in by_voter {
            digests.sort_unstable();
            digests.dedup();
            if digests.len() > 1 {
                env::log_str(
                    &serde_json::json!({
                        "event": "checkpoint_vote_migration_conflict",
                        "chain": chain,
                        "height": height,
                        "voter": voter.as_str(),
                        "digest_count": digests.len(),
                    })
                    .to_string(),
                );
            }
            upgraded.votes.insert((chain, height, voter), digests[0]);
        }
        upgraded
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
    pub checkpoint_votes: PreviousCheckpointVotes,
}

impl PreviousDevnet {
    fn upgrade(self) -> MpcContract {
        MpcContract {
            protocol_state: self.protocol_state,
            pending_requests: self.pending_requests,
            proposed_updates: self.proposed_updates,
            config: self.config.upgrade(),
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
    pub latest_checkpoints: IterableMap<Chain, CheckpointDigest>,
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
    pub latest_checkpoints: IterableMap<Chain, CheckpointDigest>,
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
            checkpoint_votes: PreviousCheckpointVotes::new(),
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
    fn migrating_old_checkpoint_votes_keeps_one_vote_per_voter_per_height() {
        testing_env!(VMContextBuilder::new().build());

        let alice: AccountId = "alice.near".parse().unwrap();
        let bob: AccountId = "bob.near".parse().unwrap();
        let chain = Chain::Solana;
        let height = 42;
        let digest_a = [1u8; 32];
        let digest_b = [2u8; 32];

        let mut votes = HashMap::new();
        votes.insert(
            CheckpointDigest::new(chain, height, digest_a),
            HashSet::from([alice.clone()]),
        );
        votes.insert(
            CheckpointDigest::new(chain, height, digest_b),
            HashSet::from([bob.clone()]),
        );
        // Old state could hold the same voter under two digests at one height
        // (changed mind, or byzantine). The upgrade must collapse it to one.
        votes
            .get_mut(&CheckpointDigest::new(chain, height, digest_b))
            .unwrap()
            .insert(alice.clone());

        let upgraded = PreviousCheckpointVotes { votes }.upgrade();

        // alice's conflict resolves deterministically to the smaller digest and
        // bob keeps the other: one vote per voter, no tally inflation.
        assert_eq!(upgraded.count(chain, height, digest_a), 1);
        assert_eq!(upgraded.count(chain, height, digest_b), 1);
        assert_eq!(upgraded.votes.len(), 2);
        assert_eq!(
            upgraded.for_chain(chain),
            vec![
                (CheckpointDigest::new(chain, height, digest_a), 1),
                (CheckpointDigest::new(chain, height, digest_b), 1),
            ]
        );
        assert!(near_sdk::test_utils::get_logs()
            .iter()
            .any(|line| line.contains("checkpoint_vote_migration_conflict")));
    }

    #[test]
    fn migrate_contract_with_old_checkpoint_votes() {
        testing_env!(VMContextBuilder::new().build());

        let alice: AccountId = "alice.near".parse().unwrap();
        let chain = Chain::Solana;
        let checkpoint = CheckpointDigest::new(chain, 7, [4u8; 32]);
        let previous = PreviousDevnet {
            protocol_state: ProtocolContractState::NotInitialized,
            pending_requests: IterableMap::new(StorageKey::PendingRequests),
            proposed_updates: ProposedUpdates::default(),
            config: ProtocolConfig::default().into(),
            latest_checkpoints: IterableMap::new(StorageKey::LatestCheckpointDigests),
            checkpoint_votes: PreviousCheckpointVotes {
                votes: HashMap::from([(checkpoint, HashSet::from([alice]))]),
            },
        };

        // The old bytes must not deserialize as the new MpcContract; the
        // migration falls through to PreviousDevnet and upgrades the votes.
        let migrated = migrate(&borsh::to_vec(&previous).unwrap()).unwrap();
        assert_eq!(migrated.checkpoint_votes.count(chain, 7, [4u8; 32]), 1);
        assert_eq!(
            migrated.checkpoint_votes.for_chain(chain),
            vec![(checkpoint, 1)]
        );
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
