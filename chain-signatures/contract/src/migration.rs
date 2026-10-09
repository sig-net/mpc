use crate::config::Config;
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

/// The state currently deployed on devnet (`dev.sig-net.testnet`).
#[derive(BorshDeserialize, BorshSerialize)]
pub(crate) struct PreviousDevnet {
    pub protocol_state: PreviousProtocolContractState,
    pub pending_requests: IterableMap<SignId, PendingRequest>,
    pub proposed_updates: ProposedUpdates,
    pub config: Config,
    pub latest_checkpoints: IterableMap<Chain, CheckpointDigest>,
    pub checkpoint_votes: CheckpointVotes,
}

impl PreviousDevnet {
    fn upgrade(self) -> MpcContract {
        MpcContract {
            protocol_state: self.protocol_state.upgrade(),
            pending_requests: self.pending_requests,
            proposed_updates: self.proposed_updates,
            config: self.config,
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
    pub config: Config,
    pub latest_checkpoints: IterableMap<Chain, CheckpointDigest>,
    pub checkpoint_votes: CheckpointVotes,
}

impl PreviousTestnet {
    fn upgrade(self) -> MpcContract {
        MpcContract {
            protocol_state: self.protocol_state.upgrade(),
            pending_requests: self.pending_requests,
            proposed_updates: self.proposed_updates,
            config: self.config,
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
    pub config: Config,
    pub latest_checkpoints: IterableMap<Chain, CheckpointDigest>,
    pub checkpoint_votes: CheckpointVotes,
}

impl PreviousMainnet {
    fn upgrade(self) -> MpcContract {
        MpcContract {
            protocol_state: self.protocol_state.upgrade(),
            pending_requests: self.pending_requests,
            proposed_updates: self.proposed_updates,
            config: self.config,
            latest_checkpoints: self.latest_checkpoints,
            checkpoint_votes: self.checkpoint_votes,
        }
    }
}

pub(crate) fn migrate(state_bytes: &[u8]) -> Result<MpcContract, Error> {
    if let Ok(previous) = PreviousDevnet::try_from_slice(state_bytes) {
        return Ok(previous.upgrade());
    }

    if let Ok(previous) = PreviousTestnet::try_from_slice(state_bytes) {
        return Ok(previous.upgrade());
    }

    if let Ok(previous) = PreviousMainnet::try_from_slice(state_bytes) {
        return Ok(previous.upgrade());
    }

    if let Ok(current) = MpcContract::try_from_slice(state_bytes) {
        return Ok(current);
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
            protocol_state: PreviousProtocolContractState::NotInitialized,
            pending_requests: IterableMap::new(StorageKey::PendingRequests),
            proposed_updates: ProposedUpdates::default(),
            config: Config::default(),
            latest_checkpoints: IterableMap::new(StorageKey::LatestCheckpointDigests),
            checkpoint_votes: CheckpointVotes::new(),
        };

        let bytes = borsh::to_vec(&devnet).unwrap();
        let migrated = migrate(&bytes).expect("migration should succeed");
        assert!(matches!(
            migrated.protocol_state,
            ProtocolContractState::NotInitialized
        ));
    }

    #[test]
    fn migrate_is_idempotent_on_current_state() {
        testing_env!(VMContextBuilder::new().build());

        let current = MpcContract {
            protocol_state: ProtocolContractState::NotInitialized,
            pending_requests: IterableMap::new(StorageKey::PendingRequests),
            proposed_updates: ProposedUpdates::default(),
            config: Config::default(),
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
}
