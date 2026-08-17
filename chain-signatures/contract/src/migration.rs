use crate::config::Config;
use crate::errors::{Error, InvalidState};
use crate::primitives::{
    CandidateInfo, Candidates, CheckpointVotes, Participants, PendingRequest, StorageKey,
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

fn migrate_candidates(candidates: Candidates) -> IterableMap<AccountId, CandidateInfo> {
    let mut migrated = IterableMap::new(StorageKey::Candidates);
    for (account_id, info) in candidates.candidates {
        migrated.insert(account_id, info);
    }
    migrated
}

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
                candidates: migrate_candidates(state.candidates),
                join_votes: state.join_votes,
                leave_votes: state.leave_votes,
                threshold_votes: ThresholdVotes::new(),
            })
        }
        OldProtocolContractState::Resharing(state) => ProtocolContractState::Resharing(state),
    }
}

#[derive(BorshDeserialize)]
struct InlineRunningContractState {
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
enum InlineProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(InlineRunningContractState),
    Resharing(ResharingContractState),
}

fn upgrade_inline_protocol_state(old: InlineProtocolContractState) -> ProtocolContractState {
    match old {
        InlineProtocolContractState::NotInitialized => ProtocolContractState::NotInitialized,
        InlineProtocolContractState::Initializing(state) => {
            ProtocolContractState::Initializing(state)
        }
        InlineProtocolContractState::Running(state) => {
            ProtocolContractState::Running(RunningContractState {
                epoch: state.epoch,
                participants: state.participants,
                threshold: state.threshold,
                public_key: state.public_key,
                candidates: migrate_candidates(state.candidates),
                join_votes: state.join_votes,
                leave_votes: state.leave_votes,
                threshold_votes: state.threshold_votes,
            })
        }
        InlineProtocolContractState::Resharing(state) => ProtocolContractState::Resharing(state),
    }
}

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
        MpcContract {
            protocol_state: upgrade_inline_protocol_state(self.protocol_state),
            pending_requests: self.pending_requests,
            proposed_updates: self.proposed_updates,
            config: self.config,
            latest_checkpoints: self.latest_checkpoints,
            checkpoint_votes: self.checkpoint_votes,
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

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use std::str::FromStr;

    #[test]
    fn migrating_inline_running_state_preserves_candidates_and_join_votes() {
        testing_env!(VMContextBuilder::new().build());

        let candidate_id: AccountId = "candidate.near".parse().unwrap();
        let voter_id: AccountId = "voter.near".parse().unwrap();
        let candidate = CandidateInfo {
            account_id: candidate_id.clone(),
            url: "https://candidate.example".to_owned(),
            cipher_pk: [7; 32],
            sign_pk: PublicKey::from_str("ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae")
                .unwrap(),
        };
        let mut candidates = Candidates::new();
        candidates.insert(candidate_id.clone(), candidate.clone());
        let mut join_votes = Votes::new();
        join_votes
            .entry(candidate_id.clone())
            .insert(voter_id.clone());

        let migrated = upgrade_inline_protocol_state(InlineProtocolContractState::Running(
            InlineRunningContractState {
                epoch: 3,
                participants: Participants::new(),
                threshold: 2,
                public_key: candidate.sign_pk.clone(),
                candidates,
                join_votes,
                leave_votes: Votes::new(),
                threshold_votes: ThresholdVotes::new(),
            },
        ));

        let ProtocolContractState::Running(running) = migrated else {
            panic!("expected running state");
        };
        assert_eq!(running.candidates.get(&candidate_id), Some(&candidate));
        assert!(running
            .join_votes
            .votes
            .get(&candidate_id)
            .is_some_and(|votes| votes.contains(&voter_id)));
    }
}
