pub mod primitives;

use self::primitives::{Candidates, Participants, PkVotes};
use crate::{rpc::GovernanceInfo, util::NearPublicKeyExt as _};

use mpc_contract::ProtocolContractStateView;
use mpc_crypto::PublicKey;
use near_account_id::AccountId;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, str::FromStr};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct InitializingContractState {
    pub candidates: Candidates,
    pub threshold: usize,
    pub pk_votes: PkVotes,
}

impl From<mpc_contract::InitializingContractStateView> for InitializingContractState {
    fn from(value: mpc_contract::InitializingContractStateView) -> Self {
        InitializingContractState {
            candidates: value.candidates.into(),
            threshold: value.threshold,
            pk_votes: value.pk_votes.into(),
        }
    }
}

/// The node's model of the contract's `Running` state, mirroring the lean
/// `RunningContractStateView` the contract exposes: only the fields a node
/// consumes. The stored contract state additionally holds vote maps
/// (`candidates`, `join_votes`, `leave_votes`, `threshold_votes`) that no node
/// reads from the polled state, so they are not carried here — a joining node
/// reads its own candidacy via the `candidate_status` view instead.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct RunningContractState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
}

impl From<mpc_contract::RunningContractStateView> for RunningContractState {
    fn from(value: mpc_contract::RunningContractStateView) -> Self {
        RunningContractState {
            epoch: value.epoch,
            participants: value.participants.into(),
            threshold: value.threshold,
            public_key: value.public_key.into_affine_point(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct ResharingContractState {
    pub old_epoch: u64,
    pub old_participants: Participants,
    pub new_participants: Participants,
    /// Threshold of the current shares held by `old_participants`.
    pub threshold: usize,
    /// Threshold baked into the reshared shares for `new_participants`.
    pub new_threshold: usize,
    pub public_key: PublicKey,
    pub finished_votes: HashSet<AccountId>,
    pub cancel_votes: HashSet<AccountId>,
}

impl From<mpc_contract::ResharingContractState> for ResharingContractState {
    fn from(contract_state: mpc_contract::ResharingContractState) -> Self {
        ResharingContractState {
            old_epoch: contract_state.old_epoch,
            old_participants: contract_state.old_participants.into(),
            new_participants: contract_state.new_participants.into(),
            threshold: contract_state.threshold,
            new_threshold: contract_state.new_threshold,
            public_key: contract_state.public_key.into_affine_point(),
            finished_votes: contract_state
                .finished_votes
                .into_iter()
                .map(|acc_id| AccountId::from_str(acc_id.as_ref()).unwrap())
                .collect(),
            cancel_votes: contract_state
                .cancel_votes
                .into_iter()
                .map(|acc_id| AccountId::from_str(acc_id.as_ref()).unwrap())
                .collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProtocolState {
    Initializing(InitializingContractState),
    Running(RunningContractState),
    Resharing(ResharingContractState),
}

impl ProtocolState {
    pub fn public_key(&self) -> Option<&PublicKey> {
        match self {
            ProtocolState::Initializing { .. } => None,
            ProtocolState::Running(RunningContractState { public_key, .. }) => Some(public_key),
            ProtocolState::Resharing(ResharingContractState { public_key, .. }) => Some(public_key),
        }
    }

    pub fn threshold(&self) -> usize {
        match self {
            ProtocolState::Initializing(InitializingContractState { threshold, .. }) => *threshold,
            ProtocolState::Running(RunningContractState { threshold, .. }) => *threshold,
            ProtocolState::Resharing(ResharingContractState { threshold, .. }) => *threshold,
        }
    }

    pub fn governance(&self, account_id: &AccountId) -> Option<GovernanceInfo> {
        match self {
            ProtocolState::Running(state) => Some(GovernanceInfo {
                me: *state.participants.find_participant(account_id)?,
                threshold: state.threshold,
                epoch: state.epoch,
                public_key: state.public_key,
                participants: state.participants.keys().copied().collect(),
                is_running: true,
            }),
            ProtocolState::Resharing(state) => Some(GovernanceInfo {
                me: *state.new_participants.find_participant(account_id)?,
                threshold: state.new_threshold,
                epoch: state.old_epoch + 1,
                public_key: state.public_key,
                participants: state.new_participants.keys().copied().collect(),
                is_running: false,
            }),
            ProtocolState::Initializing(_) => None,
        }
    }
}

impl TryFrom<ProtocolContractStateView> for ProtocolState {
    type Error = ();

    fn try_from(value: ProtocolContractStateView) -> Result<Self, Self::Error> {
        match value {
            ProtocolContractStateView::Initializing(state) => {
                Ok(ProtocolState::Initializing(state.into()))
            }
            ProtocolContractStateView::Running(state) => Ok(ProtocolState::Running(state.into())),
            ProtocolContractStateView::Resharing(state) => {
                Ok(ProtocolState::Resharing(state.into()))
            }
            ProtocolContractStateView::NotInitialized => Err(()),
        }
    }
}
