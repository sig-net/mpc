use super::contract::primitives::{ParticipantMap, Participants};
use super::presignature::PresignatureManager;
use super::signature::SignatureManager;
use super::triple::TripleManager;
use crate::types::{KeygenProtocol, ReshareProtocol, SecretKeyShare};

use cait_sith::protocol::Participant;
use mpc_crypto::PublicKey;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

#[derive(Clone, Serialize, Deserialize)]
pub struct PersistentNodeData {
    pub epoch: u64,
    pub private_share: SecretKeyShare,
    pub public_key: PublicKey,
}

impl fmt::Debug for PersistentNodeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistentNodeData")
            .field("epoch", &self.epoch)
            .field("public_key", &self.public_key)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct StartedState {
    pub persistent_node_data: Option<PersistentNodeData>,
}

#[derive(Clone)]
pub struct GeneratingState {
    pub me: Participant,
    pub participants: Participants,
    pub threshold: usize,
    pub protocol: KeygenProtocol,
}

#[derive(Clone)]
pub struct WaitingForConsensusState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub private_share: SecretKeyShare,
    pub public_key: PublicKey,
}

impl fmt::Debug for WaitingForConsensusState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WaitingForConsensusState")
            .field("epoch", &self.epoch)
            .field("threshold", &self.threshold)
            .field("public_key", &self.public_key)
            .field("participants", &self.participants)
            .finish()
    }
}

#[derive(Clone)]
pub struct RunningState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub private_share: SecretKeyShare,
    pub public_key: PublicKey,
    pub triple_manager: TripleManager,
    pub presignature_manager: Arc<RwLock<PresignatureManager>>,
    pub signature_manager: Arc<RwLock<SignatureManager>>,
}

#[derive(Clone)]
pub struct ResharingState {
    pub me: Participant,
    pub old_epoch: u64,
    pub old_participants: Participants,
    pub new_participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub protocol: ReshareProtocol,
    pub timestamp: Instant,
}

#[derive(Clone)]
pub struct JoiningState {
    pub participants: Participants,
    pub public_key: PublicKey,
}

#[derive(Clone, Default)]
#[allow(clippy::large_enum_variant)]
pub enum NodeState {
    #[default]
    Starting,
    Started(StartedState),
    Generating(GeneratingState),
    WaitingForConsensus(WaitingForConsensusState),
    Running(RunningState),
    Resharing(ResharingState),
    Joining(JoiningState),
}

impl Display for NodeState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            NodeState::Starting => write!(f, "Starting"),
            NodeState::Started(_) => write!(f, "Started"),
            NodeState::Generating(_) => write!(f, "Generating"),
            NodeState::WaitingForConsensus(_) => write!(f, "WaitingForConsensus"),
            NodeState::Running(_) => write!(f, "Running"),
            NodeState::Resharing(_) => write!(f, "Resharing"),
            NodeState::Joining(_) => write!(f, "Joining"),
        }
    }
}

impl NodeState {
    pub fn participants(&self) -> ParticipantMap {
        match self {
            NodeState::Generating(state) => ParticipantMap::One(state.participants.clone()),
            NodeState::WaitingForConsensus(state) => {
                ParticipantMap::One(state.participants.clone())
            }
            NodeState::Running(state) => ParticipantMap::One(state.participants.clone()),
            NodeState::Resharing(state) => ParticipantMap::Two(
                state.new_participants.clone(),
                state.old_participants.clone(),
            ),
            NodeState::Joining(state) => ParticipantMap::One(state.participants.clone()),
            _ => ParticipantMap::Zero,
        }
    }
}
