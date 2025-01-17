use super::contract::primitives::{ParticipantInfo, Participants};
use super::message::MessageError;
use super::presignature::PresignatureManager;
use super::signature::SignatureManager;
use super::triple::TripleManager;
use crate::types::{KeygenProtocol, ReshareProtocol, SecretKeyShare};

use cait_sith::protocol::Participant;
use crypto_shared::PublicKey;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
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

impl GeneratingState {
    pub fn fetch_participant(&self, p: &Participant) -> Result<&ParticipantInfo, MessageError> {
        fetch_participant(p, &self.participants)
    }
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

impl WaitingForConsensusState {
    pub fn fetch_participant(&self, p: &Participant) -> Result<&ParticipantInfo, MessageError> {
        fetch_participant(p, &self.participants)
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

impl RunningState {
    pub fn fetch_participant(&self, p: &Participant) -> Result<&ParticipantInfo, MessageError> {
        fetch_participant(p, &self.participants)
    }
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
}

impl ResharingState {
    pub fn fetch_participant(&self, p: &Participant) -> Result<&ParticipantInfo, MessageError> {
        fetch_participant(p, &self.new_participants)
            .or_else(|_| fetch_participant(p, &self.old_participants))
    }
}

#[derive(Clone)]
pub struct JoiningState {
    pub participants: Participants,
    pub public_key: PublicKey,
}

impl JoiningState {
    pub fn fetch_participant(&self, p: &Participant) -> Result<&ParticipantInfo, MessageError> {
        fetch_participant(p, &self.participants)
    }
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
    pub fn fetch_participant(&self, p: &Participant) -> Result<&ParticipantInfo, MessageError> {
        match self {
            NodeState::Running(state) => state.fetch_participant(p),
            NodeState::Generating(state) => state.fetch_participant(p),
            NodeState::WaitingForConsensus(state) => state.fetch_participant(p),
            NodeState::Resharing(state) => state.fetch_participant(p),
            NodeState::Joining(state) => state.fetch_participant(p),
            _ => Err(MessageError::UnknownParticipant(*p)),
        }
    }

    pub fn participants(&self) -> Option<&Participants> {
        match self {
            NodeState::Generating(state) => Some(&state.participants),
            NodeState::WaitingForConsensus(state) => Some(&state.participants),
            NodeState::Running(state) => Some(&state.participants),
            NodeState::Resharing(state) => Some(&state.new_participants),
            NodeState::Joining(state) => Some(&state.participants),
            _ => None,
        }
    }
}

fn fetch_participant<'a>(
    p: &Participant,
    participants: &'a Participants,
) -> Result<&'a ParticipantInfo, MessageError> {
    participants
        .get(p)
        .ok_or_else(|| MessageError::UnknownParticipant(*p))
}
