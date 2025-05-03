use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash as _};

use cait_sith::protocol::{MessageData, Participant};
use serde::{Deserialize, Serialize};

use crate::protocol::posit::PositAction;
use crate::protocol::presignature::{FullPresignatureId, PresignatureId};
use crate::protocol::triple::TripleId;
use crate::types::Epoch;
use mpc_keys::hpke;
use mpc_primitives::SignId;

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum Protocols {
    Generating,
    Resharing,
    Triple,
    Presignature,
    Signature,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum PositProtocolId {
    Triple(TripleId),
    Presignature(FullPresignatureId),
    Signature(SignId, PresignatureId),
}

/// The message associated with positing a new protocol.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct PositMessage {
    pub id: PositProtocolId,
    pub from: Participant,
    pub action: PositAction,
}

impl PositMessage {
    pub fn data_len(&self) -> usize {
        match &self.action {
            PositAction::Propose => 0,
            PositAction::Start(participants) => {
                participants.len() * std::mem::size_of::<Participant>()
            }
            PositAction::Accept => 0,
            PositAction::Reject => 0,
            PositAction::Abort => 0,
        }
    }
}

impl From<PositMessage> for Message {
    fn from(msg: PositMessage) -> Self {
        Message::Posit(msg)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct GeneratingMessage {
    pub from: Participant,
    #[serde(with = "serde_bytes")]
    pub data: MessageData,
}

impl From<GeneratingMessage> for Message {
    fn from(msg: GeneratingMessage) -> Self {
        Message::Generating(msg)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ResharingMessage {
    pub epoch: Epoch,
    pub from: Participant,
    #[serde(with = "serde_bytes")]
    pub data: MessageData,
}

impl From<ResharingMessage> for Message {
    fn from(msg: ResharingMessage) -> Self {
        Message::Resharing(msg)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct TripleMessage {
    pub id: u64,
    pub epoch: Epoch,
    pub from: Participant,
    #[serde(with = "serde_bytes")]
    pub data: MessageData,
    // UNIX timestamp as seconds since the epoch
    pub timestamp: u64,
}

impl From<TripleMessage> for Message {
    fn from(msg: TripleMessage) -> Self {
        Message::Triple(msg)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct PresignatureMessage {
    pub id: u64,
    pub triple0: TripleId,
    pub triple1: TripleId,
    pub epoch: Epoch,
    pub from: Participant,
    #[serde(with = "serde_bytes")]
    pub data: MessageData,
    // UNIX timestamp as seconds since the epoch
    pub timestamp: u64,
}

impl From<PresignatureMessage> for Message {
    fn from(msg: PresignatureMessage) -> Self {
        Message::Presignature(msg)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SignatureMessage {
    pub id: SignId,
    pub proposer: Participant,
    pub presignature_id: PresignatureId,
    pub epoch: u64,
    pub from: Participant,
    #[serde(with = "serde_bytes")]
    pub data: MessageData,
    // UNIX timestamp as seconds since the epoch
    pub timestamp: u64,
}

impl From<SignatureMessage> for Message {
    fn from(msg: SignatureMessage) -> Self {
        Message::Signature(msg)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum Message {
    Posit(PositMessage),
    Generating(GeneratingMessage),
    Resharing(ResharingMessage),
    Triple(TripleMessage),
    Presignature(PresignatureMessage),
    Signature(SignatureMessage),

    /// Future compatibility with other messages. If in the future, we were to add a new
    /// enum variant here, we can still deserialize the message as Unknown.
    #[serde(untagged)]
    Unknown(HashMap<String, ciborium::Value>),
}

impl Message {
    pub const fn typename(&self) -> &'static str {
        match self {
            Message::Posit(_) => "Proposal",
            Message::Generating(_) => "Generating",
            Message::Resharing(_) => "Resharing",
            Message::Triple(_) => "Triple",
            Message::Presignature(_) => "Presignature",
            Message::Signature(_) => "Signature",
            Message::Unknown(_) => "Unknown",
        }
    }

    /// The size of the message in bytes.
    pub fn size(&self) -> usize {
        match self {
            Message::Posit(proposal) => std::mem::size_of::<PositMessage>() + proposal.data_len(),
            Message::Generating(msg) => std::mem::size_of::<GeneratingMessage>() + msg.data.len(),
            Message::Resharing(msg) => std::mem::size_of::<ResharingMessage>() + msg.data.len(),
            Message::Triple(msg) => std::mem::size_of::<TripleMessage>() + msg.data.len(),
            Message::Presignature(msg) => {
                std::mem::size_of::<PresignatureMessage>() + msg.data.len()
            }
            Message::Signature(msg) => std::mem::size_of::<SignatureMessage>() + msg.data.len(),
            Message::Unknown(_msg) => usize::MAX,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum MessageError {
    #[error("unknown participant: {0:?}")]
    UnknownParticipant(Participant),
    #[error(transparent)]
    JsonConversion(#[from] serde_json::Error),
    #[error("cbor: {0:?}")]
    CborConversion(String),
    #[error("encryption failed: {0}")]
    Encryption(#[from] hpke::Error),
    #[error("verify failed: {0}")]
    Verification(&'static str),
    #[error("idempotent check failed")]
    Idempotent,
}

pub trait ProtocolType {
    const PROTOCOL: Protocols;
}

impl ProtocolType for GeneratingMessage {
    const PROTOCOL: Protocols = Protocols::Generating;
}

impl ProtocolType for ResharingMessage {
    const PROTOCOL: Protocols = Protocols::Resharing;
}

impl ProtocolType for TripleMessage {
    const PROTOCOL: Protocols = Protocols::Triple;
}

impl ProtocolType for PresignatureMessage {
    const PROTOCOL: Protocols = Protocols::Presignature;
}

impl ProtocolType for SignatureMessage {
    const PROTOCOL: Protocols = Protocols::Signature;
}

impl ProtocolType for (SignId, PresignatureId) {
    const PROTOCOL: Protocols = Protocols::Signature;
}

pub trait MessageFilterId: ProtocolType {
    fn id(&self) -> u64;
}

impl MessageFilterId for TripleMessage {
    fn id(&self) -> u64 {
        self.id
    }
}

impl MessageFilterId for PresignatureMessage {
    fn id(&self) -> u64 {
        self.id
    }
}

impl MessageFilterId for SignatureMessage {
    fn id(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.id.hash(&mut hasher);
        self.presignature_id.hash(&mut hasher);
        std::hash::Hasher::finish(&hasher)
    }
}

impl MessageFilterId for (SignId, PresignatureId) {
    fn id(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.0.hash(&mut hasher);
        self.1.hash(&mut hasher);
        std::hash::Hasher::finish(&hasher)
    }
}
