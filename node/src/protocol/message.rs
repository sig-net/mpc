use super::presignature::{self, PresignatureId};
use super::state::{GeneratingState, NodeState, ResharingState, RunningState};
use super::triple::TripleId;
use async_trait::async_trait;
use cait_sith::protocol::{InitializationError, MessageData, Participant, ProtocolError};
use near_primitives::hash::CryptoHash;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

pub trait MessageCtx {
    fn me(&self) -> Participant;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GeneratingMessage {
    pub from: Participant,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResharingMessage {
    pub epoch: u64,
    pub from: Participant,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TripleMessage {
    pub id: u64,
    pub epoch: u64,
    pub from: Participant,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PresignatureMessage {
    pub id: u64,
    pub triple0: TripleId,
    pub triple1: TripleId,
    pub epoch: u64,
    pub from: Participant,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignatureMessage {
    pub receipt_id: CryptoHash,
    pub proposer: Participant,
    pub presignature_id: PresignatureId,
    pub msg_hash: [u8; 32],
    pub epoch: u64,
    pub from: Participant,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum MpcMessage {
    Generating(GeneratingMessage),
    Resharing(ResharingMessage),
    Triple(TripleMessage),
    Presignature(PresignatureMessage),
    Signature(SignatureMessage),
}

#[derive(Default)]
pub struct MpcMessageQueue {
    generating: VecDeque<GeneratingMessage>,
    resharing_bins: HashMap<u64, VecDeque<ResharingMessage>>,
    triple_bins: HashMap<u64, HashMap<TripleId, VecDeque<TripleMessage>>>,
    presignature_bins: HashMap<u64, HashMap<PresignatureId, VecDeque<PresignatureMessage>>>,
    signature_bins: HashMap<u64, HashMap<CryptoHash, VecDeque<SignatureMessage>>>,
}

impl MpcMessageQueue {
    pub fn push(&mut self, message: MpcMessage) {
        match message {
            MpcMessage::Generating(message) => self.generating.push_back(message),
            MpcMessage::Resharing(message) => self
                .resharing_bins
                .entry(message.epoch)
                .or_default()
                .push_back(message),
            MpcMessage::Triple(message) => self
                .triple_bins
                .entry(message.epoch)
                .or_default()
                .entry(message.id)
                .or_default()
                .push_back(message),
            MpcMessage::Presignature(message) => self
                .presignature_bins
                .entry(message.epoch)
                .or_default()
                .entry(message.id)
                .or_default()
                .push_back(message),
            MpcMessage::Signature(message) => self
                .signature_bins
                .entry(message.epoch)
                .or_default()
                .entry(message.receipt_id)
                .or_default()
                .push_back(message),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum MessageHandleError {
    #[error("cait-sith initialization error: {0}")]
    CaitSithInitializationError(#[from] InitializationError),
    #[error("cait-sith protocol error: {0}")]
    CaitSithProtocolError(#[from] ProtocolError),
}

#[async_trait]
pub trait MessageHandler {
    async fn handle<C: MessageCtx + Send + Sync>(
        &mut self,
        ctx: C,
        queue: &mut MpcMessageQueue,
    ) -> Result<(), MessageHandleError>;
}

#[async_trait]
impl MessageHandler for GeneratingState {
    async fn handle<C: MessageCtx + Send + Sync>(
        &mut self,
        _ctx: C,
        queue: &mut MpcMessageQueue,
    ) -> Result<(), MessageHandleError> {
        while let Some(msg) = queue.generating.pop_front() {
            tracing::debug!("handling new generating message");
            self.protocol.message(msg.from, msg.data);
        }
        Ok(())
    }
}

#[async_trait]
impl MessageHandler for ResharingState {
    async fn handle<C: MessageCtx + Send + Sync>(
        &mut self,
        _ctx: C,
        queue: &mut MpcMessageQueue,
    ) -> Result<(), MessageHandleError> {
        let q = queue.resharing_bins.entry(self.old_epoch).or_default();
        while let Some(msg) = q.pop_front() {
            tracing::debug!("handling new resharing message");
            self.protocol.message(msg.from, msg.data);
        }
        Ok(())
    }
}

#[async_trait]
impl MessageHandler for RunningState {
    async fn handle<C: MessageCtx + Send + Sync>(
        &mut self,
        _ctx: C,
        queue: &mut MpcMessageQueue,
    ) -> Result<(), MessageHandleError> {
        for (id, queue) in queue.triple_bins.entry(self.epoch).or_default() {
            if let Some(protocol) = self.triple_manager.get_or_generate(*id)? {
                while let Some(message) = queue.pop_front() {
                    protocol.message(message.from, message.data);
                }
            }
        }
        for (id, queue) in queue.presignature_bins.entry(self.epoch).or_default() {
            let mut leftover_messages = Vec::new();
            while let Some(message) = queue.pop_front() {
                match self.presignature_manager.get_or_generate(
                    *id,
                    message.triple0,
                    message.triple1,
                    &mut self.triple_manager,
                    &self.public_key,
                    &self.private_share,
                ) {
                    Ok(protocol) => protocol.message(message.from, message.data),
                    Err(presignature::GenerationError::AlreadyGenerated) => {
                        tracing::info!(id, "presignature already generated, nothing left to do")
                    }
                    Err(presignature::GenerationError::TripleIsMissing(_)) => {
                        // Store the message until we are ready to process it
                        leftover_messages.push(message)
                    }
                    Err(presignature::GenerationError::CaitSithInitializationError(error)) => {
                        return Err(error.into())
                    }
                }
            }
            if !leftover_messages.is_empty() {
                tracing::warn!(
                    msg_count = leftover_messages.len(),
                    "unable to process messages, storing for future"
                );
                queue.extend(leftover_messages);
            }
        }
        for (receipt_id, queue) in queue.signature_bins.entry(self.epoch).or_default() {
            let mut leftover_messages = Vec::new();
            while let Some(message) = queue.pop_front() {
                tracing::info!(
                    presignature_id = message.presignature_id,
                    "new signature message"
                );
                // if !self
                //     .sign_queue
                //     .read()
                //     .await
                //     .contains(message.proposer, receipt_id.clone())
                // {
                //     leftover_messages.push(message);
                //     continue;
                // };
                // TODO: Validate that the message matches our sign_queue
                match self.signature_manager.get_or_generate(
                    *receipt_id,
                    message.proposer,
                    message.presignature_id,
                    message.msg_hash,
                    &mut self.presignature_manager,
                )? {
                    Some(protocol) => protocol.message(message.from, message.data),
                    None => {
                        // Store the message until we are ready to process it
                        leftover_messages.push(message)
                    }
                }
            }
            if !leftover_messages.is_empty() {
                tracing::warn!(
                    msg_count = leftover_messages.len(),
                    "unable to process messages, storing for future"
                );
                queue.extend(leftover_messages);
            }
        }
        Ok(())
    }
}

#[async_trait]
impl MessageHandler for NodeState {
    async fn handle<C: MessageCtx + Send + Sync>(
        &mut self,
        ctx: C,
        queue: &mut MpcMessageQueue,
    ) -> Result<(), MessageHandleError> {
        match self {
            NodeState::Generating(state) => state.handle(ctx, queue).await,
            NodeState::Resharing(state) => state.handle(ctx, queue).await,
            NodeState::Running(state) => state.handle(ctx, queue).await,
            _ => {
                tracing::debug!("skipping message processing");
                Ok(())
            }
        }
    }
}
