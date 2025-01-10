use super::cryptography::CryptographicError;
use super::presignature::{GenerationError, PresignatureId};
use super::signature::SignRequestIdentifier;
use super::state::{GeneratingState, NodeState, ResharingState, RunningState};
use super::triple::TripleId;
use crate::gcp::error::SecretStorageError;
use crate::http_client::{NodeClient, SendError};
use crate::indexer::ContractSignRequest;
use crate::protocol::Config;
use crate::protocol::MeshState;
use crate::types::Epoch;
use crate::util;

use async_trait::async_trait;
use cait_sith::protocol::{InitializationError, MessageData, Participant, ProtocolError};
use k256::Scalar;
use mpc_keys::hpke::{self, Ciphered};
use near_crypto::Signature;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::{mpsc, RwLock};

pub const MAX_MESSAGE_INCOMING: usize = 1024 * 1024;
pub const MAX_MESSAGE_OUTGOING: usize = 1024 * 1024;

#[async_trait::async_trait]
pub trait MessageCtx {
    async fn me(&self) -> Participant;
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct GeneratingMessage {
    pub from: Participant,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ResharingMessage {
    pub epoch: Epoch,
    pub from: Participant,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct TripleMessage {
    pub id: u64,
    pub epoch: Epoch,
    pub from: Participant,
    pub data: MessageData,
    // UNIX timestamp as seconds since the epoch
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct PresignatureMessage {
    pub id: u64,
    pub triple0: TripleId,
    pub triple1: TripleId,
    pub epoch: Epoch,
    pub from: Participant,
    pub data: MessageData,
    // UNIX timestamp as seconds since the epoch
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct SignatureMessage {
    pub request_id: [u8; 32],
    pub proposer: Participant,
    pub presignature_id: PresignatureId,
    pub request: ContractSignRequest,
    pub epsilon: Scalar,
    pub entropy: [u8; 32],
    pub epoch: u64,
    pub from: Participant,
    pub data: MessageData,
    // UNIX timestamp as seconds since the epoch
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum MpcMessage {
    Generating(GeneratingMessage),
    Resharing(ResharingMessage),
    Triple(TripleMessage),
    Presignature(PresignatureMessage),
    Signature(SignatureMessage),
}

impl MpcMessage {
    pub const fn typename(&self) -> &'static str {
        match self {
            MpcMessage::Generating(_) => "Generating",
            MpcMessage::Resharing(_) => "Resharing",
            MpcMessage::Triple(_) => "Triple",
            MpcMessage::Presignature(_) => "Presignature",
            MpcMessage::Signature(_) => "Signature",
        }
    }
}

#[derive(Default)]
pub struct MessageIncomingBins {
    generating: VecDeque<GeneratingMessage>,
    resharing: HashMap<Epoch, VecDeque<ResharingMessage>>,
    triple: HashMap<Epoch, HashMap<TripleId, VecDeque<TripleMessage>>>,
    presignature: HashMap<Epoch, HashMap<PresignatureId, VecDeque<PresignatureMessage>>>,
    signature: HashMap<Epoch, HashMap<SignRequestIdentifier, VecDeque<SignatureMessage>>>,
}

impl MessageIncomingBins {
    pub fn push(&mut self, message: MpcMessage) {
        match message {
            MpcMessage::Generating(message) => self.generating.push_back(message),
            MpcMessage::Resharing(message) => self
                .resharing
                .entry(message.epoch)
                .or_default()
                .push_back(message),
            MpcMessage::Triple(message) => self
                .triple
                .entry(message.epoch)
                .or_default()
                .entry(message.id)
                .or_default()
                .push_back(message),
            MpcMessage::Presignature(message) => self
                .presignature
                .entry(message.epoch)
                .or_default()
                .entry(message.id)
                .or_default()
                .push_back(message),
            MpcMessage::Signature(message) => self
                .signature
                .entry(message.epoch)
                .or_default()
                .entry(SignRequestIdentifier::new(
                    message.request_id,
                    message.epsilon,
                    message.request.payload,
                ))
                .or_default()
                .push_back(message),
        }
    }

    pub fn extend(&mut self, incoming: &mut mpsc::Receiver<MpcMessage>) -> usize {
        let mut count = 0;
        loop {
            let msg = match incoming.try_recv() {
                Ok(msg) => {
                    count += 1;
                    msg
                }
                Err(TryRecvError::Empty) => {
                    break;
                }
                Err(TryRecvError::Disconnected) => {
                    tracing::error!("communication was disconnected, no more messages will be received, spinning down");
                    break;
                }
            };
            self.push(msg);
        }
        count
    }
}

struct MessageExecutor {
    incoming: mpsc::Receiver<MpcMessage>,
    outgoing: mpsc::Receiver<(Participant, Participant, MpcMessage, Instant)>,
    bins: Arc<RwLock<MessageIncomingBins>>,
    config: Arc<RwLock<Config>>,
    mesh_state: Arc<RwLock<MeshState>>,
    queue: crate::http_client::MessageQueue,
}

impl MessageExecutor {
    pub async fn execute(mut self) {
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        loop {
            interval.tick().await;
            self.bins.write().await.extend(&mut self.incoming);

            let mut me = None;
            loop {
                let (from, to, msg, _timestamp) = match self.outgoing.try_recv() {
                    Ok(msg) => msg,
                    Err(TryRecvError::Empty) => {
                        break;
                    }
                    Err(TryRecvError::Disconnected) => {
                        tracing::error!("communication was disconnected for sending outcoming messages, no more messages will be received, spinning down");
                        break;
                    }
                };
                self.queue.push(to, msg);
                me = Some(from);
            }

            // crate::metrics::MESSAGE_QUEUE_SIZE
            //     .with_label_values(&[ctx.my_account_id().as_str()])
            //     .set(self.queue.len() as i64);

            if let Some(me) = me {
                let (sign_sk, protocol) = {
                    let config = self.config.read().await;
                    (
                        config.local.network.sign_sk.clone(),
                        config.protocol.clone(),
                    )
                };
                let active = {
                    let mesh_state = self.mesh_state.read().await;
                    mesh_state.active.clone()
                };

                let failures = self
                    .queue
                    .send_encrypted(me, &sign_sk, &active, &protocol)
                    .await;
                if !failures.is_empty() {
                    tracing::warn!(
                        active = ?active.keys_vec(),
                        ?failures,
                        "failed to send messages to participants"
                    );
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct MessageChannel {
    outgoing: mpsc::Sender<(Participant, Participant, MpcMessage, Instant)>,
    bins: Arc<RwLock<MessageIncomingBins>>,
    _task: Arc<tokio::task::JoinHandle<()>>,
}

impl MessageChannel {
    pub async fn spawn(
        client: NodeClient,
        config: &Arc<RwLock<Config>>,
        mesh_state: &Arc<RwLock<MeshState>>,
    ) -> (mpsc::Sender<MpcMessage>, Self) {
        let (incoming_tx, incoming_rx) = mpsc::channel(MAX_MESSAGE_INCOMING);
        let (outgoing_tx, outgoing_rx) = mpsc::channel(MAX_MESSAGE_OUTGOING);

        let bins = Arc::new(RwLock::new(MessageIncomingBins::default()));
        let processor = MessageExecutor {
            incoming: incoming_rx,
            outgoing: outgoing_rx,
            bins: bins.clone(),
            config: config.clone(),
            mesh_state: mesh_state.clone(),
            queue: crate::http_client::MessageQueue::new(client),
        };

        (
            incoming_tx,
            Self {
                bins,
                outgoing: outgoing_tx,
                _task: Arc::new(tokio::spawn(processor.execute())),
            },
        )
    }

    pub fn bins(&self) -> &Arc<RwLock<MessageIncomingBins>> {
        &self.bins
    }

    pub async fn send(&self, from: Participant, to: Participant, message: MpcMessage) {
        if let Err(err) = self
            .outgoing
            .send((from, to, message, Instant::now()))
            .await
        {
            tracing::error!(?err, "failed to send message to participants");
        }
    }

    pub async fn send_many(
        &self,
        other: impl IntoIterator<Item = (Participant, Participant, MpcMessage)>,
    ) {
        for (from, to, message) in other {
            self.send(from, to, message).await
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum MessageRecvError {
    #[error("cait-sith initialization error: {0}")]
    CaitSithInitializationError(#[from] InitializationError),
    #[error("cait-sith protocol error: {0}")]
    CaitSithProtocolError(#[from] ProtocolError),
    #[error("sync failed: {0}")]
    SyncError(String),
    #[error("failed to send a message: {0}")]
    SendError(SendError),
    #[error("unknown participant: {0:?}")]
    UnknownParticipant(Participant),
    #[error(transparent)]
    DataConversion(#[from] serde_json::Error),
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("invalid state")]
    InvalidStateHandle(String),
    #[error("rpc error: {0}")]
    RpcError(#[from] near_fetch::Error),
    #[error("secret storage error: {0}")]
    SecretStorageError(#[from] SecretStorageError),
}

impl From<CryptographicError> for MessageRecvError {
    fn from(value: CryptographicError) -> Self {
        match value {
            CryptographicError::CaitSithInitializationError(e) => {
                Self::CaitSithInitializationError(e)
            }
            CryptographicError::CaitSithProtocolError(e) => Self::CaitSithProtocolError(e),
            CryptographicError::SyncError(e) => Self::SyncError(e),
            CryptographicError::SendError(e) => Self::SendError(e),
            CryptographicError::UnknownParticipant(e) => Self::UnknownParticipant(e),
            CryptographicError::DataConversion(e) => Self::DataConversion(e),
            CryptographicError::Encryption(e) => Self::Encryption(e),
            CryptographicError::InvalidStateHandle(e) => Self::InvalidStateHandle(e),
            CryptographicError::RpcError(e) => Self::RpcError(e),
            CryptographicError::SecretStorageError(e) => Self::SecretStorageError(e),
        }
    }
}

#[async_trait]
pub trait MessageReceiver {
    async fn recv(
        &mut self,
        channel: &MessageChannel,
        cfg: Config,
        mesh_state: MeshState,
    ) -> Result<(), MessageRecvError>;
}

#[async_trait]
impl MessageReceiver for GeneratingState {
    async fn recv(
        &mut self,
        channel: &MessageChannel,
        _cfg: Config,
        _mesh_state: MeshState,
    ) -> Result<(), MessageRecvError> {
        let mut bins = channel.bins().write().await;
        let mut protocol = self.protocol.write().await;
        while let Some(msg) = bins.generating.pop_front() {
            tracing::debug!("handling new generating message");
            protocol.message(msg.from, msg.data);
        }
        Ok(())
    }
}

#[async_trait]
impl MessageReceiver for ResharingState {
    async fn recv(
        &mut self,
        channel: &MessageChannel,
        _cfg: Config,
        _mesh_state: MeshState,
    ) -> Result<(), MessageRecvError> {
        let mut bins = channel.bins().write().await;
        tracing::debug!("handling {} resharing messages", bins.resharing.len());
        let q = bins.resharing.entry(self.old_epoch).or_default();
        let mut protocol = self.protocol.write().await;
        while let Some(msg) = q.pop_front() {
            protocol.message(msg.from, msg.data);
        }
        Ok(())
    }
}

#[async_trait]
impl MessageReceiver for RunningState {
    async fn recv(
        &mut self,
        channel: &MessageChannel,
        cfg: Config,
        mesh_state: MeshState,
    ) -> Result<(), MessageRecvError> {
        let protocol_cfg = &cfg.protocol;
        let participants = &mesh_state.active;
        let mut bins = channel.bins().write().await;

        // remove the triple_id that has already failed or taken from the triple_bins
        // and refresh the timestamp of failed and taken
        let triple_messages = bins.triple.remove(&self.epoch).unwrap_or_default();
        for (id, mut queue) in triple_messages {
            if queue.is_empty()
                || queue.iter().any(|msg| {
                    util::is_elapsed_longer_than_timeout(
                        msg.timestamp,
                        protocol_cfg.triple.generation_timeout,
                    )
                })
            {
                continue;
            }

            // if triple id is in GC, remove these messages because the triple is currently
            // being GC'ed, where this particular triple has previously failed or been utilized.
            if self.triple_manager.refresh_gc(id).await {
                continue;
            }

            let protocol = match self
                .triple_manager
                .get_or_start_generation(id, participants, protocol_cfg)
                .await
            {
                Ok(protocol) => protocol,
                Err(err) => {
                    // ignore the message since the generation had bad parameters. Also have the other node who
                    // initiated the protocol resend the message or have it timeout on their side.
                    tracing::warn!(?err, "unable to initialize incoming triple protocol");
                    continue;
                }
            };

            if let Some(protocol) = protocol {
                while let Some(message) = queue.pop_front() {
                    protocol.message(message.from, message.data).await;
                }
            }
        }

        let mut presignature_manager = self.presignature_manager.write().await;
        let presignature_messages = bins.presignature.entry(self.epoch).or_default();
        presignature_messages.retain(|id, queue| {
            // Skip message if it already timed out
            if queue.is_empty()
                || queue.iter().any(|msg| {
                    util::is_elapsed_longer_than_timeout(
                        msg.timestamp,
                        protocol_cfg.presignature.generation_timeout,
                    )
                })
            {
                return false;
            }

            // if presignature id is in GC, remove these messages because the presignature is currently
            // being GC'ed, where this particular presignature has previously failed or been utilized.
            !presignature_manager.refresh_gc(id)
        });
        for (id, queue) in presignature_messages {
            // SAFETY: this unwrap() is safe since we have already checked that the queue is not empty.
            let PresignatureMessage {
                triple0, triple1, ..
            } = queue.front().unwrap();

            if !queue
                .iter()
                .all(|msg| triple0 == &msg.triple0 && triple1 == &msg.triple1)
            {
                // Check that all messages in the queue have the same triple0 and triple1, otherwise this is an
                // invalid message, so we should just bin the whole entire protocol and its message for this presignature id.
                queue.clear();
                continue;
            }

            let protocol = match presignature_manager
                .get_or_start_generation(
                    participants,
                    *id,
                    *triple0,
                    *triple1,
                    &self.triple_manager,
                    &self.public_key,
                    &self.private_share,
                    protocol_cfg,
                )
                .await
            {
                Ok(protocol) => protocol,
                Err(GenerationError::TripleIsGenerating(_)) => {
                    // We will go back to this presignature bin later when the triple is generated.
                    continue;
                }
                Err(
                    err @ (GenerationError::AlreadyGenerated
                    | GenerationError::TripleIsGarbageCollected(_)
                    | GenerationError::TripleStoreError(_)),
                ) => {
                    // This triple has already been generated or removed from the triple manager, so we will have to bin
                    // the entirety of the messages we received for this presignature id, and have the other nodes timeout
                    tracing::warn!(id, ?err, "presignature cannot be generated");
                    queue.clear();
                    continue;
                }
                Err(GenerationError::CaitSithInitializationError(error)) => {
                    // ignore these messages since the generation had bad parameters. Also have the other node who
                    // initiated the protocol resend the message or have it timeout on their side.
                    tracing::warn!(
                        presignature_id = id,
                        ?error,
                        "unable to initialize incoming presignature protocol"
                    );
                    queue.clear();
                    continue;
                }
                Err(err) => {
                    tracing::warn!(
                        presignature_id = id,
                        ?err,
                        "Unexpected error encounted while generating presignature"
                    );
                    queue.clear();
                    continue;
                }
            };

            while let Some(message) = queue.pop_front() {
                protocol.message(message.from, message.data);
            }
        }

        let mut signature_manager = self.signature_manager.write().await;
        let signature_messages = bins.signature.entry(self.epoch).or_default();
        signature_messages.retain(|sign_request_identifier, queue| {
            // Skip message if it already timed out
            if queue.is_empty()
                || queue.iter().any(|msg| {
                    util::is_elapsed_longer_than_timeout(
                        msg.timestamp,
                        protocol_cfg.signature.generation_timeout,
                    )
                })
            {
                return false;
            }

            !signature_manager.refresh_gc(sign_request_identifier)
        });
        for (sign_request_identifier, queue) in signature_messages {
            // SAFETY: this unwrap() is safe since we have already checked that the queue is not empty.
            let SignatureMessage {
                proposer,
                presignature_id,
                request,
                epsilon,
                entropy,
                ..
            } = queue.front().unwrap();

            if !queue
                .iter()
                .all(|msg| presignature_id == &msg.presignature_id)
            {
                // Check that all messages in the queue have the same triple0 and triple1, otherwise this is an
                // invalid message, so we should just bin the whole entire protocol and its message for this presignature id.
                queue.clear();
                continue;
            }

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
            let protocol = match signature_manager
                .get_or_start_protocol(
                    participants,
                    sign_request_identifier.request_id,
                    *proposer,
                    *presignature_id,
                    request,
                    *epsilon,
                    *entropy,
                    &mut presignature_manager,
                    protocol_cfg,
                )
                .await
            {
                Ok(protocol) => protocol,
                Err(GenerationError::PresignatureIsGenerating(_)) => {
                    // We will revisit this this signature request later when the presignature has been generated.
                    continue;
                }
                Err(
                    err @ (GenerationError::AlreadyGenerated
                    | GenerationError::PresignatureIsGarbageCollected(_)
                    | GenerationError::PresignatureIsMissing(_)),
                ) => {
                    // We will have to remove the entirety of the messages we received for this signature request,
                    // and have the other nodes timeout in the following cases:
                    // - If a presignature is in GC, then it was used already or failed to be produced.
                    // - If a presignature is missing, that means our system cannot process this signature.
                    tracing::warn!(
                        ?sign_request_identifier,
                        ?err,
                        "signature cannot be generated"
                    );
                    queue.clear();
                    continue;
                }
                Err(GenerationError::CaitSithInitializationError(error)) => {
                    // ignore the whole of the messages since the generation had bad parameters. Also have the other node who
                    // initiated the protocol resend the message or have it timeout on their side.
                    tracing::warn!(
                        ?sign_request_identifier,
                        presignature_id,
                        ?error,
                        "unable to initialize incoming signature protocol"
                    );
                    queue.clear();
                    continue;
                }
                Err(err) => {
                    tracing::warn!(
                        ?sign_request_identifier,
                        ?err,
                        "Unexpected error encounted while generating signature"
                    );
                    queue.clear();
                    continue;
                }
            };

            while let Some(message) = queue.pop_front() {
                protocol.message(message.from, message.data);
            }
        }
        self.triple_manager.garbage_collect(protocol_cfg).await;
        presignature_manager.garbage_collect(protocol_cfg);
        signature_manager.garbage_collect(protocol_cfg);
        Ok(())
    }
}

#[async_trait]
impl MessageReceiver for NodeState {
    async fn recv(
        &mut self,
        channel: &MessageChannel,
        cfg: Config,
        mesh_state: MeshState,
    ) -> Result<(), MessageRecvError> {
        match self {
            NodeState::Generating(state) => state.recv(channel, cfg, mesh_state).await,
            NodeState::Resharing(state) => state.recv(channel, cfg, mesh_state).await,
            NodeState::Running(state) => state.recv(channel, cfg, mesh_state).await,
            _ => {
                tracing::debug!("skipping message processing");
                Ok(())
            }
        }
    }
}

/// A signed message that can be encrypted. Note that the message's signature is included
/// in the encrypted message to avoid from it being tampered with without first decrypting.
#[derive(Serialize, Deserialize)]
pub struct SignedMessage<T> {
    /// The message with all it's related info.
    pub msg: T,
    /// The signature used to verify the authenticity of the encrypted message.
    pub sig: Signature,
    /// From which particpant the message was sent.
    pub from: Participant,
}

impl<T> SignedMessage<T> {
    pub const ASSOCIATED_DATA: &'static [u8] = b"";
}

impl<T> SignedMessage<T>
where
    T: Serialize,
{
    pub fn encrypt(
        msg: &T,
        from: Participant,
        sign_sk: &near_crypto::SecretKey,
        cipher_pk: &hpke::PublicKey,
    ) -> Result<Ciphered, CryptographicError> {
        let msg = serde_json::to_vec(msg)?;
        let sig = sign_sk.sign(&msg);
        let msg = SignedMessage { msg, sig, from };
        let msg = serde_json::to_vec(&msg)?;
        let ciphered = cipher_pk
            .encrypt(&msg, SignedMessage::<T>::ASSOCIATED_DATA)
            .map_err(|e| {
                tracing::error!(error = ?e, "failed to encrypt message");
                CryptographicError::Encryption(e.to_string())
            })?;
        Ok(ciphered)
    }
}

impl<T> SignedMessage<T>
where
    T: for<'a> Deserialize<'a>,
{
    pub async fn decrypt(
        cipher_sk: &hpke::SecretKey,
        protocol_state: &Arc<RwLock<NodeState>>,
        encrypted: Ciphered,
    ) -> Result<T, CryptographicError> {
        let message = cipher_sk
            .decrypt(&encrypted, SignedMessage::<T>::ASSOCIATED_DATA)
            .map_err(|err| {
                tracing::error!(error = ?err, "failed to decrypt message");
                CryptographicError::Encryption(err.to_string())
            })?;
        let SignedMessage::<Vec<u8>> { msg, sig, from } = serde_json::from_slice(&message)?;
        if !sig.verify(
            &msg,
            &protocol_state
                .read()
                .await
                .fetch_participant(&from)?
                .sign_pk,
        ) {
            tracing::error!(from = ?from, "signed message erred out with invalid signature");
            return Err(CryptographicError::Encryption(
                "invalid signature while verifying authenticity of encrypted protocol message"
                    .to_string(),
            ));
        }

        Ok(serde_json::from_slice(&msg)?)
    }
}
