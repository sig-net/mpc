use super::contract::primitives::Participants;
use super::cryptography::CryptographicError;
use super::presignature::{GenerationError, PresignatureId};
use super::signature::SignRequestIdentifier;
use super::state::{GeneratingState, NodeState, ResharingState, RunningState};
use super::triple::TripleId;
use crate::gcp::error::SecretStorageError;
use crate::indexer::ContractSignRequest;
use crate::node_client::{NodeClient, SendError};
use crate::protocol::Config;
use crate::protocol::MeshState;
use crate::types::Epoch;
use crate::util;

use async_trait::async_trait;
use cait_sith::protocol::{InitializationError, MessageData, Participant, ProtocolError};
use k256::Scalar;
use mpc_contract::config::ProtocolConfig;
use mpc_keys::hpke::{self, Ciphered};
use near_account_id::AccountId;
use near_crypto::Signature;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::{mpsc, RwLock};

pub const MAX_MESSAGE_INCOMING: usize = 1024 * 1024;
pub const MAX_MESSAGE_OUTGOING: usize = 1024 * 1024;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct GeneratingMessage {
    pub from: Participant,
    pub data: MessageData,
}

impl From<GeneratingMessage> for Message {
    fn from(msg: GeneratingMessage) -> Self {
        Message::Generating(msg)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ResharingMessage {
    pub epoch: Epoch,
    pub from: Participant,
    pub data: MessageData,
}

impl From<ResharingMessage> for Message {
    fn from(msg: ResharingMessage) -> Self {
        Message::Resharing(msg)
    }
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

impl From<TripleMessage> for Message {
    fn from(msg: TripleMessage) -> Self {
        Message::Triple(msg)
    }
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

impl From<PresignatureMessage> for Message {
    fn from(msg: PresignatureMessage) -> Self {
        Message::Presignature(msg)
    }
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

impl From<SignatureMessage> for Message {
    fn from(msg: SignatureMessage) -> Self {
        Message::Signature(msg)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum Message {
    Generating(GeneratingMessage),
    Resharing(ResharingMessage),
    Triple(TripleMessage),
    Presignature(PresignatureMessage),
    Signature(SignatureMessage),
}

impl Message {
    pub const fn typename(&self) -> &'static str {
        match self {
            Message::Generating(_) => "Generating",
            Message::Resharing(_) => "Resharing",
            Message::Triple(_) => "Triple",
            Message::Presignature(_) => "Presignature",
            Message::Signature(_) => "Signature",
        }
    }
}

#[derive(Default)]
pub struct MessageInbox {
    generating: VecDeque<GeneratingMessage>,
    resharing: HashMap<Epoch, VecDeque<ResharingMessage>>,
    triple: HashMap<Epoch, HashMap<TripleId, VecDeque<TripleMessage>>>,
    presignature: HashMap<Epoch, HashMap<PresignatureId, VecDeque<PresignatureMessage>>>,
    signature: HashMap<Epoch, HashMap<SignRequestIdentifier, VecDeque<SignatureMessage>>>,
}

impl MessageInbox {
    pub fn push(&mut self, message: Message) {
        match message {
            Message::Generating(message) => self.generating.push_back(message),
            Message::Resharing(message) => self
                .resharing
                .entry(message.epoch)
                .or_default()
                .push_back(message),
            Message::Triple(message) => self
                .triple
                .entry(message.epoch)
                .or_default()
                .entry(message.id)
                .or_default()
                .push_back(message),
            Message::Presignature(message) => self
                .presignature
                .entry(message.epoch)
                .or_default()
                .entry(message.id)
                .or_default()
                .push_back(message),
            Message::Signature(message) => self
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

    pub fn extend(&mut self, incoming: &mut mpsc::Receiver<Message>) -> usize {
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
                    tracing::error!(
                        "inbox: communication disconnected, no more messages will be received"
                    );
                    break;
                }
            };
            self.push(msg);
        }
        count
    }
}

struct MessageExecutor {
    incoming: mpsc::Receiver<Message>,
    outgoing: mpsc::Receiver<SendMessage>,
    inbox: Arc<RwLock<MessageInbox>>,
    outbox: MessageOutbox,

    config: Arc<RwLock<Config>>,
    mesh_state: Arc<RwLock<MeshState>>,
}

impl MessageExecutor {
    pub async fn execute(mut self) {
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        loop {
            interval.tick().await;
            self.inbox.write().await.extend(&mut self.incoming);

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
            self.outbox.extend(&mut self.outgoing);
            self.outbox.expire(&protocol);
            let encrypted = self.outbox.encrypt(&sign_sk, &active);
            self.outbox.send(&active, encrypted).await;
        }
    }
}

#[derive(Clone)]
pub struct MessageChannel {
    outgoing: mpsc::Sender<SendMessage>,
    inbox: Arc<RwLock<MessageInbox>>,
    _task: Arc<tokio::task::JoinHandle<()>>,
}

impl MessageChannel {
    pub async fn spawn(
        client: NodeClient,
        id: &AccountId,
        config: &Arc<RwLock<Config>>,
        mesh_state: &Arc<RwLock<MeshState>>,
    ) -> (mpsc::Sender<Message>, Self) {
        let (incoming_tx, incoming_rx) = mpsc::channel(MAX_MESSAGE_INCOMING);
        let (outgoing_tx, outgoing_rx) = mpsc::channel(MAX_MESSAGE_OUTGOING);

        let inbox = Arc::new(RwLock::new(MessageInbox::default()));
        let processor = MessageExecutor {
            incoming: incoming_rx,
            outgoing: outgoing_rx,
            inbox: inbox.clone(),
            config: config.clone(),
            mesh_state: mesh_state.clone(),
            outbox: MessageOutbox::new(client, id),
        };

        (
            incoming_tx,
            Self {
                inbox,
                outgoing: outgoing_tx,
                _task: Arc::new(tokio::spawn(processor.execute())),
            },
        )
    }

    /// Grab the inbox for all the messages we received from the network.
    pub fn inbox(&self) -> &Arc<RwLock<MessageInbox>> {
        &self.inbox
    }

    /// Send a message to the participants in the network.
    pub async fn send(&self, from: Participant, to: Participant, message: impl Into<Message>) {
        if let Err(err) = self
            .outgoing
            .send((from, to, message.into(), Instant::now()))
            .await
        {
            tracing::error!(?err, "failed to send message to participants");
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
        let mut inbox = channel.inbox().write().await;
        let mut protocol = self.protocol.write().await;
        while let Some(msg) = inbox.generating.pop_front() {
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
        let mut inbox = channel.inbox().write().await;
        tracing::debug!("handling {} resharing messages", inbox.resharing.len());
        let q = inbox.resharing.entry(self.old_epoch).or_default();
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
        let mut inbox = channel.inbox().write().await;

        // remove the triple_id that has already failed or taken from the triple_bins
        // and refresh the timestamp of failed and taken
        let triple_messages = inbox.triple.remove(&self.epoch).unwrap_or_default();
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
        let presignature_messages = inbox.presignature.entry(self.epoch).or_default();
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
        let signature_messages = inbox.signature.entry(self.epoch).or_default();
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

type SendMessage = (Participant, Participant, Message, Instant);

/// Encrypted message with a reference to the old message. Only the ciphered portion of this
/// type will be sent over the wire, while the original message is kept just in case things
/// go wrong somewhere and the message needs to be requeued to be sent later.
type EncryptedWithOriginal = (Ciphered, SendMessage);

/// Message outbox is the set of messages that are pending to be sent to other nodes.
/// These messages will be signed and encrypted before being sent out.
pub struct MessageOutbox {
    client: NodeClient,
    messages: VecDeque<SendMessage>,
    account_id: AccountId,
}

impl MessageOutbox {
    pub fn new(client: NodeClient, id: &AccountId) -> Self {
        Self {
            client,
            messages: VecDeque::default(),
            account_id: id.clone(),
        }
    }

    pub fn extend(&mut self, outgoing: &mut mpsc::Receiver<SendMessage>) {
        loop {
            let (from, to, msg, instant) = match outgoing.try_recv() {
                Ok(msg) => msg,
                Err(TryRecvError::Empty) => {
                    break;
                }
                Err(TryRecvError::Disconnected) => {
                    tracing::error!(
                        "outbox: communication disconnected, no more messages will be received"
                    );
                    break;
                }
            };
            self.messages.push_back((from, to, msg, instant));
        }
        crate::metrics::MESSAGE_QUEUE_SIZE
            .with_label_values(&[self.account_id.as_str()])
            .set(self.messages.len() as i64);
    }

    /// Expire messages that have been in the outbox for too long.
    pub fn expire(&mut self, cfg: &ProtocolConfig) {
        // timeout errors are very common for a message expiring, so map them to counts here:
        let mut timeouts = HashMap::<String, usize>::new();
        self.messages.retain(|(_, to, msg, instant)| {
            if instant.elapsed() > timeout(msg, cfg) {
                let counter = timeouts
                    .entry(format!(
                        "timeout message={} for node={to:?}",
                        msg.typename(),
                    ))
                    .or_insert(0);
                *counter += 1;
                false
            } else {
                true
            }
        });

        if !timeouts.is_empty() {
            tracing::warn!(?timeouts, "messages expired");
        }
    }

    /// Encrypt all the messages in the outbox and return a map of participant to encrypted messages.
    pub fn encrypt(
        &mut self,
        sign_sk: &near_crypto::SecretKey,
        active: &Participants,
    ) -> HashMap<Participant, Vec<EncryptedWithOriginal>> {
        // failed for when a participant is not active, so keep this message for next round.
        let mut retry = VecDeque::new();
        let mut errors = Vec::new();
        let mut not_active = HashSet::new();

        let mut encrypted = HashMap::new();
        while let Some((from, to, msg, instant)) = self.messages.pop_front() {
            let Some(info) = active.get(&to) else {
                not_active.insert(to);
                retry.push_back((from, to, msg, instant));
                continue;
            };

            let encrypted_msg = match SignedMessage::encrypt(&msg, from, sign_sk, &info.cipher_pk) {
                Ok(encrypted) => encrypted,
                Err(err) => {
                    errors.push(SendError::EncryptionError(err.to_string()));
                    continue;
                }
            };
            let encrypted = encrypted.entry(to).or_insert_with(Vec::new);
            encrypted.push((encrypted_msg, (from, to, msg, instant)));
        }

        if !errors.is_empty() {
            tracing::warn!(?errors, "outbox: encrypting messages failed on some");
        }

        if !not_active.is_empty() {
            tracing::warn!(
                ?not_active,
                "some participants are not active even though mesh says they are"
            );
        }

        // Add back the failed attempts for next time.
        self.messages.extend(retry);
        encrypted
    }

    /// Compact together all the requests up to 256kb per request, and then send them out.
    pub async fn send(
        &mut self,
        active: &Participants,
        encrypted: HashMap<Participant, Vec<EncryptedWithOriginal>>,
    ) {
        let start = Instant::now();
        let mut send_tasks = Vec::new();
        for (id, encrypted) in encrypted {
            for partition in partition_ciphered_256kb(encrypted) {
                let (encrypted_partition, msgs): (Vec<_>, Vec<_>) = partition.into_iter().unzip();
                // guaranteed to unwrap due to our previous loop check:
                let info = active.get(&id).unwrap();
                let account_id = info.account_id.clone();
                let url = info.url.clone();

                crate::metrics::NUM_SEND_ENCRYPTED_TOTAL
                    .with_label_values(&[account_id.as_str()])
                    .inc_by(msgs.len() as f64);

                let client = self.client.clone();
                send_tasks.push(tokio::spawn(async move {
                    let start = Instant::now();
                    if let Err(err) = client.msg(url, &encrypted_partition).await {
                        crate::metrics::NUM_SEND_ENCRYPTED_FAILURE
                            .with_label_values(&[account_id.as_str()])
                            .inc_by(msgs.len() as f64);
                        crate::metrics::FAILED_SEND_ENCRYPTED_LATENCY
                            .with_label_values(&[account_id.as_str()])
                            .observe(start.elapsed().as_millis() as f64);
                        Err((msgs, err))
                    } else {
                        crate::metrics::SEND_ENCRYPTED_LATENCY
                            .with_label_values(&[account_id.as_str()])
                            .observe(start.elapsed().as_millis() as f64);
                        Ok(msgs.len())
                    }
                }));
            }
        }

        let mut errors = Vec::new();
        let mut retry = VecDeque::new();
        let mut uncompacted = 0;
        let mut compacted = 0;
        for task in send_tasks {
            match task.await {
                Ok(Ok(msgs_len)) => {
                    uncompacted += msgs_len;
                    compacted += 1;
                }
                Ok(Err((msgs, err))) => {
                    // since we failed, put back all the messages related to this
                    retry.extend(msgs);
                    errors.push(err);
                }
                Err(err) => {
                    tracing::warn!(?err, "outbox: task failed to send message");
                }
            }
        }

        if uncompacted > 0 {
            tracing::debug!(
                uncompacted,
                compacted,
                "sent messages in {:?}",
                start.elapsed()
            );
        }

        if !errors.is_empty() {
            tracing::warn!(?errors, "outbox: failed sending encrypted messages");
        }

        // Add back the failed attempts for next time.
        self.messages.extend(retry);
    }
}

fn partition_ciphered_256kb(
    encrypted: Vec<EncryptedWithOriginal>,
) -> Vec<Vec<EncryptedWithOriginal>> {
    let mut result = Vec::new();
    let mut current_partition = Vec::new();
    let mut current_size: usize = 0;

    for ciphered in encrypted {
        let bytesize = ciphered.0.text.len();
        if current_size + bytesize > 256 * 1024 {
            // If adding this byte vector exceeds 256kb, start a new partition
            result.push(current_partition);
            current_partition = Vec::new();
            current_size = 0;
        }
        current_partition.push(ciphered);
        current_size += bytesize;
    }

    if !current_partition.is_empty() {
        // Add the last partition
        result.push(current_partition);
    }

    result
}

fn timeout(msg: &Message, cfg: &ProtocolConfig) -> Duration {
    match msg {
        Message::Generating(_) => Duration::from_millis(cfg.message_timeout),
        Message::Resharing(_) => Duration::from_millis(cfg.message_timeout),
        Message::Triple(_) => Duration::from_millis(cfg.triple.generation_timeout),
        Message::Presignature(_) => Duration::from_millis(cfg.presignature.generation_timeout),
        Message::Signature(_) => Duration::from_millis(cfg.signature.generation_timeout),
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::message::{GeneratingMessage, Message};

    #[test]
    fn test_sending_encrypted_message() {
        let associated_data = b"";
        let (sk, pk) = mpc_keys::hpke::generate();
        let starting_message = Message::Generating(GeneratingMessage {
            from: cait_sith::protocol::Participant::from(0),
            data: vec![],
        });

        let message = serde_json::to_vec(&starting_message).unwrap();
        let message = pk.encrypt(&message, associated_data).unwrap();

        let message = serde_json::to_vec(&message).unwrap();
        let cipher = serde_json::from_slice(&message).unwrap();
        let message = sk.decrypt(&cipher, associated_data).unwrap();
        let message: Message = serde_json::from_slice(&message).unwrap();

        assert_eq!(starting_message, message);
    }
}
