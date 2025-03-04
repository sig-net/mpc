use super::contract::primitives::{ParticipantMap, Participants};
use super::error::GenerationError;
use super::presignature::PresignatureId;
use super::state::{GeneratingState, NodeState, ResharingState, RunningState};
use super::triple::TripleId;
use crate::node_client::NodeClient;
use crate::protocol::Config;
use crate::protocol::MeshState;
use crate::types::Epoch;
use crate::util;

use async_trait::async_trait;
use cait_sith::protocol::{MessageData, Participant};
use mpc_contract::config::ProtocolConfig;
use mpc_keys::hpke::{self, Ciphered};
use mpc_primitives::SignId;
use near_account_id::AccountId;
use near_crypto::Signature;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::{mpsc, RwLock};

pub const MAX_MESSAGE_INCOMING: usize = 1024 * 1024;
pub const MAX_MESSAGE_OUTGOING: usize = 1024 * 1024;

/// Maximum size for the filter of messages. This is roughly determined by the
/// max number of protocols that can be within our system. It's not an upper
/// bound but merely to serve as a good enough amount to maintain the IDs of
/// protocols long enough on the case that they make it back into the system
/// somehow after being erased.
pub const MAX_FILTER_SIZE: NonZeroUsize = NonZeroUsize::new(64 * 1024).unwrap();

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

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessageType {
    Generating,
    Resharing,
    Triple,
    Presignature,
    Signature,
}

pub trait MessageId {
    const TYPE: MessageType;
    fn id(&self) -> u64;
}

impl MessageId for TripleMessage {
    const TYPE: MessageType = MessageType::Triple;
    fn id(&self) -> u64 {
        self.id
    }
}

impl MessageId for PresignatureMessage {
    const TYPE: MessageType = MessageType::Presignature;
    fn id(&self) -> u64 {
        self.id
    }
}

impl MessageId for SignatureMessage {
    const TYPE: MessageType = MessageType::Signature;
    fn id(&self) -> u64 {
        let mut hasher = std::hash::DefaultHasher::new();
        self.id.hash(&mut hasher);
        std::hash::Hasher::finish(&hasher)
    }
}

#[derive(Debug)]
struct MessageFilter {
    filter_rx: mpsc::Receiver<(MessageType, u64)>,
    filter: lru::LruCache<(MessageType, u64), ()>,
}

impl MessageFilter {
    pub fn new(filter_rx: mpsc::Receiver<(MessageType, u64)>) -> Self {
        Self {
            filter_rx,
            filter: lru::LruCache::new(MAX_FILTER_SIZE),
        }
    }

    pub fn contains<M: MessageId>(&mut self, msg: &M) -> bool {
        self.filter.get(&(M::TYPE, msg.id())).is_some()
    }

    fn extend(&mut self) {
        loop {
            let (msg_type, id) = match self.filter_rx.try_recv() {
                Ok(msg) => msg,
                Err(TryRecvError::Empty) => {
                    break;
                }
                Err(TryRecvError::Disconnected) => {
                    tracing::error!(
                        "filter: channel disconnected, no more messages will be received"
                    );
                    break;
                }
            };

            self.filter.put((msg_type, id), ());
        }
    }
}

pub struct MessageInbox {
    /// encrypted messages that are pending to be decrypted. These are messages that we received
    /// from other nodes that weren't able to be processed yet due to missing info such as the
    /// participant id in the case of slow resharing.
    try_decrypt: VecDeque<(Ciphered, Instant)>,

    filter: MessageFilter,

    generating: VecDeque<GeneratingMessage>,
    resharing: HashMap<Epoch, VecDeque<ResharingMessage>>,
    triple: HashMap<Epoch, HashMap<TripleId, VecDeque<TripleMessage>>>,
    presignature: HashMap<Epoch, HashMap<PresignatureId, VecDeque<PresignatureMessage>>>,
    signature: HashMap<Epoch, HashMap<SignId, VecDeque<SignatureMessage>>>,
}

impl MessageInbox {
    pub fn new(filter_rx: mpsc::Receiver<(MessageType, u64)>) -> Self {
        Self {
            try_decrypt: VecDeque::new(),
            filter: MessageFilter::new(filter_rx),
            generating: VecDeque::new(),
            resharing: HashMap::new(),
            triple: HashMap::new(),
            presignature: HashMap::new(),
            signature: HashMap::new(),
        }
    }

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
                .entry(message.id.clone())
                .or_default()
                .push_back(message),
            Message::Unknown(entries) => {
                tracing::warn!(
                    entries = ?entries.iter().map(|(k, v)| (k, cbor_name(v))).collect::<Vec<_>>(),
                    "inbox: received unknown message type",
                );
            }
        }
    }

    pub fn expire(&mut self, protocol: &ProtocolConfig) {
        self.try_decrypt.retain(|(_, timestamp)| {
            timestamp.elapsed() < Duration::from_secs(protocol.message_timeout)
        });
    }

    pub fn extend(&mut self, incoming: &mut mpsc::Receiver<Ciphered>) {
        self.filter.extend();
        loop {
            let encrypted = match incoming.try_recv() {
                Ok(msg) => msg,
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

            self.try_decrypt.push_back((encrypted, Instant::now()));
        }
    }

    pub fn decrypt(
        &mut self,
        cipher_sk: &hpke::SecretKey,
        participants: &ParticipantMap,
    ) -> Vec<Message> {
        let mut retry = Vec::new();

        let mut messages = Vec::new();
        while let Some((encrypted, timestamp)) = self.try_decrypt.pop_front() {
            let decrypted: Vec<Message> =
                match SignedMessage::decrypt(&encrypted, cipher_sk, participants) {
                    Ok(decrypted) => decrypted,
                    Err(err) => {
                        if matches!(err, MessageError::UnknownParticipant(_)) {
                            retry.push((encrypted, timestamp));
                        } else {
                            tracing::error!(?err, "inbox: failed to decrypt/verify messages");
                        }
                        continue;
                    }
                };

            messages.extend(decrypted);
        }

        self.try_decrypt.extend(retry);
        messages
    }

    /// Filter out all messages that have been filtered
    pub fn filter(&mut self, mut messages: Vec<Message>) -> Vec<Message> {
        messages.retain(|msg| match msg {
            Message::Triple(msg) => !self.filter.contains(msg),
            Message::Presignature(msg) => !self.filter.contains(msg),
            Message::Signature(msg) => !self.filter.contains(msg),
            _ => true,
        });
        messages
    }

    pub fn recv(&mut self, messages: Vec<Message>) {
        for message in messages {
            self.push(message);
        }
    }
}

struct MessageExecutor {
    incoming: mpsc::Receiver<Ciphered>,
    outgoing: mpsc::Receiver<SendMessage>,
    inbox: Arc<RwLock<MessageInbox>>,
    outbox: MessageOutbox,

    config: Arc<RwLock<Config>>,
    protocol_state: Arc<RwLock<NodeState>>,
    mesh_state: Arc<RwLock<MeshState>>,
}

impl MessageExecutor {
    pub async fn execute(mut self) {
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        loop {
            interval.tick().await;
            let (sign_sk, cipher_sk, protocol) = {
                let config = self.config.read().await;
                (
                    config.local.network.sign_sk.clone(),
                    config.local.network.cipher_sk.clone(),
                    config.protocol.clone(),
                )
            };

            let participants = {
                let state = self.protocol_state.read().await;
                state.participants()
            };
            {
                let mut inbox = self.inbox.write().await;
                inbox.expire(&protocol);
                inbox.extend(&mut self.incoming);
                let messages = inbox.decrypt(&cipher_sk, &participants);
                let messages = inbox.filter(messages);
                inbox.recv(messages);
            }

            let active = {
                let mesh_state = self.mesh_state.read().await;
                mesh_state.active_with_potential()
            };
            self.outbox.expire(&protocol);
            self.outbox.extend(&mut self.outgoing);
            let compacted = self.outbox.compact();
            let encrypted = self.outbox.encrypt(&sign_sk, &active, compacted);
            self.outbox.send(&active, encrypted).await;
        }
    }
}

#[derive(Clone)]
pub struct MessageChannel {
    outgoing: mpsc::Sender<SendMessage>,
    inbox: Arc<RwLock<MessageInbox>>,
    filter: mpsc::Sender<(MessageType, u64)>,
    _task: Arc<tokio::task::JoinHandle<()>>,
}

impl MessageChannel {
    pub async fn spawn(
        client: NodeClient,
        id: &AccountId,
        config: &Arc<RwLock<Config>>,
        protocol_state: &Arc<RwLock<NodeState>>,
        mesh_state: &Arc<RwLock<MeshState>>,
    ) -> (mpsc::Sender<Ciphered>, Self) {
        let (incoming_tx, incoming_rx) = mpsc::channel(MAX_MESSAGE_INCOMING);
        let (outgoing_tx, outgoing_rx) = mpsc::channel(MAX_MESSAGE_OUTGOING);

        let (filter_tx, filter_rx) = mpsc::channel(MAX_MESSAGE_INCOMING);

        let inbox = Arc::new(RwLock::new(MessageInbox::new(filter_rx)));
        let processor = MessageExecutor {
            incoming: incoming_rx,
            outgoing: outgoing_rx,
            inbox: inbox.clone(),
            outbox: MessageOutbox::new(client, id),

            config: config.clone(),
            protocol_state: protocol_state.clone(),
            mesh_state: mesh_state.clone(),
        };

        (
            incoming_tx,
            Self {
                inbox,
                outgoing: outgoing_tx,
                filter: filter_tx,
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
            .send((message.into(), (from, to, Instant::now())))
            .await
        {
            tracing::error!(?err, "outbox: failed to send message to participants");
        }
    }

    /// Marks this message as filtered. This is used to prevent the same message with the
    /// corresponding MessageId from being processed again.
    pub async fn mark_filtered<M: MessageId>(&self, msg: &M) {
        if let Err(err) = self.filter.send((M::TYPE, msg.id())).await {
            tracing::error!(?err, "failed to send filter message");
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
    Verification(String),
}

#[async_trait]
pub trait MessageReceiver {
    async fn recv(
        &mut self,
        channel: &MessageChannel,
        cfg: Config,
        mesh_state: MeshState,
    ) -> Result<(), MessageError>;
}

#[async_trait]
impl MessageReceiver for GeneratingState {
    async fn recv(
        &mut self,
        channel: &MessageChannel,
        _cfg: Config,
        _mesh_state: MeshState,
    ) -> Result<(), MessageError> {
        let mut inbox = channel.inbox().write().await;
        let mut protocol = self.protocol.write().await;
        let message_counts: HashMap<Participant, usize> =
            inbox
                .generating
                .iter()
                .fold(HashMap::new(), |mut acc, msg| {
                    *acc.entry(msg.from).or_default() += 1;
                    acc
                });
        if !message_counts.is_empty() {
            tracing::info!(?message_counts, "generating: handling new messages");
        }
        while let Some(msg) = inbox.generating.pop_front() {
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
    ) -> Result<(), MessageError> {
        let mut inbox = channel.inbox().write().await;
        let message_counts: HashMap<(Participant, Epoch), usize> =
            inbox
                .resharing
                .iter()
                .fold(HashMap::new(), |mut acc, (epoch, messages)| {
                    for msg in messages {
                        *acc.entry((msg.from, *epoch)).or_default() += 1;
                    }
                    acc
                });
        if !message_counts.is_empty() {
            tracing::info!(?message_counts, "resharing: handling new messages");
        }
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
    ) -> Result<(), MessageError> {
        let protocol_cfg = &cfg.protocol;
        let active = &mesh_state.active;
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
                .get_or_start_generation(id, active, protocol_cfg)
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
                    active,
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
        signature_messages.retain(|sign_id, queue| {
            let mut expired = HashSet::new();
            let mut active = HashSet::new();

            for msg in queue.iter() {
                if expired.contains(&msg.presignature_id) {
                    continue;
                }

                if util::is_elapsed_longer_than_timeout(
                    msg.timestamp,
                    protocol_cfg.signature.generation_timeout,
                ) {
                    expired.insert(msg.presignature_id);
                } else {
                    active.insert(msg.presignature_id);
                }
            }

            active.retain(|presig_id| !signature_manager.refresh_gc(sign_id, *presig_id));

            queue.retain(|msg| active.contains(&msg.presignature_id));

            !queue.is_empty()
        });

        for (sign_id, queue) in signature_messages {
            // SAFETY: this unwrap() is safe since we have already checked that the queue is not empty.
            let SignatureMessage {
                proposer,
                presignature_id,
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

            let protocol = match signature_manager
                .get_or_start_protocol(
                    sign_id,
                    *proposer,
                    *presignature_id,
                    protocol_cfg,
                    &mut presignature_manager,
                )
                .await
            {
                Ok(protocol) => protocol,
                Err(GenerationError::PresignatureIsGenerating(_)) => {
                    // We will revisit this this signature request later when the presignature has been generated.
                    continue;
                }
                Err(err @ GenerationError::WaitingForIndexer(_)) => {
                    // We will revisit this this signature request later when we have the request indexed.
                    tracing::warn!(?sign_id, ?proposer, ?err, "waiting for indexer");
                    continue;
                }
                Err(err @ GenerationError::InvalidProposer(_, _)) => {
                    // trash the whole of these messages since we got an invalid set of participants.
                    tracing::warn!(?sign_id, ?err, "signature generation cannot be started");
                    queue.clear();
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
                    tracing::warn!(?sign_id, ?err, "signature cannot be generated");
                    queue.clear();
                    continue;
                }
                Err(GenerationError::CaitSithInitializationError(error)) => {
                    // ignore the whole of the messages since the generation had bad parameters. Also have the other node who
                    // initiated the protocol resend the message or have it timeout on their side.
                    tracing::warn!(
                        ?sign_id,
                        presignature_id,
                        ?error,
                        "unable to initialize incoming signature protocol"
                    );
                    queue.clear();
                    continue;
                }
                Err(err) => {
                    tracing::warn!(
                        ?sign_id,
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
    ) -> Result<(), MessageError> {
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
pub struct SignedMessage {
    /// The message with all it's related info.
    #[serde(with = "serde_bytes")]
    pub msg: Vec<u8>,
    /// The signature used to verify the authenticity of the encrypted message.
    pub sig: Signature,
    /// From which particpant the message was sent.
    pub from: Participant,
}

impl SignedMessage {
    pub const ASSOCIATED_DATA: &'static [u8] = b"";
}

impl SignedMessage {
    pub fn encrypt<T: Serialize>(
        msg: &T,
        from: Participant,
        sign_sk: &near_crypto::SecretKey,
        cipher_pk: &hpke::PublicKey,
    ) -> Result<Ciphered, MessageError> {
        let msg = cbor_to_bytes(msg)?;
        let sig = sign_sk.sign(&msg);
        let msg = Self { msg, sig, from };
        let msg = cbor_to_bytes(&msg)?;
        let ciphered = cipher_pk
            .encrypt(&msg, Self::ASSOCIATED_DATA)
            .inspect_err(|err| {
                tracing::error!(?err, "failed to encrypt message");
            })?;
        Ok(ciphered)
    }
}

impl SignedMessage {
    pub fn decrypt<T: DeserializeOwned>(
        encrypted: &Ciphered,
        cipher_sk: &hpke::SecretKey,
        participants: &ParticipantMap,
    ) -> Result<T, MessageError> {
        let msg = cipher_sk
            .decrypt(encrypted, Self::ASSOCIATED_DATA)
            .inspect_err(|err| {
                tracing::error!(?err, "failed to decrypt message");
            })?;
        let Self { msg, sig, from } = cbor_from_bytes(&msg)?;
        let info = participants
            .get(&from)
            .ok_or(MessageError::UnknownParticipant(from))?;
        if !sig.verify(&msg, &info.sign_pk) {
            tracing::error!(?from, "signed message erred out with invalid signature");
            return Err(MessageError::Verification(
                "invalid signature while verifying authenticity of encrypted protocol message"
                    .to_string(),
            ));
        }

        cbor_from_bytes(&msg)
    }
}

type FromParticipant = Participant;
type ToParticipant = Participant;
type MessageRoute = (FromParticipant, ToParticipant);
type SendMessage = (Message, (FromParticipant, ToParticipant, Instant));

pub struct Partition {
    messages: Vec<Message>,
    timestamps: Vec<Instant>,
}

/// Message outbox is the set of messages that are pending to be sent to other nodes.
/// These messages will be signed and encrypted before being sent out.
pub struct MessageOutbox {
    client: NodeClient,
    account_id: AccountId,

    // NOTE: we have FromParticipant here to circumvent the chance that we change Participant
    // id for our own node in the middle of something like resharing or adding another curve
    // type.
    /// Messsages sorted by participant map to a list of partitioned messages to be sent as
    /// a single request to other participants.
    messages: HashMap<MessageRoute, Vec<(Message, Instant)>>,
}

impl MessageOutbox {
    pub fn new(client: NodeClient, id: &AccountId) -> Self {
        Self {
            client,
            messages: HashMap::new(),
            account_id: id.clone(),
        }
    }

    pub fn extend(&mut self, outgoing: &mut mpsc::Receiver<SendMessage>) {
        let mut message_count: i64 = 0;
        loop {
            let (msg, (from, to, timestamp)) = match outgoing.try_recv() {
                Ok(msg) => msg,
                Err(TryRecvError::Empty) => {
                    break;
                }
                Err(TryRecvError::Disconnected) => {
                    tracing::error!(
                        "outbox: channel disconnected, no more messages will be received"
                    );
                    break;
                }
            };
            // add it to the outbox and sort it by from and to participant
            let entry = self.messages.entry((from, to)).or_default();
            entry.push((msg, timestamp));
            message_count += 1;
        }
        crate::metrics::MESSAGE_QUEUE_SIZE
            .with_label_values(&[self.account_id.as_str()])
            .set(message_count);
    }

    /// Expire messages that have been in the outbox for too long.
    pub fn expire(&mut self, cfg: &ProtocolConfig) {
        // timeout errors are very common for a message expiring, so map them to counts here:
        let mut timeouts = HashMap::<String, usize>::new();
        for ((_from, to), messages) in self.messages.iter_mut() {
            messages.retain(|(msg, timestamp)| {
                if timestamp.elapsed() > timeout(msg, cfg) {
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
        }

        if !timeouts.is_empty() {
            tracing::warn!(?timeouts, "messages expired");
        }
    }

    /// Compact the messages in the outbox into partitions of at most 256kb.
    pub fn compact(&mut self) -> HashMap<MessageRoute, Vec<Partition>> {
        let mut compacted = HashMap::new();
        for (route, messages) in self.messages.drain() {
            let entry = compacted.entry(route).or_insert_with(Vec::new);
            entry.extend(partition_256kb(messages));
        }
        compacted
    }

    /// Encrypt all the messages in the outbox and return a map of participant to encrypted messages.
    pub fn encrypt(
        &mut self,
        sign_sk: &near_crypto::SecretKey,
        active: &Participants,
        compacted: HashMap<MessageRoute, Vec<Partition>>,
    ) -> HashMap<MessageRoute, Vec<(Ciphered, Partition)>> {
        // failed for when a participant is not active, so keep this message for next round.
        let mut retry = VecDeque::new();
        let mut errors = Vec::new();
        let mut not_active = HashSet::new();

        let mut encrypted_with_original = HashMap::new();
        for ((from, to), compacted) in compacted {
            let Some(info) = active.get(&to) else {
                not_active.insert(to);
                retry.push_back(((from, to), compacted));
                continue;
            };

            for partition in compacted {
                let encrypted = match SignedMessage::encrypt(
                    &partition.messages,
                    from,
                    sign_sk,
                    &info.cipher_pk,
                ) {
                    Ok(encrypted) => encrypted,
                    Err(err) => {
                        errors.push(err);
                        continue;
                    }
                };

                encrypted_with_original
                    .entry((from, to))
                    .or_insert_with(Vec::new)
                    .push((encrypted, partition));
            }
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
        for (route, partitions) in retry {
            let entry = self.messages.entry(route).or_default();
            for partition in partitions {
                entry.extend(
                    partition
                        .messages
                        .into_iter()
                        .zip(partition.timestamps.into_iter()),
                );
            }
        }

        encrypted_with_original
    }

    /// Send the encrypted messages to other participants.
    pub async fn send(
        &mut self,
        active: &Participants,
        encrypted: HashMap<MessageRoute, Vec<(Ciphered, Partition)>>,
    ) {
        let start = Instant::now();
        let mut send_tasks = Vec::new();
        for ((from, to), encrypted) in encrypted {
            for (encrypted_partition, partition) in encrypted {
                // guaranteed to unwrap due to our previous loop check:
                let info = active.get(&to).unwrap();
                let account_id = info.account_id.clone();
                let url = info.url.clone();

                crate::metrics::NUM_SEND_ENCRYPTED_TOTAL
                    .with_label_values(&[account_id.as_str()])
                    .inc_by(partition.messages.len() as f64);

                let client = self.client.clone();
                send_tasks.push(tokio::spawn(async move {
                    let start = Instant::now();
                    if let Err(err) = client.msg(url, &[&encrypted_partition]).await {
                        crate::metrics::NUM_SEND_ENCRYPTED_FAILURE
                            .with_label_values(&[account_id.as_str()])
                            .inc_by(partition.messages.len() as f64);
                        crate::metrics::FAILED_SEND_ENCRYPTED_LATENCY
                            .with_label_values(&[account_id.as_str()])
                            .observe(start.elapsed().as_millis() as f64);
                        Err(((from, to), partition, err))
                    } else {
                        crate::metrics::SEND_ENCRYPTED_LATENCY
                            .with_label_values(&[account_id.as_str()])
                            .observe(start.elapsed().as_millis() as f64);
                        Ok(partition.messages.len())
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
                Ok(Err((route, partition, err))) => {
                    // since we failed, put back all the messages related to this
                    retry.push_back((route, partition));
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
        for (route, partition) in retry {
            let entry = self.messages.entry(route).or_default();
            entry.extend(
                partition
                    .messages
                    .into_iter()
                    .zip(partition.timestamps.into_iter()),
            );
        }
    }
}

/// Partition a list of messages into a list of partitions where each partition is at most 256kb
/// worth of `Message`s.
fn partition_256kb(outgoing: impl IntoIterator<Item = (Message, Instant)>) -> Vec<Partition> {
    let mut partitions = Vec::new();
    let mut current_messages = Vec::new();
    let mut current_timestamps = Vec::new();
    let mut current_size: usize = 0;

    for (msg, timestamp) in outgoing {
        if matches!(msg, Message::Unknown(_)) {
            // Unknown messages should never be created directly by us. The outbox should never
            // be sending these out to other nodes. We should only be receiving them from the
            // inbox and processed as such there. If we get to this point, that means our system
            // is wrong somewhere such that the node is creating an Unknown message itself.
            tracing::warn!("trying to send unknown message out?");
            continue;
        }

        let bytesize = msg.size();
        if current_size + bytesize > 256 * 1024 {
            // If adding this byte vector exceeds 256kb, start a new partition
            partitions.push(Partition {
                messages: std::mem::take(&mut current_messages),
                timestamps: std::mem::take(&mut current_timestamps),
            });
            current_size = 0;
        }
        current_messages.push(msg);
        current_timestamps.push(timestamp);
        current_size += bytesize;
    }

    if !current_messages.is_empty() {
        // Add the last partition
        partitions.push(Partition {
            messages: current_messages,
            timestamps: current_timestamps,
        });
    }

    partitions
}

fn timeout(msg: &Message, cfg: &ProtocolConfig) -> Duration {
    match msg {
        Message::Generating(_) => Duration::from_millis(cfg.message_timeout),
        Message::Resharing(_) => Duration::from_millis(cfg.message_timeout),
        Message::Triple(_) => Duration::from_millis(cfg.triple.generation_timeout),
        Message::Presignature(_) => Duration::from_millis(cfg.presignature.generation_timeout),
        Message::Signature(_) => Duration::from_millis(cfg.signature.generation_timeout),

        // unknown message cannot be handled at all, so we just expire them immediately.
        Message::Unknown(_) => Duration::from_millis(1),
    }
}

fn cbor_to_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, MessageError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|err| MessageError::CborConversion(err.to_string()))?;
    Ok(buf)
}

fn cbor_from_bytes<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, MessageError> {
    ciborium::from_reader(bytes).map_err(|err| MessageError::CborConversion(err.to_string()))
}

const fn cbor_name(value: &ciborium::Value) -> &'static str {
    match value {
        ciborium::Value::Integer(_) => "integer",
        ciborium::Value::Bytes(_) => "bytes",
        ciborium::Value::Text(_) => "text",
        ciborium::Value::Float(_) => "float",
        ciborium::Value::Null => "null",
        ciborium::Value::Bool(_) => "bool",
        ciborium::Value::Array(_) => "array",
        ciborium::Value::Map(_) => "map",
        ciborium::Value::Tag(_, _) => "tag",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use cait_sith::protocol::Participant;
    use mpc_keys::hpke::{self, Ciphered};
    use mpc_primitives::SignId;
    use serde::{de::DeserializeOwned, Deserialize, Serialize};

    use crate::protocol::{
        contract::primitives::{ParticipantMap, Participants},
        message::{GeneratingMessage, Message, SignatureMessage, SignedMessage, TripleMessage},
        ParticipantInfo,
    };

    #[test]
    fn test_sending_encrypted_message() {
        let associated_data = b"";
        let (cipher_sk, cipher_pk) = mpc_keys::hpke::generate();
        let starting_message = Message::Generating(GeneratingMessage {
            from: cait_sith::protocol::Participant::from(0),
            data: vec![],
        });

        let message = serde_json::to_vec(&starting_message).unwrap();
        let message = cipher_pk.encrypt(&message, associated_data).unwrap();

        let message = serde_json::to_vec(&message).unwrap();
        let cipher = serde_json::from_slice(&message).unwrap();
        let message = cipher_sk.decrypt(&cipher, associated_data).unwrap();
        let message: Message = serde_json::from_slice(&message).unwrap();

        assert_eq!(starting_message, message);
    }

    #[test]
    fn test_encrypt_then_decrypt() {
        let (cipher_sk, cipher_pk) = mpc_keys::hpke::generate();
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt0");
        let from = Participant::from(7);
        let mut participants = Participants::default();
        participants.insert(
            &from,
            ParticipantInfo {
                sign_pk: sign_sk.public_key(),
                cipher_pk: cipher_pk.clone(),
                id: from.into(),
                url: "http://localhost:3030".to_string(),
                account_id: "test.near".parse().unwrap(),
            },
        );
        let participants = ParticipantMap::One(participants);

        let batch = vec![Message::Triple(TripleMessage {
            id: 1234,
            epoch: 0,
            from,
            data: vec![128u8; 1024],
            timestamp: 1234567,
        })];
        let encrypted = SignedMessage::encrypt(&batch, from, &sign_sk, &cipher_pk).unwrap();
        let decrypted_batch: Vec<Message> =
            SignedMessage::decrypt(&encrypted, &cipher_sk, &participants).unwrap();

        assert_eq!(
            batch, decrypted_batch,
            "batch messages did not get encrypted and decrypted correctly"
        );
    }

    #[test]
    fn test_serialization_change() {
        #[derive(Serialize, Deserialize)]
        struct NewSignedMessage {
            #[serde(with = "serde_bytes")]
            msg: Vec<u8>,
            sig: near_crypto::Signature,
            from: Participant,

            // default will call Default::default() if missing in serialized bytes.
            #[serde(default)]
            added_field: Vec<u32>,
        }

        impl NewSignedMessage {
            const ASSOCIATED_DATA: &'static [u8] = SignedMessage::ASSOCIATED_DATA;

            fn encrypt<T: Serialize>(
                batch: &T,
                from: Participant,
                sign_sk: &near_crypto::SecretKey,
                cipher_pk: &hpke::PublicKey,
            ) -> Ciphered {
                let msg = super::cbor_to_bytes(batch).unwrap();
                let sig = sign_sk.sign(&msg);
                let msg = Self {
                    msg,
                    sig,
                    from,
                    added_field: vec![127; 1024],
                };
                let msg = super::cbor_to_bytes(&msg).unwrap();
                cipher_pk.encrypt(&msg, Self::ASSOCIATED_DATA).unwrap()
            }

            fn decrypt<T: DeserializeOwned>(
                encrypted: &Ciphered,
                cipher_sk: &hpke::SecretKey,
            ) -> T {
                let msg = cipher_sk.decrypt(encrypted, Self::ASSOCIATED_DATA).unwrap();
                let Self { msg, .. } = super::cbor_from_bytes(&msg).unwrap();
                super::cbor_from_bytes(&msg).unwrap()
            }
        }

        #[derive(Debug, Serialize, Deserialize)]
        enum NewMessage {
            Triple(NewTripleMessage),
            NewVariant(String),
            #[serde(untagged)]
            Unknown(ciborium::Value),
        }

        impl PartialEq<Message> for NewMessage {
            fn eq(&self, other: &Message) -> bool {
                match (self, other) {
                    (NewMessage::Triple(a), Message::Triple(b)) => a == b,
                    // ignore the unknowns for comparison since we don't care about them here.
                    _ => true,
                }
            }
        }

        #[derive(Debug, Serialize, Deserialize)]
        struct NewTripleMessage {
            id: u64,
            epoch: u64,
            from: Participant,
            #[serde(with = "serde_bytes")]
            data: Vec<u8>,
            timestamp: u64,
            // added this new timestamp in the future:
            #[serde(default)]
            new_timestamp: Option<u64>,
        }

        impl PartialEq<TripleMessage> for NewTripleMessage {
            fn eq(&self, other: &TripleMessage) -> bool {
                self.id == other.id
                    && self.epoch == other.epoch
                    && self.from == other.from
                    && self.data == other.data
                    && self.timestamp == other.timestamp
            }
        }

        let from = Participant::from(1337);
        let (cipher_sk, cipher_pk) = mpc_keys::hpke::generate();
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt1");
        let mut participants = Participants::default();
        participants.insert(
            &from,
            ParticipantInfo {
                sign_pk: sign_sk.public_key(),
                cipher_pk: cipher_pk.clone(),
                id: from.into(),
                url: "http://localhost:3030".to_string(),
                account_id: "test.near".parse().unwrap(),
            },
        );
        let participants = ParticipantMap::One(participants);

        // Test forward compatibility
        let old_batch = vec![
            Message::Triple(TripleMessage {
                id: 1234,
                epoch: 0,
                from,
                data: vec![128; 1024],
                timestamp: 1234567,
            }),
            Message::Generating(GeneratingMessage {
                from,
                data: vec![8; 512],
            }),
            Message::Signature(SignatureMessage {
                id: SignId::new([7; 32]),
                proposer: from,
                presignature_id: 1234,
                epoch: 0,
                from,
                data: vec![78; 1222],
                timestamp: 1234567,
            }),
        ];
        let encrypted = SignedMessage::encrypt(&old_batch, from, &sign_sk, &cipher_pk).unwrap();
        let new_batch: Vec<NewMessage> = NewSignedMessage::decrypt(&encrypted, &cipher_sk);
        assert_eq!(
            new_batch, old_batch,
            "encrypt/decrypt failed forward compatibility"
        );

        // Test backward compatibility
        let new_batch = vec![
            NewMessage::Triple(NewTripleMessage {
                id: 1234,
                epoch: 0,
                from,
                data: vec![128u8; 1024],
                timestamp: 1234567,
                new_timestamp: Some(777),
            }),
            NewMessage::NewVariant("hello".to_string()),
        ];
        let new_ciphered = NewSignedMessage::encrypt(&new_batch, from, &sign_sk, &cipher_pk);
        let old_batch: Vec<Message> =
            SignedMessage::decrypt(&new_ciphered, &cipher_sk, &participants).unwrap();
        assert_eq!(
            new_batch, old_batch,
            "encrypt/decrypt failed backward compatibility"
        );
    }

    #[test]
    fn test_encrypt_size() {
        let epoch = 1;
        let from = Participant::from(0);
        let batch = vec![
            Message::Triple(TripleMessage {
                id: 1,
                epoch,
                from,
                data: vec![128u8; 1024],
                timestamp: 1,
            }),
            Message::Triple(crate::protocol::message::TripleMessage {
                id: 2,
                epoch,
                from,
                data: vec![255u8; 2048],
                timestamp: 2,
            }),
            Message::Triple(TripleMessage {
                id: 3,
                epoch,
                from,
                data: vec![101u8; 1337],
                timestamp: 3,
            }),
        ];

        let batch_bytesize = batch.iter().map(|msg| msg.size()).sum::<usize>();
        dbg!(batch_bytesize);

        let (_cipher_sk, cipher_pk) = mpc_keys::hpke::generate();
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt0");
        let ciphered = SignedMessage::encrypt(&batch, from, &sign_sk, &cipher_pk).unwrap();
        let ciphered_bytesize = ciphered.text.len();
        dbg!(ciphered_bytesize);

        let margin_percent = 0.05;
        let margin_of_err = (batch_bytesize as f64 * margin_percent) as usize;
        dbg!(margin_of_err);
        assert!(
            ((batch_bytesize - margin_of_err)..(batch_bytesize + margin_of_err))
                .contains(&ciphered_bytesize),
            "ciphered message size is not within 5% of the original message size"
        );
    }
}
