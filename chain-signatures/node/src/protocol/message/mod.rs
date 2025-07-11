mod filter;
mod types;

pub use crate::protocol::message::types::{
    GeneratingMessage, Message, MessageError, MessageFilterId, PositMessage, PositProtocolId,
    PresignatureMessage, Protocols, ResharingMessage, SignatureMessage, TripleMessage,
};
use crate::protocol::posit::PositAction;
use crate::protocol::presignature::FullPresignatureId;
use crate::rpc::ContractStateWatcher;

use super::contract::primitives::{ParticipantMap, Participants};
use super::presignature::PresignatureId;
use super::state::{GeneratingState, NodeState, ResharingState};
use super::triple::TripleId;
use crate::node_client::NodeClient;
use crate::protocol::message::filter::{MessageFilter, MAX_FILTER_SIZE};
use crate::protocol::Config;
use crate::protocol::MeshState;
use crate::types::Epoch;

use async_trait::async_trait;
use cait_sith::protocol::Participant;
use mpc_contract::config::ProtocolConfig;
use mpc_keys::hpke::{self, Ciphered};
use mpc_primitives::SignId;
use near_account_id::AccountId;
use near_crypto::Signature;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::{mpsc, watch, RwLock};

pub const MAX_MESSAGE_INCOMING: usize = 1024 * 1024;
pub const MAX_MESSAGE_OUTGOING: usize = 1024 * 1024;

/// This should be enough to hold a few messages in the inbox.
pub const MAX_MESSAGE_SUB_CHANNEL_SIZE: usize = 4 * 1024;

enum Subscriber<T> {
    /// Temporary/replaceable value, and will never be used. Only here so we can have a
    /// way to convert from an Unsubscribed to a Subscribed subscription.
    Unknown,
    /// A subscribed channel where the subscriber has a handle to the receiver.
    Subscribed(mpsc::Sender<T>),
    /// An unsubscribed channel where there's potentially messages that have yet to be sent.
    Unsubscribed(mpsc::Sender<T>, mpsc::Receiver<T>),
}

impl<T> Subscriber<T> {
    pub fn subscribed() -> (Self, mpsc::Receiver<T>) {
        let (tx, rx) = mpsc::channel(MAX_MESSAGE_SUB_CHANNEL_SIZE);
        (Self::Subscribed(tx), rx)
    }

    pub fn unsubscribed() -> Self {
        let (tx, rx) = mpsc::channel(MAX_MESSAGE_SUB_CHANNEL_SIZE);
        Self::Unsubscribed(tx, rx)
    }

    /// Convert this subscriber into a subscribed one, returning the receiver.
    /// If the subscriber is already subscribed, it overrides the existing subscription.
    pub fn subscribe(&mut self) -> mpsc::Receiver<T> {
        let sub = std::mem::replace(self, Self::Unknown);
        let (sub, rx) = match sub {
            Self::Subscribed(_) | Self::Unknown => Self::subscribed(),
            Self::Unsubscribed(tx, rx) => (Self::Subscribed(tx), rx),
        };
        *self = sub;
        rx
    }

    /// Unsubscribe from the subscriber, converting it into an unsubscribed one.
    pub fn unsubscribe(&mut self) {
        if matches!(self, Self::Subscribed(_) | Self::Unknown) {
            *self = Self::unsubscribed();
        }
    }

    pub async fn send(&self, msg: T) -> Result<(), mpsc::error::SendError<T>> {
        match self {
            Self::Subscribed(tx) => tx.send(msg).await,
            Self::Unsubscribed(tx, _) => tx.send(msg).await,
            Self::Unknown => Ok(()),
        }
    }
}

impl<T> Default for Subscriber<T> {
    fn default() -> Self {
        Self::unsubscribed()
    }
}

pub struct MessageInbox {
    /// encrypted messages that are pending to be decrypted. These are messages that we received
    /// from other nodes that weren't able to be processed yet due to missing info such as the
    /// participant id in the case of slow resharing.
    try_decrypt: VecDeque<(Ciphered, Instant)>,

    /// This idempotent checker is used to check that the same batch of messages does not make
    /// it back in the system somehow. Uses the signature to make this check.
    idempotent: lru::LruCache<Signature, ()>,

    /// A filter to filter out messages that have somehow made it back into the system after
    /// being processed.
    filter: MessageFilter,

    /// Incoming messages that are pending to be processed. These are encrypted and signed.
    inbox_rx: mpsc::Receiver<Ciphered>,

    generating: VecDeque<GeneratingMessage>,
    resharing: HashMap<Epoch, VecDeque<ResharingMessage>>,
    triple: HashMap<TripleId, Subscriber<TripleMessage>>,
    triple_init: Subscriber<(TripleId, Participant, PositAction)>,
    presignature: HashMap<PresignatureId, Subscriber<PresignatureMessage>>,
    presignature_init: Subscriber<(FullPresignatureId, Participant, PositAction)>,
    signature: HashMap<(SignId, PresignatureId), Subscriber<SignatureMessage>>,
    signature_init: Subscriber<(SignId, PresignatureId, Participant, PositAction)>,
}

impl MessageInbox {
    pub fn new(
        inbox_rx: mpsc::Receiver<Ciphered>,
        filter_rx: mpsc::Receiver<(Protocols, u64)>,
    ) -> Self {
        Self {
            try_decrypt: VecDeque::new(),
            idempotent: lru::LruCache::new(MAX_FILTER_SIZE),
            filter: MessageFilter::new(filter_rx),
            inbox_rx,
            generating: VecDeque::new(),
            resharing: HashMap::new(),
            triple: HashMap::new(),
            triple_init: Subscriber::unsubscribed(),
            presignature: HashMap::new(),
            presignature_init: Subscriber::unsubscribed(),
            signature: HashMap::new(),
            signature_init: Subscriber::unsubscribed(),
        }
    }

    async fn send(&mut self, message: Message) {
        match message {
            Message::Posit(message) => match message.id {
                PositProtocolId::Triple(id) => {
                    let _ = self
                        .triple_init
                        .send((id, message.from, message.action))
                        .await;
                }
                PositProtocolId::Presignature(id) => {
                    let _ = self
                        .presignature_init
                        .send((id, message.from, message.action))
                        .await;
                }
                PositProtocolId::Signature(sign_id, presignature_id) => {
                    let _ = self
                        .signature_init
                        .send((sign_id, presignature_id, message.from, message.action))
                        .await;
                }
            },
            Message::Generating(message) => self.generating.push_back(message),
            Message::Resharing(message) => self
                .resharing
                .entry(message.epoch)
                .or_default()
                .push_back(message),
            Message::Triple(message) => {
                // NOTE: not logging the error because this is simply just channel closure.
                // The error message should be reported on the generator side.
                let _ = self
                    .triple
                    .entry(message.id)
                    .or_default()
                    .send(message)
                    .await;
            }
            Message::Presignature(message) => {
                let _ = self
                    .presignature
                    .entry(message.id)
                    .or_default()
                    .send(message)
                    .await;
            }
            Message::Signature(message) => {
                let _ = self
                    .signature
                    .entry((message.id, message.presignature_id))
                    .or_default()
                    .send(message)
                    .await;
            }
            Message::Unknown(entries) => {
                tracing::warn!(
                    entries = ?entries.iter().map(|(k, v)| (k, cbor_name(v))).collect::<Vec<_>>(),
                    "inbox: received unknown message type",
                );
            }
        }
    }

    fn expire(&mut self, timeout: Duration) {
        self.try_decrypt
            .retain(|(_, timestamp)| timestamp.elapsed() < timeout);
    }

    fn recv_updates(&mut self) {
        self.filter.recv_updates();
        loop {
            let encrypted = match self.inbox_rx.try_recv() {
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

    fn decrypt(
        &mut self,
        cipher_sk: &hpke::SecretKey,
        participants: &ParticipantMap,
    ) -> Vec<Message> {
        let mut retry = Vec::new();

        let mut messages = Vec::new();
        while let Some((encrypted, timestamp)) = self.try_decrypt.pop_front() {
            let decrypted: Result<Vec<Message>, _> =
                SignedMessage::decrypt_with(&encrypted, cipher_sk, participants, |sig| {
                    if self.idempotent.put(sig.clone(), ()).is_some() {
                        Err(MessageError::Idempotent)
                    } else {
                        Ok(())
                    }
                });

            match decrypted {
                Ok(decrypted) => messages.extend(decrypted),
                Err(err) => {
                    if matches!(err, MessageError::UnknownParticipant(_)) {
                        retry.push((encrypted, timestamp));
                    } else {
                        tracing::warn!(?err, "inbox: failed to decrypt/verify messages");
                    }
                    continue;
                }
            };
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

    pub fn filter_internal(&mut self) {
        // NOTE: this might cause some warnings to pop up such as:
        // "trying to unsub from an unknown triple subscription".
        // This is fine since the filter made it here first before the
        // subscription gets removed on TripleGenerator drop.
        self.triple
            .retain(|id, _| !self.filter.contains_id(*id, Protocols::Triple));
        self.presignature
            .retain(|id, _| !self.filter.contains_id(*id, Protocols::Presignature));
        self.signature
            .retain(|id, _| !self.filter.contains_id(id.id(), Protocols::Signature));
    }

    async fn recv(&mut self, messages: Vec<Message>) {
        for message in messages {
            self.send(message).await;
        }
    }

    pub async fn update(
        &mut self,
        expiration: Duration,
        cipher_sk: &hpke::SecretKey,
        participants: &ParticipantMap,
    ) {
        self.expire(expiration);
        self.recv_updates();
        let messages = self.decrypt(cipher_sk, participants);
        let messages = self.filter(messages);
        self.recv(messages).await;
    }

    pub fn clear(&mut self) {
        self.try_decrypt.clear();
        self.generating.clear();
        self.resharing.clear();
        self.triple.clear();
        self.presignature.clear();
        self.signature.clear();
    }

    pub fn clear_filters(&mut self) {
        self.filter.clear();
    }

    pub fn clear_idempotent(&mut self) {
        self.idempotent.clear();
    }
}

struct MessageExecutor {
    inbox: Arc<RwLock<MessageInbox>>,
    outbox: MessageOutbox,

    config: watch::Receiver<Config>,
    contract: ContractStateWatcher,
    mesh_state: watch::Receiver<MeshState>,
}

impl MessageExecutor {
    pub async fn execute(mut self) {
        let mut interval = tokio::time::interval(Duration::from_millis(10));
        loop {
            interval.tick().await;
            let config = self.config.borrow().clone();

            let participants = self.contract.participants().await;
            {
                let mut inbox = self.inbox.write().await;
                let expiration = Duration::from_millis(config.protocol.message_timeout);
                inbox
                    .update(expiration, &config.local.network.cipher_sk, &participants)
                    .await;
            }

            let active = self.mesh_state.borrow().active.clone();
            self.outbox.expire(&config.protocol);
            self.outbox.recv_updates();
            let compacted = self.outbox.compact();
            let encrypted = self
                .outbox
                .encrypt(&config.local.network.sign_sk, &active, compacted);
            self.outbox.send(&active, encrypted).await;
        }
    }
}

#[derive(Clone)]
pub struct MessageChannel {
    outgoing: mpsc::Sender<SendMessage>,
    inbox: Arc<RwLock<MessageInbox>>,
    filter: mpsc::Sender<(Protocols, u64)>,
}

impl MessageChannel {
    pub fn new() -> (mpsc::Sender<Ciphered>, mpsc::Receiver<SendMessage>, Self) {
        let (inbox_tx, inbox_rx) = mpsc::channel(MAX_MESSAGE_INCOMING);
        let (outbox_tx, outbox_rx) = mpsc::channel(MAX_MESSAGE_OUTGOING);
        let (filter_tx, filter_rx) = mpsc::channel(MAX_FILTER_SIZE.into());

        let inbox = Arc::new(RwLock::new(MessageInbox::new(inbox_rx, filter_rx)));
        let channel = Self {
            inbox,
            outgoing: outbox_tx,
            filter: filter_tx,
        };

        (inbox_tx, outbox_rx, channel)
    }

    pub async fn spawn(
        client: NodeClient,
        id: &AccountId,
        config: watch::Receiver<Config>,
        contract: ContractStateWatcher,
        mesh_state: watch::Receiver<MeshState>,
    ) -> (mpsc::Sender<Ciphered>, Self) {
        let (inbox_tx, outbox_rx, channel) = Self::new();
        let runner = MessageExecutor {
            inbox: channel.inbox.clone(),
            outbox: MessageOutbox::new(id, client, outbox_rx),

            config,
            contract,
            mesh_state,
        };
        tokio::spawn(runner.execute());

        (inbox_tx, channel)
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
    pub async fn filter<M: MessageFilterId>(&self, msg: &M) {
        if let Err(err) = self.filter.send((M::PROTOCOL, msg.id())).await {
            tracing::warn!(?err, "failed to send filter message");
        }
    }

    pub async fn filter_triple(&self, id: TripleId) {
        if let Err(err) = self.filter.send((Protocols::Triple, id)).await {
            tracing::warn!(?err, "failed to send filter message");
        }
    }

    pub async fn filter_presignature(&self, id: PresignatureId) {
        if let Err(err) = self.filter.send((Protocols::Presignature, id)).await {
            tracing::warn!(?err, "failed to send filter message");
        }
    }

    pub async fn filter_sign(&self, sign_id: SignId, presignature_id: PresignatureId) {
        self.filter(&(sign_id, presignature_id)).await;
    }

    pub async fn subscribe_triple(&self, id: TripleId) -> mpsc::Receiver<TripleMessage> {
        let mut inbox = self.inbox.write().await;
        inbox.triple.entry(id).or_default().subscribe()
    }

    pub async fn unsubscribe_triple(&self, id: TripleId) {
        let mut inbox = self.inbox.write().await;
        if inbox.triple.remove(&id).is_none() {
            tracing::warn!(id, "trying to unsub from an unknown triple subscription");
        }
    }

    pub async fn subscribe_triple_posit(
        &self,
    ) -> mpsc::Receiver<(TripleId, Participant, PositAction)> {
        let mut inbox = self.inbox.write().await;
        inbox.triple_init.subscribe()
    }

    pub async fn unsubscribe_triple_posit(self) {
        let mut inbox = self.inbox.write().await;
        inbox.triple_init.unsubscribe();
    }

    pub async fn subscribe_presignature(
        &self,
        id: PresignatureId,
    ) -> mpsc::Receiver<PresignatureMessage> {
        let mut inbox = self.inbox.write().await;
        inbox.presignature.entry(id).or_default().subscribe()
    }

    pub async fn unsubscribe_presignature(&self, id: PresignatureId) {
        let mut inbox = self.inbox.write().await;
        if inbox.presignature.remove(&id).is_none() {
            tracing::warn!(
                id,
                "trying to unsub from an unknown presignature subscription"
            );
        }
    }

    pub async fn subscribe_presignature_posit(
        &self,
    ) -> mpsc::Receiver<(FullPresignatureId, Participant, PositAction)> {
        let mut inbox = self.inbox.write().await;
        inbox.presignature_init.subscribe()
    }

    pub async fn unsubscribe_presignature_posit(self) {
        let mut inbox = self.inbox.write().await;
        inbox.presignature_init.unsubscribe();
    }

    pub async fn subscribe_signature(
        &self,
        sign_id: SignId,
        presignature_id: PresignatureId,
    ) -> mpsc::Receiver<SignatureMessage> {
        let mut inbox = self.inbox.write().await;
        inbox
            .signature
            .entry((sign_id, presignature_id))
            .or_default()
            .subscribe()
    }

    pub async fn unsubscribe_signature(&self, sign_id: SignId, presignature_id: PresignatureId) {
        let mut inbox = self.inbox.write().await;
        if inbox
            .signature
            .remove(&(sign_id, presignature_id))
            .is_none()
        {
            tracing::warn!(
                ?sign_id,
                presignature_id,
                "trying to unsub from an unknown signature subscription"
            );
        }
    }

    pub async fn subscribe_signature_posit(
        &self,
    ) -> mpsc::Receiver<(SignId, PresignatureId, Participant, PositAction)> {
        let mut inbox = self.inbox.write().await;
        inbox.signature_init.subscribe()
    }

    pub async fn unsubscribe_signature_posit(self) {
        let mut inbox = self.inbox.write().await;
        inbox.signature_init.unsubscribe();
    }
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
        if !inbox.generating.is_empty() {
            let message_counts: HashMap<Participant, usize> =
                inbox
                    .generating
                    .iter()
                    .fold(HashMap::new(), |mut acc, msg| {
                        *acc.entry(msg.from).or_default() += 1;
                        acc
                    });
            tracing::info!(?message_counts, "generating: handling new messages");
        }
        while let Some(msg) = inbox.generating.pop_front() {
            self.protocol.message(msg.from, msg.data);
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
        if !inbox.resharing.is_empty() {
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

            tracing::info!(?message_counts, "resharing: handling new messages");
        }
        let q = inbox.resharing.entry(self.old_epoch).or_default();
        while let Some(msg) = q.pop_front() {
            self.protocol.message(msg.from, msg.data);
        }
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
        {
            // TODO: remove this after adding subscription model for tasks
            // This is a temporary fix to ensure that the filter is updated before processing messages,
            // such that we avoid the race condition where a message is filtered out before it is processed.
            let mut inbox = channel.inbox().write().await;
            inbox.filter.recv_updates();
            inbox.filter_internal();
        }

        match self {
            NodeState::Generating(state) => state.recv(channel, cfg, mesh_state).await,
            NodeState::Resharing(state) => state.recv(channel, cfg, mesh_state).await,
            _ => Ok(()),
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
        Self::decrypt_with(encrypted, cipher_sk, participants, |_| Ok(()))
    }

    pub fn decrypt_with<T: DeserializeOwned, F: FnMut(&Signature) -> Result<(), MessageError>>(
        encrypted: &Ciphered,
        cipher_sk: &hpke::SecretKey,
        participants: &ParticipantMap,
        mut check: F,
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

        // Do external check before verifying the signature.
        check(&sig)?;

        if !sig.verify(&msg, &info.sign_pk) {
            tracing::error!(?from, "signed message erred out with invalid signature");
            return Err(MessageError::Verification(
                "invalid signature while verifying authenticity of encrypted protocol message",
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
    account_id: AccountId,
    client: NodeClient,

    /// The messages that are pending to be sent to other nodes.
    outbox_rx: mpsc::Receiver<SendMessage>,

    // NOTE: we have FromParticipant here to circumvent the chance that we change Participant
    // id for our own node in the middle of something like resharing or adding another curve
    // type.
    /// Messsages sorted by participant map to a list of partitioned messages to be sent as
    /// a single request to other participants.
    messages: HashMap<MessageRoute, Vec<(Message, Instant)>>,
}

impl MessageOutbox {
    pub fn new(id: &AccountId, client: NodeClient, outbox_rx: mpsc::Receiver<SendMessage>) -> Self {
        Self {
            client,
            account_id: id.clone(),
            outbox_rx,
            messages: HashMap::new(),
        }
    }

    pub fn recv_updates(&mut self) {
        let mut message_count: i64 = 0;
        loop {
            let (msg, (from, to, timestamp)) = match self.outbox_rx.try_recv() {
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

        let msg_send_delay_metric =
            crate::metrics::MSG_CLIENT_SEND_DELAY.with_label_values(&[self.account_id.as_str()]);
        let num_send_encrypted_failure_metric = crate::metrics::NUM_SEND_ENCRYPTED_FAILURE
            .with_label_values(&[self.account_id.as_str()]);
        let send_encrypted_latency_metric =
            crate::metrics::SEND_ENCRYPTED_LATENCY.with_label_values(&[self.account_id.as_str()]);
        let failed_send_encrypted_latency_metric = crate::metrics::FAILED_SEND_ENCRYPTED_LATENCY
            .with_label_values(&[self.account_id.as_str()]);

        for ((from, to), encrypted) in encrypted {
            for (encrypted_partition, partition) in encrypted {
                // guaranteed to unwrap due to our previous loop check:
                let info = active.get(&to).unwrap();
                let account_id = info.account_id.clone();
                let url = info.url.clone();

                crate::metrics::NUM_SEND_ENCRYPTED_TOTAL
                    .with_label_values(&[account_id.as_str()])
                    .inc_by(partition.messages.len() as f64);

                let msg_send_delay_metric = msg_send_delay_metric.clone();
                let num_send_encrypted_failure_metric = num_send_encrypted_failure_metric.clone();
                let send_encrypted_latency_metric = send_encrypted_latency_metric.clone();
                let failed_send_encrypted_latency_metric =
                    failed_send_encrypted_latency_metric.clone();

                let client = self.client.clone();
                send_tasks.push(tokio::spawn(async move {
                    let start = Instant::now();
                    for msg_inbox_time in partition.timestamps.iter() {
                        msg_send_delay_metric.observe((start - *msg_inbox_time).as_millis() as f64);
                    }
                    if let Err(err) = client.msg(url, &[&encrypted_partition]).await {
                        num_send_encrypted_failure_metric.inc_by(partition.messages.len() as f64);
                        failed_send_encrypted_latency_metric
                            .observe(start.elapsed().as_millis() as f64);
                        Err(((from, to), partition, err))
                    } else {
                        send_encrypted_latency_metric.observe(start.elapsed().as_millis() as f64);
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
        Message::Posit(_) => Duration::from_millis(cfg.message_timeout),
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
    use std::time::Duration;

    use cait_sith::protocol::Participant;
    use mpc_keys::hpke::{self, Ciphered};
    use mpc_primitives::SignId;
    use serde::{de::DeserializeOwned, Deserialize, Serialize};

    use crate::protocol::{
        contract::primitives::{ParticipantMap, Participants},
        message::{GeneratingMessage, Message, SignatureMessage, SignedMessage, TripleMessage},
        ParticipantInfo,
    };

    use super::MessageChannel;

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

        let (_cipher_sk, cipher_pk) = hpke::generate();
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

    #[tokio::test]
    async fn test_inbox() {
        let expiration = Duration::from_secs(300);
        let epoch = 299;
        let from = Participant::from(0);
        let (cipher_sk, cipher_pk) = hpke::generate();
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt0");
        let participants = {
            let mut map = Participants::default();
            for i in 0..2 {
                map.insert(
                    &Participant::from(i),
                    ParticipantInfo {
                        sign_pk: sign_sk.public_key(),
                        cipher_pk: cipher_pk.clone(),
                        id: from.into(),
                        url: "http://localhost:3030".to_string(),
                        account_id: "test.near".parse().unwrap(),
                    },
                );
            }
            ParticipantMap::One(map)
        };
        let (inbox_tx, _outbox_rx, channel) = MessageChannel::new();

        // Case 1:
        // Check that the inbox received our messages correctly:
        {
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
            let encrypted = SignedMessage::encrypt(&batch, from, &sign_sk, &cipher_pk).unwrap();
            inbox_tx.try_send(encrypted).unwrap();
            let mut inbox = channel.inbox().try_write().unwrap();
            inbox.update(expiration, &cipher_sk, &participants).await;
            assert_eq!(inbox.triple.len(), 3, "initial triple messages not found");
            inbox.clear();
        }

        // Case 2:
        // Check that inbox filters work correctly, and that the first message did not make it through:
        let filter_id = 2;
        let batch = vec![
            Message::Triple(TripleMessage {
                id: 1,
                epoch,
                from,
                data: vec![129u8; 1024],
                timestamp: 1,
            }),
            Message::Triple(crate::protocol::message::TripleMessage {
                id: filter_id,
                epoch,
                from,
                data: vec![229u8; 2048],
                timestamp: 2,
            }),
            Message::Triple(TripleMessage {
                id: 3,
                epoch,
                from,
                data: vec![121u8; 1337],
                timestamp: 3,
            }),
        ];
        {
            let encrypted = SignedMessage::encrypt(&batch, from, &sign_sk, &cipher_pk).unwrap();
            channel.filter_triple(filter_id).await;
            inbox_tx.try_send(encrypted).unwrap();
            let mut inbox = channel.inbox().try_write().unwrap();
            inbox.update(expiration, &cipher_sk, &participants).await;
            assert_eq!(
                inbox.triple.len(),
                2,
                "inbox triple messages was not successfully filtered"
            );
            // do not clear messages, but clear the filters, have the next case check idempotentcy
            inbox.clear_filters();
        }

        // Case 3:
        // Check idempotentcy. The same set of messages (from case 2) encrypted and signed again should produce
        // the same signature. Thus sending the same encrypted message should be idempotent.
        {
            let encrypted = SignedMessage::encrypt(&batch, from, &sign_sk, &cipher_pk).unwrap();
            channel.filter_triple(filter_id).await;
            inbox_tx.try_send(encrypted).unwrap();
            let mut inbox = channel.inbox().try_write().unwrap();
            inbox.update(expiration, &cipher_sk, &participants).await;
            assert_eq!(
                inbox.triple.len(),
                2,
                "inbox should have two messages from prev case for idempotentcy"
            );
            inbox.clear();
        }
    }
}
