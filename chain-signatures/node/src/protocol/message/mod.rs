mod filter;
mod sub;
mod types;

pub use sub::Subscriber;

use crate::protocol::message::sub::{
    SubscribeId, SubscribeRequest, SubscribeRequestAction, SubscribeResponse,
};
use crate::protocol::message::types::Round;
pub use crate::protocol::message::types::{
    GeneratingMessage, Message, MessageError, MessageFilterId, PositMessage, PositProtocolId,
    PresignatureMessage, Protocols, ReadyMessage, ResharingMessage, SignatureMessage,
    TripleMessage,
};
use crate::protocol::posit::PositAction;
use crate::protocol::presignature::FullPresignatureId;
use crate::rpc::ContractStateWatcher;

use super::contract::primitives::{ParticipantMap, Participants};
use super::presignature::PresignatureId;
use super::triple::TripleId;
use crate::node_client::NodeClient;
use crate::protocol::message::filter::{MessageFilter, MAX_FILTER_SIZE};
use crate::protocol::Config;

use cait_sith::protocol::Participant;
use mpc_contract::config::ProtocolConfig;
use mpc_keys::hpke::{self, Ciphered};
use mpc_primitives::SignId;
use near_crypto::Signature;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub const MAX_MESSAGE_INCOMING: usize = 1024 * 1024;
pub const MAX_MESSAGE_OUTGOING: usize = 1024 * 1024;
pub const MAX_OUTBOX_PAYLOAD_LIMIT: usize = 256 * 1024;
pub const MAX_INBOX_BATCH_SIZE: usize = 32;

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

    /// Subscription requests from MessageChannel
    subscribe_rx: mpsc::Receiver<SubscribeRequest>,

    generating: Subscriber<GeneratingMessage>,
    resharing: Subscriber<ResharingMessage>,
    ready: Subscriber<ReadyMessage>,
    triple: HashMap<TripleId, Subscriber<TripleMessage>>,
    triple_init: Subscriber<(TripleId, Participant, PositAction)>,
    presignature: HashMap<PresignatureId, Subscriber<PresignatureMessage>>,
    presignature_init: Subscriber<(FullPresignatureId, Participant, PositAction)>,
    signature: HashMap<(SignId, PresignatureId), Subscriber<SignatureMessage>>,
    signature_init: Subscriber<(SignId, PresignatureId, Round, Participant, PositAction)>,
}

impl MessageInbox {
    pub fn new(
        inbox_rx: mpsc::Receiver<Ciphered>,
        filter_rx: mpsc::Receiver<(Protocols, u64)>,
        subscribe_rx: mpsc::Receiver<SubscribeRequest>,
    ) -> Self {
        Self {
            try_decrypt: VecDeque::new(),
            idempotent: lru::LruCache::new(MAX_FILTER_SIZE),
            filter: MessageFilter::new(filter_rx),
            inbox_rx,
            subscribe_rx,
            generating: Subscriber::unsubscribed(),
            resharing: Subscriber::unsubscribed(),
            ready: Subscriber::unsubscribed(),
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
                PositProtocolId::Signature(sign_id, presignature_id, round) => {
                    let _ = self
                        .signature_init
                        .send((
                            sign_id,
                            presignature_id,
                            round,
                            message.from,
                            message.action,
                        ))
                        .await;
                }
            },
            Message::Generating(message) => {
                let _ = self.generating.send(message).await;
            }
            Message::Resharing(message) => {
                let _ = self.resharing.send(message).await;
            }
            Message::Ready(message) => {
                let _ = self.ready.send(message).await;
            }
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

    /// Publish messages to subscribers
    async fn publish(&mut self, messages: Vec<Message>) {
        for message in messages {
            self.send(message).await;
        }
    }

    pub fn clear_filters(&mut self) {
        self.filter.clear();
    }

    pub fn clear_idempotent(&mut self) {
        self.idempotent.clear();
    }

    pub fn process_subscribe(&mut self, sub: SubscribeRequest) {
        match sub.id {
            SubscribeId::Generating => match sub.action {
                SubscribeRequestAction::Subscribe(resp) => {
                    let rx = self.generating.subscribe();
                    let _ = resp.send(SubscribeResponse::Generating(rx));
                }
                SubscribeRequestAction::Unsubscribe => {
                    tracing::warn!("unsubscribing from generation not supported");
                }
            },
            SubscribeId::Resharing => match sub.action {
                SubscribeRequestAction::Subscribe(resp) => {
                    let rx = self.resharing.subscribe();
                    let _ = resp.send(SubscribeResponse::Resharing(rx));
                }
                SubscribeRequestAction::Unsubscribe => {
                    tracing::warn!("unsubscribing from resharing not supported");
                }
            },
            SubscribeId::Triple(id) => match sub.action {
                SubscribeRequestAction::Subscribe(resp) => {
                    let rx = self.triple.entry(id).or_default().subscribe();
                    let _ = resp.send(SubscribeResponse::Triple(rx));
                }
                SubscribeRequestAction::Unsubscribe => {
                    if self.triple.remove(&id).is_none() {
                        tracing::warn!(id, "trying to unsub from an unknown triple subscription");
                    }
                }
            },
            SubscribeId::Presignature(id) => match sub.action {
                SubscribeRequestAction::Subscribe(resp) => {
                    let rx = self.presignature.entry(id).or_default().subscribe();
                    let _ = resp.send(SubscribeResponse::Presignature(rx));
                }
                SubscribeRequestAction::Unsubscribe => {
                    if self.presignature.remove(&id).is_none() {
                        tracing::warn!(
                            id,
                            "trying to unsub from an unknown presignature subscription"
                        );
                    }
                }
            },
            SubscribeId::Signature(sign_id, presignature_id) => match sub.action {
                SubscribeRequestAction::Subscribe(resp) => {
                    let rx = self
                        .signature
                        .entry((sign_id, presignature_id))
                        .or_default()
                        .subscribe();
                    let _ = resp.send(SubscribeResponse::Signature(rx));
                }
                SubscribeRequestAction::Unsubscribe => {
                    if self.signature.remove(&(sign_id, presignature_id)).is_none() {
                        tracing::warn!(
                            ?sign_id,
                            ?presignature_id,
                            "trying to unsub from an unknown signature subscription"
                        );
                    }
                }
            },
            SubscribeId::Ready => match sub.action {
                SubscribeRequestAction::Subscribe(resp) => {
                    let rx = self.ready.subscribe();
                    let _ = resp.send(SubscribeResponse::Ready(rx));
                }
                SubscribeRequestAction::Unsubscribe => {
                    self.ready.unsubscribe();
                }
            },
            SubscribeId::Triples => match sub.action {
                SubscribeRequestAction::Subscribe(resp) => {
                    let rx = self.triple_init.subscribe();
                    let _ = resp.send(SubscribeResponse::TriplePosit(rx));
                }
                SubscribeRequestAction::Unsubscribe => {
                    self.triple_init.unsubscribe();
                }
            },
            SubscribeId::Presignatures => match sub.action {
                SubscribeRequestAction::Subscribe(resp) => {
                    let rx = self.presignature_init.subscribe();
                    let _ = resp.send(SubscribeResponse::PresignaturePosit(rx));
                }
                SubscribeRequestAction::Unsubscribe => {
                    self.presignature_init.unsubscribe();
                }
            },
            SubscribeId::Signatures => match sub.action {
                SubscribeRequestAction::Subscribe(resp) => {
                    let rx = self.signature_init.subscribe();
                    let _ = resp.send(SubscribeResponse::SignaturePosit(rx));
                }
                SubscribeRequestAction::Unsubscribe => {
                    self.signature_init.unsubscribe();
                }
            },
        }
    }

    pub async fn run(
        mut self,
        mut config: watch::Receiver<Config>,
        contract: ContractStateWatcher,
    ) {
        let mut buf = Vec::with_capacity(MAX_INBOX_BATCH_SIZE);
        let mut expiration = Duration::from_millis(config.borrow().protocol.message_timeout);
        let mut cipher_sk = config.borrow().local.network.cipher_sk.clone();

        loop {
            tokio::select! {
                _ = self.filter.update() => {}
                Some(sub) = self.subscribe_rx.recv() => {
                    self.process_subscribe(sub);
                }
                received = self.inbox_rx.recv_many(&mut buf, MAX_INBOX_BATCH_SIZE) => {
                    if received == 0 {
                        continue;
                    }

                    for encrypted in buf.drain(..) {
                        self.try_decrypt.push_back((encrypted, Instant::now()));
                    }

                    let participants = contract.participant_map().await;

                    self.expire(expiration);
                    let messages = self.decrypt(&cipher_sk, &participants);

                    // update filter before fanning out messages.
                    self.filter.try_update();

                    let messages = self.filter(messages);
                    let messages_len = messages.len();
                    self.publish(messages).await;

                    crate::metrics::messaging::NUM_RECEIVED_ENCRYPTED_TOTAL
                        .inc_by(messages_len as f64);
                }
                Ok(()) = config.changed() => {
                    let config = config.borrow();
                    expiration = Duration::from_millis(config.protocol.message_timeout);
                    cipher_sk = config.local.network.cipher_sk.clone();
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct MessageChannel {
    outgoing: mpsc::Sender<SendMessage>,
    subscribe: mpsc::Sender<SubscribeRequest>,
    filter: mpsc::Sender<(Protocols, u64)>,
    pub inbox: mpsc::Sender<Ciphered>,
}

impl MessageChannel {
    pub fn new() -> (MessageInbox, MessageOutbox, Self) {
        let (inbox_tx, inbox_rx) = mpsc::channel(MAX_MESSAGE_INCOMING);
        let (outbox_tx, outbox_rx) = mpsc::channel(MAX_MESSAGE_OUTGOING);
        let (filter_tx, filter_rx) = mpsc::channel(MAX_FILTER_SIZE.into());
        let (subscribe_tx, subscribe_rx) = mpsc::channel(16384);
        let inbox = MessageInbox::new(inbox_rx, filter_rx, subscribe_rx);
        let outbox = MessageOutbox::new(outbox_rx);

        let channel = Self {
            inbox: inbox_tx,
            outgoing: outbox_tx,
            subscribe: subscribe_tx,
            filter: filter_tx,
        };

        (inbox, outbox, channel)
    }

    pub async fn spawn(
        client: NodeClient,
        config: watch::Receiver<Config>,
        contract: ContractStateWatcher,
    ) -> Self {
        let (inbox, outbox, channel) = Self::new();
        tokio::spawn(inbox.run(config.clone(), contract.clone()));
        tokio::spawn(outbox.run(client, config, contract));

        channel
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

    async fn subscribe(&self, id: SubscribeId) -> Option<SubscribeResponse> {
        let (req, resp) = SubscribeRequest::subscribe(id);
        if self.subscribe.send(req).await.is_err() {
            return None;
        };
        let Ok(subscription) = resp.await else {
            return None;
        };
        Some(subscription)
    }

    pub async fn subscribe_triple(&self, id: TripleId) -> mpsc::Receiver<TripleMessage> {
        let Some(subscription) = self.subscribe(SubscribeId::Triple(id)).await else {
            tracing::warn!(id, "failed to subscribe for triple");
            return mpsc::channel(1).1;
        };
        match subscription {
            SubscribeResponse::Triple(rx) => rx,
            _ => {
                tracing::warn!(id, "received unexpected subscribe response for triple");
                mpsc::channel(1).1
            }
        }
    }

    pub async fn unsubscribe_triple(&self, id: TripleId) {
        if self
            .subscribe
            .send(SubscribeRequest::unsubscribe(SubscribeId::Triple(id)))
            .await
            .is_err()
        {
            tracing::warn!(id, "unable to send unsubscribe request for triple message");
        };
    }

    /// Subscribe to the triple posit. It returns a dropped channel in the case that something
    /// in the MessageInbox has gone wrong and unexpected, leading to the handling loop of whoever
    /// has a handle to this newly created channel to just abort.
    pub async fn subscribe_triple_posit(
        &self,
    ) -> mpsc::Receiver<(TripleId, Participant, PositAction)> {
        let Some(subscription) = self.subscribe(SubscribeId::Triples).await else {
            tracing::warn!("failed to subscribe for triple posits");
            return mpsc::channel(1).1;
        };
        match subscription {
            SubscribeResponse::TriplePosit(rx) => rx,
            _ => {
                tracing::warn!("received unexpected subscribe response for triple posits");
                mpsc::channel(1).1
            }
        }
    }

    pub async fn unsubscribe_triple_posit(self) {
        if self
            .subscribe
            .send(SubscribeRequest::unsubscribe(SubscribeId::Triples))
            .await
            .is_err()
        {
            tracing::warn!("unable to send unsubscribe request for triple posits");
        };
    }

    pub async fn subscribe_presignature(
        &self,
        id: PresignatureId,
    ) -> mpsc::Receiver<PresignatureMessage> {
        let Some(subscription) = self.subscribe(SubscribeId::Presignature(id)).await else {
            tracing::warn!(id, "failed to subscribe for presignature");
            return mpsc::channel(1).1;
        };
        match subscription {
            SubscribeResponse::Presignature(rx) => rx,
            _ => {
                tracing::warn!(
                    id,
                    "received unexpected subscribe response for presignature"
                );
                mpsc::channel(1).1
            }
        }
    }

    pub async fn unsubscribe_presignature(&self, id: PresignatureId) {
        if self
            .subscribe
            .send(SubscribeRequest::unsubscribe(SubscribeId::Presignature(id)))
            .await
            .is_err()
        {
            tracing::warn!("unable to send unsubscribe request for presignature");
        };
    }

    pub async fn subscribe_presignature_posit(
        &self,
    ) -> mpsc::Receiver<(FullPresignatureId, Participant, PositAction)> {
        let Some(subscription) = self.subscribe(SubscribeId::Presignatures).await else {
            tracing::warn!("failed to subscribe for presignature posits");
            return mpsc::channel(1).1;
        };
        match subscription {
            SubscribeResponse::PresignaturePosit(rx) => rx,
            _ => {
                tracing::warn!("received unexpected subscribe response for presignature posits");
                mpsc::channel(1).1
            }
        }
    }

    pub async fn unsubscribe_presignature_posit(self) {
        if self
            .subscribe
            .send(SubscribeRequest::unsubscribe(SubscribeId::Presignatures))
            .await
            .is_err()
        {
            tracing::warn!("unable to send unsubscribe request for presignature posits");
        };
    }

    pub async fn subscribe_signature(
        &self,
        sign_id: SignId,
        presignature_id: PresignatureId,
    ) -> mpsc::Receiver<SignatureMessage> {
        let Some(subscription) = self
            .subscribe(SubscribeId::Signature(sign_id, presignature_id))
            .await
        else {
            tracing::warn!(
                ?sign_id,
                ?presignature_id,
                "failed to subscribe for signature"
            );
            return mpsc::channel(1).1;
        };
        match subscription {
            SubscribeResponse::Signature(rx) => rx,
            _ => {
                tracing::warn!(
                    ?sign_id,
                    ?presignature_id,
                    "received unexpected subscribe response for signature"
                );
                mpsc::channel(1).1
            }
        }
    }

    pub async fn unsubscribe_signature(&self, sign_id: SignId, presignature_id: PresignatureId) {
        if self
            .subscribe
            .send(SubscribeRequest::unsubscribe(SubscribeId::Signature(
                sign_id,
                presignature_id,
            )))
            .await
            .is_err()
        {
            tracing::warn!(
                ?sign_id,
                ?presignature_id,
                "unable to send unsubscribe request for signature"
            );
        };
    }

    pub async fn subscribe_signature_posit(
        &self,
    ) -> mpsc::Receiver<(SignId, PresignatureId, Round, Participant, PositAction)> {
        let Some(subscription) = self.subscribe(SubscribeId::Signatures).await else {
            tracing::warn!("failed to subscribe for signature posit");
            return mpsc::channel(1).1;
        };

        match subscription {
            SubscribeResponse::SignaturePosit(rx) => rx,
            _ => {
                tracing::warn!("received unexpected subscribe response for signature posit");
                mpsc::channel(1).1
            }
        }
    }

    pub async fn unsubscribe_signature_posit(self) {
        if self
            .subscribe
            .send(SubscribeRequest::unsubscribe(SubscribeId::Signatures))
            .await
            .is_err()
        {
            tracing::warn!("unable to send unsubscribe request for signature posit");
        };
    }

    pub async fn subscribe_generation(&self) -> mpsc::Receiver<GeneratingMessage> {
        let Some(subscription) = self.subscribe(SubscribeId::Generating).await else {
            panic!("failed to subscribe for generation");
        };
        match subscription {
            SubscribeResponse::Generating(rx) => rx,
            _ => {
                panic!("received unexpected subscribe response for generation");
            }
        }
    }

    pub async fn subscribe_resharing(&self) -> mpsc::Receiver<ResharingMessage> {
        let Some(subscription) = self.subscribe(SubscribeId::Resharing).await else {
            panic!("failed to subscribe for resharing");
        };
        match subscription {
            SubscribeResponse::Resharing(rx) => rx,
            _ => {
                panic!("received unexpected subscribe response for resharing");
            }
        }
    }

    pub async fn subscribe_ready(&self) -> mpsc::Receiver<ReadyMessage> {
        let Some(subscription) = self.subscribe(SubscribeId::Ready).await else {
            panic!("failed to subscribe for resharing readiness");
        };
        match subscription {
            SubscribeResponse::Ready(rx) => rx,
            _ => {
                panic!("received unexpected subscribe response for resharing readiness");
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
pub type SendMessage = (Message, (FromParticipant, ToParticipant, Instant));

#[derive(Default)]
struct PendingRouteMessages {
    messages: Vec<(Message, Instant)>,
    payload_bytes: usize,
    earliest: Option<Instant>,
}

impl PendingRouteMessages {
    fn push(&mut self, message: Message, timestamp: Instant) {
        self.payload_bytes += message.size();
        self.earliest = Some(self.earliest.unwrap_or(timestamp).min(timestamp));
        self.messages.push((message, timestamp));
    }

    fn flush_due_in(&self, timeout: Duration, now: Instant) -> Option<Duration> {
        let earliest = self.earliest?;
        let deadline = earliest + timeout;
        Some(deadline.saturating_duration_since(now))
    }
}

pub struct Partition {
    messages: Vec<Message>,
    /// The earliest timestamp from all the messages.
    timestamp: Instant,
    /// The earliest protocol deadline from all the messages.
    deadline: Instant,
}

/// Message outbox is the set of messages that are pending to be sent to other nodes.
/// These messages will be signed and encrypted before being sent out.
pub struct MessageOutbox {
    /// The messages that are pending to be sent to other nodes.
    outbox_rx: mpsc::Receiver<SendMessage>,

    // NOTE: we have FromParticipant here to circumvent the chance that we change Participant
    // id for our own node in the middle of something like resharing or adding another curve
    // type.
    /// Messsages sorted by participant map to a list of partitioned messages to be sent as
    /// a single request to other participants.
    messages: HashMap<MessageRoute, PendingRouteMessages>,
}

impl MessageOutbox {
    const FLUSH_INTERVAL: Duration = Duration::from_millis(10);

    pub fn new(outbox_rx: mpsc::Receiver<SendMessage>) -> Self {
        Self {
            outbox_rx,
            messages: HashMap::new(),
        }
    }

    fn compact(
        &mut self,
        route: MessageRoute,
        cfg: &ProtocolConfig,
        compacted: &mut HashMap<MessageRoute, Vec<Partition>>,
    ) {
        let Some(messages) = self.messages.remove(&route) else {
            return;
        };

        let entry = compacted.entry(route).or_default();
        entry.extend(partition_256kb(messages.messages, cfg));
    }

    /// Queue a message and immediately flush the route when it reaches the payload threshold.
    pub fn push_message(
        &mut self,
        from: Participant,
        to: Participant,
        message: Message,
        timestamp: Instant,
        payload_limit: usize,
        cfg: &ProtocolConfig,
    ) -> HashMap<MessageRoute, Vec<Partition>> {
        let route = (from, to);
        let pending = self.messages.entry(route).or_default();
        pending.push(message, timestamp);

        if pending.payload_bytes < payload_limit {
            return HashMap::new();
        }

        let mut compacted = HashMap::new();
        self.compact(route, cfg, &mut compacted);
        compacted
    }

    /// Flush any routes whose oldest pending message has waited past the timeout.
    pub fn take_expired_partitions(
        &mut self,
        timeout: Duration,
        now: Instant,
        cfg: &ProtocolConfig,
    ) -> HashMap<MessageRoute, Vec<Partition>> {
        let expired: Vec<_> = self
            .messages
            .iter()
            .filter_map(|(route, pending)| {
                let flush_due = pending
                    .flush_due_in(timeout, now)
                    .is_some_and(|remaining| remaining.is_zero());
                flush_due.then_some(*route)
            })
            .collect();

        let mut compacted = HashMap::new();
        for route in expired {
            self.compact(route, cfg, &mut compacted);
        }
        compacted
    }

    fn next_flush_delay(&self, timeout: Duration, now: Instant) -> Option<Duration> {
        self.messages
            .values()
            .filter_map(|pending| pending.flush_due_in(timeout, now))
            .min()
    }

    /// Encrypt all the messages in the outbox and return a map of participant to encrypted messages.
    pub fn encrypt(
        &self,
        sign_sk: &near_crypto::SecretKey,
        participants: &Participants,
        cfg: &ProtocolConfig,
        compacted: HashMap<MessageRoute, Vec<Partition>>,
    ) -> HashMap<MessageRoute, Vec<(Ciphered, Instant, usize, Instant)>> {
        // failed for when a participant is not active, so keep this message for next round.
        let mut errors = Vec::new();

        let mut encrypted = HashMap::new();
        for ((from, to), compacted) in compacted {
            let Some(info) = participants.get(&to) else {
                tracing::warn!(?to, "outbox: participant not found in all participants");
                continue;
            };

            for partition in compacted {
                let message = match SignedMessage::encrypt(
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

                let deadline = partition
                    .deadline
                    .min(partition.timestamp + message_timeout(cfg, &partition.messages[0]));
                encrypted.entry((from, to)).or_insert_with(Vec::new).push((
                    message,
                    partition.timestamp,
                    partition.messages.len(),
                    deadline,
                ));
            }
        }

        if !errors.is_empty() {
            tracing::warn!(?errors, "outbox: encrypting messages failed on some");
        }

        encrypted
    }

    /// Send the encrypted messages to other participants.
    pub async fn send(
        &self,
        client: &NodeClient,
        participants: &Participants,
        encrypted: HashMap<MessageRoute, Vec<(Ciphered, Instant, usize, Instant)>>,
    ) {
        let start = Instant::now();

        for ((_from, to), encrypted) in encrypted {
            for (encrypted_partition, timestamp, message_len, deadline) in encrypted {
                // guaranteed to unwrap due to our previous loop check:
                let info = participants.get(&to).unwrap();
                let url = info.url.clone();

                crate::metrics::messaging::NUM_SEND_ENCRYPTED_TOTAL.inc_by(message_len as f64);

                let client = client.clone();
                tokio::spawn(async move {
                    let instant = Instant::now();
                    crate::metrics::messaging::MSG_CLIENT_SEND_DELAY
                        .observe((instant - timestamp).as_millis() as f64);
                    let payload = &[&encrypted_partition];
                    let timeout = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
                    tokio::pin!(timeout);

                    loop {
                        let attempt_timestamp = Instant::now();
                        tokio::select! {
                            () = &mut timeout => {
                                tracing::warn!(
                                    ?to, ?url, elapsed = ?instant.elapsed(),
                                    "outbox: failed to send messages, timeout reached",
                                );
                                break;
                            }
                            result = client.msg(&url, payload) => {
                                let Err(err) = result else {
                                    crate::metrics::messaging::SEND_ENCRYPTED_LATENCY.observe(start.elapsed().as_millis() as f64);
                                    break;
                                };

                                tracing::warn!(
                                    ?to, ?url, elapsed = ?attempt_timestamp.elapsed(), ?err,
                                    "outbox: failed to send messages, retrying...",
                                );
                                crate::metrics::messaging::NUM_SEND_ENCRYPTED_FAILURE.inc_by(message_len as f64);
                                crate::metrics::messaging::FAILED_SEND_ENCRYPTED_LATENCY
                                    .observe(attempt_timestamp.elapsed().as_millis() as f64);
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                });
            }
        }
    }

    /// Publish pre-partitioned messages to other nodes.
    async fn publish_partitions(
        &self,
        client: &NodeClient,
        sign_sk: &near_crypto::SecretKey,
        protocol: &ProtocolConfig,
        contract: &ContractStateWatcher,
        compacted: HashMap<MessageRoute, Vec<Partition>>,
    ) {
        if compacted.is_empty() {
            return;
        }

        let Some(participants) = contract.participants() else {
            return;
        };
        let encrypted = self.encrypt(
            sign_sk,
            &participants,
            protocol,
            compacted,
        );
        self.send(client, &participants, encrypted).await;
    }

    pub async fn run(
        mut self,
        client: NodeClient,
        mut config: watch::Receiver<Config>,
        contract: ContractStateWatcher,
    ) {
        let mut protocol = config.borrow().protocol.clone();
        let mut sign_sk = config.borrow().local.network.sign_sk.clone();

        loop {
            let next_flush_delay = self.next_flush_delay(Self::FLUSH_INTERVAL, Instant::now());
            let sleep_until_flush = async {
                match next_flush_delay {
                    Some(delay) => tokio::time::sleep(delay).await,
                    None => std::future::pending::<()>().await,
                }
            };

            tokio::select! {
                Some((msg, (from, to, timestamp))) = self.outbox_rx.recv() => {
                    let ready = self.push_message(
                        from,
                        to,
                        msg,
                        timestamp,
                        MAX_OUTBOX_PAYLOAD_LIMIT,
                        &protocol,
                    );
                    self.publish_partitions(&client, &sign_sk, &protocol, &contract, ready).await;
                }
                _ = sleep_until_flush => {
                    let ready = self.take_expired_partitions(
                        Self::FLUSH_INTERVAL,
                        Instant::now(),
                        &protocol,
                    );
                    self.publish_partitions(&client, &sign_sk, &protocol, &contract, ready).await;
                }
                Ok(()) = config.changed() => {
                    let config = config.borrow();
                    protocol = config.protocol.clone();
                    sign_sk = config.local.network.sign_sk.clone();
                }
            }
        }
    }

    /// Allows tests to manually handle outgoing message before they are
    /// encrypted and published.
    #[cfg(feature = "test-feature")]
    pub fn intercept_outgoing_messages(&mut self) -> &mut mpsc::Receiver<SendMessage> {
        &mut self.outbox_rx
    }
}

fn message_timeout(cfg: &ProtocolConfig, message: &Message) -> Duration {
    let millis = match message {
        Message::Posit(message) => match message.id {
            PositProtocolId::Triple(_) => cfg.triple.generation_timeout,
            PositProtocolId::Presignature(_) => cfg.presignature.generation_timeout,
            PositProtocolId::Signature(_, _, _) => cfg.signature.generation_timeout,
        },
        Message::Triple(_) => cfg.triple.generation_timeout,
        Message::Presignature(_) => cfg.presignature.generation_timeout,
        Message::Signature(_) => cfg.signature.generation_timeout,
        Message::Generating(_) | Message::Resharing(_) | Message::Ready(_) | Message::Unknown(_) => {
            cfg.message_timeout
        }
    };

    Duration::from_millis(millis)
}

/// Partition a list of messages into a list of partitions where each partition is at most 256kb
/// worth of `Message`s.
fn partition_256kb(
    outgoing: impl IntoIterator<Item = (Message, Instant)>,
    cfg: &ProtocolConfig,
) -> Vec<Partition> {
    let mut partitions = Vec::new();
    let mut current_messages = Vec::new();
    let mut current_size: usize = 0;
    let mut earliest = None;
    let mut deadline = None;

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
        if current_size + bytesize > 256 * 1024 && !current_messages.is_empty() {
            // If adding this byte vector exceeds 256kb, start a new partition
            partitions.push(Partition {
                messages: std::mem::take(&mut current_messages),
                timestamp: earliest.unwrap_or_else(Instant::now),
                deadline: deadline.unwrap_or_else(Instant::now),
            });
            current_size = 0;
            earliest = None;
            deadline = None;
        }

        let message_deadline = timestamp + message_timeout(cfg, &msg);
        earliest = Some(earliest.map_or(timestamp, |current| current.min(timestamp)));
        deadline = Some(deadline.map_or(message_deadline, |current| current.min(message_deadline)));
        current_messages.push(msg);
        current_size += bytesize;
    }

    if !current_messages.is_empty() {
        // Add the last partition
        partitions.push(Partition {
            messages: current_messages,
            timestamp: earliest.unwrap_or_else(Instant::now),
            deadline: deadline.unwrap_or_else(Instant::now),
        });
    }

    partitions
}

pub fn cbor_to_bytes<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, MessageError> {
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
    use std::time::{Duration, Instant};

    use cait_sith::protocol::Participant;
    use mpc_contract::config::ProtocolConfig;
    use mpc_keys::hpke::{self, Ciphered};
    use mpc_primitives::SignId;
    use serde::{de::DeserializeOwned, Deserialize, Serialize};

    use crate::{
        config::{Config, LocalConfig, NetworkConfig, OverrideConfig},
        protocol::{
            contract::primitives::{ParticipantMap, Participants},
            message::{
                GeneratingMessage, Message, MessageError, SignatureMessage, SignedMessage,
                TripleMessage,
            },
            ParticipantInfo,
        },
        rpc::ContractStateWatcher,
        util::NearPublicKeyExt,
    };

    use super::{partition_256kb, MessageChannel, MessageOutbox, MAX_OUTBOX_PAYLOAD_LIMIT};

    fn triple_message(id: u64, data_len: usize) -> Message {
        Message::Triple(TripleMessage {
            id,
            epoch: 0,
            from: Participant::from(0),
            data: vec![1; data_len],
            timestamp: id,
        })
    }

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
    fn test_decrypt_rejects_invalid_signature() {
        let (cipher_sk, cipher_pk) = mpc_keys::hpke::generate();
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt2");
        let wrong_sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt3");
        let from = Participant::from(8);
        let mut participants = Participants::default();
        participants.insert(
            &from,
            ParticipantInfo {
                sign_pk: wrong_sign_sk.public_key(),
                cipher_pk: cipher_pk.clone(),
                id: from.into(),
                url: "http://localhost:3030".to_string(),
                account_id: "test.near".parse().unwrap(),
            },
        );
        let participants = ParticipantMap::One(participants);
        let batch = vec![triple_message(9, 32)];

        let encrypted = SignedMessage::encrypt(&batch, from, &sign_sk, &cipher_pk).unwrap();
        let err = SignedMessage::decrypt::<Vec<Message>>(&encrypted, &cipher_sk, &participants)
            .unwrap_err();

        assert!(matches!(err, MessageError::Verification(_)));
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

    #[test]
    fn test_partition_256kb_splits_messages_and_keeps_earliest_timestamp() {
        let earliest = Instant::now() - Duration::from_secs(5);
        let later = Instant::now();
        let first = triple_message(1, 180 * 1024);
        let second = triple_message(2, 180 * 1024);

        let partitions = partition_256kb([(first, earliest), (second, later)], &ProtocolConfig::default());

        assert_eq!(
            partitions.len(),
            2,
            "messages should split into two partitions"
        );
        assert_eq!(partitions[0].messages.len(), 1);
        assert_eq!(partitions[1].messages.len(), 1);
        assert_eq!(partitions[0].timestamp, earliest);
        assert_eq!(partitions[1].timestamp, later);
    }

    #[test]
    fn test_outbox_flushes_route_once_payload_limit_reached() {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        let mut outbox = MessageOutbox::new(rx);
        let from = Participant::from(0);
        let to = Participant::from(1);
        let timestamp = Instant::now();

        let ready = outbox.push_message(
            from,
            to,
            triple_message(1, MAX_OUTBOX_PAYLOAD_LIMIT / 2),
            timestamp,
            MAX_OUTBOX_PAYLOAD_LIMIT,
            &ProtocolConfig::default(),
        );
        assert!(ready.is_empty(), "single message should stay buffered");

        let ready = outbox.push_message(
            from,
            to,
            triple_message(2, MAX_OUTBOX_PAYLOAD_LIMIT / 2),
            timestamp,
            MAX_OUTBOX_PAYLOAD_LIMIT,
            &ProtocolConfig::default(),
        );
        let partitions = ready
            .get(&(from, to))
            .expect("route should flush once payload threshold reached");

        assert_eq!(
            partitions
                .iter()
                .map(|partition| partition.messages.len())
                .sum::<usize>(),
            2
        );
        assert!(
            outbox.messages.is_empty(),
            "flushed route should be removed"
        );
    }

    #[test]
    fn test_outbox_flushes_expired_routes_only() {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        let mut outbox = MessageOutbox::new(rx);
        let timeout = Duration::from_millis(10);
        let stale = Instant::now() - Duration::from_millis(20);
        let fresh = Instant::now();
        let route_a = (Participant::from(0), Participant::from(1));
        let route_b = (Participant::from(0), Participant::from(2));
        let cfg = ProtocolConfig::default();

        let _ = outbox.push_message(
            route_a.0,
            route_a.1,
            triple_message(1, 32),
            stale,
            MAX_OUTBOX_PAYLOAD_LIMIT,
            &cfg,
        );
        let _ = outbox.push_message(
            route_b.0,
            route_b.1,
            triple_message(2, 32),
            fresh,
            MAX_OUTBOX_PAYLOAD_LIMIT,
            &cfg,
        );

        let ready = outbox.take_expired_partitions(timeout, fresh, &cfg);

        assert!(ready.contains_key(&route_a), "stale route should flush");
        assert!(
            !ready.contains_key(&route_b),
            "fresh route should remain buffered"
        );
        assert!(outbox.messages.contains_key(&route_b));
    }

    #[test]
    fn test_partition_uses_earliest_protocol_deadline() {
        let cfg = ProtocolConfig::default();
        let timestamp = Instant::now() - Duration::from_secs(1);
        let triple = triple_message(1, 32);
        let presignature = Message::Presignature(crate::protocol::message::PresignatureMessage {
            id: 2,
            pair_id: 3,
            epoch: 0,
            from: Participant::from(0),
            data: vec![7; 32],
            timestamp: 2,
        });

        let partitions = partition_256kb([(triple, timestamp), (presignature, timestamp)], &cfg);

        assert_eq!(partitions.len(), 1);
        assert_eq!(
            partitions[0].deadline,
            timestamp + Duration::from_millis(cfg.presignature.generation_timeout),
        );
    }

    #[tokio::test]
    async fn test_inbox() {
        let epoch = 299;
        let from = Participant::from(0);
        let (cipher_sk, cipher_pk) = hpke::generate();
        let root_sk = near_crypto::SecretKey::from_seed(near_crypto::KeyType::SECP256K1, "root");
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt0");
        let node_id = "node0".parse().unwrap();
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
            map
        };
        let (_config_tx, config_rx) = Config::channel(LocalConfig {
            over: OverrideConfig::default(),
            network: NetworkConfig {
                sign_sk: sign_sk.clone(),
                cipher_sk,
            },
        });
        let (contract_watcher, _contract_tx) = ContractStateWatcher::with_running(
            &node_id,
            root_sk.public_key().into_affine_point(),
            2,
            participants,
        );
        let (inbox, _outbox, channel) = MessageChannel::new();
        let inbox = tokio::spawn(inbox.run(config_rx, contract_watcher));

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
            channel.inbox.send(encrypted).await.unwrap();

            let mut recv1 = channel.subscribe_triple(1).await;
            let mut recv2 = channel.subscribe_triple(2).await;
            let mut recv3 = channel.subscribe_triple(3).await;

            let (m1, m2, m3) = match tokio::join!(recv1.recv(), recv2.recv(), recv3.recv()) {
                (Some(m1), Some(m2), Some(m3)) => (m1, m2, m3),
                _ => panic!("failed to join on inbox"),
            };

            assert_eq!(m1.id, 1);
            assert_eq!(m2.id, 2);
            assert_eq!(m3.id, 3);

            channel.unsubscribe_triple(1).await;
            channel.unsubscribe_triple(2).await;
            channel.unsubscribe_triple(3).await;
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
            Message::Triple(TripleMessage {
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

            let mut recv1 = channel.subscribe_triple(1).await;
            let mut recv2 = channel.subscribe_triple(filter_id).await;
            let mut recv3 = channel.subscribe_triple(3).await;

            channel.filter_triple(filter_id).await;
            channel.inbox.send(encrypted).await.unwrap();

            let (m1, m3) = match tokio::join!(recv1.recv(), recv3.recv()) {
                (Some(m1), Some(m3)) => (m1, m3),
                _ => panic!("failed to join on inbox"),
            };

            assert_eq!(m1.id, 1);
            assert_eq!(m3.id, 3);

            // Expect to timeout here since the message gets filtered out.
            let result = tokio::time::timeout(Duration::from_millis(100), recv2.recv()).await;
            assert!(result.is_err());

            channel.unsubscribe_triple(1).await;
            channel.unsubscribe_triple(2).await;
            channel.unsubscribe_triple(3).await;
        }

        // Case 3:
        // Check idempotentcy. The same set of messages (from case 2) encrypted and signed again should produce
        // the same signature. Thus sending the same encrypted message should be idempotent and no new messages
        // should be received by the subscribers.
        {
            let encrypted = SignedMessage::encrypt(&batch, from, &sign_sk, &cipher_pk).unwrap();
            channel.inbox.send(encrypted).await.unwrap();
            let mut recv1 =
                tokio::time::timeout(Duration::from_millis(300), channel.subscribe_triple(1))
                    .await
                    .unwrap();
            let mut recv2 =
                tokio::time::timeout(Duration::from_millis(300), channel.subscribe_triple(2))
                    .await
                    .unwrap();
            let mut recv3 =
                tokio::time::timeout(Duration::from_millis(300), channel.subscribe_triple(3))
                    .await
                    .unwrap();

            let result1 = tokio::time::timeout(Duration::from_millis(100), recv1.recv()).await;
            let result2 = tokio::time::timeout(Duration::from_millis(100), recv2.recv()).await;
            let result3 = tokio::time::timeout(Duration::from_millis(100), recv3.recv()).await;

            assert!(result1.is_err());
            assert!(result2.is_err());
            assert!(result3.is_err());
        }

        inbox.abort();
    }
}
