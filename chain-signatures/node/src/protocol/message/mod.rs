mod filter;
mod sub;
mod types;

use crate::protocol::message::sub::{
    SubscribeId, SubscribeRequest, SubscribeRequestAction, SubscribeResponse, Subscriber,
};
pub use crate::protocol::message::types::{
    GeneratingMessage, Message, MessageError, MessageFilterId, PositMessage, PositProtocolId,
    PresignatureMessage, Protocols, ResharingMessage, SignatureMessage, TripleMessage,
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
use near_account_id::AccountId;
use near_crypto::Signature;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub const MAX_MESSAGE_INCOMING: usize = 1024 * 1024;
pub const MAX_MESSAGE_OUTGOING: usize = 1024 * 1024;
pub const MAX_OUTBOX_PAYLOAD_LIMIT: usize = 256 * 1024;

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
            Message::Generating(message) => {
                let _ = self.generating.send(message).await;
            }
            Message::Resharing(message) => {
                let _ = self.resharing.send(message).await;
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
                            presignature_id,
                            "trying to unsub from an unknown signature subscription"
                        );
                    }
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

    pub async fn run(mut self, config: watch::Receiver<Config>, contract: ContractStateWatcher) {
        loop {
            tokio::select! {
                _ = self.filter.update() => {}
                Some(sub) = self.subscribe_rx.recv() => {
                    self.process_subscribe(sub);
                }
                Some(encrypted) = self.inbox_rx.recv() => {
                    let config = config.borrow().clone();
                    let expiration = Duration::from_millis(config.protocol.message_timeout);
                    let participants = contract.participant_map().await;
                    let cipher_sk = config.local.network.cipher_sk;

                    self.expire(expiration);
                    self.try_decrypt.push_back((encrypted, Instant::now()));
                    let messages = self.decrypt(&cipher_sk, &participants);

                    // update filter before fanning out messages.
                    self.filter.try_update();

                    let messages = self.filter(messages);
                    self.publish(messages).await;
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
        id: &AccountId,
        config: watch::Receiver<Config>,
        contract: ContractStateWatcher,
    ) -> Self {
        let (inbox, outbox, channel) = Self::new();
        tokio::spawn(inbox.run(config.clone(), contract.clone()));
        tokio::spawn(outbox.run(id.clone(), client, config, contract));

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
                presignature_id,
                "failed to subscribe for signature"
            );
            return mpsc::channel(1).1;
        };
        match subscription {
            SubscribeResponse::Signature(rx) => rx,
            _ => {
                tracing::warn!(
                    ?sign_id,
                    presignature_id,
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
                presignature_id,
                "unable to send unsubscribe request for signature"
            );
        };
    }

    pub async fn subscribe_signature_posit(
        &self,
    ) -> mpsc::Receiver<(SignId, PresignatureId, Participant, PositAction)> {
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
    /// The earliest timestamp from all the messages.
    timestamp: Instant,
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
    messages: HashMap<MessageRoute, Vec<(Message, Instant)>>,
}

impl MessageOutbox {
    pub fn new(outbox_rx: mpsc::Receiver<SendMessage>) -> Self {
        Self {
            outbox_rx,
            messages: HashMap::new(),
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
        participants: &Participants,
        compacted: HashMap<MessageRoute, Vec<Partition>>,
    ) -> HashMap<MessageRoute, Vec<(Ciphered, Instant, usize)>> {
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

                encrypted.entry((from, to)).or_insert_with(Vec::new).push((
                    message,
                    partition.timestamp,
                    partition.messages.len(),
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
        &mut self,
        account_id: &AccountId,
        client: &NodeClient,
        participants: &Participants,
        cfg: &ProtocolConfig,
        encrypted: HashMap<MessageRoute, Vec<(Ciphered, Instant, usize)>>,
    ) {
        let start = Instant::now();
        let timeout = Duration::from_millis(cfg.message_timeout);

        let msg_send_delay_metric =
            crate::metrics::MSG_CLIENT_SEND_DELAY.with_label_values(&[account_id.as_str()]);
        let num_send_encrypted_failure_metric =
            crate::metrics::NUM_SEND_ENCRYPTED_FAILURE.with_label_values(&[account_id.as_str()]);
        let send_encrypted_latency_metric =
            crate::metrics::SEND_ENCRYPTED_LATENCY.with_label_values(&[account_id.as_str()]);
        let failed_send_encrypted_latency_metric =
            crate::metrics::FAILED_SEND_ENCRYPTED_LATENCY.with_label_values(&[account_id.as_str()]);

        for ((_from, to), encrypted) in encrypted {
            for (encrypted_partition, timestamp, message_len) in encrypted {
                // guaranteed to unwrap due to our previous loop check:
                let info = participants.get(&to).unwrap();
                let url = info.url.clone();

                crate::metrics::NUM_SEND_ENCRYPTED_TOTAL
                    .with_label_values(&[account_id.as_str()])
                    .inc_by(message_len as f64);

                let msg_send_delay_metric = msg_send_delay_metric.clone();
                let num_send_encrypted_failure_metric = num_send_encrypted_failure_metric.clone();
                let send_encrypted_latency_metric = send_encrypted_latency_metric.clone();
                let failed_send_encrypted_latency_metric =
                    failed_send_encrypted_latency_metric.clone();

                let client = client.clone();
                tokio::spawn(async move {
                    let instant = Instant::now();
                    msg_send_delay_metric.observe((instant - timestamp).as_millis() as f64);
                    let payload = &[&encrypted_partition];
                    let timeout = tokio::time::sleep(timeout);
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
                                    send_encrypted_latency_metric.observe(start.elapsed().as_millis() as f64);
                                    tracing::debug!(?to, ?url, elapsed = ?instant.elapsed(), "finished sending messages");
                                    break;
                                };

                                tracing::warn!(
                                    ?to, ?url, elapsed = ?attempt_timestamp.elapsed(), ?err,
                                    "outbox: failed to send messages, retrying...",
                                );
                                num_send_encrypted_failure_metric.inc_by(message_len as f64);
                                failed_send_encrypted_latency_metric
                                    .observe(attempt_timestamp.elapsed().as_millis() as f64);
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                });
            }
        }
    }

    /// Publish messages to other nodes
    async fn publish(
        &mut self,
        id: &AccountId,
        client: &NodeClient,
        config: &watch::Receiver<Config>,
        contract: &ContractStateWatcher,
    ) {
        let Some(participants) = contract.participants() else {
            return;
        };
        let config = config.borrow().clone();
        let compacted = self.compact();
        let encrypted = self.encrypt(&config.local.network.sign_sk, &participants, compacted);
        self.send(id, client, &participants, &config.protocol, encrypted)
            .await;
    }

    pub async fn run(
        mut self,
        id: AccountId,
        client: NodeClient,
        config: watch::Receiver<Config>,
        contract: ContractStateWatcher,
    ) {
        let mut interval = tokio::time::interval(Duration::from_millis(10));
        loop {
            tokio::select! {
                Some((msg, (from, to, timestamp))) = self.outbox_rx.recv() => {
                    // add it to the outbox and sort it by from and to participant
                    let entry = self.messages.entry((from, to)).or_default();
                    entry.push((msg, timestamp));
                }
                _ = interval.tick() => {
                    self.publish(&id, &client, &config, &contract).await;
                }
            }
        }
    }
}

/// Partition a list of messages into a list of partitions where each partition is at most 256kb
/// worth of `Message`s.
fn partition_256kb(outgoing: impl IntoIterator<Item = (Message, Instant)>) -> Vec<Partition> {
    let mut partitions = Vec::new();
    let mut current_messages = Vec::new();
    let mut current_size: usize = 0;
    let mut earliest = Instant::now();

    for (msg, timestamp) in outgoing {
        if matches!(msg, Message::Unknown(_)) {
            // Unknown messages should never be created directly by us. The outbox should never
            // be sending these out to other nodes. We should only be receiving them from the
            // inbox and processed as such there. If we get to this point, that means our system
            // is wrong somewhere such that the node is creating an Unknown message itself.
            tracing::warn!("trying to send unknown message out?");
            continue;
        }

        earliest = earliest.min(timestamp);
        let bytesize = msg.size();
        if current_size + bytesize > 256 * 1024 {
            // If adding this byte vector exceeds 256kb, start a new partition
            partitions.push(Partition {
                messages: std::mem::take(&mut current_messages),
                timestamp: earliest,
            });
            current_size = 0;
        }
        current_messages.push(msg);
        current_size += bytesize;
    }

    if !current_messages.is_empty() {
        // Add the last partition
        partitions.push(Partition {
            messages: current_messages,
            timestamp: earliest,
        });
    }

    partitions
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

    use crate::{
        config::{Config, LocalConfig, NetworkConfig, OverrideConfig},
        protocol::{
            contract::primitives::{ParticipantMap, Participants},
            message::{GeneratingMessage, Message, SignatureMessage, SignedMessage, TripleMessage},
            ParticipantInfo,
        },
        rpc::ContractStateWatcher,
        util::NearPublicKeyExt,
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
