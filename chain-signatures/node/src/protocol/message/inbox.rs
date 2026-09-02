//! The receiving actor: decrypts, dedups, and routes incoming messages.

use super::crypto::{cbor_name, SignedMessage};
use crate::metrics::messaging::{set_channel_capacity_tx, set_inbox_count};
use crate::protocol::contract::primitives::ParticipantMap;
use crate::protocol::message::filter::{MessageFilter, MAX_FILTER_SIZE};
use crate::protocol::message::sub::{
    self, SubscribeId, SubscribeRequest, SubscribeRequestAction, SubscribeResponse, Subscriber,
};
use crate::protocol::message::types::Round;
use crate::protocol::posit::PositAction;
use crate::protocol::presignature::{FullPresignatureId, PresignatureId};
use crate::protocol::triple::TripleId;
use crate::protocol::Config;
use crate::rpc::ContractStateWatcher;

use crate::protocol::message::types::{
    GeneratingMessage, Message, MessageError, PositProtocolId, PresignatureMessage, Protocols,
    ReadyMessage, ResharingMessage, SignatureMessage, TripleMessage,
};

use cait_sith::protocol::Participant;
use mpc_keys::hpke::{self, Ciphered};
use mpc_primitives::SignId;
use near_crypto::Signature;
use tokio::sync::{mpsc, watch};

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Metric labels for the per-generation subscriber maps
const TRIPLE_TASK_LABEL: &str = "triple_task";
const PRESIGNATURE_TASK_LABEL: &str = "presign_task";
const SIGNATURE_TASK_LABEL: &str = "sign_task";

/// Receiving half of the message system: accepts encrypted messages from peers,
/// decrypts and dedups them, and routes each to its subscriber channel.
pub struct MessageInbox {
    /// Received messages staged for decryption, with arrival time. A message
    /// from an unknown participant (e.g. mid-resharing) is retried on later
    /// passes until `expire` drops it.
    pending_decrypt: VecDeque<(Ciphered, Instant)>,

    /// This idempotent checker is used to check that the same batch of messages does not make
    /// it back in the system somehow. Uses the signature to make this check.
    idempotent: lru::LruCache<Signature, ()>,

    /// Kill-list of finished protocol instances (fed by generator `Drop`s, on
    /// completion or abort). Late messages for these ids are dropped so they
    /// can't recreate orphan subscriber entries in the maps below.
    filter: MessageFilter,

    /// Sender half of the incoming channel; kept to report capacity metrics.
    inbox_tx: mpsc::Sender<Ciphered>,
    /// Encrypted, signed messages from peers, awaiting decryption and routing.
    inbox_rx: mpsc::Receiver<Ciphered>,

    /// Sender half of the subscription channel; kept to report capacity metrics.
    subscribe_tx: mpsc::Sender<SubscribeRequest>,
    /// Subscribe/unsubscribe requests from `MessageChannel`.
    subscribe_rx: mpsc::Receiver<SubscribeRequest>,

    generating: Subscriber<GeneratingMessage>,
    resharing: Subscriber<ResharingMessage>,
    ready: Subscriber<ReadyMessage>,

    /// Protocol messages per running triple generation; entries created on
    /// demand and removed on unsubscribe.
    triple: HashMap<TripleId, Subscriber<TripleMessage>>,
    /// Posit conversations for all triples; demuxed per-id by the TripleSpawner.
    triple_posit: Subscriber<(TripleId, Participant, PositAction)>,
    /// Protocol messages per running presignature generation.
    presignature: HashMap<PresignatureId, Subscriber<PresignatureMessage>>,
    /// Posit conversations for all presignatures; demuxed by the PresignatureSpawner.
    presignature_posit: Subscriber<(FullPresignatureId, Participant, PositAction)>,
    /// Protocol messages per running signature generation.
    signature: HashMap<(SignId, PresignatureId), Subscriber<SignatureMessage>>,
    /// Posit conversations for all sign requests; demuxed per sign_id by the SignatureSpawner.
    signature_posit: Subscriber<(
        SignId,
        PresignatureId,
        Round,
        Participant,
        PositAction,
        Option<Round>,
    )>,
}

impl MessageInbox {
    pub fn new(
        inbox_tx: mpsc::Sender<Ciphered>,
        inbox_rx: mpsc::Receiver<Ciphered>,
        filter_tx: mpsc::Sender<(Protocols, u64)>,
        filter_rx: mpsc::Receiver<(Protocols, u64)>,
        subscribe_tx: mpsc::Sender<SubscribeRequest>,
        subscribe_rx: mpsc::Receiver<SubscribeRequest>,
    ) -> Self {
        Self {
            pending_decrypt: VecDeque::new(),
            idempotent: lru::LruCache::new(MAX_FILTER_SIZE),
            filter: MessageFilter::new(filter_tx, filter_rx),
            inbox_tx,
            inbox_rx,
            subscribe_tx,
            subscribe_rx,
            generating: Subscriber::unsubscribed("generating"),
            resharing: Subscriber::unsubscribed("resharing"),
            ready: Subscriber::unsubscribed("ready"),
            triple: HashMap::new(),
            triple_posit: Subscriber::unsubscribed_with_capacity(
                "triple_posit",
                sub::MAX_MESSAGE_POSIT_SUB_CHANNEL_SIZE,
            ),
            presignature: HashMap::new(),
            presignature_posit: Subscriber::unsubscribed_with_capacity(
                "presignature_posit",
                sub::MAX_MESSAGE_POSIT_SUB_CHANNEL_SIZE,
            ),
            signature: HashMap::new(),
            signature_posit: Subscriber::unsubscribed_with_capacity(
                "signature_posit",
                sub::MAX_MESSAGE_POSIT_SUB_CHANNEL_SIZE,
            ),
        }
    }

    fn send(&mut self, message: Message) {
        match message {
            Message::Posit(message) => match message.id {
                PositProtocolId::Triple(id) => {
                    let _ = self
                        .triple_posit
                        .try_send_lossy((id, message.from, message.action));
                    self.triple_posit.report_capacity_global();
                }
                PositProtocolId::Presignature(id) => {
                    let _ =
                        self.presignature_posit
                            .try_send_lossy((id, message.from, message.action));
                    self.presignature_posit.report_capacity_global();
                }
                PositProtocolId::Signature(sign_id, presignature_id, round) => {
                    let _ = self.signature_posit.try_send_lossy((
                        sign_id,
                        presignature_id,
                        round,
                        message.from,
                        message.action,
                        message.stale_round,
                    ));
                    self.signature_posit.report_capacity_global();
                }
            },
            Message::Generating(message) => {
                let _ = self.generating.try_send_lossy(message);
                self.generating.report_capacity_global();
            }
            Message::Resharing(message) => {
                let _ = self.resharing.try_send_lossy(message);
                self.resharing.report_capacity_global();
            }
            Message::Ready(message) => {
                let _ = self.ready.try_send_lossy(message);
                self.ready.report_capacity_global();
            }
            Message::Triple(message) => {
                let sub = self
                    .triple
                    .entry(message.id)
                    .or_insert_with(|| Subscriber::unsubscribed(TRIPLE_TASK_LABEL));
                let _ = sub.try_send_lossy(message);
                sub.report_capacity();
                set_inbox_count(TRIPLE_TASK_LABEL, self.triple.len());
            }
            Message::Presignature(message) => {
                let sub = self
                    .presignature
                    .entry(message.id)
                    .or_insert_with(|| Subscriber::unsubscribed(PRESIGNATURE_TASK_LABEL));
                let _ = sub.try_send_lossy(message);
                sub.report_capacity();
                set_inbox_count(PRESIGNATURE_TASK_LABEL, self.presignature.len());
            }
            Message::Signature(message) => {
                let sub = self
                    .signature
                    .entry((message.id, message.presignature_id))
                    .or_insert_with(|| Subscriber::unsubscribed(SIGNATURE_TASK_LABEL));
                let _ = sub.try_send_lossy(message);
                sub.report_capacity();
                set_inbox_count(SIGNATURE_TASK_LABEL, self.signature.len());
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
        self.pending_decrypt
            .retain(|(_, timestamp)| timestamp.elapsed() < timeout);
    }

    /// Decrypt and dedup pending batches, returning each alongside its
    /// authenticated sender.
    fn decrypt(
        &mut self,
        cipher_sk: &hpke::SecretKey,
        participants: &ParticipantMap,
    ) -> Vec<(Participant, Vec<Message>)> {
        let mut retry = Vec::new();

        let mut batches = Vec::new();
        while let Some((encrypted, timestamp)) = self.pending_decrypt.pop_front() {
            let decrypted: Result<(Participant, Vec<Message>), _> =
                SignedMessage::decrypt_with(&encrypted, cipher_sk, participants, |sig| {
                    if self.idempotent.put(sig.clone(), ()).is_some() {
                        Err(MessageError::Idempotent)
                    } else {
                        Ok(())
                    }
                });

            match decrypted {
                Ok(batch) => batches.push(batch),
                // Sender is not in our participant map yet; keep the batch and
                // retry once the map catches up.
                Err(MessageError::UnknownParticipant(_)) => retry.push((encrypted, timestamp)),
                // A batch we have already ingested, resent because the peer's
                // outbox retried a send that had in fact landed.
                Err(MessageError::Idempotent) => {
                    tracing::debug!("inbox: dropped duplicate message batch");
                }
                Err(err) => tracing::warn!(?err, "inbox: failed to decrypt/verify messages"),
            };
        }

        self.pending_decrypt.extend(retry);
        batches
    }

    /// Drop messages whose claimed sender differs from the authenticated
    /// envelope sender, and whole batches we sent to ourselves.
    fn verify_senders(
        batches: Vec<(Participant, Vec<Message>)>,
        me: Option<Participant>,
    ) -> Vec<Message> {
        let mut messages = Vec::new();
        for (authenticated_from, batch) in batches {
            // Only our key signs as us: a local send bug or a peer
            // echoing our own traffic back.
            if Some(authenticated_from) == me {
                tracing::error!("inbox: dropping a batch we sent to ourselves");
                continue;
            }
            messages.extend(batch.into_iter().filter(|msg| match msg.claimed_sender() {
                Some(claimed_from) if claimed_from != authenticated_from => {
                    tracing::error!(
                        ?authenticated_from,
                        ?claimed_from,
                        typename = msg.typename(),
                        "inbox: dropping message with spoofed sender"
                    );
                    false
                }
                _ => true,
            }));
        }
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
    fn publish(&mut self, messages: Vec<Message>) {
        for message in messages {
            self.send(message);
        }
    }

    pub fn clear_filters(&mut self) {
        self.filter.clear();
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
                    let sub = self
                        .triple
                        .entry(id)
                        .or_insert_with(|| Subscriber::unsubscribed(TRIPLE_TASK_LABEL));
                    let rx = sub.subscribe();
                    let _ = resp.send(SubscribeResponse::Triple(rx));
                }
                SubscribeRequestAction::Unsubscribe => {
                    if let Some(sub) = self.triple.remove(&id) {
                        sub.clear_capacity_global();
                    } else {
                        tracing::warn!(id, "trying to unsub from an unknown triple subscription");
                    }
                    set_inbox_count(TRIPLE_TASK_LABEL, self.triple.len());
                }
            },
            SubscribeId::Presignature(id) => match sub.action {
                SubscribeRequestAction::Subscribe(resp) => {
                    let sub = self
                        .presignature
                        .entry(id)
                        .or_insert_with(|| Subscriber::unsubscribed(PRESIGNATURE_TASK_LABEL));
                    let rx = sub.subscribe();
                    let _ = resp.send(SubscribeResponse::Presignature(rx));
                }
                SubscribeRequestAction::Unsubscribe => {
                    if let Some(sub) = self.presignature.remove(&id) {
                        sub.clear_capacity_global();
                    } else {
                        tracing::warn!(
                            id,
                            "trying to unsub from an unknown presignature subscription"
                        );
                    }
                    set_inbox_count(PRESIGNATURE_TASK_LABEL, self.presignature.len());
                }
            },
            SubscribeId::Signature(sign_id, presignature_id) => match sub.action {
                SubscribeRequestAction::Subscribe(resp) => {
                    let sub = self
                        .signature
                        .entry((sign_id, presignature_id))
                        .or_insert_with(|| Subscriber::unsubscribed(SIGNATURE_TASK_LABEL));
                    let rx = sub.subscribe();
                    let _ = resp.send(SubscribeResponse::Signature(rx));
                }
                SubscribeRequestAction::Unsubscribe => {
                    if let Some(sub) = self.signature.remove(&(sign_id, presignature_id)) {
                        sub.clear_capacity_global();
                    } else {
                        tracing::warn!(
                            ?sign_id,
                            ?presignature_id,
                            "trying to unsub from an unknown signature subscription"
                        );
                    }
                    set_inbox_count(SIGNATURE_TASK_LABEL, self.signature.len());
                }
            },
            SubscribeId::Ready => match sub.action {
                SubscribeRequestAction::Subscribe(resp) => {
                    let rx = self.ready.subscribe();
                    let _ = resp.send(SubscribeResponse::Ready(rx));
                }
                SubscribeRequestAction::Unsubscribe => {
                    self.ready.unsubscribe();
                    self.ready.clear_capacity_global();
                }
            },
            SubscribeId::TriplePosit => match sub.action {
                SubscribeRequestAction::Subscribe(resp) => {
                    let rx = self.triple_posit.subscribe();
                    let _ = resp.send(SubscribeResponse::TriplePosit(rx));
                }
                SubscribeRequestAction::Unsubscribe => {
                    self.triple_posit.unsubscribe();
                }
            },
            SubscribeId::PresignaturePosit => match sub.action {
                SubscribeRequestAction::Subscribe(resp) => {
                    let rx = self.presignature_posit.subscribe();
                    let _ = resp.send(SubscribeResponse::PresignaturePosit(rx));
                }
                SubscribeRequestAction::Unsubscribe => {
                    self.presignature_posit.unsubscribe();
                }
            },
            SubscribeId::SignaturePosit => match sub.action {
                SubscribeRequestAction::Subscribe(resp) => {
                    let rx = self.signature_posit.subscribe();
                    let _ = resp.send(SubscribeResponse::SignaturePosit(rx));
                }
                SubscribeRequestAction::Unsubscribe => {
                    self.signature_posit.unsubscribe();
                }
            },
        }
    }

    pub async fn run(mut self, config: watch::Receiver<Config>, contract: ContractStateWatcher) {
        loop {
            tokio::select! {
                _ = self.filter.update() => {}
                Some(sub) = self.subscribe_rx.recv() => {
                    set_channel_capacity_tx("subscribe", &self.subscribe_tx);
                    self.process_subscribe(sub);
                }
                Some(encrypted) = self.inbox_rx.recv() => {
                    set_channel_capacity_tx("incoming", &self.inbox_tx);
                    let config = config.borrow().clone();
                    let expiration = Duration::from_millis(config.protocol.message_timeout);
                    let participants = contract.participant_map().await;
                    let me = contract.me().await;
                    let cipher_sk = config.local.network.cipher_sk;

                    self.expire(expiration);
                    self.pending_decrypt.push_back((encrypted, Instant::now()));
                    let batches = self.decrypt(&cipher_sk, &participants);
                    let messages = Self::verify_senders(batches, me);

                    // update filter before fanning out messages.
                    self.filter.try_update();

                    let messages = self.filter(messages);
                    let messages_len = messages.len();
                    self.publish(messages);

                    crate::metrics::messaging::NUM_RECEIVED_ENCRYPTED_TOTAL
                        .inc_by(messages_len as f64);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, LocalConfig, NetworkConfig, OverrideConfig};
    use crate::protocol::contract::primitives::Participants;
    use crate::protocol::message::{MessageChannel, SignedMessage};
    use crate::protocol::ParticipantInfo;
    use crate::rpc::ContractStateWatcher;
    use crate::util::NearPublicKeyExt;

    use mpc_keys::hpke;
    use std::time::Duration;

    struct InboxTestSetup {
        epoch: u64,
        from: Participant,
        sign_sk: near_crypto::SecretKey,
        cipher_pk: hpke::PublicKey,
        channel: MessageChannel,
        inbox: tokio::task::JoinHandle<()>,
        _config_tx: watch::Sender<Config>,
        _contract_tx: watch::Sender<Option<crate::protocol::ProtocolState>>,
    }

    fn inbox_setup() -> InboxTestSetup {
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

        InboxTestSetup {
            epoch,
            from,
            sign_sk,
            cipher_pk,
            channel,
            inbox,
            _config_tx,
            _contract_tx,
        }
    }

    fn triple_batch(epoch: u64, from: Participant) -> Vec<Message> {
        vec![
            Message::Triple(TripleMessage {
                id: 1,
                epoch,
                from,
                data: vec![128u8; 1024],
                timestamp: 1,
            }),
            Message::Triple(TripleMessage {
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
        ]
    }

    /// Check that the inbox receives our messages correctly.
    #[tokio::test]
    async fn test_inbox_receives_messages() {
        let setup = inbox_setup();
        let batch = triple_batch(setup.epoch, setup.from);
        let encrypted =
            SignedMessage::encrypt(&batch, setup.from, &setup.sign_sk, &setup.cipher_pk).unwrap();
        setup.channel.send_inbox(encrypted).await;

        let mut recv1 = setup.channel.subscribe_triple(1).await;
        let mut recv2 = setup.channel.subscribe_triple(2).await;
        let mut recv3 = setup.channel.subscribe_triple(3).await;

        let (m1, m2, m3) = match tokio::join!(recv1.recv(), recv2.recv(), recv3.recv()) {
            (Some(m1), Some(m2), Some(m3)) => (m1, m2, m3),
            _ => panic!("failed to join on inbox"),
        };

        assert_eq!(m1.id, 1);
        assert_eq!(m2.id, 2);
        assert_eq!(m3.id, 3);

        setup.inbox.abort();
    }

    /// Check that inbox filters work correctly, and that the filtered message
    /// does not make it through.
    #[tokio::test]
    async fn test_inbox_filters_messages() {
        let setup = inbox_setup();
        let filter_id = 2;
        let batch = triple_batch(setup.epoch, setup.from);
        let encrypted =
            SignedMessage::encrypt(&batch, setup.from, &setup.sign_sk, &setup.cipher_pk).unwrap();

        let mut recv1 = setup.channel.subscribe_triple(1).await;
        let mut recv2 = setup.channel.subscribe_triple(filter_id).await;
        let mut recv3 = setup.channel.subscribe_triple(3).await;

        setup.channel.filter_triple(filter_id).await;
        setup.channel.send_inbox(encrypted).await;

        let (m1, m3) = match tokio::join!(recv1.recv(), recv3.recv()) {
            (Some(m1), Some(m3)) => (m1, m3),
            _ => panic!("failed to join on inbox"),
        };

        assert_eq!(m1.id, 1);
        assert_eq!(m3.id, 3);

        // Expect to timeout here since the message gets filtered out.
        let result = tokio::time::timeout(Duration::from_millis(100), recv2.recv()).await;
        assert!(result.is_err());

        setup.inbox.abort();
    }

    /// Check idempotency. The same set of messages encrypted and signed again
    /// should produce the same signature. Thus sending the same encrypted
    /// message should be idempotent and no new messages should be received by
    /// the subscribers.
    #[tokio::test]
    async fn test_inbox_idempotency() {
        let setup = inbox_setup();
        let batch = triple_batch(setup.epoch, setup.from);
        let encrypted =
            SignedMessage::encrypt(&batch, setup.from, &setup.sign_sk, &setup.cipher_pk).unwrap();
        setup.channel.send_inbox(encrypted).await;

        let mut recv1 = setup.channel.subscribe_triple(1).await;
        let mut recv2 = setup.channel.subscribe_triple(2).await;
        let mut recv3 = setup.channel.subscribe_triple(3).await;

        match tokio::join!(recv1.recv(), recv2.recv(), recv3.recv()) {
            (Some(_), Some(_), Some(_)) => {}
            _ => panic!("failed to join on inbox"),
        }

        setup.channel.unsubscribe_triple(1).await;
        setup.channel.unsubscribe_triple(2).await;
        setup.channel.unsubscribe_triple(3).await;

        // Encrypting the same batch again produces the same signature, so the
        // inbox should drop it as a duplicate.
        let encrypted =
            SignedMessage::encrypt(&batch, setup.from, &setup.sign_sk, &setup.cipher_pk).unwrap();
        setup.channel.send_inbox(encrypted).await;
        let mut recv1 = tokio::time::timeout(
            Duration::from_millis(300),
            setup.channel.subscribe_triple(1),
        )
        .await
        .unwrap();
        let mut recv2 = tokio::time::timeout(
            Duration::from_millis(300),
            setup.channel.subscribe_triple(2),
        )
        .await
        .unwrap();
        let mut recv3 = tokio::time::timeout(
            Duration::from_millis(300),
            setup.channel.subscribe_triple(3),
        )
        .await
        .unwrap();

        let result1 = tokio::time::timeout(Duration::from_millis(100), recv1.recv()).await;
        let result2 = tokio::time::timeout(Duration::from_millis(100), recv2.recv()).await;
        let result3 = tokio::time::timeout(Duration::from_millis(100), recv3.recv()).await;

        assert!(result1.is_err());
        assert!(result2.is_err());
        assert!(result3.is_err());

        setup.inbox.abort();
    }

    /// Forged inner senders and self-sent batches are dropped.
    #[test]
    fn test_inbox_drops_spoofed_and_self_sent_messages() {
        let me = Participant::from(0);
        let peer = Participant::from(1);
        let (cipher_sk, cipher_pk) = hpke::generate();
        let my_sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt0");
        let peer_sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt1");
        let mut participants = Participants::default();
        for (p, sign_sk) in [(me, &my_sign_sk), (peer, &peer_sign_sk)] {
            participants.insert(
                &p,
                ParticipantInfo {
                    sign_pk: sign_sk.public_key(),
                    cipher_pk: cipher_pk.clone(),
                    id: p.into(),
                    url: "http://localhost:3030".to_string(),
                    account_id: "test.near".parse().unwrap(),
                },
            );
        }
        let participants = ParticipantMap::One(participants);
        let (mut inbox, _outbox, _channel) = MessageChannel::new();

        // Envelope signed by `peer`, inner messages claiming `me`: forged.
        let spoofed = triple_batch(0, me);
        let encrypted = SignedMessage::encrypt(&spoofed, peer, &peer_sign_sk, &cipher_pk).unwrap();
        inbox.pending_decrypt.push_back((encrypted, Instant::now()));
        let batches = inbox.decrypt(&cipher_sk, &participants);
        assert!(MessageInbox::verify_senders(batches, Some(me)).is_empty());

        // Mixed batch: only the forged message is dropped.
        let mixed = vec![
            Message::Triple(TripleMessage {
                id: 4,
                epoch: 0,
                from: me, // forged: envelope is signed by `peer`
                data: vec![1u8; 8],
                timestamp: 1,
            }),
            Message::Triple(TripleMessage {
                id: 5,
                epoch: 0,
                from: peer,
                data: vec![2u8; 8],
                timestamp: 2,
            }),
            Message::Unknown(HashMap::new()),
        ];
        let encrypted = SignedMessage::encrypt(&mixed, peer, &peer_sign_sk, &cipher_pk).unwrap();
        inbox.pending_decrypt.push_back((encrypted, Instant::now()));
        let batches = inbox.decrypt(&cipher_sk, &participants);
        let survivors = MessageInbox::verify_senders(batches, Some(me));
        assert_eq!(survivors.len(), 2);
        assert!(matches!(&survivors[0], Message::Triple(msg) if msg.id == 5));
        assert!(matches!(&survivors[1], Message::Unknown(_)));

        // Self-signed batch: dropped whole.
        let self_sent = triple_batch(1, me);
        let encrypted = SignedMessage::encrypt(&self_sent, me, &my_sign_sk, &cipher_pk).unwrap();
        inbox.pending_decrypt.push_back((encrypted, Instant::now()));
        let batches = inbox.decrypt(&cipher_sk, &participants);
        assert!(MessageInbox::verify_senders(batches, Some(me)).is_empty());

        // Wrong signing key: rejected at signature verification already.
        let forged_envelope = triple_batch(3, peer);
        let encrypted =
            SignedMessage::encrypt(&forged_envelope, peer, &my_sign_sk, &cipher_pk).unwrap();
        inbox.pending_decrypt.push_back((encrypted, Instant::now()));
        assert!(inbox.decrypt(&cipher_sk, &participants).is_empty());

        // Control: consistent sender passes through.
        let valid = triple_batch(2, peer);
        let encrypted = SignedMessage::encrypt(&valid, peer, &peer_sign_sk, &cipher_pk).unwrap();
        inbox.pending_decrypt.push_back((encrypted, Instant::now()));
        let batches = inbox.decrypt(&cipher_sk, &participants);
        assert_eq!(MessageInbox::verify_senders(batches, Some(me)).len(), 3);
    }

    #[tokio::test]
    async fn test_signature_posit_backpressure_does_not_block_ready_messages() {
        use crate::protocol::message::{
            sub, MessageInbox, PositMessage, PositProtocolId, ReadyMessage,
        };
        use crate::protocol::posit::PositAction;
        use tokio::sync::mpsc;

        let (inbox_tx, inbox_rx) = mpsc::channel(1);
        let (filter_tx, filter_rx) = mpsc::channel(1);
        let (subscribe_tx, subscribe_rx) = mpsc::channel(1);
        let mut inbox = MessageInbox::new(
            inbox_tx,
            inbox_rx,
            filter_tx,
            filter_rx,
            subscribe_tx,
            subscribe_rx,
        );

        // Override to a small capacity so we can easily fill it
        inbox.signature_posit = sub::Subscriber::unsubscribed_with_capacity("signature_posit", 1);

        let (signature_req, signature_resp) =
            sub::SubscribeRequest::subscribe(sub::SubscribeId::SignaturePosit);
        inbox.process_subscribe(signature_req);
        let mut signature_posit_rx = match signature_resp.await.unwrap() {
            sub::SubscribeResponse::SignaturePosit(rx) => rx,
            _ => panic!("expected signature posit subscription"),
        };

        let (ready_req, ready_resp) = sub::SubscribeRequest::subscribe(sub::SubscribeId::Ready);
        inbox.process_subscribe(ready_req);
        let mut ready_rx = match ready_resp.await.unwrap() {
            sub::SubscribeResponse::Ready(rx) => rx,
            _ => panic!("expected ready subscription"),
        };

        let sign_id = SignId::new([9; 32]);
        let from = Participant::from(0);
        // Flood the signature posit channel beyond its capacity
        let mut messages = Vec::with_capacity(sub::MAX_MESSAGE_SUB_CHANNEL_SIZE + 2);
        for round in 0..=sub::MAX_MESSAGE_SUB_CHANNEL_SIZE {
            messages.push(Message::Posit(PositMessage {
                id: PositProtocolId::Signature(sign_id, 77, round),
                from,
                action: PositAction::Accept,
                stale_round: None,
            }));
        }
        messages.push(Message::Ready(ReadyMessage {
            epoch: 1,
            from,
            nonce: 1,
            token: 1,
        }));

        inbox.publish(messages);
        let ready_message = tokio::time::timeout(Duration::from_millis(100), ready_rx.recv())
            .await
            .expect("ready message should not be blocked by signature posit backlog")
            .expect("ready subscription unexpectedly closed");
        assert_eq!(ready_message.epoch, 1);

        let first_signature_posit = signature_posit_rx
            .recv()
            .await
            .expect("signature posit subscription unexpectedly closed");
        assert_eq!(first_signature_posit.0, sign_id);
    }
}
