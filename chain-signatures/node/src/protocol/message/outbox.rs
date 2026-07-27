//! The sending actor: partitions, encrypts, and posts outgoing messages to peers.

use super::crypto::SignedMessage;
use crate::metrics;
use crate::metrics::messaging::set_channel_capacity_tx;
use crate::node_client::NodeClient;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::Config;
use crate::rpc::ContractStateWatcher;

use crate::protocol::message::types::Message;

use cait_sith::protocol::Participant;
use mpc_contract::config::ProtocolConfig;
use mpc_keys::hpke::Ciphered;
use tokio::sync::{mpsc, watch};

use std::collections::HashMap;
use std::time::{Duration, Instant};

type FromParticipant = Participant;
type ToParticipant = Participant;
type MessageRoute = (FromParticipant, ToParticipant);
/// An outbound message with its route.
pub struct SendMessage {
    pub message: Message,
    pub from: FromParticipant,
    pub to: ToParticipant,
    pub queued_at: Instant,
}

pub struct Partition {
    messages: Vec<Message>,
    /// The earliest timestamp from all the messages.
    timestamp: Instant,
}

/// Message outbox is the set of messages that are pending to be sent to other nodes.
/// These messages will be signed and encrypted before being sent out.
pub struct MessageOutbox {
    /// Sender half of the outbox channel; kept to report capacity metrics.
    outbox_tx: mpsc::Sender<SendMessage>,
    /// Messages queued via `MessageChannel::send`, awaiting partition + encrypt + send.
    outbox_rx: mpsc::Receiver<SendMessage>,

    // NOTE: we have FromParticipant here to circumvent the chance that we change Participant
    // id for our own node in the middle of something like resharing or adding another curve
    // type.
    /// Messsages sorted by participant map to a list of partitioned messages to be sent as
    /// a single request to other participants.
    messages: HashMap<MessageRoute, Vec<(Message, Instant)>>,
}

impl MessageOutbox {
    pub fn new(
        outbox_tx: mpsc::Sender<SendMessage>,
        outbox_rx: mpsc::Receiver<SendMessage>,
    ) -> Self {
        Self {
            outbox_tx,
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
    ///
    /// Messages to unknown participants or that fail to encrypt are intentionally dropped.
    pub fn encrypt(
        &mut self,
        sign_sk: &near_crypto::SecretKey,
        participants: &Participants,
        compacted: HashMap<MessageRoute, Vec<Partition>>,
    ) -> HashMap<MessageRoute, Vec<(Ciphered, Instant, usize)>> {
        let mut errors = Vec::new();

        let mut encrypted = HashMap::new();
        for ((from, to), partitions) in compacted {
            let Some(info) = participants.get(&to) else {
                // Should never happen, since we pass full list of participants; dropping also keeps the outbox from accumulating
                // messages for recipients that will never receive them.
                tracing::warn!(
                    ?to,
                    "outbox: participant not found in all participants, dropping messages"
                );
                continue;
            };

            for partition in partitions {
                let message = match SignedMessage::encrypt(
                    &partition.messages,
                    from,
                    sign_sk,
                    &info.cipher_pk,
                ) {
                    Ok(encrypted) => encrypted,
                    Err(err) => {
                        // Encryption failure is deterministic, so a retry would fail
                        // the same way. Drop the partition.
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
        client: &NodeClient,
        participants: &Participants,
        cfg: &ProtocolConfig,
        encrypted: HashMap<MessageRoute, Vec<(Ciphered, Instant, usize)>>,
    ) {
        let start = Instant::now();
        let timeout = Duration::from_millis(cfg.message_timeout);

        for ((_from, to), encrypted) in encrypted {
            for (encrypted_partition, timestamp, message_len) in encrypted {
                // guaranteed to unwrap due to our previous loop check:
                let info = participants.get(&to).unwrap();
                let url = info.url.clone();

                metrics::messaging::NUM_SEND_ENCRYPTED_TOTAL.inc_by(message_len as f64);

                let client = client.clone();
                tokio::spawn(async move {
                    let instant = Instant::now();
                    metrics::messaging::MSG_CLIENT_SEND_DELAY
                        .observe((instant - timestamp).as_millis() as f64);
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

    /// Publish messages to other nodes
    async fn publish(
        &mut self,
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
        self.send(client, &participants, &config.protocol, encrypted)
            .await;
    }

    pub async fn run(
        mut self,
        client: NodeClient,
        config: watch::Receiver<Config>,
        contract: ContractStateWatcher,
    ) {
        let mut interval = tokio::time::interval(Duration::from_millis(10));
        loop {
            tokio::select! {
                Some(SendMessage { message, from, to, queued_at }) = self.outbox_rx.recv() => {
                    set_channel_capacity_tx("outgoing", &self.outbox_tx);
                    // add it to the outbox and sort it by from and to participant
                    let entry = self.messages.entry((from, to)).or_default();
                    entry.push((message, queued_at));
                }
                _ = interval.tick() => {
                    self.publish(&client, &config, &contract).await;
                }
            }
        }
    }

    /// Allows tests to manually handle outgoing message before they are
    /// encrypted and published.
    #[cfg(any(test, feature = "test-feature"))]
    pub fn intercept_outgoing_messages(&mut self) -> &mut mpsc::Receiver<SendMessage> {
        &mut self.outbox_rx
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::message::types::TripleMessage;

    fn triple_message(id: u64, data_size: usize) -> Message {
        Message::Triple(TripleMessage {
            id,
            epoch: 0,
            from: Participant::from(0),
            data: vec![0u8; data_size],
            timestamp: 1,
        })
    }

    fn triple_ids(partition: &Partition) -> Vec<u64> {
        partition
            .messages
            .iter()
            .map(|msg| match msg {
                Message::Triple(msg) => msg.id,
                other => panic!("expected triple message, got {}", other.typename()),
            })
            .collect()
    }

    #[test]
    fn test_partition_256kb_empty() {
        let partitions = partition_256kb(Vec::new());
        assert!(partitions.is_empty());
    }

    #[test]
    fn test_partition_256kb_single_partition() {
        let outgoing = vec![
            (triple_message(1, 1024), Instant::now()),
            (triple_message(2, 2048), Instant::now()),
        ];
        let partitions = partition_256kb(outgoing);

        assert_eq!(partitions.len(), 1);
        assert_eq!(triple_ids(&partitions[0]), vec![1, 2]);
    }

    #[test]
    fn test_partition_256kb_splits_over_limit() {
        // Each message is ~100kb, so the first two fit into one 256kb
        // partition and the third starts a new one.
        let outgoing = (1..=3)
            .map(|id| (triple_message(id, 100 * 1024), Instant::now()))
            .collect::<Vec<_>>();
        let partitions = partition_256kb(outgoing);

        assert_eq!(partitions.len(), 2);
        assert_eq!(triple_ids(&partitions[0]), vec![1, 2]);
        assert_eq!(triple_ids(&partitions[1]), vec![3]);
        for partition in &partitions {
            let bytesize = partition
                .messages
                .iter()
                .map(|msg| msg.size())
                .sum::<usize>();
            assert!(bytesize <= 256 * 1024);
        }
    }

    #[test]
    fn test_partition_256kb_drops_unknown_messages() {
        let outgoing = vec![
            (Message::Unknown(HashMap::new()), Instant::now()),
            (triple_message(1, 1024), Instant::now()),
        ];
        let partitions = partition_256kb(outgoing);

        assert_eq!(partitions.len(), 1);
        assert_eq!(triple_ids(&partitions[0]), vec![1]);
    }
}
