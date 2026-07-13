//! Peer messaging: encrypted transport between MPC nodes.
//!
//! Three cooperating pieces, created together by [`MessageChannel::new`]:
//! - [`MessageInbox`] (worker): decrypts, dedups, routes incoming messages.
//! - [`MessageOutbox`] (worker): partitions, encrypts, sends outgoing messages.
//! - [`MessageChannel`] (handle): cloneable senders into the workers' channels.

mod crypto;
mod filter;
mod inbox;
mod outbox;
mod sub;
mod types;

pub use crate::protocol::message::types::{
    GeneratingMessage, Message, MessageError, MessageFilterId, PositMessage, PositProtocolId,
    PresignatureMessage, Protocols, ReadyMessage, ResharingMessage, SignatureMessage,
    TripleMessage,
};
pub(crate) use crypto::cbor_to_bytes;
pub use crypto::SignedMessage;
pub use inbox::MessageInbox;
pub use outbox::{MessageOutbox, SendMessage};
pub use sub::{Subscriber, POSIT_INBOX_CHANNEL_SIZE};

pub const MAX_MESSAGE_INCOMING: usize = 1024 * 1024;
pub const MAX_MESSAGE_OUTGOING: usize = 1024 * 1024;
pub const MAX_OUTBOX_PAYLOAD_LIMIT: usize = 256 * 1024;

use crate::metrics::messaging::set_channel_capacity_tx;
use crate::node_client::NodeClient;
use crate::protocol::message::filter::MAX_FILTER_SIZE;
use crate::protocol::message::sub::{SubscribeId, SubscribeRequest, SubscribeResponse};
use crate::protocol::message::types::Round;
use crate::protocol::posit::PositAction;
use crate::protocol::presignature::{FullPresignatureId, PresignatureId};
use crate::protocol::triple::TripleId;
use crate::protocol::Config;
use crate::rpc::ContractStateWatcher;
use cait_sith::protocol::Participant;
use mpc_keys::hpke::Ciphered;
use mpc_primitives::SignId;
use std::time::Instant;
use tokio::sync::{mpsc, watch};

/// Cloneable handle to the message system: the senders into each of its
/// channels. The receiving ends live in [`MessageInbox`] / [`MessageOutbox`].
#[derive(Clone)]
pub struct MessageChannel {
    /// Messages to be signed, encrypted, and sent to peers (drained by `MessageOutbox`).
    outgoing: mpsc::Sender<SendMessage>,
    /// Subscription control: asks `MessageInbox` to create/drop subscriber channels.
    subscribe: mpsc::Sender<SubscribeRequest>,
    /// Marks completed protocols so their late messages are dropped.
    filter: mpsc::Sender<(Protocols, u64)>,
    /// Entry point for encrypted messages from peers (drained by `MessageInbox`).
    pub inbox: mpsc::Sender<Ciphered>,
}

impl MessageChannel {
    pub fn new() -> (MessageInbox, MessageOutbox, Self) {
        let (inbox_tx, inbox_rx) = mpsc::channel(MAX_MESSAGE_INCOMING);
        let (outbox_tx, outbox_rx) = mpsc::channel(MAX_MESSAGE_OUTGOING);
        let (filter_tx, filter_rx) = mpsc::channel(MAX_FILTER_SIZE.into());
        let (subscribe_tx, subscribe_rx) = mpsc::channel(16384);
        let inbox = MessageInbox::new(
            inbox_tx.clone(),
            inbox_rx,
            filter_tx.clone(),
            filter_rx,
            subscribe_tx.clone(),
            subscribe_rx,
        );
        let outbox = MessageOutbox::new(outbox_tx.clone(), outbox_rx);

        let channel = Self {
            inbox: inbox_tx,
            outgoing: outbox_tx,
            subscribe: subscribe_tx,
            filter: filter_tx,
        };

        set_channel_capacity_tx("incoming", &channel.inbox);
        set_channel_capacity_tx("outgoing", &channel.outgoing);
        set_channel_capacity_tx("filter", &channel.filter);
        set_channel_capacity_tx("subscribe", &channel.subscribe);

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
        } else {
            set_channel_capacity_tx("outgoing", &self.outgoing);
        }
    }

    pub async fn send_inbox(&self, encrypted: Ciphered) {
        if let Err(err) = self.inbox.send(encrypted).await {
            tracing::error!(?err, "failed to forward an encrypted protocol message");
        } else {
            set_channel_capacity_tx("incoming", &self.inbox);
        }
    }

    /// Marks this message as filtered. This is used to prevent the same message with the
    /// corresponding MessageId from being processed again.
    pub async fn filter<M: MessageFilterId>(&self, msg: &M) {
        if let Err(err) = self.filter.send((M::PROTOCOL, msg.id())).await {
            tracing::warn!(?err, "failed to send filter message");
        } else {
            set_channel_capacity_tx("filter", &self.filter);
        }
    }

    pub async fn filter_triple(&self, id: TripleId) {
        if let Err(err) = self.filter.send((Protocols::Triple, id)).await {
            tracing::warn!(?err, "failed to send filter message");
        } else {
            set_channel_capacity_tx("filter", &self.filter);
        }
    }

    pub async fn filter_presignature(&self, id: PresignatureId) {
        if let Err(err) = self.filter.send((Protocols::Presignature, id)).await {
            tracing::warn!(?err, "failed to send filter message");
        } else {
            set_channel_capacity_tx("filter", &self.filter);
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
        set_channel_capacity_tx("subscribe", &self.subscribe);
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
        } else {
            set_channel_capacity_tx("subscribe", &self.subscribe);
        };
    }

    /// Subscribe to the triple posit. It returns a dropped channel in the case that something
    /// in the MessageInbox has gone wrong and unexpected, leading to the handling loop of whoever
    /// has a handle to this newly created channel to just abort.
    pub async fn subscribe_triple_posit(
        &self,
    ) -> mpsc::Receiver<(TripleId, Participant, PositAction)> {
        let Some(subscription) = self.subscribe(SubscribeId::TriplePosit).await else {
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
            .send(SubscribeRequest::unsubscribe(SubscribeId::TriplePosit))
            .await
            .is_err()
        {
            tracing::warn!("unable to send unsubscribe request for triple posits");
        } else {
            set_channel_capacity_tx("subscribe", &self.subscribe);
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
        } else {
            set_channel_capacity_tx("subscribe", &self.subscribe);
        };
    }

    pub async fn subscribe_presignature_posit(
        &self,
    ) -> mpsc::Receiver<(FullPresignatureId, Participant, PositAction)> {
        let Some(subscription) = self.subscribe(SubscribeId::PresignaturePosit).await else {
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
            .send(SubscribeRequest::unsubscribe(
                SubscribeId::PresignaturePosit,
            ))
            .await
            .is_err()
        {
            tracing::warn!("unable to send unsubscribe request for presignature posits");
        } else {
            set_channel_capacity_tx("subscribe", &self.subscribe);
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
        } else {
            set_channel_capacity_tx("subscribe", &self.subscribe);
        };
    }

    pub async fn subscribe_signature_posit(
        &self,
    ) -> mpsc::Receiver<(SignId, PresignatureId, Round, Participant, PositAction)> {
        let Some(subscription) = self.subscribe(SubscribeId::SignaturePosit).await else {
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
            .send(SubscribeRequest::unsubscribe(SubscribeId::SignaturePosit))
            .await
            .is_err()
        {
            tracing::warn!("unable to send unsubscribe request for signature posit");
        } else {
            set_channel_capacity_tx("subscribe", &self.subscribe);
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
