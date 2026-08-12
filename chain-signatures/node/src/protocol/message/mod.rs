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
pub use sub::Subscriber;

/// Depth of the inbox queue of undecrypted, unauthenticated `Ciphered` from
/// `/msg` — a memory ceiling (~depth x body limit) that fills only under a
/// flood the microsecond-scale consumer can't drain. Past it `send_inbox`
/// backpressures and the sender retries. Tune via the `channel="incoming"` gauge.
pub const MAX_MESSAGE_INCOMING: usize = 16 * 1024;
pub const MAX_MESSAGE_OUTGOING: usize = 1024 * 1024;
pub const MAX_OUTBOX_PAYLOAD_LIMIT: usize = 256 * 1024;
pub const MAX_SUBSCRIBE_REQUESTS: usize = 16 * 1024;

use crate::metrics::messaging::set_channel_capacity_tx;
use crate::node_client::NodeClient;
use crate::protocol::message::filter::MAX_FILTER_SIZE;
use crate::protocol::message::sub::{
    SubscribeId, SubscribeRequest, SubscribeResponse, SubscriptionMessage,
};
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
    inbox: mpsc::Sender<Ciphered>,
}

impl MessageChannel {
    pub fn new() -> (MessageInbox, MessageOutbox, Self) {
        let (inbox_tx, inbox_rx) = mpsc::channel(MAX_MESSAGE_INCOMING);
        let (outbox_tx, outbox_rx) = mpsc::channel(MAX_MESSAGE_OUTGOING);
        let (filter_tx, filter_rx) = mpsc::channel(MAX_FILTER_SIZE.into());
        let (subscribe_tx, subscribe_rx) = mpsc::channel(MAX_SUBSCRIBE_REQUESTS);
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
            .send(SendMessage {
                message: message.into(),
                from,
                to,
                queued_at: Instant::now(),
            })
            .await
        {
            tracing::error!(?err, "outbox: failed to send message to participants");
        } else {
            set_channel_capacity_tx("outgoing", &self.outgoing);
        }
    }

    /// Raw sender into the inbox, for test fixtures that route messages
    /// between in-process nodes directly instead of over HTTP.
    #[cfg(feature = "test-feature")]
    pub fn inbox_sender(&self) -> mpsc::Sender<Ciphered> {
        self.inbox.clone()
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

    /// Subscribe, returning an already-closed receiver on failure so the
    /// caller's recv loop ends instead of panicking.
    async fn subscribe_or_closed<T: SubscriptionMessage>(
        &self,
        id: SubscribeId,
        what: &'static str,
    ) -> mpsc::Receiver<T> {
        let Some(subscription) = self.subscribe(id).await else {
            tracing::warn!(what, ?id, "failed to subscribe");
            return mpsc::channel(1).1;
        };
        T::receiver(subscription).unwrap_or_else(|| {
            tracing::warn!(what, ?id, "received unexpected subscribe response");
            mpsc::channel(1).1
        })
    }

    /// Like `subscribe_or_closed`, but panics: these subscriptions are
    /// required for the node to make progress.
    async fn subscribe_required<T: SubscriptionMessage>(
        &self,
        id: SubscribeId,
        what: &'static str,
    ) -> mpsc::Receiver<T> {
        let Some(subscription) = self.subscribe(id).await else {
            panic!("failed to subscribe for {what} {id:?}");
        };
        T::receiver(subscription)
            .unwrap_or_else(|| panic!("received unexpected subscribe response for {what} {id:?}"))
    }

    async fn send_unsubscribe(&self, id: SubscribeId, what: &'static str) {
        if self
            .subscribe
            .send(SubscribeRequest::unsubscribe(id))
            .await
            .is_err()
        {
            tracing::warn!(what, ?id, "unable to send unsubscribe request");
        } else {
            set_channel_capacity_tx("subscribe", &self.subscribe);
        }
    }

    pub async fn subscribe_triple(&self, id: TripleId) -> mpsc::Receiver<TripleMessage> {
        self.subscribe_or_closed(SubscribeId::Triple(id), "triple")
            .await
    }

    pub async fn unsubscribe_triple(&self, id: TripleId) {
        self.send_unsubscribe(SubscribeId::Triple(id), "triple")
            .await;
    }

    pub async fn subscribe_triple_posit(
        &self,
    ) -> mpsc::Receiver<(TripleId, Participant, PositAction)> {
        self.subscribe_or_closed(SubscribeId::TriplePosit, "triple posit")
            .await
    }

    pub async fn unsubscribe_triple_posit(self) {
        self.send_unsubscribe(SubscribeId::TriplePosit, "triple posit")
            .await;
    }

    pub async fn subscribe_presignature(
        &self,
        id: PresignatureId,
    ) -> mpsc::Receiver<PresignatureMessage> {
        self.subscribe_or_closed(SubscribeId::Presignature(id), "presignature")
            .await
    }

    pub async fn unsubscribe_presignature(&self, id: PresignatureId) {
        self.send_unsubscribe(SubscribeId::Presignature(id), "presignature")
            .await;
    }

    pub async fn subscribe_presignature_posit(
        &self,
    ) -> mpsc::Receiver<(FullPresignatureId, Participant, PositAction)> {
        self.subscribe_or_closed(SubscribeId::PresignaturePosit, "presignature posit")
            .await
    }

    pub async fn unsubscribe_presignature_posit(self) {
        self.send_unsubscribe(SubscribeId::PresignaturePosit, "presignature posit")
            .await;
    }

    pub async fn subscribe_signature(
        &self,
        sign_id: SignId,
        presignature_id: PresignatureId,
    ) -> mpsc::Receiver<SignatureMessage> {
        self.subscribe_or_closed(
            SubscribeId::Signature(sign_id, presignature_id),
            "signature",
        )
        .await
    }

    pub async fn unsubscribe_signature(&self, sign_id: SignId, presignature_id: PresignatureId) {
        self.send_unsubscribe(
            SubscribeId::Signature(sign_id, presignature_id),
            "signature",
        )
        .await;
    }

    pub async fn subscribe_signature_posit(
        &self,
    ) -> mpsc::Receiver<(
        SignId,
        PresignatureId,
        Round,
        Participant,
        PositAction,
        Option<Round>,
    )> {
        self.subscribe_or_closed(SubscribeId::SignaturePosit, "signature posit")
            .await
    }

    pub async fn unsubscribe_signature_posit(self) {
        self.send_unsubscribe(SubscribeId::SignaturePosit, "signature posit")
            .await;
    }

    pub async fn subscribe_generation(&self) -> mpsc::Receiver<GeneratingMessage> {
        self.subscribe_required(SubscribeId::Generating, "generation")
            .await
    }

    pub async fn subscribe_resharing(&self) -> mpsc::Receiver<ResharingMessage> {
        self.subscribe_required(SubscribeId::Resharing, "resharing")
            .await
    }

    pub async fn subscribe_ready(&self) -> mpsc::Receiver<ReadyMessage> {
        self.subscribe_required(SubscribeId::Ready, "resharing readiness")
            .await
    }
}
