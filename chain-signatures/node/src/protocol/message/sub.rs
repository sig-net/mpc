use cait_sith::protocol::Participant;
use mpc_primitives::SignId;
use tokio::sync::{mpsc, oneshot};

use crate::protocol::message::types::Round;
use crate::protocol::message::{
    GeneratingMessage, PresignatureMessage, ReadyMessage, ResharingMessage, SignatureMessage,
    TripleMessage,
};
use crate::protocol::posit::PositAction;
use crate::protocol::presignature::{FullPresignatureId, PresignatureId};
use crate::protocol::triple::TripleId;

/// This should be enough to hold a few messages in the inbox.
pub const MAX_MESSAGE_SUB_CHANNEL_SIZE: usize = 4 * 1024;
pub const MAX_MESSAGE_POSIT_SUB_CHANNEL_SIZE: usize = 1 << 24;

pub enum SubscribeId {
    Generating,
    Resharing,
    Ready,
    Triples,
    Presignatures,
    Signatures,
    Triple(TripleId),
    Presignature(PresignatureId),
    Signature(SignId, PresignatureId),
}

pub enum SubscribeResponse {
    Generating(mpsc::Receiver<GeneratingMessage>),
    Resharing(mpsc::Receiver<ResharingMessage>),
    Ready(mpsc::Receiver<ReadyMessage>),
    Triple(mpsc::Receiver<TripleMessage>),
    TriplePosit(mpsc::Receiver<(TripleId, Participant, PositAction)>),
    Presignature(mpsc::Receiver<PresignatureMessage>),
    PresignaturePosit(mpsc::Receiver<(FullPresignatureId, Participant, PositAction)>),
    Signature(mpsc::Receiver<SignatureMessage>),
    SignaturePosit(mpsc::Receiver<(SignId, PresignatureId, Round, Participant, PositAction)>),
}

pub enum SubscribeRequestAction {
    Subscribe(oneshot::Sender<SubscribeResponse>),
    Unsubscribe,
}

pub struct SubscribeRequest {
    pub id: SubscribeId,
    pub action: SubscribeRequestAction,
}

impl SubscribeRequest {
    pub fn subscribe(id: SubscribeId) -> (Self, oneshot::Receiver<SubscribeResponse>) {
        let (resp_tx, resp_rx) = oneshot::channel();
        (
            Self {
                id,
                action: SubscribeRequestAction::Subscribe(resp_tx),
            },
            resp_rx,
        )
    }

    pub fn unsubscribe(id: SubscribeId) -> Self {
        Self {
            id,
            action: SubscribeRequestAction::Unsubscribe,
        }
    }
}

pub struct Subscriber<T> {
    metrics: SubscriberMetrics,
    kind: SubscriberKind<T>,
}

pub enum SubscriberKind<T> {
    /// Temporary/replaceable value, and will never be used. Only here so we can have a
    /// way to convert from an Unsubscribed to a Subscribed subscription.
    Unknown,
    /// A subscribed channel where the subscriber has a handle to the receiver.
    Subscribed(mpsc::Sender<T>),
    /// An unsubscribed channel where there's potentially messages that have yet to be sent.
    Unsubscribed(mpsc::Sender<T>, mpsc::Receiver<T>),
}

#[derive(Clone)]
pub struct SubscriberMetrics {
    name: &'static str,
    channel_id: String,
    capacity: usize,
}

impl<T> Subscriber<T> {
    pub fn subscribed(
        name: &'static str,
        channel_id: impl Into<String>,
    ) -> (Self, mpsc::Receiver<T>) {
        Self::subscribed_with_capacity(name, channel_id, MAX_MESSAGE_SUB_CHANNEL_SIZE)
    }

    pub fn subscribed_with_capacity(
        name: &'static str,
        channel_id: impl Into<String>,
        capacity: usize,
    ) -> (Self, mpsc::Receiver<T>) {
        let metrics = SubscriberMetrics {
            name,
            channel_id: channel_id.into(),
            capacity,
        };
        Self::subscribed_with_metrics(metrics)
    }

    fn subscribed_with_metrics(metrics: SubscriberMetrics) -> (Self, mpsc::Receiver<T>) {
        let (tx, rx) = mpsc::channel(metrics.capacity);
        (
            Self {
                metrics,
                kind: SubscriberKind::Subscribed(tx),
            },
            rx,
        )
    }

    pub fn unsubscribed(name: &'static str, channel_id: impl Into<String>) -> Self {
        Self::unsubscribed_with_capacity(name, channel_id, MAX_MESSAGE_SUB_CHANNEL_SIZE)
    }

    pub fn unsubscribed_with_capacity(
        name: &'static str,
        channel_id: impl Into<String>,
        capacity: usize,
    ) -> Self {
        let metrics = SubscriberMetrics {
            name,
            channel_id: channel_id.into(),
            capacity,
        };
        Self::unsubscribed_with_metrics(metrics)
    }

    fn unsubscribed_with_metrics(metrics: SubscriberMetrics) -> Self {
        let (tx, rx) = mpsc::channel(metrics.capacity);
        Self {
            metrics,
            kind: SubscriberKind::Unsubscribed(tx, rx),
        }
    }

    /// Convert this subscriber into a subscribed one, returning the receiver.
    /// If the subscriber is already subscribed, it overrides the existing subscription.
    pub fn subscribe(&mut self) -> mpsc::Receiver<T> {
        let kind = std::mem::replace(&mut self.kind, SubscriberKind::Unknown);
        let (next_kind, rx) = match kind {
            SubscriberKind::Subscribed(_) | SubscriberKind::Unknown => {
                let (tx, rx) = mpsc::channel(self.metrics.capacity);
                (SubscriberKind::Subscribed(tx), rx)
            }
            SubscriberKind::Unsubscribed(tx, rx) => (SubscriberKind::Subscribed(tx), rx),
        };
        self.kind = next_kind;
        rx
    }

    /// Unsubscribe from the subscriber, converting it into an unsubscribed one.
    pub fn unsubscribe(&mut self) {
        if let SubscriberKind::Subscribed(_) = self.kind {
            let (tx, rx) = mpsc::channel(self.metrics.capacity);
            self.kind = SubscriberKind::Unsubscribed(tx, rx);
        }
    }

    pub fn estimated_queue_len(&self) -> usize {
        match &self.kind {
            SubscriberKind::Subscribed(tx) | SubscriberKind::Unsubscribed(tx, _) => {
                tx.max_capacity() - tx.capacity()
            }
            SubscriberKind::Unknown => 0,
        }
    }

    pub fn report_queue_len(&self) {
        crate::metrics::messaging::set_channel_queue_size(
            self.metrics.name,
            &self.metrics.channel_id,
            self.estimated_queue_len(),
        );
    }

    fn capacity(&self) -> usize {
        self.metrics.capacity
    }

    pub fn channel_id(&self) -> &str {
        &self.metrics.channel_id
    }

    pub fn clear_queue_len_metric(&self) {
        crate::metrics::messaging::remove_channel_queue_size(
            self.metrics.name,
            &self.metrics.channel_id,
        );
    }

    pub fn subscriber_name(&self) -> &'static str {
        self.metrics.name
    }

    fn report_after_enqueue(&self) {
        self.report_queue_len();
    }

    pub fn is_unknown(&self) -> bool {
        matches!(self.kind, SubscriberKind::Unknown)
    }

    pub async fn send(&self, msg: T) -> Result<(), mpsc::error::SendError<T>> {
        match &self.kind {
            SubscriberKind::Subscribed(tx) | SubscriberKind::Unsubscribed(tx, _) => {
                tx.send(msg).await
            }
            SubscriberKind::Unknown => Ok(()),
        }
    }

    pub fn try_send_lossy(&self, msg: T) -> Result<(), mpsc::error::SendError<T>> {
        let result = match &self.kind {
            SubscriberKind::Subscribed(tx) | SubscriberKind::Unsubscribed(tx, _) => {
                match tx.try_send(msg) {
                    Ok(()) => Ok(()),
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        tracing::warn!(
                            subscriber = self.metrics.name,
                            subscriber_id = self.metrics.channel_id,
                            capacity = self.capacity(),
                            "dropping message because subscriber channel is full"
                        );
                        Ok(())
                    }
                    Err(mpsc::error::TrySendError::Closed(msg)) => Err(mpsc::error::SendError(msg)),
                }
            }
            SubscriberKind::Unknown => Ok(()),
        };

        self.report_after_enqueue();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::Subscriber;

    #[test]
    fn estimated_queue_len_tracks_buffered_messages() {
        let sub = Subscriber::unsubscribed_with_capacity("test", "singleton", 4);

        assert_eq!(sub.estimated_queue_len(), 0);

        sub.try_send_lossy(1u8).unwrap();
        sub.try_send_lossy(2u8).unwrap();

        assert_eq!(sub.estimated_queue_len(), 2);
    }
}
