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

pub enum Subscriber<T> {
    /// Temporary/replaceable value, and will never be used. Only here so we can have a
    /// way to convert from an Unsubscribed to a Subscribed subscription.
    Unknown(SubscriberMetrics),
    /// A subscribed channel where the subscriber has a handle to the receiver.
    Subscribed(mpsc::Sender<T>, SubscriberMetrics),
    /// An unsubscribed channel where there's potentially messages that have yet to be sent.
    Unsubscribed(mpsc::Sender<T>, mpsc::Receiver<T>, SubscriberMetrics),
}

#[derive(Clone)]
pub struct SubscriberMetrics {
    name: &'static str,
    channel_id: String,
    capacity: usize,
}

impl<T> Subscriber<T> {
    pub fn subscribed(name: &'static str, channel_id: impl Into<String>) -> (Self, mpsc::Receiver<T>) {
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
        (Self::Subscribed(tx, metrics), rx)
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
        Self::Unsubscribed(tx, rx, metrics)
    }

    /// Convert this subscriber into a subscribed one, returning the receiver.
    /// If the subscriber is already subscribed, it overrides the existing subscription.
    pub fn subscribe(&mut self) -> mpsc::Receiver<T> {
        let sub = std::mem::replace(self, Self::Unknown(self.metrics().clone()));
        let (sub, rx) = match sub {
            Self::Subscribed(_, metrics) | Self::Unknown(metrics) => {
                Self::subscribed_with_metrics(metrics)
            }
            Self::Unsubscribed(tx, rx, metrics) => (Self::Subscribed(tx, metrics), rx),
        };
        *self = sub;
        rx
    }

    /// Unsubscribe from the subscriber, converting it into an unsubscribed one.
    pub fn unsubscribe(&mut self) {
        if matches!(self, Self::Unknown(_)) {
            *self = Self::unsubscribed_with_metrics(self.metrics().clone());
            return;
        }

        if matches!(self, Self::Subscribed(_, _)) {
            *self = Self::unsubscribed_with_metrics(self.metrics().clone());
        }
    }

    pub fn estimated_queue_len(&self) -> usize {
        match self {
            Self::Subscribed(tx, _) | Self::Unsubscribed(tx, _, _) => tx.max_capacity() - tx.capacity(),
            Self::Unknown(_) => 0,
        }
    }

    pub fn report_queue_len(&self) {
        let metrics = self.metrics();
        crate::metrics::messaging::set_channel_queue_size(
            metrics.name,
            &metrics.channel_id,
            self.estimated_queue_len(),
        );
    }

    fn metrics(&self) -> &SubscriberMetrics {
        match self {
            Self::Subscribed(_, metrics)
            | Self::Unsubscribed(_, _, metrics)
            | Self::Unknown(metrics) => metrics,
        }
    }

    fn capacity(&self) -> usize {
        self.metrics().capacity
    }

    pub fn channel_id(&self) -> &str {
        &self.metrics().channel_id
    }

    pub fn clear_queue_len_metric(&self) {
        let metrics = self.metrics();
        crate::metrics::messaging::remove_channel_queue_size(metrics.name, &metrics.channel_id);
    }

    pub fn subscriber_name(&self) -> &'static str {
        self.metrics().name
    }

    fn report_after_enqueue(&self) {
        self.report_queue_len();
    }

    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown(_))
    }

    pub async fn send(&self, msg: T) -> Result<(), mpsc::error::SendError<T>> {
        match self {
            Self::Subscribed(tx, _) | Self::Unsubscribed(tx, _, _) => tx.send(msg).await,
            Self::Unknown(_) => Ok(()),
        }
    }

    pub fn try_send_lossy(&self, msg: T) -> Result<(), mpsc::error::SendError<T>> {
        let result = match self {
            Self::Subscribed(tx, _) | Self::Unsubscribed(tx, _, _) => match tx.try_send(msg) {
                Ok(()) => Ok(()),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    let metrics = self.metrics();
                    tracing::warn!(
                        subscriber = metrics.name,
                        subscriber_id = metrics.channel_id,
                        capacity = self.capacity(),
                        "dropping message because subscriber channel is full"
                    );
                    Ok(())
                }
                Err(mpsc::error::TrySendError::Closed(msg)) => Err(mpsc::error::SendError(msg)),
            },
            Self::Unknown(_) => Ok(()),
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
