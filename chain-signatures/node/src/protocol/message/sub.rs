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
/// Posit channels can accumulate many small control-plane messages; use a large
/// capacity to avoid backpressure or deadlock under high concurrency.
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

    pub fn try_send_lossy(&self, msg: T) -> Result<(), mpsc::error::SendError<T>> {
        let result = match &self.kind {
            SubscriberKind::Subscribed(tx) | SubscriberKind::Unsubscribed(tx, _) => {
                match tx.try_send(msg) {
                    Ok(()) => Ok(()),
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        tracing::warn!(
                            subscriber = self.metrics.name,
                            capacity = self.metrics.capacity,
                            "dropping message: subscriber channel full"
                        );
                        Ok(())
                    }
                    Err(mpsc::error::TrySendError::Closed(msg)) => Err(mpsc::error::SendError(msg)),
                }
            }
            SubscriberKind::Unknown => Ok(()),
        };
        self.report_queue_len();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::Subscriber;

    #[test]
    fn estimated_queue_len_tracks_buffered_messages() {
        let sub = Subscriber::unsubscribed_with_capacity("test", 4);

        assert_eq!(sub.estimated_queue_len(), 0);

        sub.try_send_lossy(1u8).unwrap();
        sub.try_send_lossy(2u8).unwrap();

        assert_eq!(sub.estimated_queue_len(), 2);
    }
}
