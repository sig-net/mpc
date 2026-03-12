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
    Unknown,
    /// A subscribed channel where the subscriber has a handle to the receiver.
    Subscribed(mpsc::Sender<T>, usize),
    /// An unsubscribed channel where there's potentially messages that have yet to be sent.
    Unsubscribed(mpsc::Sender<T>, mpsc::Receiver<T>, usize),
}

impl<T> Subscriber<T> {
    pub fn subscribed() -> (Self, mpsc::Receiver<T>) {
        Self::subscribed_with_capacity(MAX_MESSAGE_SUB_CHANNEL_SIZE)
    }

    pub fn subscribed_with_capacity(capacity: usize) -> (Self, mpsc::Receiver<T>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self::Subscribed(tx, capacity), rx)
    }

    pub fn unsubscribed() -> Self {
        Self::unsubscribed_with_capacity(MAX_MESSAGE_SUB_CHANNEL_SIZE)
    }

    pub fn unsubscribed_with_capacity(capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        Self::Unsubscribed(tx, rx, capacity)
    }

    /// Convert this subscriber into a subscribed one, returning the receiver.
    /// If the subscriber is already subscribed, it overrides the existing subscription.
    pub fn subscribe(&mut self) -> mpsc::Receiver<T> {
        let sub = std::mem::replace(self, Self::Unknown);
        let (sub, rx) = match sub {
            Self::Subscribed(_, _) | Self::Unknown => Self::subscribed(),
            Self::Unsubscribed(tx, rx, capacity) => (Self::Subscribed(tx, capacity), rx),
        };
        *self = sub;
        rx
    }

    /// Unsubscribe from the subscriber, converting it into an unsubscribed one.
    pub fn unsubscribe(&mut self) {
        if matches!(self, Self::Unknown) {
            *self = Self::unsubscribed();
            return;
        }

        let capacity = self.capacity();
        if matches!(self, Self::Subscribed(_, _)) {
            *self = Self::unsubscribed_with_capacity(capacity);
        }
    }

    fn capacity(&self) -> usize {
        match self {
            Self::Subscribed(_, capacity) | Self::Unsubscribed(_, _, capacity) => *capacity,
            Self::Unknown => MAX_MESSAGE_SUB_CHANNEL_SIZE,
        }
    }

    pub async fn send(&self, msg: T) -> Result<(), mpsc::error::SendError<T>> {
        match self {
            Self::Subscribed(tx, _) => tx.send(msg).await,
            Self::Unsubscribed(tx, _, _) => tx.send(msg).await,
            Self::Unknown => Ok(()),
        }
    }

    pub fn try_send_lossy(
        &self,
        msg: T,
        name: &'static str,
    ) -> Result<(), mpsc::error::SendError<T>> {
        match self {
            Self::Subscribed(tx, _) | Self::Unsubscribed(tx, _, _) => match tx.try_send(msg) {
                Ok(()) => Ok(()),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tracing::warn!(
                        subscriber = name,
                        capacity = self.capacity(),
                        "dropping message because subscriber channel is full"
                    );
                    Ok(())
                }
                Err(mpsc::error::TrySendError::Closed(msg)) => Err(mpsc::error::SendError(msg)),
            },
            Self::Unknown => Ok(()),
        }
    }
}

impl<T> Default for Subscriber<T> {
    fn default() -> Self {
        Self::unsubscribed()
    }
}
