use cait_sith::protocol::Participant;
use mpc_primitives::SignId;
use tokio::sync::{mpsc, oneshot};

use crate::protocol::message::{
    GeneratingMessage, PresignatureMessage, ResharingMessage, SignatureMessage, TripleMessage,
};
use crate::protocol::posit::PositAction;
use crate::protocol::presignature::{FullPresignatureId, PresignatureId};
use crate::protocol::triple::TripleId;

/// This should be enough to hold a few messages in the inbox.
pub const MAX_MESSAGE_SUB_CHANNEL_SIZE: usize = 4 * 1024;

pub enum SubscribeId {
    Generating,
    Resharing,
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
    Triple(mpsc::Receiver<TripleMessage>),
    TriplePosit(mpsc::Receiver<(TripleId, Participant, PositAction)>),
    Presignature(mpsc::Receiver<PresignatureMessage>),
    PresignaturePosit(mpsc::Receiver<(FullPresignatureId, Participant, PositAction)>),
    Signature(mpsc::Receiver<SignatureMessage>),
    SignaturePosit(mpsc::Receiver<(SignId, PresignatureId, Participant, PositAction)>),
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
}

impl<T> Default for Subscriber<T> {
    fn default() -> Self {
        Self::unsubscribed()
    }
}
