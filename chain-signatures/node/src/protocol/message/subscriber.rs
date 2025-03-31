use tokio::sync::mpsc;

pub(crate) enum MessageSubscriber<T> {
    Subscribed(mpsc::Sender<T>),
    Unsubscribed(Vec<T>),
}

impl<T> MessageSubscriber<T>
where
    T: Send + Sync + 'static,
{
    pub fn send(&mut self, message: T) {
        match self {
            Self::Subscribed(tx) => {
                let tx = tx.clone();
                tokio::spawn(async move {
                    if let Err(err) = tx.send(message).await {
                        tracing::warn!(?err, "failed to send message");
                    }
                });
            }
            Self::Unsubscribed(queue) => {
                queue.push(message);
            }
        }
    }
}

impl<T> Default for MessageSubscriber<T> {
    fn default() -> Self {
        Self::Unsubscribed(Vec::new())
    }
}
