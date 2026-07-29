use crate::protocol::posit::PositAction;
use crate::protocol::presignature::PresignatureId;

use std::collections::HashMap;
use std::sync::Arc;

use cait_sith::protocol::Participant;
use tokio::sync::Notify;

/// A posit message routed to a signature task.
pub(crate) struct SignPositMessage {
    pub presignature_id: PresignatureId,
    pub round: usize,
    pub from: Participant,
    pub action: PositAction,
}

/// Mailbox holding the latest posit message per sending participant — a
/// sender's newest message supersedes its previous one.
///
/// Deliberately round-agnostic: arrival order decides, never rounds (which can
/// legitimately go down after a reset). Round classification is the task's job.
pub(crate) struct PositMailbox {
    // using std Mutex here, do not hold across .await
    messages: std::sync::Mutex<HashMap<Participant, SignPositMessage>>,
    notify: Notify,
}

impl PositMailbox {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            messages: std::sync::Mutex::new(HashMap::new()),
            notify: Notify::new(),
        })
    }

    /// Store `msg` in its sender's slot — last arrived wins — then wake one
    /// consumer.
    pub(crate) fn push(&self, msg: SignPositMessage) {
        self.messages.lock().unwrap().insert(msg.from, msg);
        // Wake up potential work consumers. (after releasing the lock)
        self.notify.notify_one();
    }

    fn try_recv(&self) -> Option<SignPositMessage> {
        let mut guard = self.messages.lock().unwrap();
        let key = guard.keys().next().copied()?;
        guard.remove(&key)
    }

    /// Wait for the next available posit message.
    pub(crate) async fn recv(&self) -> SignPositMessage {
        loop {
            // Register for wakeup BEFORE checking to avoid races with a push.
            let notified = self.notify.notified();
            if let Some(msg) = self.try_recv() {
                return msg;
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn posit(from: u32, round: usize, action: PositAction) -> SignPositMessage {
        SignPositMessage {
            presignature_id: 0,
            round,
            from: Participant::from(from),
            action,
        }
    }

    /// One slot per sender, last arrived wins — regardless of rounds. A lower
    /// round can legitimately arrive after a higher one (peers restart at
    /// round 0 after a governance change) and must not be silenced; judging
    /// rounds is the task's job.
    #[test]
    fn one_slot_per_sender_last_arrived_wins() {
        let mailbox = PositMailbox::new();
        mailbox.push(posit(1, 5, PositAction::Propose));
        mailbox.push(posit(1, 5, PositAction::Accept));
        mailbox.push(posit(1, 0, PositAction::Propose));
        mailbox.push(posit(2, 3, PositAction::Accept));

        let mut got = [
            mailbox.try_recv().expect("sender 1"),
            mailbox.try_recv().expect("sender 2"),
        ];
        got.sort_by_key(|msg| u32::from(msg.from));
        assert!(matches!(got[0].action, PositAction::Propose));
        assert_eq!(got[0].round, 0, "round 0 must replace the round-5 slot");
        assert_eq!(got[1].round, 3);
        assert!(mailbox.try_recv().is_none());
    }

    #[tokio::test]
    async fn recv_wakes_on_push() {
        let mailbox = PositMailbox::new();
        let consumer = {
            let mailbox = Arc::clone(&mailbox);
            tokio::spawn(async move { mailbox.recv().await })
        };
        tokio::task::yield_now().await;
        mailbox.push(posit(3, 1, PositAction::Accept));

        let got = tokio::time::timeout(std::time::Duration::from_secs(1), consumer)
            .await
            .expect("recv should wake on push")
            .unwrap();
        assert_eq!(got.from, Participant::from(3));
    }
}
