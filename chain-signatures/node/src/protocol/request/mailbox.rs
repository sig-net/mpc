use crate::protocol::posit::PositAction;
use crate::protocol::presignature::PresignatureId;

use std::collections::hash_map::Entry;
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
    /// The rejector's own round, set only alongside a `StaleRound` reject.
    pub stale_round: Option<usize>,
}

/// Mailbox holding the latest posit message per sending participant.
///
/// A message for round N from sender P replaces messages from P for earlier or equal rounds.
///
/// Only a single message per round and sender buffered. This is enough because:
///
/// - When we are proposer for a round, only Reject or Accept will be sent to us.
/// - When we are deliberator, we can only receive `Propose` or `Start` messages
///   here. But we can't get a `Start` message for a round that we haven't already
///   responded to a `Propose` message. Therefore, one message per round is all we
///   need to buffer.
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

    /// Buffer `msg` in its sender's slot, overwriting when its round is `>=` the
    /// buffered one, then wake one consumer.
    pub(crate) fn push(&self, msg: SignPositMessage) {
        let SignPositMessage {
            from,
            round: new_round,
            ..
        } = msg;
        let mut guard = self.messages.lock().unwrap();
        let mut inserted = false;
        match guard.entry(from) {
            Entry::Occupied(mut occupied_entry) => {
                let SignPositMessage {
                    round: existing, ..
                } = occupied_entry.get();

                if new_round >= *existing {
                    occupied_entry.insert(msg);
                    inserted = true;
                }
            }
            Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(msg);
                inserted = true;
            }
        }
        drop(guard);
        // Wake up potential work consumers. (after releasing the lock)
        if inserted {
            self.notify.notify_one();
        }
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
            stale_round: None,
        }
    }

    /// One slot per sender, highest round wins. An equal round still
    /// overwrites: that is a sender superseding its own message (Propose then
    /// Accept), not a reordering.
    #[test]
    fn one_slot_per_sender_highest_round_wins() {
        let mailbox = PositMailbox::new();
        mailbox.push(posit(1, 5, PositAction::Propose));
        mailbox.push(posit(1, 5, PositAction::Accept));
        mailbox.push(posit(1, 2, PositAction::Propose));
        mailbox.push(posit(2, 3, PositAction::Accept));

        let mut got = [
            mailbox.try_recv().expect("first message"),
            mailbox.try_recv().expect("second message"),
        ];
        got.sort_by_key(|msg| u32::from(msg.from));
        assert!(matches!(got[0].action, PositAction::Accept));
        assert_eq!(got[0].round, 5, "the round-2 straggler must not win");
        assert_eq!(got[1].round, 3);
        assert!(mailbox.try_recv().is_none());
    }
}
