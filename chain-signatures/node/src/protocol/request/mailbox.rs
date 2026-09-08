use crate::protocol::posit::PositAction;
use crate::protocol::presignature::PresignatureId;

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
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
///
/// Messages for a round the task has not reached stay here until it gets there
/// ([`recv_up_to`](Self::recv_up_to)). The mailbox also remembers the highest
/// round peers have shown us, so the task's next round bump can jump straight
/// to it.
pub(crate) struct PositMailbox {
    // using std Mutex here, do not hold across .await
    messages: std::sync::Mutex<HashMap<Participant, SignPositMessage>>,
    /// Highest round carried by a message pushed here, or named by a peer in a
    /// `StaleRound` reject (see [`record_round`](Self::record_round)).
    highest_round: AtomicUsize,
    notify: Notify,
}

impl PositMailbox {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            messages: std::sync::Mutex::new(HashMap::new()),
            highest_round: AtomicUsize::new(0),
            notify: Notify::new(),
        })
    }

    /// Highest round any peer has shown us so far.
    pub(crate) fn highest_round(&self) -> usize {
        self.highest_round.load(Ordering::Relaxed)
    }

    /// Note a round a peer is at, from a message or from the payload of a
    /// `StaleRound` reject. Never goes down.
    pub(crate) fn record_round(&self, round: usize) {
        self.highest_round.fetch_max(round, Ordering::Relaxed);
    }

    /// Buffer `msg` in its sender's slot, overwriting when its round is `>=` the
    /// buffered one, then wake one consumer.
    pub(crate) fn push(&self, msg: SignPositMessage) {
        let SignPositMessage {
            from,
            round: new_round,
            ..
        } = msg;
        self.record_round(new_round);
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

    /// Take one message whose round is at most `round`, if any.
    fn try_recv_up_to(&self, round: usize) -> Option<SignPositMessage> {
        let mut guard = self.messages.lock().unwrap();
        let key = guard
            .iter()
            .find(|(_, msg)| msg.round <= round)
            .map(|(from, _)| *from)?;
        guard.remove(&key)
    }

    /// Wait for the next available posit message, whatever its round.
    pub(crate) async fn recv(&self) -> SignPositMessage {
        self.recv_up_to(usize::MAX).await
    }

    /// Wait for the next posit message from round `round` or earlier. Messages
    /// for later rounds stay put until a call names a round that includes them.
    pub(crate) async fn recv_up_to(&self, round: usize) -> SignPositMessage {
        loop {
            // Register for wakeup BEFORE checking to avoid races with a push.
            let notified = self.notify.notified();
            if let Some(msg) = self.try_recv_up_to(round) {
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
            mailbox.try_recv_up_to(usize::MAX).expect("first message"),
            mailbox.try_recv_up_to(usize::MAX).expect("second message"),
        ];
        got.sort_by_key(|msg| u32::from(msg.from));
        assert!(matches!(got[0].action, PositAction::Accept));
        assert_eq!(got[0].round, 5, "the round-2 straggler must not win");
        assert_eq!(got[1].round, 3);
        assert!(mailbox.try_recv_up_to(usize::MAX).is_none());
    }

    /// A message for a round the task has not reached is not handed out; it
    /// waits, and is delivered once the task's round catches up.
    #[tokio::test]
    async fn future_rounds_wait_for_the_task() {
        let mailbox = PositMailbox::new();
        mailbox.push(posit(1, 5, PositAction::Propose));
        mailbox.push(posit(2, 3, PositAction::Propose));

        let current = mailbox.recv_up_to(3).await;
        assert_eq!(current.round, 3);
        assert!(
            mailbox.try_recv_up_to(3).is_none(),
            "the round-5 message must stay in the mailbox"
        );

        let later = mailbox.recv_up_to(5).await;
        assert_eq!(later.round, 5);
        assert!(mailbox.try_recv_up_to(usize::MAX).is_none());
    }

    /// The highest round moves with what peers show us, from pushed messages
    /// and from rounds recorded out of StaleRound rejects, and never down.
    #[test]
    fn highest_round_follows_peers() {
        let mailbox = PositMailbox::new();
        assert_eq!(mailbox.highest_round(), 0);

        mailbox.push(posit(1, 4, PositAction::Propose));
        assert_eq!(mailbox.highest_round(), 4);

        mailbox.record_round(9);
        assert_eq!(mailbox.highest_round(), 9);

        mailbox.push(posit(2, 2, PositAction::Accept));
        mailbox.record_round(1);
        assert_eq!(mailbox.highest_round(), 9);
    }
}
