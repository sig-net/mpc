use crate::mpc_fixture::fixture_tasks::MessageFilter;
use cait_sith::protocol::Participant;
use mpc_node::protocol;
use mpc_node::protocol::message::SendMessage;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

/// Helper to drop signature messages sent by a specific participant.
///
/// Tests can install the returned [`MessageFilter`] on a node via
/// [`MpcFixtureBuilder::with_outgoing_message_filter`](crate::mpc_fixture::MpcFixtureBuilder::with_outgoing_message_filter)
/// and keep the [`SignatureDropper`] handle around to toggle the behaviour at
/// runtime. This keeps the test code expressive about which leader is being
/// suppressed during retries.
#[derive(Clone)]
pub struct SignatureDropper {
    participant: Participant,
    enabled: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
}

impl SignatureDropper {
    /// Create a dropper for `participant` and the corresponding message filter.
    pub fn new(participant: Participant) -> (Self, MessageFilter) {
        let enabled = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicUsize::new(0));
        let filter_participant = participant;
        let filter_enabled = Arc::clone(&enabled);
        let filter_dropped = Arc::clone(&dropped);

        let filter: MessageFilter = Box::new(move |send_message: &SendMessage| {
            if !filter_enabled.load(Ordering::SeqCst) {
                return true;
            }

            let (message, (from, _, _)) = send_message;
            if *from != filter_participant {
                return true;
            }

            if matches!(message, protocol::Message::Signature(_)) {
                filter_dropped.fetch_add(1, Ordering::SeqCst);
                false
            } else {
                true
            }
        });

        (
            SignatureDropper {
                participant,
                enabled,
                dropped,
            },
            filter,
        )
    }

    /// Enable dropping signature messages for the configured participant.
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::SeqCst);
    }

    /// Disable dropping signature messages for the configured participant.
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::SeqCst);
    }

    /// Returns the participant whose messages are affected by this dropper.
    pub fn participant(&self) -> Participant {
        self.participant
    }

    /// Returns whether the dropper is currently active.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    pub fn dropped(&self) -> usize {
        self.dropped.load(Ordering::SeqCst)
    }
}
