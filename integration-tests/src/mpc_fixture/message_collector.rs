use cait_sith::protocol::Participant;
use mpc_node::protocol::message::{PositProtocolId, SendMessage};
use mpc_node::protocol::Message;
use std::collections::HashMap;

/// Collect information about sent messages during a test.
///
/// Each test can in theory define what exactly they want to collect about
/// messages. In practice, most tests should pick one of the collector
/// implementations defined in this file.
///
/// Storing the full context of messages is usually too much and fills up memory
/// quickly. But some tests may need that level of detail.
pub trait CollectMessages {
    fn observe_message(&mut self, msg: &SendMessage, passed_filter: bool);

    /// May be called at the end of a test to print a summary of all collected
    /// messages.
    fn print_summary(&self);

    /// Get back the discrete type for extra checks after running a test.
    fn clone_as_message_counter(&self) -> Option<MessageCounter> {
        None
    }
}

/// Print a shortened from of all incoming messages to tracing::debug without
/// keeping anything in memory.
///
/// This is the default message collector, allowing to inspect what happens in
/// the test log output without requiring obsessive memory during the test.
pub struct MessagePrinter;

impl CollectMessages for MessagePrinter {
    fn observe_message(&mut self, msg: &SendMessage, passed_filter: bool) {
        let (msg, (from, to, _ts)) = msg;
        let msg_type = message_type_str(msg);
        let action = if passed_filter {
            "Forwarded"
        } else {
            "Dropped"
        };
        tracing::debug!(target: "mock_network", "{action} {msg_type} from {from:?} to {to:?}");
    }

    fn print_summary(&self) {
        // NOOP: Already printed everything when messages came in
    }
}

/// Count how many messages have been sent between participants and of which
/// type.
///
/// This is a good message collector when a test want to check what kind of
/// messages have been sent. It has a low memory footprint and makes it quite
/// easy to assert a specific message has (or has not been) sent during the
/// test.
#[derive(Default, Clone)]
pub struct MessageCounter {
    /// For each directed participant -> participant linke, collect message counters.
    pub links: HashMap<Participant, HashMap<Participant, PerLinkCounter>>,
}

#[derive(Default, Clone)]
pub struct PerLinkCounter {
    pub message_counts: HashMap<String, u64>,
}

impl CollectMessages for MessageCounter {
    fn observe_message(&mut self, msg: &SendMessage, passed_filter: bool) {
        let (msg, (from, to, _ts)) = msg;

        let sender_stats = self.links.entry(*from).or_default();
        let link_stats = sender_stats.entry(*to).or_default();
        link_stats.observe_message(msg, passed_filter);
    }

    fn print_summary(&self) {
        for (from, to, link_stats) in self.link_stats() {
            tracing::info!(target: "mock_network", "### {from:?} -> {to:?}");
            for (key, num) in &link_stats.message_counts {
                tracing::info!(target: "mock_network", "{num:>12}    {key}");
            }
            tracing::info!(target: "mock_network", "");
        }
    }

    fn clone_as_message_counter(&self) -> Option<MessageCounter> {
        Some(self.clone())
    }
}

impl MessageCounter {
    pub fn link_stats(&self) -> impl Iterator<Item = (Participant, Participant, &PerLinkCounter)> {
        self.links.iter().flat_map(|(from, sent_stats)| {
            sent_stats
                .iter()
                .map(|(to, link_stats)| (*from, *to, link_stats))
        })
    }
}

impl PerLinkCounter {
    fn observe_message(&mut self, msg: &Message, passed_filter: bool) {
        let msg_type = message_type_str(msg);
        let id = message_id_num(msg);
        let action = if passed_filter {
            "Forwarded"
        } else {
            "Dropped"
        };

        let key = if let Some(id) = id {
            format!("{action} {msg_type}({id})")
        } else {
            format!("{action} {msg_type}")
        };

        *self.message_counts.entry(key).or_default() += 1;
    }
}

fn message_type_str(msg: &Message) -> &str {
    match msg {
        Message::Posit(_) => "Posit",
        Message::Generating(_) => "Generating",
        Message::Ready(_) => "Ready",
        Message::Resharing(_) => "Resharing",
        Message::Triple(_) => "Triple",
        Message::Presignature(_) => "Presignature",
        Message::Signature(_) => "Signature",
        Message::Unknown(_) => "Unknown",
    }
}

fn message_id_num(msg: &Message) -> Option<u64> {
    match msg {
        Message::Posit(inner) => Some(posit_id_num(&inner.id)),
        Message::Generating(_) => None,
        Message::Ready(_) => None,
        Message::Resharing(_) => None,
        Message::Triple(inner) => Some(inner.id),
        Message::Presignature(inner) => Some(inner.id),
        Message::Signature(inner) => Some(inner.presignature_id),
        Message::Unknown(_) => None,
    }
}

/// A single number that should be unique per posit invocation.
fn posit_id_num(posit_id: &PositProtocolId) -> u64 {
    match posit_id {
        PositProtocolId::Triple(id) => *id,
        PositProtocolId::Presignature(id) => id.id,
        PositProtocolId::Signature(sig_id, _presig_id, _round) => {
            // extract a 8-byte hash from a 32-byte hash
            let mut hash8: u64 = 0;
            for chunk in sig_id.request_id.chunks_exact(8) {
                hash8 ^= u64::from_be_bytes(chunk.try_into().unwrap());
            }
            hash8
        }
    }
}
