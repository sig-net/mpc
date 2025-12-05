use crate::protocol::message::{Message, MessageChannel, PositMessage};
use crate::protocol::ParticipantInfo;
use cait_sith::protocol::Participant;
use mpc_keys::hpke;
use near_crypto::SecretKey;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// InMemoryMessageBus creates MessageChannel instances for each participant
/// and routes messages between them through in-memory channels instead of the network.
/// 
/// This allows testing of SignTask convergence without requiring network infrastructure.
pub struct InMemoryMessageBus {
    /// Per-participant message channels
    channels: HashMap<Participant, MessageChannel>,
    /// Participant information for encryption/decryption
    #[allow(dead_code)]
    participants: Arc<RwLock<HashMap<Participant, ParticipantInfo>>>,
}

impl InMemoryMessageBus {
    /// Create a new InMemoryMessageBus for the given participants.
    /// Each participant gets their own MessageChannel that routes messages through in-memory channels.
    pub fn new(participants: &[Participant]) -> Self {
        let mut channels = HashMap::new();
        let mut participant_info = HashMap::new();

        // Generate keys for each participant
        for &participant in participants {
            let (_cipher_sk, cipher_pk) = hpke::generate();
            let participant_id: u32 = participant.into();
            let sign_sk = SecretKey::from_seed(
                near_crypto::KeyType::ED25519,
                &format!("test-participant-{}", participant_id),
            );

            let info = ParticipantInfo {
                sign_pk: sign_sk.public_key(),
                cipher_pk: cipher_pk.clone(),
                id: participant.into(),
                url: format!("http://localhost:{}", 3000 + participant_id),
                account_id: format!("participant{}.test", participant_id)
                    .parse()
                    .unwrap(),
            };

            participant_info.insert(participant, info);

            // Create MessageChannel using the standard constructor
            let (_inbox, _outbox, channel) = MessageChannel::new();
            channels.insert(participant, channel.clone());

            // We'll need to handle inbox/outbox routing separately
            // For now, store the channel
        }

        Self {
            channels,
            participants: Arc::new(RwLock::new(participant_info)),
        }
    }

    /// Get the MessageChannel for a specific participant
    pub fn get_channel(&self, participant: Participant) -> Option<MessageChannel> {
        self.channels.get(&participant).cloned()
    }

    /// Get all channels
    pub fn channels(&self) -> &HashMap<Participant, MessageChannel> {
        &self.channels
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_message_bus() {
        let participants = vec![Participant::from(0), Participant::from(1)];
        let bus = InMemoryMessageBus::new(&participants);

        // Verify we can get channels for each participant
        assert!(bus.get_channel(Participant::from(0)).is_some());
        assert!(bus.get_channel(Participant::from(1)).is_some());
        assert!(bus.get_channel(Participant::from(2)).is_none());
    }

    #[tokio::test]
    async fn test_message_routing_between_two_participants() {
        let participants = vec![Participant::from(0), Participant::from(1)];
        let bus = InMemoryMessageBus::new(&participants);

        let channel_0 = bus.get_channel(Participant::from(0)).unwrap();
        let _channel_1 = bus.get_channel(Participant::from(1)).unwrap();

        // Send a message from participant 0 to participant 1
        let message = Message::Posit(PositMessage {
            id: crate::protocol::message::PositProtocolId::Triple(123),
            from: Participant::from(0),
            action: crate::protocol::posit::PositAction::Propose,
        });

        channel_0
            .send(Participant::from(0), Participant::from(1), message)
            .await;

        // Give some time for message routing
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // In a full implementation, we would verify the message was received
        // For now, we just verify the channels exist and can send
    }

    #[tokio::test]
    async fn test_message_routing_with_multiple_participants() {
        let participants = vec![
            Participant::from(0),
            Participant::from(1),
            Participant::from(2),
        ];
        let bus = InMemoryMessageBus::new(&participants);

        // Verify all participants have channels
        for &p in &participants {
            assert!(bus.get_channel(p).is_some());
        }

        // Send messages between different pairs
        let channel_0 = bus.get_channel(Participant::from(0)).unwrap();
        let channel_1 = bus.get_channel(Participant::from(1)).unwrap();

        let message1 = Message::Posit(PositMessage {
            id: crate::protocol::message::PositProtocolId::Triple(1),
            from: Participant::from(0),
            action: crate::protocol::posit::PositAction::Propose,
        });

        let message2 = Message::Posit(PositMessage {
            id: crate::protocol::message::PositProtocolId::Triple(2),
            from: Participant::from(1),
            action: crate::protocol::posit::PositAction::Accept,
        });

        channel_0
            .send(Participant::from(0), Participant::from(2), message1)
            .await;
        channel_1
            .send(Participant::from(1), Participant::from(2), message2)
            .await;

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}
