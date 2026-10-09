//! Encryption and wire serialization for peer messages.

use crate::protocol::contract::primitives::ParticipantMap;

use crate::protocol::message::types::MessageError;

use cait_sith::protocol::Participant;
use chrono::Utc;
use mpc_keys::hpke::{self, Ciphered};
use near_account_id::AccountId;
use near_crypto::Signature;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use std::time::Duration;

const MAX_CLOCK_SKEW: Duration = Duration::from_secs(30);

pub fn now_millis() -> u64 {
    Utc::now().timestamp_millis() as u64
}

/// Within `max_age` plus clock skew of our clock, in either direction.
pub(crate) fn in_window(sent_at: u64, max_age: Duration) -> bool {
    now_millis().abs_diff(sent_at) <= (max_age + MAX_CLOCK_SKEW).as_millis() as u64
}

/// What an envelope is for; one made for one use fails verification in another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageDomain {
    Message,
    SyncRequest,
    SyncReply,
}

impl MessageDomain {
    fn tag(self) -> &'static [u8] {
        match self {
            Self::Message => b"mpc-node/signed-message/v2",
            Self::SyncRequest => b"mpc-node/sync-request/v2",
            Self::SyncReply => b"mpc-node/sync-reply/v2",
        }
    }
}

/// A signed message that can be encrypted; the signature covers use, recipient and time.
#[derive(Serialize, Deserialize)]
pub struct SignedMessage {
    /// The message with all it's related info.
    #[serde(with = "serde_bytes")]
    pub msg: Vec<u8>,
    /// Signature by `from` over [`Self::signed_bytes`].
    pub sig: Signature,
    /// From which particpant the message was sent.
    pub from: Participant,
    /// When the sender signed, in milliseconds since the UNIX epoch.
    pub sent_at: u64,
}

/// A decrypted envelope whose signature and time checked out.
pub struct Opened<T> {
    pub from: Participant,
    pub sig: Signature,
    pub sent_at: u64,
    pub msg: T,
}

/// A restart forgets what was accepted, so anything signed earlier is rejected.
pub(crate) fn signed_after_start(started_at: u64, sent_at: u64) -> Result<(), MessageError> {
    if sent_at < started_at {
        return Err(MessageError::Verification(
            "signed before this node started",
        ));
    }
    Ok(())
}

impl SignedMessage {
    pub const ASSOCIATED_DATA: &'static [u8] = b"";

    /// The bytes the sender signs. The recipient is named by account, which a
    /// node always knows and the contract never hands to anyone else, unlike a
    /// participant id. It is not sent along: the recipient fills in its own.
    fn signed_bytes(domain: MessageDomain, to: &AccountId, sent_at: u64, msg: &[u8]) -> Vec<u8> {
        let to = to.as_bytes();
        [
            domain.tag(),
            &sent_at.to_le_bytes(),
            &(to.len() as u32).to_le_bytes(),
            to,
            msg,
        ]
        .concat()
    }

    /// Encrypt a peer message, signed now.
    pub fn encrypt<T: Serialize>(
        msg: &T,
        from: Participant,
        to: &AccountId,
        sign_sk: &near_crypto::SecretKey,
        cipher_pk: &hpke::PublicKey,
    ) -> Result<Ciphered, MessageError> {
        let domain = MessageDomain::Message;
        Self::encrypt_at(domain, msg, from, to, now_millis(), sign_sk, cipher_pk)
    }

    /// Encrypt under `domain`, signed at `sent_at`.
    pub fn encrypt_at<T: Serialize>(
        domain: MessageDomain,
        msg: &T,
        from: Participant,
        to: &AccountId,
        sent_at: u64,
        sign_sk: &near_crypto::SecretKey,
        cipher_pk: &hpke::PublicKey,
    ) -> Result<Ciphered, MessageError> {
        let msg = cbor_to_bytes(msg)?;
        let sig = sign_sk.sign(&Self::signed_bytes(domain, to, sent_at, &msg));
        let msg = Self {
            msg,
            sig,
            from,
            sent_at,
        };
        let msg = cbor_to_bytes(&msg)?;
        let ciphered = cipher_pk
            .encrypt(&msg, Self::ASSOCIATED_DATA)
            .inspect_err(|err| {
                tracing::error!(?err, "failed to encrypt message");
            })?;
        Ok(ciphered)
    }

    /// Decrypt and verify that the sender signed this under `domain`, for us,
    /// within `max_age`. The caller must still reject replays.
    pub fn decrypt<T: DeserializeOwned>(
        domain: MessageDomain,
        encrypted: &Ciphered,
        cipher_sk: &hpke::SecretKey,
        participants: &ParticipantMap,
        me: &AccountId,
        max_age: Duration,
    ) -> Result<Opened<T>, MessageError> {
        let msg = cipher_sk
            .decrypt(encrypted, Self::ASSOCIATED_DATA)
            .inspect_err(|err| {
                tracing::error!(?err, "failed to decrypt message");
            })?;
        let Self {
            msg,
            sig,
            from,
            sent_at,
        } = cbor_from_bytes(&msg)?;
        let info = participants
            .get(&from)
            .ok_or(MessageError::UnknownParticipant(from))?;

        // Also fails if signed for another use, recipient or time.
        if !sig.verify(
            &Self::signed_bytes(domain, me, sent_at, &msg),
            &info.sign_pk,
        ) {
            tracing::error!(?from, "signed message erred out with invalid signature");
            return Err(MessageError::Verification(
                "invalid signature while verifying authenticity of encrypted protocol message",
            ));
        }

        if !in_window(sent_at, max_age) {
            tracing::warn!(?from, sent_at, "signed message is outside the time window");
            return Err(MessageError::Verification(
                "signed message is outside the accepted time window",
            ));
        }

        Ok(Opened {
            from,
            sig,
            sent_at,
            msg: cbor_from_bytes(&msg)?,
        })
    }
}

pub fn cbor_to_bytes<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, MessageError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|err| MessageError::CborConversion(err.to_string()))?;
    Ok(buf)
}

pub(crate) fn cbor_from_bytes<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, MessageError> {
    ciborium::from_reader(bytes).map_err(|err| MessageError::CborConversion(err.to_string()))
}

pub(crate) const fn cbor_name(value: &ciborium::Value) -> &'static str {
    match value {
        ciborium::Value::Integer(_) => "integer",
        ciborium::Value::Bytes(_) => "bytes",
        ciborium::Value::Text(_) => "text",
        ciborium::Value::Float(_) => "float",
        ciborium::Value::Null => "null",
        ciborium::Value::Bool(_) => "bool",
        ciborium::Value::Array(_) => "array",
        ciborium::Value::Map(_) => "map",
        ciborium::Value::Tag(_, _) => "tag",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::contract::primitives::{ParticipantMap, Participants};
    use crate::protocol::message::{GeneratingMessage, Message, SignatureMessage, TripleMessage};
    use crate::protocol::ParticipantInfo;

    use cait_sith::protocol::Participant;
    use mpc_keys::hpke::{self, Ciphered};
    use mpc_primitives::SignId;
    use serde::{de::DeserializeOwned, Deserialize, Serialize};

    #[test]
    fn test_sending_encrypted_message() {
        let associated_data = b"";
        let (cipher_sk, cipher_pk) = mpc_keys::hpke::generate();
        let starting_message = Message::Generating(GeneratingMessage {
            from: Participant::from(0),
            data: vec![],
        });

        let message = serde_json::to_vec(&starting_message).unwrap();
        let message = cipher_pk.encrypt(&message, associated_data).unwrap();

        let message = serde_json::to_vec(&message).unwrap();
        let cipher = serde_json::from_slice(&message).unwrap();
        let message = cipher_sk.decrypt(&cipher, associated_data).unwrap();
        let message: Message = serde_json::from_slice(&message).unwrap();

        assert_eq!(starting_message, message);
    }

    #[test]
    fn test_encrypt_then_decrypt() {
        let (cipher_sk, cipher_pk) = mpc_keys::hpke::generate();
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt0");
        let from = Participant::from(7);
        let mut participants = Participants::default();
        participants.insert(
            &from,
            ParticipantInfo {
                sign_pk: sign_sk.public_key(),
                cipher_pk: cipher_pk.clone(),
                id: from.into(),
                url: "http://localhost:3030".to_string(),
                account_id: "test.near".parse().unwrap(),
            },
        );
        let participants = ParticipantMap::One(participants);

        let batch = vec![Message::Triple(TripleMessage {
            id: 1234,
            epoch: 0,
            from,
            data: vec![128u8; 1024],
            timestamp: 1234567,
        })];
        let me = account("test.near");
        let encrypted = SignedMessage::encrypt(&batch, from, &me, &sign_sk, &cipher_pk).unwrap();
        let decrypted_batch: Vec<Message> = SignedMessage::decrypt(
            MessageDomain::Message,
            &encrypted,
            &cipher_sk,
            &participants,
            &me,
            MAX_AGE,
        )
        .unwrap()
        .msg;

        assert_eq!(
            batch, decrypted_batch,
            "batch messages did not get encrypted and decrypted correctly"
        );
    }

    const MAX_AGE: Duration = Duration::from_secs(300);

    fn account(id: &str) -> AccountId {
        id.parse().unwrap()
    }

    /// Participant 0 as the only sender.
    fn sender(sign_sk: &near_crypto::SecretKey, cipher_pk: &hpke::PublicKey) -> ParticipantMap {
        let mut participants = Participants::default();
        let info = ParticipantInfo {
            sign_pk: sign_sk.public_key(),
            cipher_pk: cipher_pk.clone(),
            ..ParticipantInfo::new(0)
        };
        participants.insert(&Participant::from(0), info);
        ParticipantMap::One(participants)
    }

    fn batch(from: Participant) -> Vec<Message> {
        vec![Message::Generating(GeneratingMessage {
            from,
            data: vec![1, 2, 3],
        })]
    }

    /// An envelope opens only at the node it was signed for.
    #[test]
    fn test_rejects_envelope_signed_for_another_recipient() {
        let (cipher_sk, cipher_pk) = hpke::generate();
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt0");
        let participants = sender(&sign_sk, &cipher_pk);
        let (me, other) = (account("me.near"), account("other.near"));

        let from = Participant::from(0);
        let encrypted =
            SignedMessage::encrypt(&batch(from), from, &me, &sign_sk, &cipher_pk).unwrap();
        let open = |me| {
            let domain = MessageDomain::Message;
            SignedMessage::decrypt::<Vec<Message>>(
                domain,
                &encrypted,
                &cipher_sk,
                &participants,
                me,
                MAX_AGE,
            )
        };
        let delivered = open(&me).unwrap();
        assert_eq!((delivered.from, delivered.msg), (from, batch(from)));
        assert!(matches!(open(&other), Err(MessageError::Verification(_))));
    }

    /// An envelope is accepted only within the time window.
    #[test]
    fn test_rejects_envelope_outside_the_time_window() {
        let (cipher_sk, cipher_pk) = hpke::generate();
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt0");
        let participants = sender(&sign_sk, &cipher_pk);
        let me = account("me.near");
        let from = Participant::from(0);
        let skew = MAX_CLOCK_SKEW.as_millis() as u64;
        let max_age = MAX_AGE.as_millis() as u64;

        let verify = |sent_at: u64| -> Result<Vec<Message>, MessageError> {
            let encrypted = SignedMessage::encrypt_at(
                MessageDomain::Message,
                &batch(from),
                from,
                &me,
                sent_at,
                &sign_sk,
                &cipher_pk,
            )?;
            let domain = MessageDomain::Message;
            SignedMessage::decrypt(domain, &encrypted, &cipher_sk, &participants, &me, MAX_AGE)
                .map(|opened| opened.msg)
        };

        // Margins of 10 seconds keep the test independent of its own runtime.
        assert!(verify(now_millis()).is_ok());
        assert!(verify(now_millis() - max_age - skew + 10_000).is_ok());
        assert!(verify(now_millis() + max_age + skew - 10_000).is_ok());
        assert!(matches!(
            verify(now_millis() - max_age - skew - 10_000),
            Err(MessageError::Verification(_))
        ));
        assert!(matches!(
            verify(now_millis() + max_age + skew + 10_000),
            Err(MessageError::Verification(_))
        ));
    }

    #[test]
    fn test_serialization_change() {
        #[derive(Serialize, Deserialize)]
        struct NewSignedMessage {
            #[serde(with = "serde_bytes")]
            msg: Vec<u8>,
            sig: near_crypto::Signature,
            from: Participant,
            sent_at: u64,

            // default will call Default::default() if missing in serialized bytes.
            #[serde(default)]
            added_field: Vec<u32>,
        }

        impl NewSignedMessage {
            const ASSOCIATED_DATA: &'static [u8] = SignedMessage::ASSOCIATED_DATA;

            fn encrypt<T: Serialize>(
                batch: &T,
                from: Participant,
                to: &AccountId,
                sign_sk: &near_crypto::SecretKey,
                cipher_pk: &hpke::PublicKey,
            ) -> Ciphered {
                let msg = super::cbor_to_bytes(batch).unwrap();
                let sent_at = now_millis();
                let sig = sign_sk.sign(&SignedMessage::signed_bytes(
                    MessageDomain::Message,
                    to,
                    sent_at,
                    &msg,
                ));
                let msg = Self {
                    msg,
                    sig,
                    from,
                    sent_at,
                    added_field: vec![127; 1024],
                };
                let msg = super::cbor_to_bytes(&msg).unwrap();
                cipher_pk.encrypt(&msg, Self::ASSOCIATED_DATA).unwrap()
            }

            fn decrypt<T: DeserializeOwned>(
                encrypted: &Ciphered,
                cipher_sk: &hpke::SecretKey,
            ) -> T {
                let msg = cipher_sk.decrypt(encrypted, Self::ASSOCIATED_DATA).unwrap();
                let Self { msg, .. } = super::cbor_from_bytes(&msg).unwrap();
                super::cbor_from_bytes(&msg).unwrap()
            }
        }

        #[derive(Debug, Serialize, Deserialize)]
        enum NewMessage {
            Triple(NewTripleMessage),
            NewVariant(String),
            #[serde(untagged)]
            Unknown(ciborium::Value),
        }

        impl PartialEq<Message> for NewMessage {
            fn eq(&self, other: &Message) -> bool {
                match (self, other) {
                    (NewMessage::Triple(a), Message::Triple(b)) => a == b,
                    // ignore the unknowns for comparison since we don't care about them here.
                    _ => true,
                }
            }
        }

        #[derive(Debug, Serialize, Deserialize)]
        struct NewTripleMessage {
            id: u64,
            epoch: u64,
            from: Participant,
            #[serde(with = "serde_bytes")]
            data: Vec<u8>,
            timestamp: u64,
            // added this new timestamp in the future:
            #[serde(default)]
            new_timestamp: Option<u64>,
        }

        impl PartialEq<TripleMessage> for NewTripleMessage {
            fn eq(&self, other: &TripleMessage) -> bool {
                self.id == other.id
                    && self.epoch == other.epoch
                    && self.from == other.from
                    && self.data == other.data
                    && self.timestamp == other.timestamp
            }
        }

        let from = Participant::from(1337);
        let (cipher_sk, cipher_pk) = mpc_keys::hpke::generate();
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt1");
        let mut participants = Participants::default();
        participants.insert(
            &from,
            ParticipantInfo {
                sign_pk: sign_sk.public_key(),
                cipher_pk: cipher_pk.clone(),
                id: from.into(),
                url: "http://localhost:3030".to_string(),
                account_id: "test.near".parse().unwrap(),
            },
        );
        let participants = ParticipantMap::One(participants);
        let me = account("test.near");

        // Test forward compatibility
        let old_batch = vec![
            Message::Triple(TripleMessage {
                id: 1234,
                epoch: 0,
                from,
                data: vec![128; 1024],
                timestamp: 1234567,
            }),
            Message::Generating(GeneratingMessage {
                from,
                data: vec![8; 512],
            }),
            Message::Signature(SignatureMessage {
                id: SignId::new([7; 32]),
                proposer: from,
                presignature_id: 1234,
                epoch: 0,
                from,
                data: vec![78; 1222],
                timestamp: 1234567,
            }),
        ];
        let encrypted =
            SignedMessage::encrypt(&old_batch, from, &me, &sign_sk, &cipher_pk).unwrap();
        let new_batch: Vec<NewMessage> = NewSignedMessage::decrypt(&encrypted, &cipher_sk);
        assert_eq!(
            new_batch, old_batch,
            "encrypt/decrypt failed forward compatibility"
        );

        // Test backward compatibility
        let new_batch = vec![
            NewMessage::Triple(NewTripleMessage {
                id: 1234,
                epoch: 0,
                from,
                data: vec![128u8; 1024],
                timestamp: 1234567,
                new_timestamp: Some(777),
            }),
            NewMessage::NewVariant("hello".to_string()),
        ];
        let new_ciphered = NewSignedMessage::encrypt(&new_batch, from, &me, &sign_sk, &cipher_pk);
        let old_batch: Vec<Message> = SignedMessage::decrypt(
            MessageDomain::Message,
            &new_ciphered,
            &cipher_sk,
            &participants,
            &me,
            MAX_AGE,
        )
        .unwrap()
        .msg;
        assert_eq!(
            new_batch, old_batch,
            "encrypt/decrypt failed backward compatibility"
        );
    }

    #[test]
    fn test_encrypt_size() {
        let epoch = 1;
        let from = Participant::from(0);
        let batch = vec![
            Message::Triple(TripleMessage {
                id: 1,
                epoch,
                from,
                data: vec![128u8; 1024],
                timestamp: 1,
            }),
            Message::Triple(TripleMessage {
                id: 2,
                epoch,
                from,
                data: vec![255u8; 2048],
                timestamp: 2,
            }),
            Message::Triple(TripleMessage {
                id: 3,
                epoch,
                from,
                data: vec![101u8; 1337],
                timestamp: 3,
            }),
        ];

        let batch_bytesize = batch.iter().map(|msg| msg.size()).sum::<usize>();

        let (_cipher_sk, cipher_pk) = hpke::generate();
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt0");
        let me = account("test.near");
        let ciphered = SignedMessage::encrypt(&batch, from, &me, &sign_sk, &cipher_pk).unwrap();
        let ciphered_bytesize = ciphered.text.len();

        let margin_percent = 0.05;
        let margin_of_err = (batch_bytesize as f64 * margin_percent) as usize;
        assert!(
            ((batch_bytesize - margin_of_err)..(batch_bytesize + margin_of_err))
                .contains(&ciphered_bytesize),
            "ciphered message size is not within 5% of the original message size"
        );
    }
}
