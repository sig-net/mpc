use cait_sith::protocol::Participant;
use mpc_keys::hpke::{self, Ciphered};
use mpc_node::protocol::contract::primitives::{ParticipantInfo, Participants};
use mpc_node::protocol::message::{
    Message, MessageError, PositMessage, PositProtocolId, PresignatureMessage, SignatureMessage,
    SignedMessage, TripleMessage,
};
use mpc_node::protocol::posit::PositAction;
use mpc_node::protocol::presignature::PresignatureId;
use mpc_node::protocol::triple::TripleId;
use mpc_primitives::SignId;
use near_account_id::AccountId;
use serde::Serialize;
use url::Url;

/// Simulated MPC participant with distinct cryptographic keys for signing and HPKE encryption.
#[derive(Clone, Debug)]
pub struct SimulatedParticipant {
    pub participant: Participant,
    pub account_id: AccountId,
    pub cipher_sk: hpke::SecretKey,
    pub cipher_pk: hpke::PublicKey,
    pub sign_sk: near_crypto::SecretKey,
    pub sign_pk: near_crypto::PublicKey,
    pub url: Url,
}

impl SimulatedParticipant {
    /// Create a simulated participant with generated keys.
    pub fn try_new(index: u32) -> anyhow::Result<Self> {
        let participant = Participant::from(index);
        let account_id: AccountId = format!("node-{index}.testnet")
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid account id: {e}"))?;
        let (cipher_sk, cipher_pk) = hpke::generate();
        let sign_sk = near_crypto::SecretKey::from_seed(
            near_crypto::KeyType::ED25519,
            &format!("memory-bench-participant-{index}"),
        );
        let sign_pk = sign_sk.public_key();
        let port = 3000 + (index % 50000);
        let url = Url::parse(&format!("http://127.0.0.1:{port}"))?;

        Ok(Self {
            participant,
            account_id,
            cipher_sk,
            cipher_pk,
            sign_sk,
            sign_pk,
            url,
        })
    }

    /// Participant metadata for inclusion in `Participants`.
    pub fn info(&self) -> ParticipantInfo {
        ParticipantInfo {
            id: self.participant.into(),
            account_id: self.account_id.clone(),
            url: self.url.to_string(),
            sign_pk: self.sign_pk.clone(),
            cipher_pk: self.cipher_pk.clone(),
        }
    }

    /// Sign and encrypt a payload targeted at a recipient participant.
    pub fn encrypt_for<T: Serialize>(
        &self,
        msg: &T,
        recipient_cipher_pk: &hpke::PublicKey,
    ) -> Result<Ciphered, MessageError> {
        SignedMessage::encrypt(msg, self.participant, &self.sign_sk, recipient_cipher_pk)
    }

    /// Generate an encrypted batch of messages targeted at a recipient.
    pub fn encrypt_batch(
        &self,
        messages: &[Message],
        recipient_cipher_pk: &hpke::PublicKey,
    ) -> Result<Ciphered, MessageError> {
        self.encrypt_for(&messages, recipient_cipher_pk)
    }
}

/// Convert a list of simulated participants into contract `Participants`.
pub fn build_contract_participants(participants: &[SimulatedParticipant]) -> Participants {
    let mut map = Participants::default();
    for p in participants {
        map.insert(&p.participant, p.info());
    }
    map
}

/// Helper builders for protocol messages.
pub mod messages {
    use super::*;

    pub fn triple(id: TripleId, epoch: u64, from: Participant, payload_len: usize) -> Message {
        Message::Triple(TripleMessage {
            id,
            epoch,
            from,
            data: vec![0x42; payload_len],
            timestamp: 1,
        })
    }

    pub fn presignature(id: PresignatureId, from: Participant, payload_len: usize) -> Message {
        Message::Presignature(PresignatureMessage {
            id,
            pair_id: id,
            epoch: 0,
            from,
            data: vec![0x43; payload_len],
            timestamp: 1,
        })
    }

    pub fn signature(
        sign_id: SignId,
        presig_id: PresignatureId,
        from: Participant,
        payload_len: usize,
    ) -> Message {
        Message::Signature(SignatureMessage {
            id: sign_id,
            proposer: from,
            presignature_id: presig_id,
            epoch: 0,
            from,
            data: vec![0x44; payload_len],
            timestamp: 1,
        })
    }

    pub fn posit(id: PositProtocolId, from: Participant, action: PositAction) -> Message {
        Message::Posit(PositMessage { id, from, action })
    }
}
