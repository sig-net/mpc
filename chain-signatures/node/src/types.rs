use threshold_signatures::protocol::{Action, MessageData};
use threshold_signatures::errors::{InitializationError, ProtocolError};
use threshold_signatures::participants::Participant;
use threshold_signatures::protocol::Protocol;
use threshold_signatures::ecdsa::ot_based_ecdsa::KeygenOutput;
use threshold_signatures::ecdsa::ot_based_ecdsa::PresignOutput;
use threshold_signatures::ecdsa::ot_based_ecdsa::FullSignature;
use k256::{elliptic_curve::CurveArithmetic, Secp256k1};

use crate::protocol::contract::ResharingContractState;

pub type SecretKeyShare = <Secp256k1 as CurveArithmetic>::Scalar;
pub type TripleProtocol = Box<
    dyn Protocol<
            Output = Vec<(
                threshold_signatures::triples::TripleShare<Secp256k1>,
                threshold_signatures::triples::TriplePub<Secp256k1>,
            )>,
        > + Send
        + Sync,
>;
pub type PresignatureProtocol = Box<dyn Protocol<Output = PresignOutput<Secp256k1>> + Send + Sync>;
pub type SignatureProtocol = Box<dyn Protocol<Output = FullSignature<Secp256k1>> + Send + Sync>;

pub type Epoch = u64;

pub struct KeygenProtocol {
    me: Participant,
    threshold: usize,
    participants: Vec<Participant>,
    protocol: Box<dyn Protocol<Output = KeygenOutput<Secp256k1>> + Send + Sync>,
}

impl KeygenProtocol {
    pub fn new(
        participants: &[Participant],
        me: Participant,
        threshold: usize,
    ) -> Result<Self, InitializationError> {
        Ok(Self {
            threshold,
            me,
            participants: participants.into(),
            protocol: Box::new(threshold_signatures::keygen::<threshold_signatures::Secp256K1Sha256>(
                participants,
                me,
                self.threshold,
                // RNG param required by the new implementation - use the thread RNG for simplicity
                rand::rngs::OsRng,
            )?),
        })
    }

    pub async fn refresh(&mut self) -> Result<(), InitializationError> {
        self.protocol = Box::new(threshold_signatures::keygen::<threshold_signatures::Secp256K1Sha256>(
            &self.participants,
            self.me,
            self.threshold,
            rand::rngs::OsRng,
        )?);
        Ok(())
    }

    pub fn poke(&mut self) -> Result<Action<KeygenOutput<Secp256k1>>, ProtocolError> {
        self.protocol.poke()
    }

    pub fn message(&mut self, from: Participant, data: MessageData) {
        self.protocol.message(from, data);
    }
}

pub struct ReshareProtocol {
    protocol: Box<dyn Protocol<Output = SecretKeyShare> + Send + Sync>,
}

impl ReshareProtocol {
    pub fn new(
        private_share: Option<SecretKeyShare>,
        me: Participant,
        contract_state: &ResharingContractState,
    ) -> Result<Self, InitializationError> {
        let old_participants = contract_state.old_participants.keys_vec();
        let new_participants = contract_state.new_participants.keys_vec();
        tracing::debug!(
            "ReshareProtocol::new old participants {:?} new participants {:?} me {:?}",
            old_participants,
            new_participants,
            me
        );
    let protocol = Box::new(threshold_signatures::reshare::<Secp256k1>(
            &old_participants,
            contract_state.threshold,
            &new_participants,
            contract_state.threshold,
            me,
            private_share,
            contract_state.public_key,
        )?);
        Ok(Self { protocol })
    }

    pub fn poke(&mut self) -> Result<Action<SecretKeyShare>, ProtocolError> {
        self.protocol.poke()
    }

    pub fn message(&mut self, from: Participant, data: MessageData) {
        self.protocol.message(from, data);
    }
}
