use cait_sith::protocol::{Action, InitializationError, MessageData, Participant, ProtocolError};
use cait_sith::triples::TripleGenerationOutput;
use cait_sith::{protocol::Protocol, KeygenOutput};
use cait_sith::{FullSignature, PresignOutput};
use k256::{elliptic_curve::CurveArithmetic, Secp256k1};
use mpc_crypto::PublicKey;
use tokio::sync::RwLock;

use crate::protocol::contract::ResharingContractState;

pub type SecretKeyShare = <Secp256k1 as CurveArithmetic>::Scalar;
pub type TripleProtocol =
    RwLock<dyn Protocol<Output = TripleGenerationOutput<Secp256k1>> + Send + Sync>;
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
            protocol: Box::new(cait_sith::keygen::<Secp256k1>(participants, me, threshold)?),
        })
    }

    pub async fn refresh(&mut self) -> Result<(), InitializationError> {
        self.protocol = Box::new(cait_sith::keygen::<Secp256k1>(
            &self.participants,
            self.me,
            self.threshold,
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
    old_participants: Vec<Participant>,
    new_participants: Vec<Participant>,
    me: Participant,
    threshold: usize,
    private_share: Option<SecretKeyShare>,
    protocol: Box<dyn Protocol<Output = SecretKeyShare> + Send + Sync>,
    root_pk: PublicKey,
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
        Ok(Self {
            protocol: Box::new(cait_sith::reshare::<Secp256k1>(
                &old_participants,
                contract_state.threshold,
                &new_participants,
                contract_state.threshold,
                me,
                private_share,
                contract_state.public_key,
            )?),
            private_share,
            me,
            threshold: contract_state.threshold,
            old_participants,
            new_participants,
            root_pk: contract_state.public_key,
        })
    }

    pub async fn refresh(&mut self) -> Result<(), InitializationError> {
        tracing::debug!(
            "ReshareProtocol::refresh old participants {:?} new participants {:?} me {:?}",
            self.old_participants,
            self.new_participants,
            self.me
        );
        self.protocol = Box::new(cait_sith::reshare::<Secp256k1>(
            &self.old_participants,
            self.threshold,
            &self.new_participants,
            self.threshold,
            self.me,
            self.private_share,
            self.root_pk,
        )?);
        Ok(())
    }

    pub fn poke(&mut self) -> Result<Action<SecretKeyShare>, ProtocolError> {
        self.protocol.poke()
    }

    pub fn message(&mut self, from: Participant, data: MessageData) {
        self.protocol.message(from, data);
    }
}
