use threshold_signatures::ecdsa::ot_based_ecdsa::PresignOutput;
use threshold_signatures::ecdsa::KeygenOutput;
use threshold_signatures::ecdsa::Secp256K1Sha256;
use threshold_signatures::ecdsa::Signature as EcdsaSignature;
use threshold_signatures::errors::{InitializationError, ProtocolError};
use threshold_signatures::frost_core::keys::SigningShare;
use threshold_signatures::participants::Participant;
use threshold_signatures::protocol::Protocol;
use threshold_signatures::protocol::{Action, MessageData};

use crate::protocol::contract::ResharingContractState;

pub type SecretKeyShare = SigningShare<Secp256K1Sha256>;
pub type TripleProtocol = Box<
    dyn Protocol<
            Output = Vec<(
                threshold_signatures::ecdsa::ot_based_ecdsa::triples::TripleShare,
                threshold_signatures::ecdsa::ot_based_ecdsa::triples::TriplePub,
            )>,
        > + Send,
>;
// Presignature protocol implementations from `threshold-signatures` are not
// necessarily `Sync` across the board; make the trait object `Send` only.
pub type PresignatureProtocol = Box<dyn Protocol<Output = PresignOutput> + Send>;
// Signature protocols return `SignatureOption` (Option<Signature>) via
// `threshold-signatures`. Keep the boxed trait object send + sync.
pub type SignatureProtocol = Box<dyn Protocol<Output = Option<EcdsaSignature>> + Send>;

pub type Epoch = u64;

pub struct KeygenProtocol {
    me: Participant,
    threshold: usize,
    participants: Vec<Participant>,
    protocol: Box<dyn Protocol<Output = KeygenOutput> + Send>,
}

impl KeygenProtocol {
    pub fn new(
        participants: &[Participant],
        me: Participant,
        threshold: usize,
    ) -> Result<Self, InitializationError> {
        use rand::rngs::OsRng;

        Ok(Self {
            threshold,
            me,
            participants: participants.into(),
            protocol: Box::new(threshold_signatures::keygen::<Secp256K1Sha256>(
                participants,
                me,
                threshold,
                OsRng,
            )?),
        })
    }

    pub async fn refresh(&mut self) -> Result<(), InitializationError> {
        use rand::rngs::OsRng;

        self.protocol = Box::new(threshold_signatures::keygen::<Secp256K1Sha256>(
            &self.participants,
            self.me,
            self.threshold,
            OsRng,
        )?);
        Ok(())
    }

    pub fn poke(&mut self) -> Result<Action<KeygenOutput>, ProtocolError> {
        self.protocol.poke()
    }

    pub fn message(&mut self, from: Participant, data: MessageData) {
        self.protocol.message(from, data);
    }
}

pub struct ReshareProtocol {
    protocol: Box<dyn Protocol<Output = KeygenOutput> + Send>,
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
        use k256::ProjectivePoint;
        use rand::rngs::OsRng;
        use threshold_signatures::frost_core::{Group, VerifyingKey};

        // Convert the AffinePoint public key into the ciphersuite verifying key
        // `AffinePoint` -> `ProjectivePoint` conversion uses `ProjectivePoint::from`
        let public_key_element: threshold_signatures::frost_core::Element<Secp256K1Sha256> =
            ProjectivePoint::from(contract_state.public_key);

        let pk_ser =
            <Secp256K1Sha256 as threshold_signatures::frost_core::Ciphersuite>::Group::serialize(
                &public_key_element,
            )
            .map_err(|e| {
                InitializationError::BadParameters(format!(
                    "Failed to serialize public key element: {:?}",
                    e
                ))
            })?;
        let verifying_key =
            VerifyingKey::<Secp256K1Sha256>::deserialize(pk_ser.as_ref()).map_err(|e| {
                InitializationError::BadParameters(format!(
                    "Failed to deserialize verifying key: {:?}",
                    e
                ))
            })?;

        let protocol = Box::new(threshold_signatures::reshare::<Secp256K1Sha256>(
            &old_participants,
            contract_state.threshold,
            private_share,
            verifying_key,
            &new_participants,
            contract_state.threshold,
            me,
            OsRng,
        )?);
        Ok(Self { protocol })
    }

    pub fn poke(&mut self) -> Result<Action<KeygenOutput>, ProtocolError> {
        self.protocol.poke()
    }

    pub fn message(&mut self, from: Participant, data: MessageData) {
        self.protocol.message(from, data);
    }
}
