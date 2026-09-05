use cait_sith::protocol::{Action, InitializationError, MessageData, Participant, ProtocolError};
use cait_sith::{protocol::Protocol, KeygenOutput};
use cait_sith::{FullSignature, PresignOutput};
use k256::{elliptic_curve::CurveArithmetic, Secp256k1};
use mpc_primitives::{Chain, CheckpointDigest, SignId};
use tokio::sync::watch;

use crate::backlog::{Generating, SignEntry};
use crate::protocol::contract::ResharingContractState;

pub type SecretKeyShare = <Secp256k1 as CurveArithmetic>::Scalar;
pub type TripleProtocol = Box<
    dyn Protocol<
            Output = Vec<(
                cait_sith::triples::TripleShare<Secp256k1>,
                cait_sith::triples::TriplePub<Secp256k1>,
            )>,
        > + Send
        + Sync,
>;
pub type PresignatureProtocol = Box<dyn Protocol<Output = PresignOutput<Secp256k1>> + Send + Sync>;
pub type SignatureProtocol = Box<dyn Protocol<Output = FullSignature<Secp256k1>> + Send + Sync>;

pub type Epoch = u64;

pub type CheckpointWatcher = watch::Receiver<Option<CheckpointDigest>>;

/// Messages sent into the node's sign-request processing queue.
#[derive(Debug, Clone, PartialEq)]
pub enum SignCommand {
    Request(SignEntry<Generating>),
    Completion(SignId),
    AbortChain(Chain),
}

impl SignCommand {
    /// Spawn a forwarder task that translates NEAR indexer [`mpc_chain_near::SignCommand`]s
    /// into node [`SignCommand`]s, returning the channel sender for the indexer.
    pub fn forward_near(
        sign_tx: tokio::sync::mpsc::Sender<Self>,
        backlog: crate::backlog::Backlog,
    ) -> tokio::sync::mpsc::Sender<mpc_chain_near::SignCommand> {
        const MAX_NEAR_COMMANDS: usize = 16384;
        let (near_sign_tx, mut near_sign_rx) = tokio::sync::mpsc::channel(MAX_NEAR_COMMANDS);
        tokio::spawn(async move {
            while let Some(cmd) = near_sign_rx.recv().await {
                match cmd {
                    mpc_chain_near::SignCommand::Request(req) => {
                        let (entry, _) = backlog.insert(req).await;
                        if sign_tx.send(Self::Request(entry)).await.is_err() {
                            break;
                        }
                    }
                    mpc_chain_near::SignCommand::Completion(id) => {
                        if sign_tx.send(Self::Completion(id)).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        near_sign_tx
    }
}

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
        let protocol = Box::new(cait_sith::reshare::<Secp256k1>(
            &old_participants,
            contract_state.threshold,
            &new_participants,
            contract_state.new_threshold,
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
