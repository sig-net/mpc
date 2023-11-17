use super::presignature::PresignatureManager;
use super::signature::SignatureManager;
use super::triple::TripleManager;
use super::SignQueue;
use crate::types::{KeygenProtocol, PrivateKeyShare, PublicKey, ReshareProtocol};
use cait_sith::protocol::Participant;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

pub struct PersistentNodeData {
    pub epoch: u64,
    pub private_share: PrivateKeyShare,
    pub public_key: PublicKey,
}

pub struct StartedState(pub Option<PersistentNodeData>);

pub struct GeneratingState {
    pub participants: BTreeMap<Participant, Url>,
    pub threshold: usize,
    pub protocol: KeygenProtocol,
}

pub struct WaitingForConsensusState {
    pub epoch: u64,
    pub participants: BTreeMap<Participant, Url>,
    pub threshold: usize,
    pub private_share: PrivateKeyShare,
    pub public_key: PublicKey,
}

pub struct RunningState {
    pub epoch: u64,
    pub participants: BTreeMap<Participant, Url>,
    pub threshold: usize,
    pub private_share: PrivateKeyShare,
    pub public_key: PublicKey,
    pub sign_queue: Arc<RwLock<SignQueue>>,
    pub triple_manager: TripleManager,
    pub presignature_manager: PresignatureManager,
    pub signature_manager: SignatureManager,
}

pub struct ResharingState {
    pub old_epoch: u64,
    pub old_participants: BTreeMap<Participant, Url>,
    pub new_participants: BTreeMap<Participant, Url>,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub protocol: ReshareProtocol,
}

pub struct JoiningState {
    pub public_key: PublicKey,
}

#[derive(Default)]
#[allow(clippy::large_enum_variant)]
pub enum NodeState {
    #[default]
    Starting,
    Started(StartedState),
    Generating(GeneratingState),
    WaitingForConsensus(WaitingForConsensusState),
    Running(RunningState),
    Resharing(ResharingState),
    Joining(JoiningState),
}
