use super::presignature::PresignatureManager;
use super::{contract::Participants, triple::TripleManager};
use crate::types::{KeygenProtocol, PrivateKeyShare, PublicKey, ReshareProtocol};

pub struct PersistentNodeData {
    pub epoch: u64,
    pub private_share: PrivateKeyShare,
    pub public_key: PublicKey,
}

pub struct StartedState(pub Option<PersistentNodeData>);

pub struct GeneratingState {
    pub participants: Participants,
    pub threshold: usize,
    pub protocol: KeygenProtocol,
}

pub struct WaitingForConsensusState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub private_share: PrivateKeyShare,
    pub public_key: PublicKey,
}

pub struct RunningState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub private_share: PrivateKeyShare,
    pub public_key: PublicKey,
    pub triple_manager: TripleManager,
    pub presignature_manager: PresignatureManager,
}

pub struct ResharingState {
    pub old_epoch: u64,
    pub old_participants: Participants,
    pub new_participants: Participants,
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
