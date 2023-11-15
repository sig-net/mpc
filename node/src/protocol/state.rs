use super::{contract::ParticipantsInfo, triple::TripleManager};
use crate::types::{KeygenProtocol, PrivateKeyShare, PublicKey, ReshareProtocol};

pub struct PersistentNodeData {
    pub epoch: u64,
    pub private_share: PrivateKeyShare,
    pub public_key: PublicKey,
}

pub struct StartedState(pub Option<PersistentNodeData>);

pub struct GeneratingState {
    pub participants: ParticipantsInfo,
    pub threshold: usize,
    pub protocol: KeygenProtocol,
}

pub struct WaitingForConsensusState {
    pub epoch: u64,
    pub participants: ParticipantsInfo,
    pub threshold: usize,
    pub private_share: PrivateKeyShare,
    pub public_key: PublicKey,
}

pub struct RunningState {
    pub epoch: u64,
    pub participants: ParticipantsInfo,
    pub threshold: usize,
    pub private_share: PrivateKeyShare,
    pub public_key: PublicKey,
    pub triple_manager: TripleManager,
}

pub struct ResharingState {
    pub old_epoch: u64,
    pub old_participants: ParticipantsInfo,
    pub new_participants: ParticipantsInfo,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub protocol: ReshareProtocol,
}

pub struct JoiningState {
    pub public_key: PublicKey,
}

#[derive(Default)]
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
