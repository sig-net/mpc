use super::contract::primitives::Participants;
use super::presignature::PresignatureManager;
use super::signature::SignatureManager;
use super::triple::TripleSpawnerTask;
use crate::types::{KeygenProtocol, ReshareProtocol, SecretKeyShare};

use cait_sith::protocol::Participant;
use mpc_crypto::PublicKey;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::sync::Arc;

use tokio::sync::{watch, RwLock};

#[derive(Clone, Serialize, Deserialize)]
pub struct PersistentNodeData {
    pub epoch: u64,
    pub private_share: SecretKeyShare,
    pub public_key: PublicKey,
}

impl fmt::Debug for PersistentNodeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistentNodeData")
            .field("epoch", &self.epoch)
            .field("public_key", &self.public_key)
            .finish()
    }
}

#[derive(Debug)]
pub struct StartedState {
    pub persistent_node_data: Option<PersistentNodeData>,
}

pub struct GeneratingState {
    pub me: Participant,
    pub participants: Participants,
    pub threshold: usize,
    pub protocol: KeygenProtocol,

    /// If the generating state fails to store data after generating, it gets temporarily
    /// stored here and retried later.
    pub failed_store: Option<(PublicKey, SecretKeyShare)>,
}

pub struct WaitingForConsensusState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub private_share: SecretKeyShare,
    pub public_key: PublicKey,
}

impl fmt::Debug for WaitingForConsensusState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WaitingForConsensusState")
            .field("epoch", &self.epoch)
            .field("threshold", &self.threshold)
            .field("public_key", &self.public_key)
            .field("participants", &self.participants)
            .finish()
    }
}

pub struct RunningState {
    pub epoch: u64,
    pub me: Participant,
    pub participants: Participants,
    pub threshold: usize,
    pub private_share: SecretKeyShare,
    pub public_key: PublicKey,
    pub triple_task: TripleSpawnerTask,
    pub presignature_manager: Arc<RwLock<PresignatureManager>>,
    pub signature_manager: Arc<RwLock<SignatureManager>>,
}

pub struct ResharingState {
    pub me: Participant,
    pub old_epoch: u64,
    pub old_participants: Participants,
    pub new_participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub protocol: ReshareProtocol,

    /// If the resharing state fails to store data after generating, it gets temporarily
    /// stored here and retried later.
    pub failed_store: Option<SecretKeyShare>,
}

pub struct JoiningState {
    pub participants: Participants,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeStatus {
    Starting,
    Started,
    Generating {
        participants: Vec<Participant>,
    },
    WaitingForConsensus {
        participants: Vec<Participant>,
    },
    Running {
        me: Participant,
        participants: Vec<Participant>,
        ongoing_triple_gen: usize,
        ongoing_presignature_gen: usize,
    },
    Resharing {
        old_participants: Vec<Participant>,
        new_participants: Vec<Participant>,
    },
    Joining {
        participants: Vec<Participant>,
    },
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

impl Display for NodeState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            NodeState::Starting => write!(f, "Starting"),
            NodeState::Started(_) => write!(f, "Started"),
            NodeState::Generating(_) => write!(f, "Generating"),
            NodeState::WaitingForConsensus(_) => write!(f, "WaitingForConsensus"),
            NodeState::Running(_) => write!(f, "Running"),
            NodeState::Resharing(_) => write!(f, "Resharing"),
            NodeState::Joining(_) => write!(f, "Joining"),
        }
    }
}

pub struct Node {
    pub state: NodeState,
    pub watcher_tx: watch::Sender<NodeStatus>,
    pub watcher: NodeStateWatcher,
}

impl Default for Node {
    fn default() -> Self {
        Self::new()
    }
}

impl Node {
    pub fn new() -> Self {
        let (watcher_tx, watcher_rx) = watch::channel(NodeStatus::Starting);
        let watcher = NodeStateWatcher {
            watcher: watcher_rx,
        };
        Self {
            state: NodeState::Starting,
            watcher_tx,
            watcher,
        }
    }

    pub async fn update_watchers(&mut self) {
        match &self.state {
            NodeState::Started(_) => {
                let _ = self.watcher_tx.send(NodeStatus::Started);
            }
            NodeState::Starting => {
                let _ = self.watcher_tx.send(NodeStatus::Starting);
            }
            NodeState::Generating(state) => {
                let _ = self.watcher_tx.send(NodeStatus::Generating {
                    participants: state.participants.keys_vec(),
                });
            }
            NodeState::WaitingForConsensus(state) => {
                let _ = self.watcher_tx.send(NodeStatus::WaitingForConsensus {
                    participants: state.participants.keys_vec(),
                });
            }
            NodeState::Running(state) => {
                let _ = self.watcher_tx.send(NodeStatus::Running {
                    me: state.me,
                    participants: state.participants.keys_vec(),
                    ongoing_triple_gen: state.triple_task.len_ongoing(),
                    ongoing_presignature_gen: state
                        .presignature_manager
                        .read()
                        .await
                        .len_ongoing()
                        .await,
                });
            }
            NodeState::Resharing(state) => {
                let _ = self.watcher_tx.send(NodeStatus::Resharing {
                    old_participants: state.old_participants.keys_vec(),
                    new_participants: state.new_participants.keys_vec(),
                });
            }
            NodeState::Joining(state) => {
                let _ = self.watcher_tx.send(NodeStatus::Joining {
                    participants: state.participants.keys_vec(),
                });
            }
        }
    }
}

#[derive(Clone)]
pub struct NodeStateWatcher {
    watcher: watch::Receiver<NodeStatus>,
}

impl NodeStateWatcher {
    pub async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        self.watcher.changed().await
    }

    pub fn status(&self) -> NodeStatus {
        self.watcher.borrow().clone()
    }

    pub fn status_mut(&mut self) -> NodeStatus {
        self.watcher.borrow_and_update().clone()
    }

    pub fn participants(&self) -> Vec<Participant> {
        match self.status() {
            NodeStatus::Generating { participants } => participants,
            NodeStatus::WaitingForConsensus { participants } => participants,
            NodeStatus::Running { participants, .. } => participants,
            NodeStatus::Resharing {
                new_participants, ..
            } => new_participants,
            NodeStatus::Joining { participants } => participants,
            _ => Vec::new(),
        }
    }
}
