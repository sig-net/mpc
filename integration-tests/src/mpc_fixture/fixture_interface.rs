//! Types used by tests directly to control a running MPC network fixture, feed
//! it with controlled inputs, and assert on outputs.

use crate::containers::Redis;
use cait_sith::protocol::Participant;
use mpc_node::backlog::Backlog;
use mpc_node::config::Config;
use mpc_node::mesh::MeshState;
use mpc_node::protocol::presignature::Presignature;
use mpc_node::protocol::state::NodeStateWatcher;
use mpc_node::protocol::sync::SyncChannel;
use mpc_node::protocol::{MessageChannel, ProtocolState, Sign};
use mpc_node::storage::{PresignatureStorage, TripleStorage};
use mpc_primitives::SignId;
use near_sdk::AccountId;
use rand::random;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tokio::sync::{watch, Mutex};

pub struct MpcFixture {
    pub nodes: Vec<MpcFixtureNode>,
    pub redis_container: Redis,
    pub shared_contract_state: watch::Sender<Option<ProtocolState>>,
    pub output: SharedOutput,
    /// Presignatures that were held back during fixture creation.
    /// Can be added later via `add_presignatures()`.
    pub pregenerated_presignatures: BTreeMap<Participant, BTreeMap<Participant, Vec<Presignature>>>,
}

pub struct MpcFixtureNode {
    pub me: Participant,
    pub state: NodeStateWatcher,
    pub mesh: watch::Sender<MeshState>,
    pub config: watch::Sender<Config>,

    pub sign_tx: mpsc::Sender<Sign>,
    pub msg_channel: MessageChannel,

    pub triple_storage: TripleStorage,
    pub presignature_storage: PresignatureStorage,
    pub backlog: Backlog,

    pub web_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Logs for reading outputs after a test run for assertions and debugging.
#[derive(Default)]
pub struct SharedOutput {
    pub msg_log: Arc<Mutex<Vec<String>>>,
    pub rpc_actions: Arc<Mutex<HashSet<String>>>,
}

/// Broadcast channel for sign completions across all nodes.
/// When any node publishes a signature, this channel is used to notify
/// all other nodes so they can abort their tasks for the same SignId.
pub struct CompletionBroadcast {
    pub tx: broadcast::Sender<SignId>,
}

impl CompletionBroadcast {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SignId> {
        self.tx.subscribe()
    }
}

impl MpcFixture {
    pub async fn wait_for_triples(&self, threshold_per_node: usize) {
        for node in &self.nodes {
            node.wait_for_triples(threshold_per_node).await;
        }
    }

    pub async fn wait_for_presignatures(&self, threshold_per_node: usize) {
        for node in &self.nodes {
            node.wait_for_presignatures(threshold_per_node).await;
        }
    }

    pub async fn add_presignatures(&mut self) -> usize {
        let mut total_added = 0;

        let mut id_mapping = HashMap::new();
        // let mut shares = HashMap::new();

        for node in &self.nodes {
            if let Some(my_shares) = self.pregenerated_presignatures.get(&node.me) {
                for (owner, presignature_shares) in my_shares {
                    // let id: PresignatureId = random();

                    for presignature_share in presignature_shares {
                        let id = id_mapping
                            .entry(presignature_share.id)
                            .or_insert_with(random);

                        let share = Presignature {
                            id: *id,
                            output: presignature_share.output.clone(),
                            participants: presignature_share.participants.clone(),
                        };

                        // shares
                        //     .entry(*id)
                        //     .or_insert_with(Vec::new)
                        //     .push((node.me, *owner, share));

                        if let Some(mut slot) = node.presignature_storage.reserve(share.id).await {
                            slot.insert(share, *owner).await;
                            total_added += 1;
                        }
                    }
                }
            }
        }

        tracing::info!(total_added, "added more presignatures");
        total_added
    }

    pub async fn wait_for_actions(&self, threshold: usize) -> HashSet<String> {
        let interval = Duration::from_millis(100);

        loop {
            let actions = self.output.rpc_actions.lock().await;

            if actions.len() >= threshold {
                return actions.clone();
            }

            drop(actions);
            tokio::time::sleep(interval).await;
        }
    }
}

impl MpcFixtureNode {
    pub async fn wait_for_triples(&self, threshold_per_node: usize) {
        loop {
            let count = self.triple_storage.len_by_owner(self.me).await;
            if count >= threshold_per_node {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }
    }

    pub async fn wait_for_presignatures(&self, threshold_per_node: usize) {
        loop {
            let count = self.presignature_storage.len_by_owner(self.me).await;
            if count >= threshold_per_node {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }
    }

    pub fn start_web_interface(&mut self, account_id: AccountId) {
        let task = mpc_node::web::run(
            8200 + u32::from(self.me) as u16,
            self.msg_channel.clone(),
            self.state.clone(),
            self.triple_storage.clone(),
            self.presignature_storage.clone(),
            // unused but needed to call the web interface
            SyncChannel::new().1,
            account_id,
            self.backlog.clone(),
        );
        self.web_handle = Some(tokio::spawn(task));
    }
}

impl std::ops::Index<usize> for MpcFixture {
    type Output = MpcFixtureNode;

    fn index(&self, index: usize) -> &MpcFixtureNode {
        &self.nodes[index]
    }
}

impl std::ops::IndexMut<usize> for MpcFixture {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.nodes[index]
    }
}
