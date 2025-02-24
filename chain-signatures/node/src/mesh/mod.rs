use std::time::Duration;

use crate::node_client::NodeClient;
use crate::protocol::ProtocolState;
use crate::protocol::contract::primitives::Participants;
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod connection;

#[derive(Debug, Clone, clap::Parser)]
#[group(id = "mesh_options")]
pub struct Options {
    #[clap(long, env("MPC_MESH_REFRESH_ACTIVE_TIMEOUT"), default_value = "1000")]
    pub refresh_active_timeout: u64,
}

impl Options {
    pub fn into_str_args(self) -> Vec<String> {
        vec![
            "--refresh-active-timeout".to_string(),
            self.refresh_active_timeout.to_string(),
        ]
    }
}

#[derive(Clone, Default)]
pub struct MeshState {
    /// Participants that are active in the network; as in they respond when pinged.
    pub active: Participants,

    /// Potential participants that are active including participants belonging to the next epoch.
    pub active_potential: Participants,

    /// Full list of potential participants that have yet to join the network.
    pub potential: Participants,

    /// Participants that are stable in the network; as in they have met certain criterias such
    /// as indexing the latest blocks.
    pub stable: Participants,
}

impl MeshState {
    pub fn active_with_potential(&self) -> Participants {
        self.active.and(&self.active_potential)
    }
}

pub struct Mesh {
    /// Pool of connections to participants. Used to check who is alive in the network.
    connections: Arc<connection::Pool>,
    state: Arc<RwLock<MeshState>>,
}

impl Mesh {
    pub fn init(client: &NodeClient, options: Options) -> (Self, Arc<RwLock<MeshState>>) {
        let state = Arc::new(RwLock::new(MeshState::default()));
        let mesh = Self {
            connections: Arc::new(connection::Pool::new(
                client,
                Duration::from_millis(options.refresh_active_timeout),
            )),
            state: state.clone(),
        };
        (mesh, state)
    }

    async fn ping(&mut self) {
        let state = MeshState {
            active: Arc::clone(&self.connections).ping().await,
            active_potential: Arc::clone(&self.connections).ping_potential().await,
            potential: self.connections.potential_participants().await,
            stable: self.connections.stable_participants().await,
        };

        *self.state.write().await = state;
    }

    pub async fn run(
        mut self,
        contract_state: Arc<RwLock<Option<ProtocolState>>>,
    ) -> anyhow::Result<()> {
        loop {
            {
                let state = contract_state.read().await;
                if let Some(state) = &*state {
                    self.connections.establish_participants(state).await;
                    self.ping().await;
                }
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }
}
