use std::time::Duration;

use crate::protocol::contract::primitives::Participants;
use crate::protocol::ProtocolState;
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod connection;

#[derive(Debug, Clone, clap::Parser)]
#[group(id = "mesh_options")]
pub struct Options {
    #[clap(
        long,
        env("MPC_MESH_FETCH_PARTICIPANT_TIMEOUT"),
        default_value = "1000"
    )]
    pub fetch_participant_timeout: u64,
    #[clap(long, env("MPC_MESH_REFRESH_ACTIVE_TIMEOUT"), default_value = "1000")]
    pub refresh_active_timeout: u64,
}

impl Options {
    pub fn into_str_args(self) -> Vec<String> {
        vec![
            "--fetch-participant-timeout".to_string(),
            self.fetch_participant_timeout.to_string(),
            "--refresh-active-timeout".to_string(),
            self.refresh_active_timeout.to_string(),
        ]
    }
}

#[derive(Clone, Default)]
pub struct MeshState {
    pub active_participants: Participants,

    /// Potential participants that are active including participants belonging to the next epoch.
    pub active_potential_participants: Participants,

    pub potential_participants: Participants,

    pub stable_participants: Participants,
}

pub struct Mesh {
    /// Pool of connections to participants. Used to check who is alive in the network.
    connections: connection::Pool,
    state: Arc<RwLock<MeshState>>,
}

impl Mesh {
    pub fn init(options: Options) -> (Self, Arc<RwLock<MeshState>>) {
        let state = Arc::new(RwLock::new(MeshState::default()));
        let mesh = Self {
            connections: connection::Pool::new(
                Duration::from_millis(options.fetch_participant_timeout),
                Duration::from_millis(options.refresh_active_timeout),
            ),
            state: state.clone(),
        };
        (mesh, state)
    }

    async fn ping(&mut self) {
        let mut mesh_state = self.state.write().await;
        *mesh_state = MeshState {
            active_participants: self.connections.ping().await,
            active_potential_participants: self.connections.ping_potential().await,
            potential_participants: self.connections.potential_participants().await,
            stable_participants: self.connections.stable_participants().await,
        };
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
