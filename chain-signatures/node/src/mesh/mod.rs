use std::time::{Duration, Instant};

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

#[derive(Clone)]
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
}

impl Mesh {
    pub fn init(options: Options) -> Self {
        Self {
            connections: connection::Pool::new(
                Duration::from_millis(options.fetch_participant_timeout),
                Duration::from_millis(options.refresh_active_timeout),
            ),
        }
    }

    pub async fn run(
        &self,
        contract_state: Arc<RwLock<Option<ProtocolState>>>,
        mesh_state: Arc<RwLock<MeshState>>,
    ) -> anyhow::Result<()> {
        let mut last_pinged = Instant::now();
        loop {
            if last_pinged.elapsed() > Duration::from_millis(300) {
                if let Some(state) = contract_state.read().await.clone() {
                    self.connections.establish_participants(&state).await;
                    let mut mesh_state = mesh_state.write().await;
                    *mesh_state = MeshState {
                        active_participants: self.connections.ping().await,
                        active_potential_participants: self.connections.ping_potential().await,
                        potential_participants: self.connections.potential_participants().await,
                        stable_participants: self.connections.stable_participants().await,
                    };
                    last_pinged = Instant::now();
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
