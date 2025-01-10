use std::collections::HashMap;
use std::time::{Duration, Instant};

use cait_sith::protocol::Participant;
use tokio::sync::RwLock;

use crate::http_client::NodeClient;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::ProtocolState;
use crate::web::StateView;
use std::sync::Arc;
use tokio::task::JoinSet;

// TODO: this is a basic connection pool and does not do most of the work yet. This is
//       mostly here just to facilitate offline node handling for now.
// TODO/NOTE: we can use libp2p to facilitate most the of low level TCP connection work.
pub struct Pool {
    client: NodeClient,
    connections: RwLock<Participants>,
    potential_connections: RwLock<Participants>,
    status: RwLock<HashMap<Participant, StateView>>,

    /// The currently active participants for this epoch.
    current_active: RwLock<Option<(Participants, Instant)>>,
    // Potentially active participants that we can use to establish a connection in the next epoch.
    potential_active: RwLock<Option<(Participants, Instant)>>,
    refresh_active_timeout: Duration,
}

impl Pool {
    pub fn new(client: &NodeClient, refresh_active_timeout: Duration) -> Self {
        tracing::info!(?refresh_active_timeout, "creating a new pool");
        Self {
            client: client.clone(),
            connections: RwLock::new(Participants::default()),
            potential_connections: RwLock::new(Participants::default()),
            status: RwLock::new(HashMap::default()),
            current_active: RwLock::new(Option::default()),
            potential_active: RwLock::new(Option::default()),
            refresh_active_timeout,
        }
    }

    // self typed Arc<Self> so it can be passed between tokio tasks
    pub async fn ping(self: Arc<Self>) -> Participants {
        // Check if the current active participants are still valid
        if let Some((ref active, timestamp)) = *self.current_active.read().await {
            if timestamp.elapsed() < self.refresh_active_timeout {
                return active.clone();
            }
        }

        let connections = {
            let conn = self.connections.read().await;
            conn.clone()
        };

        // Spawn tasks for each participant
        let mut join_set = JoinSet::new();
        for (participant, info) in connections.into_iter() {
            let pool = Arc::clone(&self);

            join_set.spawn(async move {
                match pool.client.state(&info.url).await {
                    Ok(state) => match pool.client.msg_empty(&info.url).await {
                        Ok(()) => Ok((participant, state, info)),
                        Err(e) => {
                            tracing::warn!(
                                "Send empty msg for participant {participant:?} with url {} has failed with error {e}.",
                                info.url
                            );
                            Err(())
                        }
                    },
                    Err(e) => {
                        tracing::warn!(
                            "Fetch state for participant {participant:?} with url {} has failed with error {e}.",
                            info.url
                        );
                        Err(())
                    }
                }
            });
        }

        let mut status = self.status.write().await;
        let mut participants = Participants::default();

        // Process completed tasks
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(Ok((participant, state, info))) => {
                    status.insert(participant, state);
                    participants.insert(&participant, info);
                }
                Ok(Err(())) => {
                    // Already logged in task
                }
                Err(e) => {
                    tracing::warn!("fetch participant state task panicked: {e}");
                }
            }
        }

        drop(status);

        // Update the active participants
        let mut active = self.current_active.write().await;
        *active = Some((participants.clone(), Instant::now()));

        participants
    }

    // self typed Arc<Self> so it can be passed between tokio tasks
    pub async fn ping_potential(self: Arc<Self>) -> Participants {
        if let Some((ref active, timestamp)) = *self.potential_active.read().await {
            if timestamp.elapsed() < self.refresh_active_timeout {
                return active.clone();
            }
        }

        let connections = {
            let conn = self.potential_connections.read().await;
            conn.clone()
        };

        // Spawn tasks for each participant
        let mut join_set = JoinSet::new();
        for (participant, info) in connections.into_iter() {
            let pool = Arc::clone(&self); // Clone Arc for use inside tasks

            join_set.spawn(async move {
                match pool.client.state(&info.url).await {
                    Ok(state) => match pool.client.msg_empty(&info.url).await {
                        Ok(()) => Ok((participant, state, info)),
                        Err(e) => {
                            tracing::warn!(
                                "Send empty msg for participant {participant:?} with url {} has failed with error {e}.",
                                info.url
                            );
                            Err(())
                        }
                    },
                    Err(e) => {
                        tracing::warn!(
                            "Fetch state for participant {participant:?} with url {} has failed with error {e}.",
                            info.url
                        );
                        Err(())
                    }
                }
            });
        }

        let mut status = self.status.write().await;
        let mut participants = Participants::default();

        // Process completed tasks
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(Ok((participant, state, info))) => {
                    status.insert(participant, state);
                    participants.insert(&participant, info);
                }
                Ok(Err(())) => {
                    // Already logged in task
                }
                Err(e) => {
                    tracing::warn!("fetch participant state task panicked: {e}");
                }
            }
        }

        drop(status);

        // Update the active participants
        let mut potential_active = self.potential_active.write().await;
        *potential_active = Some((participants.clone(), Instant::now()));

        participants
    }

    pub async fn establish_participants(&self, contract_state: &ProtocolState) {
        match contract_state {
            ProtocolState::Initializing(contract_state) => {
                let participants: Participants = contract_state.candidates.clone().into();
                self.set_participants(&participants).await;
            }
            ProtocolState::Running(contract_state) => {
                self.set_participants(&contract_state.participants).await;
            }
            ProtocolState::Resharing(contract_state) => {
                self.set_participants(&contract_state.old_participants)
                    .await;
                self.set_potential_participants(&contract_state.new_participants)
                    .await;
            }
        }
        tracing::debug!(
            "Pool.establish_participants set participants to {:?}",
            self.connections.read().await.clone().keys_vec()
        );
    }

    async fn set_participants(&self, participants: &Participants) {
        *self.connections.write().await = participants.clone();
    }

    async fn set_potential_participants(&self, participants: &Participants) {
        *self.potential_connections.write().await = participants.clone();
        tracing::debug!(
            "Pool set potential participants to {:?}",
            self.potential_connections.read().await.keys_vec()
        );
    }

    pub async fn potential_participants(&self) -> Participants {
        self.potential_connections.read().await.clone()
    }

    async fn is_participant_stable(&self, participant: &Participant) -> bool {
        self.status
            .read()
            .await
            .get(participant)
            .map_or(false, |state| match state {
                StateView::Running { is_stable, .. } => *is_stable,
                _ => false,
            })
    }

    /// Get active participants that have a stable connection. This is useful for arbitrary metrics to
    /// say whether or not a node is stable, such as a node being on track with the latest block height.
    pub async fn stable_participants(&self) -> Participants {
        let mut stable = Participants::default();
        if let Some((active_participants, _)) = self.current_active.read().await.clone() {
            for (participant, info) in active_participants.iter() {
                if self.is_participant_stable(participant).await {
                    stable.insert(participant, info.clone());
                }
            }
        }
        stable
    }
}
