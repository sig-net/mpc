use std::collections::HashMap;
use std::time::{Duration, Instant};

use cait_sith::protocol::Participant;

use crate::node_client::NodeClient;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::ProtocolState;
use crate::web::StateView;
use tokio::task::JoinSet;

// TODO: this is a basic connection pool and does not do most of the work yet. This is
//       mostly here just to facilitate offline node handling for now.
// TODO/NOTE: we can use libp2p to facilitate most the of low level TCP connection work.
pub struct Pool {
    client: NodeClient,
    connections: Participants,
    potential_connections: Participants,
    status: HashMap<Participant, StateView>,

    /// The currently active participants for this epoch.
    current_active: Option<(Participants, Instant)>,
    // Potentially active participants that we can use to establish a connection in the next epoch.
    potential_active: Option<(Participants, Instant)>,
    refresh_active_timeout: Duration,
}

impl Pool {
    pub fn new(client: &NodeClient, refresh_active_timeout: Duration) -> Self {
        tracing::info!(?refresh_active_timeout, "creating a new pool");
        Self {
            client: client.clone(),
            connections: Participants::default(),
            potential_connections: Participants::default(),
            status: HashMap::default(),
            current_active: None,
            potential_active: None,
            refresh_active_timeout,
        }
    }

    pub async fn ping(&mut self) -> Participants {
        // Check if the current active participants are still valid
        if let Some((active, timestamp)) = &self.current_active {
            if timestamp.elapsed() < self.refresh_active_timeout {
                return active.clone();
            }
        }

        // Spawn tasks for each participant
        let mut join_set = JoinSet::new();
        for (participant, info) in self.connections.clone().into_iter() {
            let client = self.client.clone();

            join_set.spawn(async move {
                match client.state(&info.url).await {
                    Ok(state) => match client.msg_empty(&info.url).await {
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

        let mut participants = Participants::default();

        // Process completed tasks
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(Ok((participant, state, info))) => {
                    participants.insert(&participant, info.clone());
                    self.status.insert(participant, state);
                }
                Ok(Err(())) => {
                    // Already logged in task
                }
                Err(e) => {
                    tracing::warn!("fetch participant state task panicked: {e}");
                }
            }
        }

        // Update the active participants
        self.current_active = Some((participants.clone(), Instant::now()));

        participants
    }

    // self typed Arc<Self> so it can be passed between tokio tasks
    pub async fn ping_potential(&mut self) -> Participants {
        if let Some((potential_active, timestamp)) = &self.potential_active {
            if timestamp.elapsed() < self.refresh_active_timeout {
                return potential_active.clone();
            }
        }

        // Spawn tasks for each participant
        let mut join_set = JoinSet::new();
        for (participant, info) in self.potential_connections.clone().into_iter() {
            let client = self.client.clone();

            join_set.spawn(async move {
                match client.state(&info.url).await {
                    Ok(state) => match client.msg_empty(&info.url).await {
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

        let mut participants = Participants::default();

        // Process completed tasks
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(Ok((participant, state, info))) => {
                    participants.insert(&participant, info);
                    self.status.insert(participant, state);
                }
                Ok(Err(())) => {
                    // Already logged in task
                }
                Err(e) => {
                    tracing::warn!("fetch participant state task panicked: {e}");
                }
            }
        }

        // Update the active participants
        self.potential_active = Some((participants.clone(), Instant::now()));

        participants
    }

    pub async fn establish_participants(&mut self, contract_state: &ProtocolState) {
        match contract_state {
            ProtocolState::Initializing(contract_state) => {
                let participants: Participants = contract_state.candidates.clone().into();
                self.set_participants(&participants);
            }
            ProtocolState::Running(contract_state) => {
                self.set_participants(&contract_state.participants);
            }
            ProtocolState::Resharing(contract_state) => {
                self.set_participants(&contract_state.old_participants);
                self.set_potential_participants(&contract_state.new_participants);
            }
        }
    }

    fn set_participants(&mut self, participants: &Participants) {
        self.connections = participants.clone();
    }

    fn set_potential_participants(&mut self, participants: &Participants) {
        tracing::debug!(
            "Pool set potential participants to {:?}",
            participants.keys_vec(),
        );
        self.potential_connections = participants.clone();
    }

    pub fn potential_participants(&self) -> Participants {
        self.potential_connections.clone()
    }

    fn is_participant_stable(&self, participant: &Participant) -> bool {
        self.status
            .get(participant)
            .is_some_and(|state| match state {
                StateView::Running { is_stable, .. } => *is_stable,
                _ => false,
            })
    }

    /// Get active participants that have a stable connection. This is useful for arbitrary metrics to
    /// say whether or not a node is stable, such as a node being on track with the latest block height.
    pub fn stable_participants(&self) -> Participants {
        let mut stable = Participants::default();
        if let Some((active, _)) = &self.current_active {
            for (participant, info) in active.iter() {
                if self.is_participant_stable(participant) {
                    stable.insert(participant, info.clone());
                }
            }
        }
        stable
    }
}
