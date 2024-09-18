use std::collections::{HashMap, HashSet};
// use std::time::Duration;

use cait_sith::protocol::Participant;
use tokio::sync::RwLock;
use url::Url;

use crate::protocol::contract::primitives::{ParticipantInfo, Participants};
use crate::protocol::presignature::PresignatureId;
use crate::protocol::triple::TripleId;
use crate::protocol::ProtocolState;
use crate::web::StateView;

// const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, Default)]
struct ConnectionMap {
    /// All connections in our connection pool.
    connections: HashMap<Participant, ParticipantInfo>,

    /// The participants in our connection pool that are potential participants.
    potential: HashSet<Participant>,
}

impl ConnectionMap {
    fn extend(&mut self, participants: Participants) {
        self.connections.extend(participants.into_iter());
    }

    fn extend_potential(&mut self, participants: Participants) {
        for (participant, info) in participants.into_iter() {
            self.potential.insert(participant);
            self.connections.insert(participant, info);
        }
    }
}

impl<'a> Iterator for &'a ConnectionMap {
    type Item = (&'a Participant, &'a ParticipantInfo);

    fn next(&mut self) -> Option<Self::Item> {
        self.connections.iter().next()
    }
}

// TODO: this is a basic connection pool and does not do most of the work yet. This is
//       mostly here just to facilitate offline node handling for now.
// TODO/NOTE: we can use libp2p to facilitate most the of low level TCP connection work.
#[derive(Default)]
pub struct Pool {
    http: reqwest::Client,
    // connections: RwLock<Participants>,
    // potential_connections: RwLock<Participants>,
    connections: ConnectionMap,
    // /// The currently active participants for this epoch.
    // current_active: RwLock<Option<(Participants, Instant)>>,
    // // Potentially active participants that we can use to establish a connection in the next epoch.
    // potential_active: RwLock<Option<(Participants, Instant)>>,
    pub status: RwLock<HashMap<Participant, StateView>>,
}

impl Pool {
    pub async fn ping(
        &mut self,
        previews: Option<(HashSet<TripleId>, HashSet<PresignatureId>)>,
    ) -> (Participants, Participants) {
        // if let Some((ref active, timestamp)) = *self.current_active.read().await {
        //     if timestamp.elapsed() < DEFAULT_TIMEOUT {
        //         return active.clone();
        //     }
        // }

        // let connections = self.connections.read().await;

        let mut params = HashMap::new();
        if let Some((triples, presignatures)) = previews {
            if !triples.is_empty() {
                params.insert("triple_preview", triples);
            }
            if !presignatures.is_empty() {
                params.insert("presignature_preview", presignatures);
            }
        }

        let mut status = self.status.write().await;
        // Clear the status before we overwrite it just so we don't have any stale participant
        // statuses that are no longer in the network after a reshare.
        status.clear();

        let mut active = Participants::default();
        let mut potential = Participants::default();
        for (participant, info) in &self.connections {
            let Ok(Ok(url)) = Url::parse(&info.url).map(|url| url.join("/state")) else {
                tracing::error!(
                    "Pool.ping url is invalid participant {:?} url {} /state",
                    participant,
                    info.url
                );
                continue;
            };

            let mut req = self.http.get(url.clone());
            if !params.is_empty() {
                req = req.header("content-type", "application/json").json(&params);
            }
            let resp = match req.send().await {
                Ok(resp) => resp,
                Err(err) => {
                    tracing::warn!(
                        ?err,
                        "Pool.ping resp err participant {:?} url {}",
                        participant,
                        url
                    );
                    continue;
                }
            };

            let Ok(state): Result<StateView, _> = resp.json().await else {
                tracing::warn!(
                    "Pool.ping state view err participant {:?} url {}",
                    participant,
                    url
                );
                continue;
            };

            status.insert(*participant, state);
            if self.connections.potential.contains(participant) {
                potential.insert(participant, info.clone());
            } else {
                active.insert(participant, info.clone());
            }
        }
        drop(status);

        // {
        //     let mut current_active = self.current_active.write().await;
        //     *current_active = Some((active.clone(), Instant::now()));
        // }

        // {
        //     let mut potential_active = self.potential_active.write().await;
        //     *potential_active = Some((potential.clone(), Instant::now()));
        // }

        (active, potential)
    }

    // pub async fn ping_potential(
    //     &mut self,
    //     previews: Option<(HashSet<TripleId>, HashSet<PresignatureId>)>,
    // ) -> Participants {
    //     if let Some((ref active, timestamp)) = *self.potential_active.read().await {
    //         if timestamp.elapsed() < DEFAULT_TIMEOUT {
    //             return active.clone();
    //         }
    //     }

    //     let connections = self.potential_connections.read().await;

    //     let mut params = HashMap::new();
    //     if let Some((triples, presignatures)) = previews {
    //         if !triples.is_empty() {
    //             params.insert("triple_preview", triples);
    //         }
    //         if !presignatures.is_empty() {
    //             params.insert("presignature_preview", presignatures);
    //         }
    //     }

    //     let mut status = self.status.write().await;
    //     let mut participants = Participants::default();
    //     for (participant, info) in connections.iter() {
    //         let Ok(Ok(url)) = Url::parse(&info.url).map(|url| url.join("/state")) else {
    //             continue;
    //         };

    //         let mut req = self.http.get(url.clone());
    //         if !params.is_empty() {
    //             req = req.header("content-type", "application/json").json(&params);
    //         }
    //         let resp = match req.send().await {
    //             Ok(resp) => resp,
    //             Err(err) => {
    //                 tracing::warn!(
    //                     ?err,
    //                     "Pool.ping_potential resp err participant {:?} url {}",
    //                     participant,
    //                     url
    //                 );
    //                 continue;
    //             }
    //         };

    //         let Ok(state): Result<StateView, _> = resp.json().await else {
    //             continue;
    //         };

    //         status.insert(*participant, state);
    //         participants.insert(participant, info.clone());
    //     }

    //     let mut potential_active = self.potential_active.write().await;
    //     *potential_active = Some((participants.clone(), Instant::now()));
    //     participants
    // }

    pub async fn establish_participants(&mut self, contract_state: &ProtocolState) {
        match contract_state {
            ProtocolState::Initializing(contract_state) => {
                let participants: Participants = contract_state.candidates.clone().into();
                self.connections.extend(participants);
            }
            ProtocolState::Running(contract_state) => {
                self.connections.extend(contract_state.participants.clone());
            }
            ProtocolState::Resharing(contract_state) => {
                self.connections
                    .extend(contract_state.old_participants.clone());
                self.connections
                    .extend_potential(contract_state.new_participants.clone());
            }
        }
        // tracing::debug!(
        //     "Pool.establish_participants set participants to {:?}",
        //     self.connections.read().await.clone().keys_vec()
        // );
    }

    // pub async fn potential_participants(&self) -> Participants {
    //     self.potential_connections.read().await.clone()
    // }

    pub async fn is_participant_stable(&self, participant: &Participant) -> bool {
        self.status
            .read()
            .await
            .get(participant)
            .map_or(false, |state| match state {
                StateView::Running { is_stable, .. } => *is_stable,
                StateView::Resharing { is_stable, .. } => *is_stable,
                _ => false,
            })
    }
}
