use std::sync::Arc;
use std::time::{Duration, Instant};

use cait_sith::protocol::Participant;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};
use tokio::task::{JoinHandle, JoinSet};

use crate::mesh::connection::{ConnectionWatcher, NodeStatusUpdate};
use crate::mesh::{Mesh, MeshState};
use crate::node_client::NodeClient;
use crate::rpc::NodeStateWatcher;
use crate::storage::{PresignatureStorage, TripleStorage};

use super::contract::primitives::Participants;
use super::presignature::PresignatureId;
use super::triple::TripleId;

/// The interval at which we will broadcast our state to the network
const EVENTUAL_SYNC_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// The maximum number of update requests that can be queued. This is pretty much just
/// based on the number of participants in the network. If we have 1024 participants then
/// our issue will more than likely not be the channel size.
const MAX_SYNC_UPDATE_REQUESTS: usize = 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncUpdate {
    from: Participant,
    triples: Vec<TripleId>,
    presignatures: Vec<PresignatureId>,
}

impl SyncUpdate {
    pub fn empty() -> Self {
        Self {
            from: Participant::from(u32::MAX),
            triples: Vec::new(),
            presignatures: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.triples.is_empty() && self.presignatures.is_empty()
    }
}

pub struct SyncRequestReceiver {
    updates: mpsc::Receiver<SyncUpdate>,
}

pub struct SyncTask {
    client: NodeClient,
    triples: TripleStorage,
    presignatures: PresignatureStorage,
    mesh_state: Arc<RwLock<MeshState>>,
    conn_watcher: ConnectionWatcher,
    watcher: NodeStateWatcher,
    requests: SyncRequestReceiver,
}

// TODO: add a watch channel for mesh active participants.
impl SyncTask {
    pub fn new(
        client: &NodeClient,
        triples: TripleStorage,
        presignatures: PresignatureStorage,
        mesh: &Mesh,
        watcher: NodeStateWatcher,
    ) -> (SyncChannel, Self) {
        let (requests, channel) = SyncChannel::new();
        let task = Self {
            client: client.clone(),
            triples,
            presignatures,
            conn_watcher: mesh.watcher(),
            mesh_state: mesh.state().clone(),
            watcher,
            requests,
        };
        (channel, task)
    }

    pub async fn run(mut self) {
        tracing::info!("task has been started");
        let mut watcher_interval = tokio::time::interval(Duration::from_millis(500));
        let mut broadcast_interval = tokio::time::interval(EVENTUAL_SYNC_INTERVAL);
        let mut broadcast_check_interval = tokio::time::interval(Duration::from_millis(100));

        // skip the first immediate broadcast.
        broadcast_interval.tick().await;

        // Do NOT start until we have our own participant info.
        // TODO: constantly watch for changes on node state after this initial one so we can start/stop sync running.
        let me = loop {
            watcher_interval.tick().await;
            if let Some(info) = self.watcher.me().await {
                break info;
            }
        };
        tracing::info!(?me, "mpc network ready, running...");

        let mut broadcast = Option::<(Instant, JoinHandle<_>)>::None;
        loop {
            tokio::select! {
                // do a new broadcast if there is no ongoing broadcast.
                (p, status) = self.conn_watcher.next() => {
                    if p == me {
                        // do not sync with ourselves.
                        continue;
                    }
                    if let NodeStatusUpdate::Active(info) = status {
                        tracing::info!(?p, "node has become active, sending sync request");
                        let update = self.new_update(me).await;
                        tokio::spawn(send_sync(self.client.clone(), info.url, update));
                    }
                }
                _ = broadcast_interval.tick() => {
                    if broadcast.is_some() {
                        // task is still ongoing, skip.
                        continue;
                    }

                    let update = self.new_update(me).await;
                    let active = {
                        let state = self.mesh_state.read().await;
                        let mut active = state.active.clone();
                        // do not broadcast to me
                        active.remove(&me);
                        active
                    };

                    let start = Instant::now();
                    let task = tokio::spawn(broadcast_sync(self.client.clone(), update, active));
                    broadcast = Some((start, task));
                }
                // check that our broadcast has completed, and if so process the result.
                _ = broadcast_check_interval.tick() => {
                    let Some((start, handle)) = broadcast.take() else {
                        continue;
                    };
                    if !handle.is_finished() {
                        // task is not finished yet, put it back:
                        broadcast = Some((start, handle));
                        continue;
                    }

                    if let Err(err) = handle.await {
                        tracing::warn!(?err, "broadcast task failed");
                    } else {
                        tracing::info!(elapsed = ?start.elapsed(), "processed broadcast");
                    }
                }
                Some(req) = self.requests.updates.recv() => {
                    tokio::spawn(req.process(self.triples.clone(), self.presignatures.clone()));
                }
            }
        }
    }

    // TODO: use reserved values instead. Note that we cannot fetch our own triples via reserved
    async fn new_update(&self, me: Participant) -> SyncUpdate {
        let triples = self.triples.fetch_owned(me).await;
        let presignatures = self.presignatures.fetch_owned(me).await;

        SyncUpdate {
            from: me,
            triples,
            presignatures,
        }
    }
}

async fn send_sync(client: NodeClient, url: String, update: SyncUpdate) {
    if update.is_empty() {
        return;
    }

    let start = Instant::now();

    // try up to 100 times to send the sync update. If the node is not reachable within
    // the retry amount, odds are that it will never reply back to us.
    for _ in 0..100 {
        let Err(err) = client.sync(&url, &update).await else {
            tracing::info!(
                elapsed = ?start.elapsed(),
                "sync completed",
            );
            break;
        };
        tracing::warn!(?err, "failed to send sync update");
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// Broadcast an update to all participants specified by `active`.
async fn broadcast_sync(client: NodeClient, update: SyncUpdate, active: Participants) {
    if update.is_empty() {
        return;
    }

    let start = Instant::now();
    let mut tasks = JoinSet::new();
    let update = Arc::new(update);
    for (&p, info) in active.iter() {
        let client = client.clone();
        let update = update.clone();
        let url = info.url.clone();
        tasks.spawn(async move {
            let sync_view = client.sync(&url, &update).await;
            (p, sync_view)
        });
    }

    let resps = tasks
        .join_all()
        .await
        .into_iter()
        .filter_map(|(p, view)| if let Ok(()) = view { Some(p) } else { None })
        .collect::<Vec<_>>();

    tracing::info!(
        elapsed = ?start.elapsed(),
        responded = ?resps,
        "broadcast completed",
    );
}

impl SyncUpdate {
    async fn process(self, triples: TripleStorage, presignatures: PresignatureStorage) {
        let start = Instant::now();

        let outdated_triples = triples.remove_outdated(self.from, &self.triples).await;
        let outdated_presignatures = presignatures
            .remove_outdated(self.from, &self.presignatures)
            .await;

        if !outdated_triples.is_empty() || !outdated_presignatures.is_empty() {
            tracing::info!(
                outdated_triples = outdated_triples.len(),
                outdated_presignatures = outdated_presignatures.len(),
                elapsed = ?start.elapsed(),
                "removed outdated",
            );
        }
    }
}

#[derive(Clone)]
pub struct SyncChannel {
    request_update: mpsc::Sender<SyncUpdate>,
}

impl SyncChannel {
    pub fn new() -> (SyncRequestReceiver, Self) {
        let (request_update_tx, request_update_rx) = mpsc::channel(MAX_SYNC_UPDATE_REQUESTS);

        let requests = SyncRequestReceiver {
            updates: request_update_rx,
        };
        let channel = Self {
            request_update: request_update_tx,
        };

        (requests, channel)
    }

    pub async fn request_update(&self, update: SyncUpdate) {
        if let Err(err) = self.request_update.send(update).await {
            tracing::warn!(?err, "failed to request update");
        }
    }
}
