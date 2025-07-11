use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cait_sith::protocol::Participant;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::rpc::ContractStateWatcher;
use crate::storage::{PresignatureStorage, TripleStorage};

use super::contract::primitives::ParticipantInfo;
use super::presignature::PresignatureId;
use super::triple::TripleId;

/// The maximum number of update requests that can be queued. This is pretty much just
/// based on the number of participants in the network. If we have 1024 participants then
/// our issue will more than likely not be the channel size.
const MAX_SYNC_UPDATE_REQUESTS: usize = 1024;

/// The interval which we will try to sync with other nodes to see if they have lost track
/// of anything.
pub const RECURRING_SYNC_INTERVAL: Duration = Duration::from_secs(3600 * 24);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncUpdate {
    pub from: Participant,
    pub triples: HashSet<TripleId>,
    pub presignatures: HashSet<PresignatureId>,
}

impl SyncUpdate {
    pub fn empty() -> Self {
        Self {
            from: Participant::from(u32::MAX),
            triples: Default::default(),
            presignatures: Default::default(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.triples.is_empty() && self.presignatures.is_empty()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncView {
    pub triples: HashSet<TripleId>,
    pub presignatures: HashSet<PresignatureId>,
}

pub struct SyncRequestReceiver {
    updates: mpsc::Receiver<SyncInternalUpdate>,
}

pub struct SyncTask {
    client: NodeClient,
    triples: TripleStorage,
    presignatures: PresignatureStorage,
    mesh_state: watch::Receiver<MeshState>,
    contract: ContractStateWatcher,
    requests: SyncRequestReceiver,
    synced_peer_tx: mpsc::Sender<Participant>,
}

// TODO: add a watch channel for mesh active participants.
impl SyncTask {
    pub fn new(
        client: &NodeClient,
        triples: TripleStorage,
        presignatures: PresignatureStorage,
        mesh_state: watch::Receiver<MeshState>,
        contract: ContractStateWatcher,
        synced_peer_tx: mpsc::Sender<Participant>,
    ) -> (SyncChannel, Self) {
        let (requests, channel) = SyncChannel::new();
        let task = Self {
            client: client.clone(),
            triples,
            presignatures,
            mesh_state,
            contract,
            requests,
            synced_peer_tx,
        };
        (channel, task)
    }

    pub async fn run(mut self) {
        tracing::info!("task has been started");
        let mut watcher_interval = tokio::time::interval(Duration::from_millis(500));
        let mut sync_interval = tokio::time::interval(Duration::from_millis(100));
        // Broadcast should generally not be necessary.
        let mut broadcast_interval = tokio::time::interval(RECURRING_SYNC_INTERVAL);
        let mut broadcast_check_interval = tokio::time::interval(Duration::from_millis(100));

        // Do NOT start until we have our own participant info.
        // TODO: constantly watch for changes on node state after this initial one so we can start/stop sync running.
        let (_threshold, me) = loop {
            watcher_interval.tick().await;
            if let Some(info) = self.contract.info().await {
                break info;
            }
        };
        tracing::info!(?me, "mpc network ready, running...");

        let mut broadcast = Option::<(Instant, JoinHandle<_>)>::None;
        loop {
            tokio::select! {
                // find nodes that need syncing and initiate it
                _ = sync_interval.tick() => {
                    if broadcast.is_some() {
                        // another broadcast task is still ongoing, skip.
                        continue;
                    }

                    let need_sync = &self.mesh_state.borrow().need_sync.clone();
                    if need_sync.is_empty() {
                        continue;
                    }

                    let update = self.new_update(me).await;
                    let start = Instant::now();
                    let receivers = need_sync
                        .iter()
                        .map(|(p, info)|(*p, info.clone()))
                        .collect::<Vec<_>>();
                    let task = tokio::spawn(broadcast_sync(
                        self.client.clone(),
                        update,
                        self.triples.clone(),
                        self.presignatures.clone(),
                        receivers.into_iter(),
                        self.synced_peer_tx.clone(),
                        me,
                    ));
                    broadcast = Some((start, task));
                }
                // do a new broadcast if there is no ongoing broadcast.
                _ = broadcast_interval.tick() => {
                    if broadcast.is_some() {
                        // task is still ongoing, skip.
                        continue;
                    }

                    let update = self.new_update(me).await;
                    let active = self.mesh_state.borrow().active.clone();

                    let start = Instant::now();
                    let task = tokio::spawn(broadcast_sync(
                        self.client.clone(),
                        update,
                        self.triples.clone(),
                        self.presignatures.clone(),
                        active.into_iter(),
                        self.synced_peer_tx.clone(),
                        me
                    ));
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
                        tracing::debug!(elapsed = ?start.elapsed(), "processed broadcast");
                    }
                }
                Some(req) = self.requests.updates.recv() => {
                    tokio::spawn(req.process(self.triples.clone(), self.presignatures.clone()));
                }
            }
        }
    }

    async fn new_update(&self, me: Participant) -> SyncUpdate {
        SyncUpdate {
            from: me,
            triples: self.triples.fetch_owned(me).await,
            presignatures: self.presignatures.fetch_owned(me).await,
        }
    }

    /// Channel for communicating back from the sync task which nodes are now updated.
    pub fn synced_nodes_channel() -> (mpsc::Sender<Participant>, mpsc::Receiver<Participant>) {
        mpsc::channel(MAX_SYNC_UPDATE_REQUESTS)
    }
}

/// Broadcast an update to all participants specified by `receivers`.
async fn broadcast_sync(
    client: NodeClient,
    update: SyncUpdate,
    triples: TripleStorage,
    presignatures: PresignatureStorage,
    receivers: impl Iterator<Item = (Participant, ParticipantInfo)>,
    synced_peer_tx: mpsc::Sender<Participant>,
    me: Participant,
) -> SyncUpdate {
    if update.is_empty() {
        return update;
    }

    let start = Instant::now();
    let mut tasks = JoinSet::new();
    let arc_update = Arc::new(update.clone());
    for (p, info) in receivers {
        let client = client.clone();
        let update = arc_update.clone();
        let url = info.url;
        let synced_peer_tx_clone = synced_peer_tx.clone();
        tasks.spawn(async move {
            // Only actually do the sync on other peers, not on self. (Hack) We
            // still want to send the message to synced_peer_tx though, since
            // the mesh does not currently understand which node is self, so it
            // will trigger a sync to self.
            let sync_view = if p != me {
                let res = client.sync(&url, &update).await;
                if let Err(err) = &res {
                    tracing::warn!(?err, "failed to sync with peer {p:?}");
                }
                Some(res)
            } else {
                None
            };
            let result = synced_peer_tx_clone.send(p).await;
            if result.is_err() {
                tracing::error!(
                    "synced_peer_tx failed, receiver is down. State sync will no longer work."
                )
            }

            (p, sync_view)
        });
    }

    let resps = tasks
        .join_all()
        .await
        .into_iter()
        .filter_map(|(p, view)| {
            if let Some(Ok(view)) = view {
                Some((p, view))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    tracing::debug!(
        elapsed = ?start.elapsed(),
        responded = ?resps.iter().map(|(p, _)| *p).collect::<Vec<_>>(),
        "broadcast completed",
    );

    let mut triple_kick = HashMap::new();
    for &id in &update.triples {
        let entry: &mut Vec<_> = triple_kick.entry(id).or_default();
        for (p, view) in &resps {
            if !view.triples.contains(&id) {
                entry.push(*p);
            }
        }
    }
    triples.kick_participants(triple_kick).await;

    let mut presignature_kick = HashMap::new();
    for &id in &update.presignatures {
        let entry: &mut Vec<_> = presignature_kick.entry(id).or_default();
        for (p, view) in &resps {
            if !view.presignatures.contains(&id) {
                entry.push(*p);
            }
        }
    }
    presignatures.kick_participants(presignature_kick).await;

    update
}

pub struct SyncInternalUpdate {
    update: SyncUpdate,
    resp: oneshot::Sender<SyncView>,
}

impl SyncInternalUpdate {
    async fn process(self, triples: TripleStorage, presignatures: PresignatureStorage) {
        let SyncInternalUpdate { update, resp } = self;
        let start = Instant::now();
        let outdated_triples: HashSet<TripleId> =
            triples.remove_outdated(update.from, &update.triples).await;
        let outdated_presignatures: HashSet<PresignatureId> = presignatures
            .remove_outdated(update.from, &update.presignatures)
            .await;

        if !outdated_triples.is_empty() || !outdated_presignatures.is_empty() {
            tracing::info!(
                outdated_triples = outdated_triples.len(),
                outdated_presignatures = outdated_presignatures.len(),
                elapsed = ?start.elapsed(),
                "removed outdated",
            );
        }

        if resp
            .send(SyncView {
                triples: triples.fetch_owned(update.from).await,
                presignatures: presignatures.fetch_owned(update.from).await,
            })
            .is_err()
        {
            tracing::warn!("failed to send sync view due channel closure");
        }
    }
}

#[derive(Clone)]
pub struct SyncChannel {
    request_update: mpsc::Sender<SyncInternalUpdate>,
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

    pub async fn request_update(&self, update: SyncUpdate) -> Option<SyncView> {
        let (tx, rx) = oneshot::channel();
        let update = SyncInternalUpdate { update, resp: tx };

        if let Err(err) = self.request_update.send(update).await {
            tracing::warn!(?err, "failed to request update");
        }

        rx.await
            .inspect_err(|_err| {
                tracing::warn!("failed to receive sync view due to channel closure");
            })
            .ok()
    }
}
