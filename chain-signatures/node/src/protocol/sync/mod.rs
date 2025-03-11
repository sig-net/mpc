use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cait_sith::protocol::Participant;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::task::JoinSet;

use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::storage::{PresignatureStorage, TripleStorage};

use super::contract::primitives::{intersect, intersect_vec};
use super::presignature::{Presignature, PresignatureId};
use super::triple::{Triple, TripleId};

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncUpdate {
    // from: Participant,
    triples: Vec<TripleId>,
    presignatures: Vec<PresignatureId>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncView {
    triples: HashSet<TripleId>,
    presignatures: HashSet<PresignatureId>,
}

#[derive(Default)]
struct SyncCache {
    triples: HashMap<TripleId, HashSet<Participant>>,
    presignatures: HashMap<PresignatureId, HashSet<Participant>>,
}

struct SyncTask {
    // me: Participant,
    client: NodeClient,
    triples: TripleStorage,
    presignatures: PresignatureStorage,
    mesh_state: Arc<RwLock<MeshState>>,

    updates: SyncChannelReceiver,
}

// TODO: add a watch channel for mesh active participants.
impl SyncTask {
    pub fn new(
        // me: Participant,
        client: &NodeClient,
        triples: TripleStorage,
        presignatures: PresignatureStorage,
        mesh_state: Arc<RwLock<MeshState>>,
    ) -> (SyncChannel, Self) {
        let (updates_rx, updater) = SyncChannel::new();
        let task = Self {
            // me,
            client: client.clone(),
            triples,
            presignatures,
            mesh_state,
            updates: updates_rx,
        };

        (updater, task)
    }

    async fn process_sync(&self, update: SyncUpdate) -> anyhow::Result<SyncView> {
        // TODO: check that `from` actually owns the triples/presignatures.
        // TODO: log the errors from storage.
        // TODO: make each process_sync a separate task
        let triple_ids = self.triples.fetch_ids().await.unwrap_or_default();
        let presignature_ids = self.presignatures.fetch_ids().await.unwrap_or_default();

        // TODO: maybe instead of Vec<T> we should have HashSet<T> for more efficient intersections.
        // TODO: remove the triples/presignatures in this task or another one.
        Ok(SyncView {
            triples: intersect(&[&update.triples, &triple_ids]),
            presignatures: intersect(&[&update.presignatures, &presignature_ids]),
        })
    }

    pub async fn run(mut self) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        let mut mesh_seen_triples = HashMap::new();
        let mut mesh_seen_presignatures = HashMap::new();

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let update = self.new_update().await;
                    let views = self.broadcast_sync(update).await;

                    mesh_seen_triples.clear();
                    mesh_seen_presignatures.clear();
                    for (p, view) in views {
                        for triple in view.triples {
                            let entry = mesh_seen_triples.entry(triple).or_insert_with(HashSet::new);
                            entry.insert(p);
                        }

                        for presignature in view.presignatures {
                            let entry = mesh_seen_presignatures.entry(presignature).or_insert_with(HashSet::new);
                            entry.insert(p);
                        }
                    }
                }
                // TODO: make process updates a separate task.
                Some(req) = self.updates.update_rx.recv() => {
                    let view = self.process_sync(req.update).await.unwrap();
                    req.view_tx.send(view).unwrap();
                }
                // TODO: need to make intersection more robust otherwise we end up trying to find non-existent triples/presignatures.
                Some(req) = self.updates.request_triple_rx.recv() => {
                    match req {
                        ProtocolRequest::Take { threshold, resp } => {
                            let triple = self.take_two_triple(threshold).await;
                            resp.send(triple).unwrap();
                        }
                    }
                }
                Some(req) = self.updates.request_presignature_rx.recv() => {
                    match req {
                        ProtocolRequest::Take { threshold, resp } => {
                            let presignature = self.take_presignature(threshold).await;
                            resp.send(presignature).unwrap();
                        }
                    }
                }
            }
        }
    }

    async fn new_update(&self) -> SyncUpdate {
        SyncUpdate {
            // from: self.me,
            triples: self.triples.fetch_mine().await.unwrap(),
            presignatures: self.presignatures.fetch_mine().await.unwrap(),
        }
    }

    async fn take_two_triple(&self, threshold: usize) -> Option<(Triple, Triple)> {
        let active = self.mesh_state.read().await.active.keys_vec();

        // To ensure there is no contention between different nodes we are only using triples
        // that we proposed. This way in a non-BFT environment we are guaranteed to never try
        // to use the same triple as any other node.
        let (triple0, triple1) = match self.triples.take_two_mine().await {
            Ok(Some(triples)) => triples,
            Ok(None) => return None,
            Err(err) => {
                tracing::error!(?err, "failed to take two triples");
                return None;
            }
        };

        // TODO: make triple_storage.take intake active to do intersection in Lua script side.
        let participants = intersect_vec(&[
            &active,
            &triple0.public.participants,
            &triple1.public.participants,
        ]);
        if participants.len() < threshold {
            tracing::warn!(
                ?participants,
                "running: the intersection of participants is less than the threshold"
            );
            return None;
        }

        Some((triple0, triple1))
    }

    async fn take_presignature(&self, threshold: usize) -> Option<Presignature> {
        let active = self.mesh_state.read().await.active.keys_vec();

        let presignature = match self.presignatures.take_mine().await {
            Ok(Some(presignature)) => presignature,
            Ok(None) => return None,
            Err(err) => {
                tracing::error!(?err, "failed to take presignature");
                return None;
            }
        };

        let participants = intersect_vec(&[&active, &presignature.participants]);
        if participants.len() < threshold {
            tracing::warn!(
                ?participants,
                "running: the intersection of participants is less than the threshold"
            );
            return None;
        }

        Some(presignature)
    }

    async fn broadcast_sync(&self, update: SyncUpdate) -> Vec<(Participant, SyncView)> {
        let active = {
            let state = self.mesh_state.read().await;
            state.active.clone()
        };

        let mut tasks = JoinSet::new();
        let update = Arc::new(update);
        // let mut views = Vec::new();
        for (&p, info) in active.iter() {
            let client = self.client.clone();
            let update = update.clone();
            let url = info.url.clone();
            tasks.spawn(async move {
                let sync_view = client.sync(&url, &update).await;
                (p, sync_view)
            });
        }

        tasks
            .join_all()
            .await
            .into_iter()
            .filter_map(|(p, view)| {
                if let Ok(view) = view {
                    Some((p, view))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
    }
}

struct InternalSyncUpdate {
    update: SyncUpdate,
    view_tx: oneshot::Sender<SyncView>,
}

struct SyncChannel {
    update_tx: mpsc::Sender<InternalSyncUpdate>,
    request_triple: TripleSyncChannel,
    request_presignature: PresignatureSyncChannel,
}

impl SyncChannel {
    pub fn new() -> (SyncChannelReceiver, Self) {
        let (update_tx, update_rx) = mpsc::channel(100);
        let (request_triple_rx, request_triple) = TripleSyncChannel::new();
        let (request_presignature_rx, request_presignature) = PresignatureSyncChannel::new();

        let receiver = SyncChannelReceiver {
            update_rx,
            request_triple_rx,
            request_presignature_rx,
        };
        let sender = Self {
            update_tx,
            request_triple,
            request_presignature,
        };

        (receiver, sender)
    }

    pub async fn send(&mut self, update: SyncUpdate) -> SyncView {
        let (view_tx, view_rx) = oneshot::channel();
        self.update_tx
            .send(InternalSyncUpdate { update, view_tx })
            .await
            .unwrap();
        view_rx.await.unwrap()
    }

    pub async fn take_two_triple(&mut self, threshold: usize) -> Option<(Triple, Triple)> {
        self.request_triple.take(threshold).await
    }

    pub async fn take_presignature(&mut self, threshold: usize) -> Option<Presignature> {
        self.request_presignature.take(threshold).await
    }
}

struct SyncChannelReceiver {
    update_rx: mpsc::Receiver<InternalSyncUpdate>,
    request_triple_rx: mpsc::Receiver<ProtocolRequest<(Triple, Triple)>>,
    request_presignature_rx: mpsc::Receiver<ProtocolRequest<Presignature>>,
}

enum ProtocolRequest<T> {
    Take {
        threshold: usize,
        resp: oneshot::Sender<Option<T>>,
    },
}

struct ProtocolChannel<T> {
    request_tx: mpsc::Sender<ProtocolRequest<T>>,
}

impl<T> ProtocolChannel<T> {
    pub fn new() -> (mpsc::Receiver<ProtocolRequest<T>>, Self) {
        let (request_tx, request_rx) = mpsc::channel(10000);
        let protocol_channel = Self { request_tx };

        (request_rx, protocol_channel)
    }

    pub async fn take(&mut self, threshold: usize) -> Option<T> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.request_tx
            .send(ProtocolRequest::Take {
                threshold,
                resp: resp_tx,
            })
            .await
            .unwrap();

        resp_rx.await.unwrap()
    }
}

type TripleSyncChannel = ProtocolChannel<(Triple, Triple)>;
type PresignatureSyncChannel = ProtocolChannel<Presignature>;

// struct TripleSyncChannel {
//     triple_pair_requester: mpsc::Sender<()>,
//     triple_receiver: mpsc::Receiver<(Triple, Triple)>,
// }

// new triples/presignatures: need to recv updates from either storage or channel.
// web: /view -> timeout(sync.recv()):
//   need to read from storage for triples/presignatures

// 1. |url| sync/view
//   since we don't store who owns what, and just mine: bool,
//
//   a. Load everything:
//      owned, non-owned.
//   b. Load only owend.
//      read else from redis

#[cfg(test)]
mod tests {
    fn test_protocol_sync() {}
}
