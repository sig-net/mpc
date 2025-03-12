use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cait_sith::protocol::Participant;
use rand::seq::IteratorRandom;
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

struct SyncReceiver {
    update_rx: mpsc::Receiver<SyncUpdateRequest>,
    request_triple_rx: mpsc::Receiver<ProtocolRequest<(Triple, Triple)>>,
    request_presignature_rx: mpsc::Receiver<ProtocolRequest<Presignature>>,
}

pub struct SyncTask {
    // me: Participant,
    client: NodeClient,
    triples: TripleStorage,
    presignatures: PresignatureStorage,
    mesh_state: Arc<RwLock<MeshState>>,
    sync: SyncReceiver,
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
        let (sync_rx, syncer) = SyncChannel::new();
        let task = Self {
            // me,
            client: client.clone(),
            triples,
            presignatures,
            mesh_state,
            sync: sync_rx,
        };
        (syncer, task)
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
                            let entry = mesh_seen_triples.entry(triple).or_insert_with(Vec::new);
                            // entry.insert(p);
                            entry.push(p);
                        }

                        for presignature in view.presignatures {
                            let entry = mesh_seen_presignatures.entry(presignature).or_insert_with(Vec::new);
                            // entry.insert(p);
                            entry.push(p);
                        }
                    }

                    // TODO: pull threshold from contract updates:
                    // mesh_seen_triples.retain(|_, v| v.len() >= threshold);
                    // mesh_seen_presignatures.retain(|_, v| v.len() >= threshold);

                }
                // TODO: make process updates a separate task.
                Some(req) = self.sync.update_rx.recv() => {
                    let view = self.process_sync(req.update).await.unwrap();
                    req.view_tx.send(view).unwrap();
                }
                // TODO: need to make intersection more robust otherwise we end up trying to find non-existent triples/presignatures.
                Some(req) = self.sync.request_triple_rx.recv() => {
                    match req {
                        ProtocolRequest::Take { threshold, resp } => {
                            let triple = self.take_two_triple(threshold, &mut mesh_seen_triples).await;
                            resp.send(triple).unwrap();
                        }
                    }
                }
                Some(req) = self.sync.request_presignature_rx.recv() => {
                    match req {
                        ProtocolRequest::Take { threshold, resp } => {
                            let presignature = self.take_presignature(threshold, &mut mesh_seen_presignatures).await;
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

    async fn take_two_triple(
        &self,
        threshold: usize,
        mesh_seen: &mut HashMap<TripleId, Vec<Participant>>,
    ) -> Option<ProtocolResponse<(Triple, Triple)>> {
        if mesh_seen.len() < 2 {
            return None;
        }

        let active = self.mesh_state.read().await.active.keys_vec();

        // To ensure there is no contention between different nodes we are only using triples
        // that we proposed. This way in a non-BFT environment we are guaranteed to never try
        // to use the same triple as any other node.

        let rng = &mut rand::thread_rng();
        let mut failed = Vec::new();
        // Try to find a suitable triple pair:
        let found = loop {
            if mesh_seen.len() < 2 {
                break None;
            }

            let two = mesh_seen.keys().choose_multiple(rng, 2);
            let (&t0_id, &t1_id) = match two.as_slice() {
                &[triple0, triple1] => (triple0, triple1),
                _ => {
                    tracing::warn!("unexpected, failed to take two triples");
                    break None;
                }
            };

            let Some((t0_id, t0_participants)) = mesh_seen.remove_entry(&t0_id) else {
                tracing::warn!(t0_id, "unexpected, failed to take a seen triple");
                break None;
            };
            let Some((t1_id, t1_participants)) = mesh_seen.remove_entry(&t1_id) else {
                tracing::warn!(t1_id, "unexpected, failed to take a seen triple");
                break None;
            };

            // TODO: threshold - 1 should be invalid once me is present
            let participants = intersect_vec(&[&active, &t0_participants, &t1_participants]);
            if participants.len() < threshold - 1 {
                tracing::warn!(
                    target: "sync[triple.take]",
                    triple0 = ?(t0_id, &t0_participants),
                    triple1 = ?(t1_id, &t1_participants),
                    ?participants,
                    "intersection < threshold"
                );
                failed.push((t0_id, t0_participants));
                failed.push((t1_id, t1_participants));
                continue;
            }

            break Some((participants, t0_id, t1_id));
        };

        for (id, triple) in failed {
            mesh_seen.insert(id, triple);
        }
        let Some((mut participants, triple0, triple1)) = found else {
            return None;
        };
        // TODO: make triple_storage.take intake active to do intersection in Lua script side.
        let (triple0, triple1) = self.triples.take_two_self(triple0, triple1).await.unwrap();

        participants.sort();
        Some(ProtocolResponse {
            participants,
            value: (triple0, triple1),
        })
    }

    async fn take_presignature(
        &self,
        threshold: usize,
        mesh_seen: &mut HashMap<PresignatureId, Vec<Participant>>,
    ) -> Option<ProtocolResponse<Presignature>> {
        if mesh_seen.is_empty() {
            return None;
        }
        let active = self.mesh_state.read().await.active.keys_vec();

        let mut failed = Vec::new();
        let rng = &mut rand::thread_rng();
        let found = loop {
            if mesh_seen.is_empty() {
                break None;
            }
            let Some(&presignature_id) = mesh_seen.keys().choose(rng) else {
                tracing::warn!("unexpected, failed to take a presignature");
                break None;
            };

            let Some((presignature_id, presign_participants)) =
                mesh_seen.remove_entry(&presignature_id)
            else {
                break None;
            };

            // TODO: threshold - 1 should be invalid once me is present
            let participants = intersect_vec(&[&active, &presign_participants]);
            if participants.len() < threshold - 1 {
                tracing::warn!(
                    target: "sync[presign.take]",
                    presignature = ?(presignature_id, &presign_participants),
                    ?participants,
                    "intersection < threshold"
                );
                failed.push((presignature_id, presign_participants));
                continue;
            }

            break Some((participants, presignature_id));
        };

        for (id, triple) in failed {
            mesh_seen.insert(id, triple);
        }
        let Some((mut participants, presignature_id)) = found else {
            return None;
        };
        let presignature = self.presignatures.take_self(presignature_id).await.unwrap();

        participants.sort();
        Some(ProtocolResponse {
            participants,
            value: presignature,
        })
    }

    async fn broadcast_sync(&self, update: SyncUpdate) -> Vec<(Participant, SyncView)> {
        let active = {
            let state = self.mesh_state.read().await;
            state.active.clone()
        };

        let mut tasks = JoinSet::new();
        let update = Arc::new(update);
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

struct SyncUpdateRequest {
    update: SyncUpdate,
    view_tx: oneshot::Sender<SyncView>,
}

pub struct SyncChannel {
    update_tx: mpsc::Sender<SyncUpdateRequest>,
    request_triple: TripleChannel,
    request_presignature: PresignatureChannel,
}

impl SyncChannel {
    fn new() -> (SyncReceiver, Self) {
        let (update_tx, update_rx) = mpsc::channel(100);
        let (request_triple_rx, request_triple) = TripleChannel::new();
        let (request_presignature_rx, request_presignature) = PresignatureChannel::new();

        let receiver = SyncReceiver {
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

    pub async fn request_update(&mut self, update: SyncUpdate) -> SyncView {
        let (view_tx, view_rx) = oneshot::channel();
        self.update_tx
            .send(SyncUpdateRequest { update, view_tx })
            .await
            .unwrap();
        view_rx.await.unwrap()
    }

    pub async fn take_two_triple(
        &mut self,
        threshold: usize,
    ) -> Option<ProtocolResponse<(Triple, Triple)>> {
        self.request_triple.take(threshold).await
    }

    pub async fn take_presignature(
        &mut self,
        threshold: usize,
    ) -> Option<ProtocolResponse<Presignature>> {
        self.request_presignature.take(threshold).await
    }
}

enum ProtocolRequest<T> {
    Take {
        threshold: usize,
        resp: oneshot::Sender<Option<ProtocolResponse<T>>>,
    },
}

#[derive(Debug)]
pub struct ProtocolResponse<T> {
    pub participants: Vec<Participant>,
    pub value: T,
}

type TripleChannel = ProtocolChannel<(Triple, Triple)>;
type PresignatureChannel = ProtocolChannel<Presignature>;

struct ProtocolChannel<T> {
    request_tx: mpsc::Sender<ProtocolRequest<T>>,
}

impl<T> ProtocolChannel<T> {
    fn new() -> (mpsc::Receiver<ProtocolRequest<T>>, Self) {
        let (request_tx, request_rx) = mpsc::channel(10000);
        let protocol_channel = Self { request_tx };

        (request_rx, protocol_channel)
    }

    async fn take(&mut self, threshold: usize) -> Option<ProtocolResponse<T>> {
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

#[cfg(test)]
mod tests {
    fn test_protocol_sync() {}
}
