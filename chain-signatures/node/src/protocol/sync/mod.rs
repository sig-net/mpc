use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cait_sith::protocol::Participant;
use rand::rngs::StdRng;
use rand::seq::IteratorRandom;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::task::{JoinHandle, JoinSet};

use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::storage::{PresignatureStorage, TripleStorage};

use super::contract::primitives::{intersect, intersect_vec, Participants};
use super::presignature::{Presignature, PresignatureId};
use super::triple::{Triple, TripleId};

const REQUEST_UPDATE_TIMEOUT: Duration = Duration::from_millis(50);
const REQUEST_PROTOCOL_TIMEOUT: Duration = Duration::from_millis(50);

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncUpdate {
    triples: Vec<TripleId>,
    presignatures: Vec<PresignatureId>,
}

impl SyncUpdate {
    pub fn empty() -> Self {
        Self {
            triples: Vec::new(),
            presignatures: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.triples.is_empty() && self.presignatures.is_empty()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncView {
    triples: HashSet<TripleId>,
    presignatures: HashSet<PresignatureId>,
}

impl SyncView {
    fn empty() -> Self {
        Self {
            triples: HashSet::new(),
            presignatures: HashSet::new(),
        }
    }
}

#[derive(Default)]
struct SyncCache {
    other_seen_triples: HashMap<TripleId, HashSet<Participant>>,
    other_seen_presignatures: HashMap<PresignatureId, HashSet<Participant>>,
    taken_triples: HashSet<TripleId>,
    taken_presignatures: HashSet<PresignatureId>,
}

struct SyncReceiver {
    update_rx: mpsc::Receiver<SyncUpdateRequest>,
    request_triple_rx: mpsc::Receiver<ProtocolRequest<(Triple, Triple)>>,
    request_presignature_rx: mpsc::Receiver<ProtocolRequest<Presignature>>,
}

pub struct SyncTask {
    client: NodeClient,
    triples: TripleStorage,
    presignatures: PresignatureStorage,
    mesh_state: Arc<RwLock<MeshState>>,
    sync: SyncReceiver,
}

// TODO: add a watch channel for mesh active participants.
impl SyncTask {
    pub fn new(
        client: &NodeClient,
        triples: TripleStorage,
        presignatures: PresignatureStorage,
        mesh_state: Arc<RwLock<MeshState>>,
    ) -> (SyncChannel, Self) {
        let (sync_rx, syncer) = SyncChannel::new();
        let task = Self {
            client: client.clone(),
            triples,
            presignatures,
            mesh_state,
            sync: sync_rx,
        };
        (syncer, task)
    }

    async fn process_sync(&self, update: SyncUpdate) -> SyncView {
        // TODO: check that `from` actually owns the triples/presignatures.
        // TODO: log the errors from storage.
        // TODO: make each process_sync a separate task
        let triple_ids = self.triples.fetch_ids().await.unwrap_or_default();
        let presignature_ids = self.presignatures.fetch_ids().await.unwrap_or_default();

        // TODO: maybe instead of Vec<T> we should have HashSet<T> for more efficient intersections.
        // TODO: remove the triples/presignatures in this task or another one.
        SyncView {
            triples: intersect(&[&update.triples, &triple_ids]),
            presignatures: intersect(&[&update.presignatures, &presignature_ids]),
        }
    }

    pub async fn run(mut self) {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
        let mut mesh_seen_triples = HashMap::new();
        let mut mesh_seen_presignatures = HashMap::new();

        // TODO: after adding watch to contract, make this immediately broadcast.
        let mut broadcast = Option::<JoinHandle<Option<Vec<(Participant, SyncView)>>>>::None;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Some(handle) = broadcast.as_mut() {
                        if !handle.is_finished() {
                            continue;
                        }

                        tracing::info!(target: "sync", "processing broadcast");
                        let start = Instant::now();
                        let views = match handle.await {
                            Ok(Some(views)) => views,
                            Ok(None) => {
                                broadcast = None;
                                continue;
                            }
                            Err(err) => {
                                tracing::error!(?err, "broadcast join handle failed");
                                broadcast = None;
                                continue;
                            }
                        };
                        mesh_seen_triples.clear();
                        mesh_seen_presignatures.clear();
                        for (p, view) in views {
                            for triple in view.triples {
                                let entry = mesh_seen_triples.entry(triple).or_insert_with(Vec::new);
                                entry.push(p);
                            }

                            for presignature in view.presignatures {
                                let entry = mesh_seen_presignatures.entry(presignature).or_insert_with(Vec::new);
                                entry.push(p);
                            }
                        }

                        // TODO: pull threshold from contract updates:
                        // mesh_seen_triples.retain(|_, v| v.len() >= threshold);
                        // mesh_seen_presignatures.retain(|_, v| v.len() >= threshold);

                        broadcast = None;
                        tracing::info!(
                            target: "sync",
                            elapsed = ?start.elapsed(),
                            triples = mesh_seen_triples.len(),
                            presignatures = mesh_seen_presignatures.len(),
                             "processed broadcast",
                        );
                        continue;
                    }

                    let Some(update) = self.new_update().await else {
                        continue;
                    };

                    let active = {
                        let state = self.mesh_state.read().await;
                        state.active.clone()
                    };

                    tracing::info!(target: "sync", "commit broadcast");
                    broadcast = Some(tokio::spawn(broadcast_sync_update(self.client.clone(), update, active)));
                }
                // TODO: make process updates a separate task.
                Some(req) = self.sync.update_rx.recv() => {
                    let start = Instant::now();
                    let view = self.process_sync(req.update).await;
                    if let Err(err) = req.view_tx.send(view) {
                        tracing::error!(?err, "failed to send sync view");
                    }
                    tracing::info!(
                        target: "sync",
                        elapsed = ?start.elapsed(),
                        "processed update",
                    );
                }
                // TODO: need to make intersection more robust otherwise we end up trying to find non-existent triples/presignatures.
                Some(req) = self.sync.request_triple_rx.recv() => {
                    match req {
                        ProtocolRequest::Take { threshold, resp } => {
                            let triples = self.take_two_triple(threshold, &mut mesh_seen_triples).await;
                            let triple_ids = triples.as_ref().map(|p| (p.value.0.id, p.value.1.id));
                            if let Err(err) = resp.send(triples) {
                                tracing::error!(target: "sync[take]", ?triple_ids, ?err, "failed to respond with triple");
                            }
                        }
                    }
                }
                Some(req) = self.sync.request_presignature_rx.recv() => {
                    match req {
                        ProtocolRequest::Take { threshold, resp } => {
                            let presignature = self.take_presignature(threshold, &mut mesh_seen_presignatures).await;
                            let presignature_id = presignature.as_ref().map(|p| p.value.id);
                            if let Err(err) = resp.send(presignature) {
                                tracing::error!(target: "sync[take]", ?err, presignature_id, "failed to respond with presignature");
                            }
                        }
                    }
                }
            }
        }
    }

    async fn new_update(&self) -> Option<SyncUpdate> {
        let triples = self.triples.fetch_mine().await.unwrap_or_default();
        let presignatures = self.presignatures.fetch_mine().await.unwrap_or_default();

        Some(SyncUpdate {
            triples,
            presignatures,
        })
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

        let mut rng = StdRng::from_entropy();
        let mut failed = Vec::new();
        // Try to find a suitable triple pair:
        let found = loop {
            if mesh_seen.len() < 2 {
                break None;
            }

            let two = mesh_seen.keys().choose_multiple(&mut rng, 2);
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
                failed.push((t0_id, t0_participants));
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
        let (mut participants, triple0, triple1) = found?;
        // TODO: make triple_storage.take intake active to do intersection in Lua script side.
        let (triple0, triple1) = match self.triples.take_two_self(triple0, triple1).await {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!(target: "sync", triple_ids = ?(triple0, triple1), ?err, "failed to take two triples");
                return None;
            }
        };

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
        let mut rng = StdRng::from_entropy();
        let found = loop {
            if mesh_seen.is_empty() {
                break None;
            }
            let Some(&presignature_id) = mesh_seen.keys().choose(&mut rng) else {
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
        let (mut participants, presignature_id) = found?;
        let presignature = match self.presignatures.take_self(presignature_id).await {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!(target: "sync", presignature_id, ?err, "failed to take presignature");
                return None;
            }
        };

        participants.sort();
        Some(ProtocolResponse {
            participants,
            value: presignature,
        })
    }
}

async fn broadcast_sync_update(
    client: NodeClient,
    update: SyncUpdate,
    active: Participants,
) -> Option<Vec<(Participant, SyncView)>> {
    if update.is_empty() {
        return None;
    }

    let start = Instant::now();

    let mut tasks = JoinSet::new();
    let update = Arc::new(update);
    for (&p, info) in active.iter() {
        let client = client.clone();
        let update = update.clone();
        let url = info.url.clone();
        tasks.spawn(async move {
            let start = Instant::now();
            let sync_view = client.sync(&url, &update).await;
            tracing::info!(
                target: "sync",
                participant = ?p,
                elapsed = ?start.elapsed(),
                "call /sync completed",
            );
            (p, sync_view)
        });
    }

    let views = tasks
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
        .collect::<Vec<_>>();

    tracing::info!(
        target: "sync",
        elapsed = ?start.elapsed(),
        responded = ?views.iter().map(|(p, _)| p).collect::<Vec<_>>(),
        "broadcast completed",
    );

    Some(views)
}

struct SyncUpdateRequest {
    update: SyncUpdate,
    view_tx: oneshot::Sender<SyncView>,
}

#[derive(Clone)]
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

    pub async fn request_update(&self, update: SyncUpdate) -> SyncView {
        let (view_tx, view_rx) = oneshot::channel();
        if let Err(err) = self
            .update_tx
            .send(SyncUpdateRequest { update, view_tx })
            .await
        {
            tracing::warn!(target: "sync", ?err, "failed to request update");
            return SyncView::empty();
        }

        match tokio::time::timeout(REQUEST_UPDATE_TIMEOUT, view_rx).await {
            Ok(Ok(view)) => view,
            Ok(Err(err)) => {
                tracing::warn!(target: "sync", ?err, "failed to receive view");
                SyncView::empty()
            }
            Err(_) => {
                tracing::warn!(target: "sync", "timeout trying to receive view");
                SyncView::empty()
            }
        }
    }

    pub async fn take_two_triple(
        &mut self,
        threshold: usize,
    ) -> Option<ProtocolResponse<(Triple, Triple)>> {
        let start = Instant::now();
        let result = self.request_triple.take(threshold).await;
        tracing::info!(target: "sync", elapsed = ?start.elapsed(), "take two triple");
        result
    }

    pub async fn take_presignature(
        &mut self,
        threshold: usize,
    ) -> Option<ProtocolResponse<Presignature>> {
        let start = Instant::now();
        let result = self.request_presignature.take(threshold).await;
        tracing::info!(target: "sync", elapsed = ?start.elapsed(), "take presignature");
        result
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
        if let Err(err) = self
            .request_tx
            .send(ProtocolRequest::Take {
                threshold,
                resp: resp_tx,
            })
            .await
        {
            tracing::warn!(?err, "failed to request protocol.take");
        }

        match tokio::time::timeout(REQUEST_PROTOCOL_TIMEOUT, resp_rx).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(err)) => {
                tracing::warn!(target: "sync", ?err, "failed to receive response for protocol.take");
                None
            }
            Err(_) => {
                tracing::warn!(target: "sync", "timeout trying to receive response for protocol.take");
                None
            }
        }
    }
}

impl<T> Clone for ProtocolChannel<T> {
    fn clone(&self) -> Self {
        Self {
            request_tx: self.request_tx.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    fn test_protocol_sync() {}
}
