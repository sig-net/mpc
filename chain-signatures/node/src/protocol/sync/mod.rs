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
use crate::rpc::NodeStateWatcher;
use crate::storage::{PresignatureStorage, TripleStorage};

use super::contract::primitives::{intersect, intersect_vec, Participants};
use super::presignature::{Presignature, PresignatureId};
use super::triple::{Triple, TripleId};

/// How long for a synchronous [`SyncUpdate`] to get back a [`SyncView`] request before timeout.
const REQUEST_UPDATE_TIMEOUT: Duration = Duration::from_millis(50);
/// How long for a synchronous [`ProtocolRequest`] to get back a [`ProtocolResponse`] before timeout.
const REQUEST_PROTOCOL_TIMEOUT: Duration = Duration::from_millis(50);
/// The maximum number of protocol requests that can be queued. This will likely never get to
/// this upper bound just purely based on our ProtocolConfig.
const MAX_PROTOCOL_REQUESTS: usize = 128 * 1024;
/// The maximum number of update requests that can be queued. This is pretty much just
/// based on the number of participants in the network. If we have 1024 participants then
/// our issue will more than likely not be the channel size.
const MAX_SYNC_UPDATE_REQUESTS: usize = 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
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

struct SyncCache {
    me: Participant,
    /// The set of self owned triples seen by both us and other participants.
    owned_triples: HashMap<TripleId, Vec<Participant>>,
    /// The set of self owned presignatures seen by both us and other participants.
    owned_presignatures: HashMap<PresignatureId, Vec<Participant>>,
}

impl SyncCache {
    fn new(me: Participant) -> Self {
        Self {
            me,
            owned_triples: HashMap::new(),
            owned_presignatures: HashMap::new(),
        }
    }

    fn update(
        &mut self,
        update: SyncUpdate,
        views: Vec<(Participant, SyncView)>,
        threshold: usize,
    ) {
        // Clear the cache before updating it since we are only taking a temporary view of who has a share
        // of the triples/presignatures. This is so storage for each can be updated and we can adapt to it.
        self.clear();

        // Update the cache with our own info:
        for id in update.triples {
            let entry = self.owned_triples.entry(id).or_default();
            entry.push(self.me);
        }
        for id in update.presignatures {
            let entry = self.owned_presignatures.entry(id).or_default();
            entry.push(self.me);
        }

        // Update the cache with the info from other participants:
        for (p, view) in views {
            for triple in view.triples {
                let entry = self.owned_triples.entry(triple).or_default();
                entry.push(p);
            }

            for presignature in view.presignatures {
                let entry = self.owned_presignatures.entry(presignature).or_default();
                entry.push(p);
            }
        }

        // Remove any triples/presignatures that do not have enough participants.
        self.owned_triples
            .retain(|_, participants| participants.len() >= threshold);
        self.owned_presignatures
            .retain(|_, participants| participants.len() >= threshold);
    }

    fn clear(&mut self) {
        self.owned_triples.clear();
        self.owned_presignatures.clear();
    }
}

pub struct SyncRequestReceiver {
    updates: mpsc::Receiver<SyncUpdateRequest>,
    triples: mpsc::Receiver<ProtocolRequest<(Triple, Triple)>>,
    presignatures: mpsc::Receiver<ProtocolRequest<Presignature>>,
}

pub struct SyncTask {
    client: NodeClient,
    triples: TripleStorage,
    presignatures: PresignatureStorage,
    mesh_state: Arc<RwLock<MeshState>>,
    watcher: NodeStateWatcher,
    requests: SyncRequestReceiver,
}

// TODO: add a watch channel for mesh active participants.
impl SyncTask {
    pub fn new(
        client: &NodeClient,
        triples: TripleStorage,
        presignatures: PresignatureStorage,
        mesh_state: Arc<RwLock<MeshState>>,
        watcher: NodeStateWatcher,
    ) -> (SyncChannel, Self) {
        let (requests, channel) = SyncChannel::new();
        let task = Self {
            client: client.clone(),
            triples,
            presignatures,
            mesh_state,
            watcher,
            requests,
        };
        (channel, task)
    }

    async fn process_sync(&self, update: SyncUpdate) -> SyncView {
        // TODO: check that `from` actually owns the triples/presignatures.
        // TODO: log the errors from storage.
        // TODO: make each process_sync a separate task
        let triple_ids = self.triples.fetch_foreign_ids().await.unwrap_or_default();
        let presignature_ids = self
            .presignatures
            .fetch_foreign_ids()
            .await
            .unwrap_or_default();

        // TODO: maybe instead of Vec<T> we should have HashSet<T> for more efficient intersections.
        SyncView {
            triples: intersect(&[&update.triples, &triple_ids]),
            presignatures: intersect(&[&update.presignatures, &presignature_ids]),
        }
    }

    pub async fn run(mut self) {
        tracing::info!(target: "sync", "task has been started");
        let mut watcher_interval = tokio::time::interval(Duration::from_millis(500));
        let mut broadcast_interval = tokio::time::interval(Duration::from_millis(250));
        let mut broadcast_check_interval = tokio::time::interval(Duration::from_millis(25));

        // Do NOT start until we have our own participant info.
        // TODO: constantly watch for changes on node state after this initial one so we can start/stop sync running.
        let (threshold, me) = loop {
            watcher_interval.tick().await;
            if let Some(info) = self.watcher.info().await {
                break info;
            }
        };
        tracing::info!(target: "sync", ?me, "mpc network ready, running...");
        let mut cache = SyncCache::new(me);

        let mut broadcast = Option::<(Instant, JoinHandle<_>)>::None;
        loop {
            tokio::select! {
                // do a new broadcast if there is no ongoing broadcast.
                _ = broadcast_interval.tick() => {
                    if broadcast.is_some() {
                        // task is still ongoing, skip.
                        continue;
                    }

                    let Some(update) = self.new_update().await else {
                        continue;
                    };

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

                    let (update, views) = match handle.await {
                        Ok(result) => result,
                        Err(err) => {
                            tracing::warn!(target: "sync", ?err, "broadcast task failed");
                            continue;
                        }
                    };
                    cache.update(update, views, threshold);
                    // TODO: add ability to remove from storage, but that requires more info in storage,
                    //      like who exactly owns the triple/presignature.

                    let elapsed = start.elapsed();
                    tracing::info!(
                        target: "sync",
                        ?elapsed,
                        triples = cache.owned_triples.len(),
                        presignatures = cache.owned_presignatures.len(),
                        "processed broadcast",
                    );
                }
                // TODO: maybe make process updates a separate task.
                Some(req) = self.requests.updates.recv() => {
                    let view = self.process_sync(req.update).await;
                    if let Err(err) = req.resp.send(view) {
                        tracing::warn!(target: "sync", ?err, "failed to send sync view");
                    }
                }
                Some(req) = self.requests.triples.recv() => {
                    match req {
                        ProtocolRequest::Take { mine, resp } => {
                            let triples = self.take_two_triple(mine, threshold, &mut cache).await;
                            let triple_ids = triples.as_ref().map(|p| (p.value.0.id, p.value.1.id));
                            if let Err(err) = resp.send(triples) {
                                tracing::warn!(target: "sync", ?triple_ids, ?err, "failed to respond with two triples");
                            }
                        }
                    }
                }
                Some(req) = self.requests.presignatures.recv() => {
                    match req {
                        ProtocolRequest::Take { mine, resp } => {
                            let presignature = self.take_presignature(mine, threshold, &mut cache).await;
                            let presignature_id = presignature.as_ref().map(|p| p.value.id);
                            if let Err(err) = resp.send(presignature) {
                                tracing::warn!(target: "sync", presignature_id, ?err, "failed to respond with presignature");
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
        // TODO: utilize mine
        _mine: bool,
        threshold: usize,
        cache: &mut SyncCache,
    ) -> Option<ProtocolResponse<(Triple, Triple)>> {
        if cache.owned_triples.len() < 2 {
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
            if cache.owned_triples.len() < 2 {
                break None;
            }

            let two = cache.owned_triples.keys().choose_multiple(&mut rng, 2);
            let (&t0_id, &t1_id) = match two.as_slice() {
                &[triple0, triple1] => (triple0, triple1),
                _ => {
                    tracing::warn!(target: "sync", "unexpected, failed to take two triples");
                    break None;
                }
            };

            let Some((t0_id, t0_participants)) = cache.owned_triples.remove_entry(&t0_id) else {
                tracing::warn!(target: "sync", t0_id, "unexpected, failed to take a seen triple");
                break None;
            };
            let Some((t1_id, t1_participants)) = cache.owned_triples.remove_entry(&t1_id) else {
                tracing::warn!(target: "sync", t1_id, "unexpected, failed to take a seen triple");
                failed.push((t0_id, t0_participants));
                break None;
            };

            let participants = intersect_vec(&[&active, &t0_participants, &t1_participants]);
            if participants.len() < threshold {
                tracing::warn!(
                    target: "sync",
                    intersection = ?participants,
                    ?active,
                    triple0 = ?(t0_id, &t0_participants),
                    triple1 = ?(t1_id, &t1_participants),
                    "intersection < threshold for two triple.take"
                );
                failed.push((t0_id, t0_participants));
                failed.push((t1_id, t1_participants));
                continue;
            }

            break Some((participants, t0_id, t1_id));
        };

        for (id, triple) in failed {
            cache.owned_triples.insert(id, triple);
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
        // TODO: utilize mine
        _mine: bool,
        threshold: usize,
        cache: &mut SyncCache,
    ) -> Option<ProtocolResponse<Presignature>> {
        if cache.owned_presignatures.is_empty() {
            return None;
        }
        let active = self.mesh_state.read().await.active.keys_vec();

        let mut failed = Vec::new();
        let mut rng = StdRng::from_entropy();
        let found = loop {
            if cache.owned_presignatures.is_empty() {
                break None;
            }
            let Some(&presignature_id) = cache.owned_presignatures.keys().choose(&mut rng) else {
                tracing::warn!(target: "sync", "unexpected, failed to take a presignature");
                break None;
            };

            let Some((presignature_id, presign_participants)) =
                cache.owned_presignatures.remove_entry(&presignature_id)
            else {
                break None;
            };

            let participants = intersect_vec(&[&active, &presign_participants]);
            if participants.len() < threshold {
                tracing::warn!(
                    target: "sync",
                    intersection = ?participants,
                    ?active,
                    presignature = ?(presignature_id, &presign_participants),
                    "intersection < threshold for presignature.take"
                );
                failed.push((presignature_id, presign_participants));
                continue;
            }

            break Some((participants, presignature_id));
        };

        for (id, triple) in failed {
            cache.owned_presignatures.insert(id, triple);
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

/// Broadcast an update to all participants specified by `active`.
async fn broadcast_sync(
    client: NodeClient,
    update: SyncUpdate,
    active: Participants,
) -> (SyncUpdate, Vec<(Participant, SyncView)>) {
    if update.is_empty() {
        return (update, Vec::new());
    }

    let start = Instant::now();
    let mut tasks = JoinSet::new();
    let arc_update = Arc::new(update.clone());
    for (&p, info) in active.iter() {
        let client = client.clone();
        let update = arc_update.clone();
        let url = info.url.clone();
        tasks.spawn(async move {
            let sync_view = client.sync(&url, &update).await;
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

    (update, views)
}

struct SyncUpdateRequest {
    update: SyncUpdate,
    resp: oneshot::Sender<SyncView>,
}

#[derive(Clone)]
pub struct SyncChannel {
    request_update: mpsc::Sender<SyncUpdateRequest>,
    request_triple: TripleChannel,
    request_presignature: PresignatureChannel,
}

impl SyncChannel {
    pub fn new() -> (SyncRequestReceiver, Self) {
        let (request_update_tx, request_update_rx) = mpsc::channel(MAX_SYNC_UPDATE_REQUESTS);
        let (request_triple_rx, request_triple) = TripleChannel::new();
        let (request_presignature_rx, request_presignature) = PresignatureChannel::new();

        let requests = SyncRequestReceiver {
            updates: request_update_rx,
            triples: request_triple_rx,
            presignatures: request_presignature_rx,
        };
        let channel = Self {
            request_update: request_update_tx,
            request_triple,
            request_presignature,
        };

        (requests, channel)
    }

    pub async fn request_update(&self, update: SyncUpdate) -> SyncView {
        let (view_tx, view_rx) = oneshot::channel();
        if let Err(err) = self
            .request_update
            .send(SyncUpdateRequest {
                update,
                resp: view_tx,
            })
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

    pub async fn take_two_triple(&self, mine: bool) -> Option<ProtocolResponse<(Triple, Triple)>> {
        let start = Instant::now();
        let result = self.request_triple.take(mine).await;
        tracing::info!(target: "sync", elapsed = ?start.elapsed(), "take two triple");
        result
    }

    pub async fn take_presignature(&self, mine: bool) -> Option<ProtocolResponse<Presignature>> {
        let start = Instant::now();
        let result = self.request_presignature.take(mine).await;
        tracing::info!(target: "sync", elapsed = ?start.elapsed(), "take presignature");
        result
    }
}

enum ProtocolRequest<T> {
    Take {
        mine: bool,
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
        let (request_tx, request_rx) = mpsc::channel(MAX_PROTOCOL_REQUESTS);
        let protocol_channel = Self { request_tx };

        (request_rx, protocol_channel)
    }

    async fn take(&self, mine: bool) -> Option<ProtocolResponse<T>> {
        let (resp_tx, resp_rx) = oneshot::channel();
        if let Err(err) = self
            .request_tx
            .send(ProtocolRequest::Take {
                mine,
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
