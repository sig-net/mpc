use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cait_sith::protocol::Participant;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::rpc::ContractStateWatcher;
use crate::storage::{PresignatureStorage, StorageError, TripleStorage};

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

/// Timeout for waiting for a sync response from the sync task
const SYNC_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for the entire broadcast operation (waiting for all peers to respond)
const BROADCAST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("failed to queue sync request")]
    QueueFailed,
    #[error("failed to receive sync response")]
    ResponseFailed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncUpdate {
    pub from: Participant,
    pub triples: Vec<TripleId>,
    pub presignatures: Vec<PresignatureId>,
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

pub struct SyncRequest {
    pub update: SyncUpdate,
    pub response_tx: oneshot::Sender<Result<SyncUpdate, StorageError>>,
}

impl SyncRequest {
    async fn process(
        self,
        triples: TripleStorage,
        presignatures: PresignatureStorage,
        me: Participant,
    ) {
        let start = Instant::now();

        let outdated_triples = match triples
            .remove_outdated(self.update.from, &self.update.triples)
            .await
        {
            Ok(result) => result,
            Err(err) => {
                let _ = self.response_tx.send(Err(err));
                return;
            }
        };
        let outdated_presignatures = match presignatures
            .remove_outdated(self.update.from, &self.update.presignatures)
            .await
        {
            Ok(result) => result,
            Err(err) => {
                let _ = self.response_tx.send(Err(err));
                return;
            }
        };

        tracing::info!(
            removed_triples = outdated_triples.removed.len(),
            removed_presignatures = outdated_presignatures.removed.len(),
            not_found_triples = outdated_triples.not_found.len(),
            not_found_presignatures = outdated_presignatures.not_found.len(),
            elapsed = ?start.elapsed(),
            "processed sync update",
        );

        let response = SyncUpdate {
            from: me,
            triples: outdated_triples.not_found,
            presignatures: outdated_presignatures.not_found,
        };

        let _ = self.response_tx.send(Ok(response));
    }
}

pub struct SyncRequestReceiver {
    updates: mpsc::Receiver<SyncRequest>,
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
        tracing::info!("sync task has been started");
        // Poll for our participant info from contract state
        // TODO: constantly watch for changes on node state after this initial one so we can start/stop sync running.
        let mut watcher_interval = tokio::time::interval(Duration::from_millis(500));
        // Trigger sync broadcasts to peers in need_sync state
        let mut sync_interval = tokio::time::interval(Duration::from_millis(200));
        // Periodic full sync broadcast to all active peers (TODO: should not be necessary)
        let mut broadcast_interval = tokio::time::interval(RECURRING_SYNC_INTERVAL);
        // Poll whether any ongoing sync task has completed (from either sync_interval or broadcast_interval)
        let mut sync_check_interval = tokio::time::interval(Duration::from_millis(100));

        // Do NOT start until we have our own participant info
        let (threshold, me) = loop {
            watcher_interval.tick().await;
            if let Some(info) = self.contract.info().await {
                break info;
            }
        };
        tracing::info!(?me, "starting sync loop...");

        let mut broadcast = Option::<(Instant, JoinHandle<_>)>::None;
        loop {
            tokio::select! {
                // find nodes that need syncing and initiate it
                _ = sync_interval.tick() => {
                    if broadcast.is_some() {
                        // another broadcast task is still ongoing, skip.
                        continue;
                    }

                    let need_sync = self.mesh_state.borrow().need_sync().clone();
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
                        receivers.into_iter(),
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
                    let active = self.mesh_state.borrow().active().clone();

                    let start = Instant::now();
                    let task = tokio::spawn(broadcast_sync(
                        self.client.clone(),
                        update,
                        active.into_iter(),
                        me
                    ));
                    broadcast = Some((start, task));
                }
                // check that our broadcast has completed, and if so process the result.
                _ = sync_check_interval.tick() => {
                    let Some((start, handle)) = broadcast.take() else {
                        continue;
                    };
                    if !handle.is_finished() {
                        // task is not finished yet, put it back:
                        broadcast = Some((start, handle));
                        continue;
                    }

                    match handle.await {
                        Ok(responses) => {
                            // Process sync responses: update artifact participants based on not_found data
                            if let Err(err) = self.process_sync_responses(responses, me, threshold).await {
                                tracing::warn!(?err, "failed to process sync responses");
                            }
                            tracing::debug!(elapsed = ?start.elapsed(), "processed broadcast");
                        }
                        Err(err) => {
                            tracing::warn!(?err, "broadcast task failed");
                        }
                    }
                }
                Some(sync_req) = self.requests.updates.recv() => {
                    tokio::spawn(sync_req.process(self.triples.clone(), self.presignatures.clone(), me));
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

    /// Process sync responses:
    /// 1. Remove peers from artifact participants if they're missing data
    /// 2. Send synced peer notifications to mesh (for status transitions)
    async fn process_sync_responses(
        &self,
        responses: Vec<(Participant, Option<Result<SyncUpdate, String>>)>,
        me: Participant,
        threshold: usize,
    ) -> Result<(), String> {
        let mut triples_to_prune = HashSet::new();
        let mut presignatures_to_prune = HashSet::new();

        for (peer, result) in responses {
            match result {
                // No RPC was performed (self-peer), treat as successful
                None => {
                    if self.synced_peer_tx.send(peer).await.is_err() {
                        tracing::error!("sync reporter is down: state sync will no longer work");
                        return Err("sync reporter is down".to_string());
                    }
                }
                // RPC succeeded, process the not_found data
                Some(Ok(response)) => {
                    tracing::debug!(
                        ?peer,
                        not_found_triples = response.triples.len(),
                        not_found_presignatures = response.presignatures.len(),
                        "received sync response"
                    );

                    // Update replica tracking: remove peer from artifacts they don't have
                    for triple_id in response.triples {
                        let is_owned_by_me = self.triples.contains_by_owner(triple_id, me).await;
                        if !is_owned_by_me {
                            return Err(format!(
                                "received non-owned triple in sync response: triple_id={triple_id:?}, peer={peer:?}, me={me:?}"
                            ));
                        }

                        if let Some(mut pair) = self.triples.fetch(triple_id).await {
                            let mut updated = false;

                            // Remove peer from triple0 participants
                            if let Some(pos) = pair
                                .triple0
                                .public
                                .participants
                                .iter()
                                .position(|p| *p == peer)
                            {
                                pair.triple0.public.participants.remove(pos);
                                updated = true;
                            }

                            // Remove peer from triple1 participants
                            if let Some(pos) = pair
                                .triple1
                                .public
                                .participants
                                .iter()
                                .position(|p| *p == peer)
                            {
                                pair.triple1.public.participants.remove(pos);
                                updated = true;
                            }

                            if updated {
                                let remaining_holders = pair
                                    .triple0
                                    .public
                                    .participants
                                    .len()
                                    .min(pair.triple1.public.participants.len());

                                if remaining_holders < threshold {
                                    triples_to_prune.insert(triple_id);
                                    tracing::info!(
                                        ?triple_id,
                                        ?peer,
                                        remaining_holders,
                                        threshold,
                                        "triple dropped below threshold: scheduling owned artifact removal"
                                    );
                                } else {
                                    self.triples.update(triple_id, pair).await;
                                    tracing::debug!(
                                        ?triple_id,
                                        ?peer,
                                        "updated triple participants: removed peer"
                                    );
                                }
                            }
                        }
                    }

                    // Update presignatures: remove peer from participants if they don't have it
                    for presig_id in response.presignatures {
                        let is_owned_by_me =
                            self.presignatures.contains_by_owner(presig_id, me).await;
                        if !is_owned_by_me {
                            return Err(format!(
                                "received non-owned presignature in sync response: presig_id={presig_id:?}, peer={peer:?}, me={me:?}"
                            ));
                        }

                        if let Some(mut presig) = self.presignatures.fetch(presig_id).await {
                            if let Some(pos) = presig.participants.iter().position(|p| *p == peer) {
                                presig.participants.remove(pos);

                                if presig.participants.len() < threshold {
                                    presignatures_to_prune.insert(presig_id);
                                    tracing::info!(
                                        ?presig_id,
                                        ?peer,
                                        remaining_holders = presig.participants.len(),
                                        threshold,
                                        "presignature dropped below threshold: scheduling owned artifact removal"
                                    );
                                } else {
                                    self.presignatures.update(presig_id, presig).await;
                                    tracing::debug!(
                                        ?presig_id,
                                        ?peer,
                                        "updated presignature participants: removed peer"
                                    );
                                }
                            }
                        }
                    }

                    // Notify mesh that peer is synced (after processing) - for Active state transition
                    if self.synced_peer_tx.send(peer).await.is_err() {
                        tracing::error!(
                            ?peer,
                            "sync reporter is down: state sync will no longer work"
                        );
                        return Err("sync reporter is down".to_string());
                    }
                }
                // RPC failed, don't notify mesh (peer stays in Syncing state)
                Some(Err(err)) => {
                    tracing::warn!(?peer, ?err, "failed to sync peer");
                }
            }
        }

        self.prune_owned_triples(me, &triples_to_prune).await;
        self.prune_owned_presignatures(me, &presignatures_to_prune)
            .await;

        Ok(())
    }

    async fn prune_owned_triples(&self, me: Participant, to_prune: &HashSet<TripleId>) {
        if to_prune.is_empty() {
            return;
        }

        let mut keep = self.triples.fetch_owned(me).await;
        keep.retain(|id| !to_prune.contains(id));

        match self.triples.remove_outdated(me, &keep).await {
            Ok(result) => {
                tracing::info!(
                    removed = result.removed.len(),
                    not_found = result.not_found.len(),
                    "removed owned triples that dropped below threshold"
                );
            }
            Err(err) => {
                tracing::warn!(?err, "failed to remove owned triples below threshold");
            }
        }
    }

    async fn prune_owned_presignatures(&self, me: Participant, to_prune: &HashSet<PresignatureId>) {
        if to_prune.is_empty() {
            return;
        }

        let mut keep = self.presignatures.fetch_owned(me).await;
        keep.retain(|id| !to_prune.contains(id));

        match self.presignatures.remove_outdated(me, &keep).await {
            Ok(result) => {
                tracing::info!(
                    removed = result.removed.len(),
                    not_found = result.not_found.len(),
                    "removed owned presignatures that dropped below threshold"
                );
            }
            Err(err) => {
                tracing::warn!(?err, "failed to remove owned presignatures below threshold");
            }
        }
    }

    /// Channel for communicating back from the sync task which nodes are now updated.
    pub fn synced_nodes_channel() -> (mpsc::Sender<Participant>, mpsc::Receiver<Participant>) {
        mpsc::channel(MAX_SYNC_UPDATE_REQUESTS)
    }
}

/// Broadcast an update to all participants specified by `receivers`.
/// Returns results for all peers that complete within BROADCAST_TIMEOUT.
/// Peers that don't respond are not included in results and will be retried later.
async fn broadcast_sync(
    client: NodeClient,
    update: SyncUpdate,
    receivers: impl Iterator<Item = (Participant, ParticipantInfo)>,
    me: Participant,
) -> Vec<(Participant, Option<Result<SyncUpdate, String>>)> {
    let mut tasks = JoinSet::new();
    let update = Arc::new(update);

    for (p, info) in receivers {
        let client = client.clone();
        let update = update.clone();
        let url = info.url;
        tasks.spawn(async move {
            // Only actually do the sync on other peers, not on self.
            let sync_result = if p != me {
                Some(client.sync(&url, &update).await.map_err(|e| e.to_string()))
            } else {
                // No RPC sync is attempted for self (`p == me`); return None to indicate no-op.
                None
            };
            (p, sync_result)
        });
    }

    let deadline = Instant::now() + BROADCAST_TIMEOUT;
    let mut results = Vec::new();
    while !tasks.is_empty() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }

        tokio::select! {
            res = tasks.join_next() => {
                match res {
                    Some(Ok((p, sync_result))) => {
                        results.push((p, sync_result));
                    }
                    Some(Err(err)) => {
                        tracing::warn!(?err, "sync task failed");
                    }
                    None => break,
                }
            }
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                break;
            }
        }
    }

    if !tasks.is_empty() {
        tasks.abort_all();
    }

    results
}

#[derive(Clone)]
pub struct SyncChannel {
    request_update: mpsc::Sender<SyncRequest>,
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

    pub async fn request_update(&self, update: SyncUpdate) -> Result<SyncUpdate, SyncError> {
        let (response_tx, response_rx) = oneshot::channel();
        let request = SyncRequest {
            update: update.clone(),
            response_tx,
        };

        if let Err(_err) = self.request_update.send(request).await {
            return Err(SyncError::QueueFailed);
        }

        let result = tokio::time::timeout(SYNC_RESPONSE_TIMEOUT, response_rx)
            .await
            .map_err(|_err| {
                tracing::debug!("sync response timeout");
                SyncError::ResponseFailed
            })?
            .map_err(|_err| {
                tracing::debug!("failed to receive sync response from channel");
                SyncError::ResponseFailed
            })?;

        result.map_err(|err| {
            tracing::debug!(?err, "sync processing failed in storage layer");
            SyncError::ResponseFailed
        })
    }
}
