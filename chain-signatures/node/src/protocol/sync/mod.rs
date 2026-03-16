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

/// Timeout for waiting for a sync response from the sync task
const SYNC_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout for the entire broadcast operation (waiting for all peers to respond)
const BROADCAST_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("failed to queue sync request")]
    QueueFailed,
    #[error("failed to receive sync response")]
    ResponseFailed,
}

/// Result of a sync RPC to a single peer.
pub enum SyncPeerResponse {
    /// Self-peer: no RPC was performed.
    SelfPeer,
    /// Peer responded successfully with its view of not_found artifacts.
    Success(SyncUpdate),
    /// RPC to peer failed.
    Failed(String),
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
        // Polling loop for participant info from contract state
        let mut watcher_interval = tokio::time::interval(Duration::from_millis(500));
        // Trigger sync broadcasts to peers in need_sync state
        let mut sync_interval = tokio::time::interval(Duration::from_millis(200));
        // Poll whether any ongoing sync task has completed
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

                    let Some(update) = self.new_update(me).await else {
                        continue;
                    };
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
    async fn new_update(&self, me: Participant) -> Option<SyncUpdate> {
        let triples = match self.triples.fetch_owned(me).await {
            Ok(ids) => ids,
            Err(err) => {
                tracing::warn!(
                    ?err,
                    "failed to fetch owned triples, skipping sync broadcast"
                );
                return None;
            }
        };
        let presignatures = match self.presignatures.fetch_owned(me).await {
            Ok(ids) => ids,
            Err(err) => {
                tracing::warn!(
                    ?err,
                    "failed to fetch owned presignatures, skipping sync broadcast"
                );
                return None;
            }
        };

        Some(SyncUpdate {
            from: me,
            triples,
            presignatures,
        })
    }

    /// Process sync responses:
    /// 1. Remove peers from artifact participants if they're missing data
    /// 2. Send synced peer notifications to mesh (for status transitions)
    async fn process_sync_responses(
        &self,
        responses: Vec<(Participant, SyncPeerResponse)>,
        me: Participant,
        threshold: usize,
    ) -> Result<(), String> {
        for (peer, result) in responses {
            match result {
                SyncPeerResponse::SelfPeer => {
                    if self.synced_peer_tx.send(peer).await.is_err() {
                        tracing::error!("sync reporter is down: state sync will no longer work");
                        return Err("sync reporter is down".to_string());
                    }
                }
                SyncPeerResponse::Success(response) => {
                    tracing::debug!(
                        ?peer,
                        not_found_triples = response.triples.len(),
                        not_found_presignatures = response.presignatures.len(),
                        "received sync response"
                    );

                    // Batch remove peer from all triples and prune
                    let triple_res = self
                        .triples
                        .remove_holder_and_prune(me, peer, threshold, &response.triples)
                        .await;

                    // Batch remove peer from all presignatures and prune
                    let presig_res = self
                        .presignatures
                        .remove_holder_and_prune(me, peer, threshold, &response.presignatures)
                        .await;

                    match (triple_res, presig_res) {
                        (Ok((t_removed, t_updated)), Ok((p_removed, p_updated))) => {
                            tracing::info!(
                                ?peer,
                                removed_triples = t_removed.len(),
                                updated_triples = t_updated.len(),
                                removed_presignatures = p_removed.len(),
                                updated_presignatures = p_updated.len(),
                                "batch removed peer from artifacts and pruned"
                            );
                            // Only notify mesh if both succeeded
                            if self.synced_peer_tx.send(peer).await.is_err() {
                                tracing::error!(
                                    ?peer,
                                    "sync reporter is down: state sync will no longer work"
                                );
                                return Err("sync reporter is down".to_string());
                            }
                        }
                        (triple_res, presig_res) => {
                            tracing::warn!(
                                ?peer,
                                ?triple_res,
                                ?presig_res,
                                "sync batch failed, not notifying mesh"
                            );
                        }
                    }
                }
                SyncPeerResponse::Failed(err) => {
                    tracing::warn!(?peer, ?err, "failed to sync peer");
                }
            }
        }

        Ok(())
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
) -> Vec<(Participant, SyncPeerResponse)> {
    let mut tasks = JoinSet::new();
    let update = Arc::new(update);

    for (p, info) in receivers {
        let client = client.clone();
        let update = update.clone();
        let url = info.url;
        tasks.spawn(async move {
            let sync_result = if p != me {
                match client.sync(&url, &update).await {
                    Ok(response) => SyncPeerResponse::Success(response),
                    Err(err) => SyncPeerResponse::Failed(err.to_string()),
                }
            } else {
                SyncPeerResponse::SelfPeer
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
