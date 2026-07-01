use std::collections::HashSet;
use std::time::{Duration, Instant};

use cait_sith::protocol::Participant;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;

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

        // Do NOT start until we have our own participant info
        let (threshold, me) = self.contract.wait_info().await;
        tracing::info!(?me, "starting sync loop...");

        let mut active_syncs = HashSet::<Participant>::new();
        let mut sync_tasks = JoinSet::new();
        let (retry_tx, mut retry_rx) = mpsc::channel::<Participant>(64);

        loop {
            tokio::select! {
                // check mesh state for nodes needing sync
                _ = self.mesh_state.changed() => {
                    let need_sync = self.mesh_state.borrow_and_update().need_sync().clone();
                    for (peer, info) in need_sync {
                        if active_syncs.contains(&peer) {
                            continue;
                        }

                        let Some(update) = self.new_update(me).await else {
                            continue;
                        };

                        active_syncs.insert(peer);
                        let start = Instant::now();
                        let client = self.client.clone();
                        sync_tasks.spawn(async move {
                            let response = sync_peer(client, update, peer, info, me).await;
                            (peer, start, response)
                        });
                    }
                }
                // handle retrying of failed syncs
                Some(peer) = retry_rx.recv() => {
                    let need_sync = self.mesh_state.borrow().need_sync().clone();
                    if need_sync.contains_key(&peer) && !active_syncs.contains(&peer) {
                        if let Some(update) = self.new_update(me).await {
                            if let Some(info) = need_sync.get(&peer) {
                                let info = info.clone();
                                active_syncs.insert(peer);
                                let start = Instant::now();
                                let client = self.client.clone();
                                sync_tasks.spawn(async move {
                                    let response = sync_peer(client, update, peer, info, me).await;
                                    (peer, start, response)
                                });
                            }
                        }
                    }
                }
                // wait for any sync task to finish
                Some(res) = sync_tasks.join_next(), if !sync_tasks.is_empty() => {
                    match res {
                        Ok((peer, start, response)) => {
                            active_syncs.remove(&peer);
                            let is_failed = matches!(response, SyncPeerResponse::Failed(_));
                            let responses = vec![(peer, response)];
                            if let Err(err) = self.process_sync_responses(responses, threshold).await {
                                tracing::warn!(?err, "failed to process sync response");
                            }
                            tracing::debug!(elapsed = ?start.elapsed(), ?peer, "processed sync response");

                            if is_failed {
                                let retry_tx = retry_tx.clone();
                                tokio::spawn(async move {
                                    tokio::time::sleep(Duration::from_secs(5)).await;
                                    let _ = retry_tx.send(peer).await;
                                });
                            }
                        }
                        Err(err) => {
                            tracing::warn!(?err, "sync peer task panicked");
                        }
                    }
                }
                Some(sync_req) = self.requests.updates.recv() => {
                    tokio::spawn(sync_req.process(self.triples.clone(), self.presignatures.clone(), me));
                }
            }
        }
    }

    async fn new_update(&self, me: Participant) -> Option<SyncUpdate> {
        let triples = match self.triples.fetch_owned_with_reserved().await {
            Ok(ids) => ids,
            Err(err) => {
                tracing::warn!(
                    ?err,
                    "failed to fetch owned triples, skipping sync broadcast"
                );
                return None;
            }
        };
        let presignatures = match self.presignatures.fetch_owned_with_reserved().await {
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
                        .remove_holder_and_prune(peer, threshold, &response.triples)
                        .await;

                    // Batch remove peer from all presignatures and prune
                    let presig_res = self
                        .presignatures
                        .remove_holder_and_prune(peer, threshold, &response.presignatures)
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
/// Sync update with a single participant.
async fn sync_peer(
    client: NodeClient,
    update: SyncUpdate,
    peer: Participant,
    info: ParticipantInfo,
    me: Participant,
) -> SyncPeerResponse {
    if peer == me {
        return SyncPeerResponse::SelfPeer;
    }
    let sync_result = tokio::time::timeout(BROADCAST_TIMEOUT, client.sync(&info.url, &update)).await;
    match sync_result {
        Ok(Ok(response)) => SyncPeerResponse::Success(response),
        Ok(Err(err)) => SyncPeerResponse::Failed(err.to_string()),
        Err(_) => SyncPeerResponse::Failed("timeout".to_string()),
    }
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
