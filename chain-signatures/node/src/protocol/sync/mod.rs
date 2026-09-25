use std::sync::Arc;
use std::time::{Duration, Instant};

use cait_sith::protocol::Participant;
use mpc_keys::hpke::{self, Ciphered};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

use crate::config::NetworkConfig;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::rpc::ContractStateWatcher;
use crate::storage::{PresignatureStorage, StorageError, TripleStorage};

use super::contract::primitives::{ParticipantInfo, ParticipantMap, Participants};
use super::message::{MessageError, SignedMessage};
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
    /// A `SyncUpdate` signed by its sender and encrypted to us.
    pub update: Ciphered,
    /// Our reply, signed by us and encrypted to the sender.
    pub response_tx: oneshot::Sender<Result<Ciphered, StorageError>>,
}

impl SyncRequest {
    async fn process(
        self,
        triples: TripleStorage,
        presignatures: PresignatureStorage,
        me: Participant,
        network: NetworkConfig,
        participants: ParticipantMap,
    ) {
        let start = Instant::now();

        // `from` picks the owner whose shares we drop, so it must be the
        // signer, not the claim inside the payload.
        let update = match SignedMessage::decrypt_with::<SyncUpdate, _>(
            &self.update,
            &network.cipher_sk,
            &participants,
            |_| Ok(()),
        ) {
            Ok((from, update)) => SyncUpdate { from, ..update },
            Err(err) => {
                tracing::warn!(?err, "rejected sync update");
                return;
            }
        };

        let outdated_triples = match triples.remove_outdated(update.from, &update.triples).await {
            Ok(result) => result,
            Err(err) => {
                let _ = self.response_tx.send(Err(err));
                return;
            }
        };
        let outdated_presignatures = match presignatures
            .remove_outdated(update.from, &update.presignatures)
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
        // The signature check above found the sender in `participants`.
        let Some(info) = participants.get(&update.from) else {
            return;
        };
        let response =
            match SignedMessage::encrypt(&response, me, &network.sign_sk, &info.cipher_pk) {
                Ok(response) => response,
                Err(err) => {
                    tracing::warn!(?err, "failed to encrypt sync response");
                    return;
                }
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
    sync_report_tx: SyncReportSender,
    network: NetworkConfig,
}

// TODO: add a watch channel for mesh active participants.
impl SyncTask {
    pub fn new(
        client: &NodeClient,
        triples: TripleStorage,
        presignatures: PresignatureStorage,
        mesh_state: watch::Receiver<MeshState>,
        contract: ContractStateWatcher,
        sync_report_tx: SyncReportSender,
        network: NetworkConfig,
    ) -> (SyncChannel, Self) {
        let (requests, channel) = SyncChannel::new();
        let task = Self {
            client: client.clone(),
            triples,
            presignatures,
            mesh_state,
            contract,
            requests,
            sync_report_tx,
            network,
        };
        (channel, task)
    }

    pub async fn run(mut self) {
        tracing::info!("sync task has been started");
        // Trigger sync broadcasts to peers in need_sync state
        let mut sync_interval = tokio::time::interval(Duration::from_millis(200));
        // Poll whether any ongoing sync task has completed
        let mut sync_check_interval = tokio::time::interval(Duration::from_millis(100));

        // Do NOT start until we have our own participant info
        tracing::info!("sync waiting for participant info");
        let start = Instant::now();
        let (threshold, me) = self.contract.wait_info().await;
        tracing::info!(?me, elapsed = ?start.elapsed(), "starting sync loop...");

        self.triples.set_me(me);
        self.presignatures.set_me(me);

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
                        self.network.clone(),
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
                            if let Err(err) = self.process_sync_responses(responses, threshold).await {
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
                    let participants = self.contract.participant_map().await;
                    tokio::spawn(sync_req.process(
                        self.triples.clone(),
                        self.presignatures.clone(),
                        me,
                        self.network.clone(),
                        participants,
                    ));
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
                    if self
                        .sync_report_tx
                        .send((peer, SyncKind::Synced))
                        .await
                        .is_err()
                    {
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
                            if self
                                .sync_report_tx
                                .send((peer, SyncKind::Synced))
                                .await
                                .is_err()
                            {
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

    /// Channel for reporting to the mesh which nodes changed sync status.
    /// Sized well above the participant count: a full channel drops whatever
    /// report is being sent, and the cost of losing a desync report is one
    /// more failed round for that peer.
    pub fn sync_report_channel() -> (SyncReportSender, SyncReportReceiver) {
        mpsc::channel(MAX_SYNC_UPDATE_REQUESTS)
    }
}

/// Which way a peer's sync status changed. `Synced` comes from the sync task
/// once a peer's artifacts have been reconciled; `Desynced` comes from anyone
/// who learns our record of what that peer stores is wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncKind {
    Synced,
    Desynced,
}

pub type SyncReportSender = mpsc::Sender<(Participant, SyncKind)>;
pub type SyncReportReceiver = mpsc::Receiver<(Participant, SyncKind)>;

/// Broadcast an update to all participants specified by `receivers`.
/// Returns results for all peers that complete within BROADCAST_TIMEOUT.
/// Peers that don't respond are not included in results and will be retried later.
async fn broadcast_sync(
    client: NodeClient,
    update: SyncUpdate,
    receivers: impl Iterator<Item = (Participant, ParticipantInfo)>,
    me: Participant,
    network: NetworkConfig,
) -> Vec<(Participant, SyncPeerResponse)> {
    let mut tasks = JoinSet::new();
    let update = Arc::new(update);

    for (p, info) in receivers {
        let client = client.clone();
        let update = update.clone();
        let network = network.clone();
        tasks.spawn(async move {
            let sync_result = if p != me {
                match sync_peer(&client, &update, me, &network, p, &info).await {
                    Ok(response) => SyncPeerResponse::Success(response),
                    Err(err) => SyncPeerResponse::Failed(err),
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

/// Send our signed update to `peer` and open its signed reply.
async fn sync_peer(
    client: &NodeClient,
    update: &SyncUpdate,
    me: Participant,
    network: &NetworkConfig,
    peer: Participant,
    info: &ParticipantInfo,
) -> Result<SyncUpdate, String> {
    let encrypted = SignedMessage::encrypt(update, me, &network.sign_sk, &info.cipher_pk)
        .map_err(|err| err.to_string())?;
    let reply = client
        .sync(&info.url, &encrypted)
        .await
        .map_err(|err| err.to_string())?;
    open_reply(&reply, &network.cipher_sk, peer, info).map_err(|err| err.to_string())
}

/// Decrypt a sync reply and check it was signed by `peer`, the node we asked.
/// `info` must be `peer`'s entry from the contract.
fn open_reply(
    reply: &Ciphered,
    cipher_sk: &hpke::SecretKey,
    peer: Participant,
    info: &ParticipantInfo,
) -> Result<SyncUpdate, MessageError> {
    let mut only_peer = Participants::default();
    only_peer.insert(&peer, info.clone());
    let (from, reply) = SignedMessage::decrypt_with::<SyncUpdate, _>(
        reply,
        cipher_sk,
        &ParticipantMap::One(only_peer),
        |_| Ok(()),
    )?;
    if from != peer {
        return Err(MessageError::Verification(
            "sync reply was not signed by the peer we asked",
        ));
    }
    Ok(SyncUpdate { from, ..reply })
}

#[cfg(any(test, feature = "test-feature"))]
pub fn open_reply_for_test(
    reply: &Ciphered,
    cipher_sk: &hpke::SecretKey,
    peer: Participant,
    info: &ParticipantInfo,
) -> Result<SyncUpdate, MessageError> {
    open_reply(reply, cipher_sk, peer, info)
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

    pub async fn request_update(&self, update: Ciphered) -> Result<Ciphered, SyncError> {
        let (response_tx, response_rx) = oneshot::channel();
        let request = SyncRequest {
            update,
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
