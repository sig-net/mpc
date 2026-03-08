use std::sync::Arc;
use std::time::{Duration, Instant};

use cait_sith::protocol::Participant;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
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

/// Maximum number of IDs to send in a single chunk. This prevents payloads from becoming too large.
pub const MAX_CHUNK_SIZE: usize = 1000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncUpdate {
    pub from: Participant,
    pub triples: Vec<TripleId>,
    pub presignatures: Vec<PresignatureId>,
}

/// Chunked version of SyncUpdate that allows for large datasets to be split into smaller chunks
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkedSyncUpdate {
    pub from: Participant,
    /// Chunk information for tracking progress
    pub chunk_info: ChunkInfo,
    /// Triple IDs in this specific chunk
    pub triples: Vec<TripleId>,
    /// Presignature IDs in this specific chunk  
    pub presignatures: Vec<PresignatureId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkInfo {
    /// Unique identifier for this sync session (to group chunks together)
    pub session_id: u64,
    /// Current chunk number (0-based)
    pub chunk_id: u32,
    /// Total number of chunks in this sync session
    pub total_chunks: u32,
    /// Whether this is the last chunk
    pub is_final: bool,
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

    /// Convert a large SyncUpdate into multiple ChunkedSyncUpdate messages
    pub fn into_chunks(self, session_id: u64, chunk_size: usize) -> Vec<ChunkedSyncUpdate> {
        if self.is_empty() {
            return vec![ChunkedSyncUpdate {
                from: self.from,
                chunk_info: ChunkInfo {
                    session_id,
                    chunk_id: 0,
                    total_chunks: 1,
                    is_final: true,
                },
                triples: Vec::new(),
                presignatures: Vec::new(),
            }];
        }

        let mut chunks = Vec::new();
        let triples_chunks: Vec<_> = self.triples.chunks(chunk_size).collect();
        let presignatures_chunks: Vec<_> = self.presignatures.chunks(chunk_size).collect();
        
        // Calculate total chunks needed (max of triples and presignatures chunks)
        let total_chunks = std::cmp::max(triples_chunks.len(), presignatures_chunks.len()) as u32;
        
        for chunk_id in 0..total_chunks as usize {
            let triples = triples_chunks
                .get(chunk_id)
                .map(|chunk| chunk.to_vec())
                .unwrap_or_default();
            
            let presignatures = presignatures_chunks
                .get(chunk_id)
                .map(|chunk| chunk.to_vec())
                .unwrap_or_default();
            
            chunks.push(ChunkedSyncUpdate {
                from: self.from,
                chunk_info: ChunkInfo {
                    session_id,
                    chunk_id: chunk_id as u32,
                    total_chunks,
                    is_final: chunk_id == (total_chunks as usize - 1),
                },
                triples,
                presignatures,
            });
        }

        chunks
    }
}

impl ChunkedSyncUpdate {
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
    mesh_state: watch::Receiver<MeshState>,
    contract: ContractStateWatcher,
    requests: SyncRequestReceiver,
    synced_peer_tx: mpsc::Sender<Participant>,
    /// Manages reassembling chunked sync updates
    chunk_assembler: Arc<tokio::sync::Mutex<ChunkAssembler>>,
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
            chunk_assembler: Arc::new(tokio::sync::Mutex::new(ChunkAssembler::new())),
        };
        (channel, task)
    }

    pub async fn run(mut self) {
        tracing::info!("task has been started");
        let mut watcher_interval = tokio::time::interval(Duration::from_millis(500));
        let mut sync_interval = tokio::time::interval(Duration::from_millis(200));
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

    /// Channel for communicating back from the sync task which nodes are now updated.
    pub fn synced_nodes_channel() -> (mpsc::Sender<Participant>, mpsc::Receiver<Participant>) {
        mpsc::channel(MAX_SYNC_UPDATE_REQUESTS)
    }
}

/// Broadcast an update to all participants specified by `receivers`.
/// Automatically chunks large updates to avoid payload size issues.
async fn broadcast_sync(
    client: NodeClient,
    update: SyncUpdate,
    receivers: impl Iterator<Item = (Participant, ParticipantInfo)>,
    synced_peer_tx: mpsc::Sender<Participant>,
    me: Participant,
) {
    let receivers: Vec<_> = receivers.collect();
    
    if update.is_empty() {
        for (participant, _) in receivers {
            if synced_peer_tx.send(participant).await.is_err() {
                tracing::error!(
                    ?participant,
                    "sync reporter is down: state sync will no longer work"
                );
            }
        }
        return;
    }

    let total_items = update.triples.len() + update.presignatures.len();
    let should_chunk = total_items > MAX_CHUNK_SIZE;
    
    let start = Instant::now();
    
    if should_chunk {
        tracing::info!(
            total_items,
            max_chunk_size = MAX_CHUNK_SIZE,
            "broadcasting large sync update using chunked protocol"
        );
        
        // Generate a unique session ID for this sync session
        let session_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
            
        let chunks = update.into_chunks(session_id, MAX_CHUNK_SIZE);
        
        tracing::info!(
            session_id,
            total_chunks = chunks.len(),
            "created chunked sync update"
        );
        
        let mut tasks = JoinSet::new();
        for (p, info) in receivers {
            for chunk in &chunks {
                let client = client.clone();
                let chunk = chunk.clone();
                let url = info.url.clone();
                let sync_tx = synced_peer_tx.clone();
                tasks.spawn(async move {
                    let sync_view = if p != me {
                        let res = client.sync_chunked(&url, &chunk).await;
                        Some(res)
                    } else {
                        None
                    };
                    // Only send completion notification after the final chunk
                    if chunk.chunk_info.is_final {
                        if sync_tx.send(p).await.is_err() {
                            tracing::error!("sync reporter is down: state sync will no longer work")
                        }
                    }
                    (p, chunk.chunk_info.chunk_id, sync_view)
                });
            }
        }

        let mut success_count = 0;
        let mut total_sent = 0;
        while let Some(result) = tasks.join_next().await {
            total_sent += 1;
            if let Ok((p, chunk_id, Some(Ok(())))) = result {
                success_count += 1;
                tracing::debug!(?p, chunk_id, "chunk sent successfully");
            }
        }
        
        tracing::info!(
            session_id,
            success_count,
            total_sent,
            elapsed = ?start.elapsed(),
            "chunked sync broadcast completed",
        );
    } else {
        // Use original non-chunked protocol for small updates
        let mut tasks = JoinSet::new();
        let update = Arc::new(update);
        for (p, info) in receivers {
            let client = client.clone();
            let update = update.clone();
            let url = info.url;
            let sync_tx = synced_peer_tx.clone();
            tasks.spawn(async move {
                let sync_view = if p != me {
                    let res = client.sync(&url, &update).await;
                    Some(res)
                } else {
                    None
                };
                if sync_tx.send(p).await.is_err() {
                    tracing::error!("sync reporter is down: state sync will no longer work")
                }
                (p, sync_view)
            });
        }

        let resps = tasks
            .join_all()
            .await
            .into_iter()
            .filter_map(|(p, view)| {
                if let Some(Ok(())) = view {
                    Some(p)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        tracing::debug!(
            elapsed = ?start.elapsed(),
            responded = ?resps,
            "broadcast completed",
        );
    }
}

impl SyncUpdate {
    async fn process(self, triples: TripleStorage, presignatures: PresignatureStorage) {
        let start = Instant::now();

        let outdated_triples = if !self.triples.is_empty() {
            triples.remove_outdated(self.from, &self.triples).await
        } else {
            Vec::new()
        };
        let outdated_presignatures = if !self.presignatures.is_empty() {
            presignatures
                .remove_outdated(self.from, &self.presignatures)
                .await
        } else {
            Vec::new()
        };

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

/// Structure to manage reassembling chunked sync updates
#[derive(Debug)]
pub struct ChunkAssembler {
    /// Currently in-progress chunked sync sessions  
    sessions: std::collections::HashMap<u64, PartialSyncSession>,
}

#[derive(Debug)]
struct PartialSyncSession {
    from: Participant,
    total_chunks: u32,
    received_chunks: std::collections::HashMap<u32, ChunkedSyncUpdate>,
    triples: Vec<TripleId>,
    presignatures: Vec<PresignatureId>,
}

impl ChunkAssembler {
    pub fn new() -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
        }
    }

    /// Process a chunked sync update. Returns a complete SyncUpdate if all chunks have been received.
    pub fn process_chunk(&mut self, chunk: ChunkedSyncUpdate) -> Option<SyncUpdate> {
        let session_id = chunk.chunk_info.session_id;
        
        // Get or create session
        let session = self.sessions.entry(session_id).or_insert_with(|| {
            PartialSyncSession {
                from: chunk.from,
                total_chunks: chunk.chunk_info.total_chunks,
                received_chunks: std::collections::HashMap::new(),
                triples: Vec::new(),
                presignatures: Vec::new(),
            }
        });
        
        // Add this chunk to the session
        session.received_chunks.insert(chunk.chunk_info.chunk_id, chunk.clone());
        
        // Check if we have all chunks
        if session.received_chunks.len() == session.total_chunks as usize {
            // Reassemble the complete update
            let mut all_triples = Vec::new();
            let mut all_presignatures = Vec::new();
            
            // Process chunks in order
            for chunk_id in 0..session.total_chunks {
                if let Some(chunk) = session.received_chunks.get(&chunk_id) {
                    all_triples.extend_from_slice(&chunk.triples);
                    all_presignatures.extend_from_slice(&chunk.presignatures);
                }
            }
            
            let complete_update = SyncUpdate {
                from: session.from,
                triples: all_triples,
                presignatures: all_presignatures,
            };
            
            // Get session data before removing it to avoid borrow checker issues
            let total_chunks = session.total_chunks;
            let triples_count = complete_update.triples.len();
            let presignatures_count = complete_update.presignatures.len();
            
            // Remove the completed session
            self.sessions.remove(&session_id);
            
            tracing::info!(
                session_id,
                total_chunks,
                triples_count,
                presignatures_count,
                "reassembled chunked sync update"
            );
            
            Some(complete_update)
        } else {
            tracing::debug!(
                session_id,
                received = session.received_chunks.len(),
                total = session.total_chunks,
                "received partial chunk"
            );
            None
        }
    }

    /// Clean up old sessions that might have timed out or failed
    pub fn cleanup_stale_sessions(&mut self, max_age: Duration) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        self.sessions.retain(|&session_id, _| {
            let session_age = now.saturating_sub(session_id / 1_000_000_000); // session_id is nanoseconds
            session_age < max_age.as_secs()
        });
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_client::Options as NodeClientOptions;

    #[tokio::test]
    async fn test_broadcast_sync_on_empty_update() {
        let client = NodeClient::new(&NodeClientOptions::default());
        let update = SyncUpdate::empty();
        let (tx, mut rx) = mpsc::channel(4);

        let participants = vec![
            (Participant::from(1u32), ParticipantInfo::new(1)),
            (Participant::from(2u32), ParticipantInfo::new(2)),
        ];

        broadcast_sync(
            client,
            update,
            participants.clone().into_iter(),
            tx,
            Participant::from(0u32),
        )
        .await;

        let mut received = Vec::new();
        for _ in 0..participants.len() {
            received.push(rx.recv().await.expect("missing synced participant"));
        }

        let expected: Vec<_> = participants.iter().map(|(p, _)| *p).collect();
        assert_eq!(received, expected);
        assert!(rx.recv().await.is_none());
    }
}
