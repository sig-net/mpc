use crate::pending_requests::{PendingRequests, RequestId, Request, RequestStatus};
use crate::protocol::signature::{IndexedSignRequest, SignId};
use std::collections::{HashMap, VecDeque, BTreeSet};
use tokio::sync::{mpsc, oneshot};
use cait_sith::protocol::Participant;
use mpc_primitives::Participants;

/// Maximum number of sign requests that can be queued
const MAX_SIGN_REQUESTS: usize = 1024;

/// Maximum number of pending requests per channel
const MAX_PENDING_REQUESTS: usize = 512;

/// Messages that can be sent to the SignQueue task
#[derive(Debug)]
pub enum SignQueueMessage {
    /// Add a new sign request from an indexer
    AddRequest {
        request: IndexedSignRequest,
        /// Response channel to notify when request is processed
        respond_to: Option<oneshot::Sender<SignQueueResult>>,
    },
    /// Get the next available request for signing (from SignatureSpawner)
    GetNextRequest {
        respond_to: oneshot::Sender<Option<QueuedSignRequest>>,
    },
    /// Mark a request as completed
    CompleteRequest {
        sign_id: SignId,
        respond_to: Option<oneshot::Sender<SignQueueResult>>,
    },
    /// Mark a request as failed and potentially retry
    FailRequest {
        sign_id: SignId,
        retry: bool,
        respond_to: Option<oneshot::Sender<SignQueueResult>>,
    },
    /// Get status of a specific request
    GetRequestStatus {
        sign_id: SignId,
        respond_to: oneshot::Sender<Option<RequestStatus>>,
    },
    /// Get statistics about the queue
    GetStats {
        respond_to: oneshot::Sender<QueueStats>,
    },
}

/// Result type for SignQueue operations
#[derive(Debug)]
pub enum SignQueueResult {
    Success,
    RequestNotFound,
    QueueFull,
    InvalidRequest,
}

/// Statistics about the SignQueue state
#[derive(Debug, Clone)]
pub struct QueueStats {
    pub total_requests: usize,
    pub pending_requests: usize,
    pub in_progress_requests: usize,
    pub completed_requests: usize,
    pub failed_requests: usize,
    pub my_pending_requests: usize,
}

/// A request that's ready to be processed by the SignatureSpawner
#[derive(Debug, Clone)]
pub struct QueuedSignRequest {
    pub indexed: IndexedSignRequest,
    pub proposer: Participant,
    pub stable: BTreeSet<Participant>,
    pub round: usize,
}

/// The SignQueue task that manages all signature requests using PendingRequests
pub struct SignQueueTask {
    /// Our participant ID
    me: Participant,
    /// Channel to receive messages
    message_rx: mpsc::Receiver<SignQueueMessage>,
    /// Pending requests manager
    pending_requests: PendingRequests,
    /// Queue of my requests (where I'm the proposer)
    my_requests: VecDeque<SignId>,
    /// Failed requests that need to be retried
    failed_requests: VecDeque<SignId>,
    /// Mapping from SignId to RequestId for tracking
    sign_to_request_map: HashMap<SignId, RequestId>,
    /// Mapping from RequestId to SignId for reverse lookup
    request_to_sign_map: HashMap<RequestId, SignId>,
    /// Current stable participants
    stable_participants: BTreeSet<Participant>,
    /// All participants
    participants: Participants,
}

impl SignQueueTask {
    /// Create a new SignQueue task
    pub fn new(
        me: Participant,
        message_rx: mpsc::Receiver<SignQueueMessage>,
        stable_participants: BTreeSet<Participant>,
        participants: Participants,
    ) -> Self {
        Self {
            me,
            message_rx,
            pending_requests: PendingRequests::new(),
            my_requests: VecDeque::new(),
            failed_requests: VecDeque::new(),
            sign_to_request_map: HashMap::new(),
            request_to_sign_map: HashMap::new(),
            stable_participants,
            participants,
        }
    }

    /// Run the SignQueue task
    pub async fn run(mut self) {
        tracing::info!("SignQueue task started");
        
        while let Some(message) = self.message_rx.recv().await {
            self.handle_message(message).await;
        }
        
        tracing::info!("SignQueue task stopped");
    }

    /// Handle a single message
    async fn handle_message(&mut self, message: SignQueueMessage) {
        match message {
            SignQueueMessage::AddRequest { request, respond_to } => {
                let result = self.add_request(request).await;
                if let Some(tx) = respond_to {
                    let _ = tx.send(result);
                }
            }
            SignQueueMessage::GetNextRequest { respond_to } => {
                let request = self.get_next_request().await;
                let _ = respond_to.send(request);
            }
            SignQueueMessage::CompleteRequest { sign_id, respond_to } => {
                let result = self.complete_request(sign_id).await;
                if let Some(tx) = respond_to {
                    let _ = tx.send(result);
                }
            }
            SignQueueMessage::FailRequest { sign_id, retry, respond_to } => {
                let result = self.fail_request(sign_id, retry).await;
                if let Some(tx) = respond_to {
                    let _ = tx.send(result);
                }
            }
            SignQueueMessage::GetRequestStatus { sign_id, respond_to } => {
                let status = self.get_request_status(sign_id).await;
                let _ = respond_to.send(status);
            }
            SignQueueMessage::GetStats { respond_to } => {
                let stats = self.get_stats().await;
                let _ = respond_to.send(stats);
            }
        }
    }

    /// Add a new sign request to the queue
    async fn add_request(&mut self, indexed: IndexedSignRequest) -> SignQueueResult {
        let sign_id = indexed.id;
        
        // Check if we already have this request
        if self.sign_to_request_map.contains_key(&sign_id) {
            return SignQueueResult::Success;
        }

        // Create a Request from IndexedSignRequest
        let request = Request {
            id: RequestId::from_sign_id(sign_id),
            sign_id: Some(sign_id),
            payload: bincode::serialize(&indexed).unwrap_or_default(),
            status: RequestStatus::Pending,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            updated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            retry_count: 0,
            max_retries: 3,
            dependencies: Vec::new(),
            metadata: HashMap::new(),
        };

        // Add to pending requests
        let request_id = request.id;
        if let Err(e) = self.pending_requests.add_request(request).await {
            tracing::error!("Failed to add request to pending requests: {e}");
            return SignQueueResult::InvalidRequest;
        }

        // Update mappings
        self.sign_to_request_map.insert(sign_id, request_id);
        self.request_to_sign_map.insert(request_id, sign_id);

        // Determine if this is our request to propose
        let organized = self.organize_request(&self.stable_participants, &self.participants, indexed, 0);
        if organized.proposer == self.me {
            self.my_requests.push_back(sign_id);
        }

        tracing::debug!(?sign_id, ?request_id, "Added sign request to queue");
        SignQueueResult::Success
    }

    /// Get the next available request for signing
    async fn get_next_request(&mut self) -> Option<QueuedSignRequest> {
        // First try failed requests
        if let Some(sign_id) = self.failed_requests.pop_front() {
            if let Some(request) = self.build_queued_request(sign_id, 1).await {
                return Some(request);
            }
        }

        // Then try my requests
        if let Some(sign_id) = self.my_requests.pop_front() {
            if let Some(request) = self.build_queued_request(sign_id, 0).await {
                return Some(request);
            }
        }

        None
    }

    /// Build a QueuedSignRequest from a SignId
    async fn build_queued_request(&mut self, sign_id: SignId, round: usize) -> Option<QueuedSignRequest> {
        let request_id = self.sign_to_request_map.get(&sign_id)?;
        let request = self.pending_requests.get_request(*request_id).await.ok()??;
        
        // Deserialize the IndexedSignRequest
        let indexed: IndexedSignRequest = bincode::deserialize(&request.payload).ok()?;
        
        // Mark as in progress
        if let Err(e) = self.pending_requests.update_status(*request_id, RequestStatus::InProgress).await {
            tracing::error!("Failed to update request status: {e}");
            return None;
        }

        // Organize the request
        let organized = self.organize_request(&self.stable_participants, &self.participants, indexed, round);
        
        Some(organized)
    }

    /// Mark a request as completed
    async fn complete_request(&mut self, sign_id: SignId) -> SignQueueResult {
        let Some(request_id) = self.sign_to_request_map.get(&sign_id) else {
            return SignQueueResult::RequestNotFound;
        };

        if let Err(e) = self.pending_requests.update_status(*request_id, RequestStatus::Completed).await {
            tracing::error!("Failed to mark request as completed: {e}");
            return SignQueueResult::InvalidRequest;
        }

        tracing::debug!(?sign_id, "Marked request as completed");
        SignQueueResult::Success
    }

    /// Mark a request as failed and optionally retry
    async fn fail_request(&mut self, sign_id: SignId, retry: bool) -> SignQueueResult {
        let Some(request_id) = self.sign_to_request_map.get(&sign_id) else {
            return SignQueueResult::RequestNotFound;
        };

        if retry {
            // Add to failed requests for retry
            self.failed_requests.push_back(sign_id);
            
            if let Err(e) = self.pending_requests.update_status(*request_id, RequestStatus::Pending).await {
                tracing::error!("Failed to update request status for retry: {e}");
                return SignQueueResult::InvalidRequest;
            }
        } else {
            if let Err(e) = self.pending_requests.update_status(*request_id, RequestStatus::Failed).await {
                tracing::error!("Failed to mark request as failed: {e}");
                return SignQueueResult::InvalidRequest;
            }
        }

        tracing::debug!(?sign_id, retry, "Marked request as failed");
        SignQueueResult::Success
    }

    /// Get the status of a specific request
    async fn get_request_status(&self, sign_id: SignId) -> Option<RequestStatus> {
        let request_id = self.sign_to_request_map.get(&sign_id)?;
        let request = self.pending_requests.get_request(*request_id).await.ok()??;
        Some(request.status)
    }

    /// Get statistics about the queue
    async fn get_stats(&self) -> QueueStats {
        let stats = self.pending_requests.get_stats().await.unwrap_or_default();
        
        QueueStats {
            total_requests: self.sign_to_request_map.len(),
            pending_requests: stats.pending_requests,
            in_progress_requests: stats.in_progress_requests,
            completed_requests: stats.completed_requests,
            failed_requests: stats.failed_requests,
            my_pending_requests: self.my_requests.len(),
        }
    }

    /// Organize a request for signing (same logic as original SignQueue)
    fn organize_request(
        &self,
        stable: &BTreeSet<Participant>,
        participants: &Participants,
        indexed: IndexedSignRequest,
        initial_round: usize,
    ) -> QueuedSignRequest {
        let sign_id = indexed.id;
        let mut participants = if indexed.participants.is_some() {
            indexed.participants.clone().unwrap()
        } else {
            participants.keys().cloned().collect()
        };
        participants.sort();

        // Simple round-robin selection of the proposer
        fn proposer_per_round(
            round: usize,
            participants: &[Participant],
            entropy: &[u8; 32],
        ) -> Participant {
            let index = entropy[0] as usize + round;
            participants[index % participants.len()]
        }

        let max_rounds = initial_round + 512;
        // Use the smallest round that selects a stable proposer
        let (round, proposer) = (initial_round..max_rounds)
            .map(|round| {
                (
                    round,
                    proposer_per_round(round, &participants, &indexed.args.entropy),
                )
            })
            .find(|(_, proposer)| stable.contains(proposer))
            .unwrap_or_else(|| {
                let round = initial_round;
                let proposer = proposer_per_round(round, &participants, &indexed.args.entropy);
                (round, proposer)
            });

        QueuedSignRequest {
            indexed,
            proposer,
            stable: stable.clone(),
            round,
        }
    }

    /// Update stable participants (called when consensus changes)
    pub fn update_stable_participants(&mut self, stable: BTreeSet<Participant>) {
        self.stable_participants = stable;
    }

    /// Update all participants (called when participants change)
    pub fn update_participants(&mut self, participants: Participants) {
        self.participants = participants;
    }
}

/// Handle for communicating with the SignQueue task
#[derive(Clone)]
pub struct SignQueueHandle {
    message_tx: mpsc::Sender<SignQueueMessage>,
}

impl SignQueueHandle {
    /// Create a new SignQueue handle and task
    pub fn new(
        me: Participant,
        stable_participants: BTreeSet<Participant>,
        participants: Participants,
    ) -> (Self, SignQueueTask) {
        let (message_tx, message_rx) = mpsc::channel(MAX_SIGN_REQUESTS);
        
        let task = SignQueueTask::new(me, message_rx, stable_participants, participants);
        let handle = Self { message_tx };
        
        (handle, task)
    }

    /// Add a new sign request
    pub async fn add_request(&self, request: IndexedSignRequest) -> Result<SignQueueResult, mpsc::error::SendError<SignQueueMessage>> {
        let (tx, rx) = oneshot::channel();
        self.message_tx.send(SignQueueMessage::AddRequest {
            request,
            respond_to: Some(tx),
        }).await?;
        
        Ok(rx.await.unwrap_or(SignQueueResult::InvalidRequest))
    }

    /// Get the next available request for signing
    pub async fn get_next_request(&self) -> Result<Option<QueuedSignRequest>, mpsc::error::SendError<SignQueueMessage>> {
        let (tx, rx) = oneshot::channel();
        self.message_tx.send(SignQueueMessage::GetNextRequest {
            respond_to: tx,
        }).await?;
        
        Ok(rx.await.unwrap_or(None))
    }

    /// Mark a request as completed
    pub async fn complete_request(&self, sign_id: SignId) -> Result<SignQueueResult, mpsc::error::SendError<SignQueueMessage>> {
        let (tx, rx) = oneshot::channel();
        self.message_tx.send(SignQueueMessage::CompleteRequest {
            sign_id,
            respond_to: Some(tx),
        }).await?;
        
        Ok(rx.await.unwrap_or(SignQueueResult::InvalidRequest))
    }

    /// Mark a request as failed
    pub async fn fail_request(&self, sign_id: SignId, retry: bool) -> Result<SignQueueResult, mpsc::error::SendError<SignQueueMessage>> {
        let (tx, rx) = oneshot::channel();
        self.message_tx.send(SignQueueMessage::FailRequest {
            sign_id,
            retry,
            respond_to: Some(tx),
        }).await?;
        
        Ok(rx.await.unwrap_or(SignQueueResult::InvalidRequest))
    }

    /// Get status of a specific request
    pub async fn get_request_status(&self, sign_id: SignId) -> Result<Option<RequestStatus>, mpsc::error::SendError<SignQueueMessage>> {
        let (tx, rx) = oneshot::channel();
        self.message_tx.send(SignQueueMessage::GetRequestStatus {
            sign_id,
            respond_to: tx,
        }).await?;
        
        Ok(rx.await.unwrap_or(None))
    }

    /// Get queue statistics
    pub async fn get_stats(&self) -> Result<QueueStats, mpsc::error::SendError<SignQueueMessage>> {
        let (tx, rx) = oneshot::channel();
        self.message_tx.send(SignQueueMessage::GetStats {
            respond_to: tx,
        }).await?;
        
        Ok(rx.await.unwrap_or_default())
    }
}

impl Default for QueueStats {
    fn default() -> Self {
        Self {
            total_requests: 0,
            pending_requests: 0,
            in_progress_requests: 0,
            completed_requests: 0,
            failed_requests: 0,
            my_pending_requests: 0,
        }
    }
}

/// Extension trait for RequestId to convert from SignId
impl RequestId {
    pub fn from_sign_id(sign_id: SignId) -> Self {
        // Convert SignId bytes to RequestId format
        RequestId(sign_id.0)
    }
}
