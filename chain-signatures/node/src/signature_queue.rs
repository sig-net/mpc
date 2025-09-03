use crate::protocol::signature::IndexedSignRequest;
use mpc_primitives::SignId;
use cait_sith::protocol::Participant;
use std::collections::{HashMap, VecDeque, BTreeSet};
use tokio::sync::{mpsc, oneshot};
use serde::{Serialize, Deserialize};

/// Maximum number of sign requests that can be queued
const MAX_SIGN_REQUESTS: usize = 1024;

/// Status of a signature request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SignatureRequestStatus {
    Queued,
    InProgress, 
    Completed,
    Failed,
    Timeout,
}

/// A signature request with metadata
#[derive(Debug, Clone)]
pub struct SignatureRequest {
    pub indexed: IndexedSignRequest,
    pub status: SignatureRequestStatus,
    pub proposer: Participant,
    pub stable_participants: BTreeSet<Participant>,
    pub round: usize,
    pub created_at: u64,
    pub updated_at: u64,
    pub retry_count: u32,
}

/// Messages that can be sent to the SignQueue task
#[derive(Debug)]
pub enum SignQueueMessage {
    /// Add a new sign request from an indexer
    AddRequest {
        request: IndexedSignRequest,
        respond_to: Option<oneshot::Sender<SignQueueResult>>,
    },
    /// Get the next available request for signing (from SignatureSpawner)
    GetNextRequest {
        respond_to: oneshot::Sender<Option<SignatureRequest>>,
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
        respond_to: oneshot::Sender<Option<SignatureRequestStatus>>,
    },
    /// Get statistics about the queue
    GetStats {
        respond_to: oneshot::Sender<QueueStats>,
    },
    /// Update stable participants (called when consensus changes)
    UpdateStableParticipants {
        stable: BTreeSet<Participant>,
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
#[derive(Debug, Clone, Default)]
pub struct QueueStats {
    pub total_requests: usize,
    pub queued_requests: usize,
    pub in_progress_requests: usize,
    pub completed_requests: usize,
    pub failed_requests: usize,
    pub my_pending_requests: usize,
}

/// The SignQueue task that manages all signature requests
pub struct SignQueueTask {
    /// Our participant ID
    me: Participant,
    /// Channel to receive messages
    message_rx: mpsc::Receiver<SignQueueMessage>,
    /// All signature requests
    requests: HashMap<SignId, SignatureRequest>,
    /// Queue of my requests (where I'm the proposer)
    my_queue: VecDeque<SignId>,
    /// Failed requests that need to be retried
    failed_queue: VecDeque<SignId>,
    /// Current stable participants
    stable_participants: BTreeSet<Participant>,
}

impl SignQueueTask {
    /// Create a new SignQueue task
    pub fn new(
        me: Participant,
        message_rx: mpsc::Receiver<SignQueueMessage>,
        stable_participants: BTreeSet<Participant>,
    ) -> Self {
        Self {
            me,
            message_rx,
            requests: HashMap::new(),
            my_queue: VecDeque::new(),
            failed_queue: VecDeque::new(),
            stable_participants,
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
            SignQueueMessage::UpdateStableParticipants { stable } => {
                self.stable_participants = stable;
            }
        }
    }

    /// Add a new sign request to the queue
    async fn add_request(&mut self, indexed: IndexedSignRequest) -> SignQueueResult {
        let sign_id = indexed.id;
        
        // Check if we already have this request
        if self.requests.contains_key(&sign_id) {
            return SignQueueResult::Success;
        }

        // Check if queue is full
        if self.requests.len() >= MAX_SIGN_REQUESTS {
            return SignQueueResult::QueueFull;
        }

        // Organize the request to determine proposer
        let organized = self.organize_request(indexed.clone(), 0);
        let signature_request = SignatureRequest {
            indexed,
            status: SignatureRequestStatus::Queued,
            proposer: organized.proposer,
            stable_participants: organized.stable_participants,
            round: organized.round,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            updated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            retry_count: 0,
        };

        // Add to requests
        self.requests.insert(sign_id, signature_request);

        // Add to my queue if I'm the proposer
        if organized.proposer == self.me {
            self.my_queue.push_back(sign_id);
        }

        tracing::debug!(?sign_id, "Added sign request to queue");
        SignQueueResult::Success
    }

    /// Get the next available request for signing
    async fn get_next_request(&mut self) -> Option<SignatureRequest> {
        // First try failed requests
        if let Some(sign_id) = self.failed_queue.pop_front() {
            if let Some(mut request) = self.requests.get_mut(&sign_id) {
                request.status = SignatureRequestStatus::InProgress;
                request.updated_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                return Some(request.clone());
            }
        }

        // Then try my requests
        if let Some(sign_id) = self.my_queue.pop_front() {
            if let Some(mut request) = self.requests.get_mut(&sign_id) {
                request.status = SignatureRequestStatus::InProgress;
                request.updated_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                return Some(request.clone());
            }
        }

        None
    }

    /// Mark a request as completed
    async fn complete_request(&mut self, sign_id: SignId) -> SignQueueResult {
        if let Some(request) = self.requests.get_mut(&sign_id) {
            request.status = SignatureRequestStatus::Completed;
            request.updated_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            tracing::debug!(?sign_id, "Marked request as completed");
            SignQueueResult::Success
        } else {
            SignQueueResult::RequestNotFound
        }
    }

    /// Mark a request as failed and optionally retry
    async fn fail_request(&mut self, sign_id: SignId, retry: bool) -> SignQueueResult {
        if let Some(request) = self.requests.get_mut(&sign_id) {
            if retry && request.retry_count < 3 {
                request.status = SignatureRequestStatus::Queued;
                request.retry_count += 1;
                request.updated_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                
                // Add to failed queue for retry
                self.failed_queue.push_back(sign_id);
                tracing::debug!(?sign_id, retry_count = request.retry_count, "Request queued for retry");
            } else {
                request.status = SignatureRequestStatus::Failed;
                request.updated_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                tracing::debug!(?sign_id, "Marked request as failed");
            }
            SignQueueResult::Success
        } else {
            SignQueueResult::RequestNotFound
        }
    }

    /// Get the status of a specific request
    async fn get_request_status(&self, sign_id: SignId) -> Option<SignatureRequestStatus> {
        self.requests.get(&sign_id).map(|r| r.status.clone())
    }

    /// Get statistics about the queue
    async fn get_stats(&self) -> QueueStats {
        let mut stats = QueueStats::default();
        
        stats.total_requests = self.requests.len();
        stats.my_pending_requests = self.my_queue.len();

        for request in self.requests.values() {
            match request.status {
                SignatureRequestStatus::Queued => stats.queued_requests += 1,
                SignatureRequestStatus::InProgress => stats.in_progress_requests += 1,
                SignatureRequestStatus::Completed => stats.completed_requests += 1,
                SignatureRequestStatus::Failed | SignatureRequestStatus::Timeout => stats.failed_requests += 1,
            }
        }
        
        stats
    }

    /// Organize a request for signing (same logic as original SignQueue)
    fn organize_request(&self, indexed: IndexedSignRequest, initial_round: usize) -> OrganizedRequest {
        let participants = indexed.participants.clone().unwrap_or_else(|| {
            // Default participants if not specified
            self.stable_participants.iter().cloned().collect()
        });

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
            .find(|(_, proposer)| self.stable_participants.contains(proposer))
            .unwrap_or_else(|| {
                let round = initial_round;
                let proposer = proposer_per_round(round, &participants, &indexed.args.entropy);
                (round, proposer)
            });

        OrganizedRequest {
            proposer,
            stable_participants: self.stable_participants.clone(),
            round,
        }
    }
}

/// Helper struct for organizing requests
struct OrganizedRequest {
    proposer: Participant,
    stable_participants: BTreeSet<Participant>,
    round: usize,
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
    ) -> (Self, SignQueueTask) {
        let (message_tx, message_rx) = mpsc::channel(MAX_SIGN_REQUESTS);
        
        let task = SignQueueTask::new(me, message_rx, stable_participants);
        let handle = Self { message_tx };
        
        (handle, task)
    }

    /// Add a new sign request
    pub async fn add_request(&self, request: IndexedSignRequest) -> Result<(), mpsc::error::SendError<SignQueueMessage>> {
        let (tx, rx) = oneshot::channel();
        self.message_tx.send(SignQueueMessage::AddRequest {
            request,
            respond_to: Some(tx),
        }).await?;
        
        // Wait for response but don't propagate result errors for simplicity
        let _ = rx.await;
        Ok(())
    }

    /// Get the next available request for signing
    pub async fn get_next_request(&self) -> Result<Option<SignatureRequest>, mpsc::error::SendError<SignQueueMessage>> {
        let (tx, rx) = oneshot::channel();
        self.message_tx.send(SignQueueMessage::GetNextRequest {
            respond_to: tx,
        }).await?;
        
        Ok(rx.await.unwrap_or(None))
    }

    /// Mark a request as completed
    pub async fn complete_request(&self, sign_id: SignId) -> Result<(), mpsc::error::SendError<SignQueueMessage>> {
        let (tx, rx) = oneshot::channel();
        self.message_tx.send(SignQueueMessage::CompleteRequest {
            sign_id,
            respond_to: Some(tx),
        }).await?;
        
        let _ = rx.await;
        Ok(())
    }

    /// Mark a request as failed
    pub async fn fail_request(&self, sign_id: SignId, retry: bool) -> Result<(), mpsc::error::SendError<SignQueueMessage>> {
        let (tx, rx) = oneshot::channel();
        self.message_tx.send(SignQueueMessage::FailRequest {
            sign_id,
            retry,
            respond_to: Some(tx),
        }).await?;
        
        let _ = rx.await;
        Ok(())
    }

    /// Get status of a specific request
    pub async fn get_request_status(&self, sign_id: SignId) -> Result<Option<SignatureRequestStatus>, mpsc::error::SendError<SignQueueMessage>> {
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

    /// Update stable participants
    pub async fn update_stable_participants(&self, stable: BTreeSet<Participant>) -> Result<(), mpsc::error::SendError<SignQueueMessage>> {
        self.message_tx.send(SignQueueMessage::UpdateStableParticipants {
            stable,
        }).await
    }
}
