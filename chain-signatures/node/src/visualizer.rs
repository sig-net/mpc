use crate::protocol::SignRequestType;
use mpc_primitives::SignId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SignRequestStatus {
    InPosits,
    Generating,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequestLifecycleEvent {
    pub sign_id: SignId,
    pub status: SignRequestStatus,
    pub sign_request_type: SignRequestTypeView,
    pub timestamp: u64, // Unix timestamp in milliseconds
    pub messages_sent: usize,
    pub messages_received: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SignRequestTypeView {
    Sign,
    SignBidirectional,
    RespondBidirectional,
}

impl From<&SignRequestType> for SignRequestTypeView {
    fn from(value: &SignRequestType) -> Self {
        match value {
            SignRequestType::Sign => SignRequestTypeView::Sign,
            SignRequestType::SignBidirectional(_) => SignRequestTypeView::SignBidirectional,
            SignRequestType::RespondBidirectional(_) => SignRequestTypeView::RespondBidirectional,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SignRequestTracking {
    pub sign_id: SignId,
    pub sign_request_type: SignRequestTypeView,
    pub status: SignRequestStatus,
    pub status_timestamp: Instant,
    pub started: Instant,
    pub messages_sent: usize,
    pub messages_received: usize,
    pub last_action: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequestView {
    pub sign_id: SignId,
    pub sign_request_type: SignRequestTypeView,
    pub status: SignRequestStatus,
    pub time_in_status_ms: u64,
    pub time_since_last_action_ms: u64,
    pub messages_sent: usize,
    pub messages_received: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedSignRequestView {
    pub sign_id: SignId,
    pub sign_request_type: SignRequestTypeView,
    pub total_time_ms: u64,
    pub messages_sent: usize,
    pub messages_received: usize,
}

#[derive(Debug, Clone, Default)]
pub struct VisualizerState {
    active_requests: Arc<RwLock<HashMap<SignId, SignRequestTracking>>>,
    completed_requests: Arc<RwLock<Vec<CompletedSignRequestView>>>,
}

impl VisualizerState {
    pub fn new() -> Self {
        Self {
            active_requests: Arc::new(RwLock::new(HashMap::new())),
            completed_requests: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn start_request(
        &self,
        sign_id: SignId,
        sign_request_type: SignRequestTypeView,
        status: SignRequestStatus,
    ) {
        let now = Instant::now();
        let tracking = SignRequestTracking {
            sign_id,
            sign_request_type,
            status,
            status_timestamp: now,
            started: now,
            messages_sent: 0,
            messages_received: 0,
            last_action: now,
        };
        self.active_requests.write().await.insert(sign_id, tracking);
    }

    pub async fn update_status(&self, sign_id: SignId, status: SignRequestStatus) {
        if let Some(tracking) = self.active_requests.write().await.get_mut(&sign_id) {
            tracking.status = status;
            tracking.status_timestamp = Instant::now();
            tracking.last_action = Instant::now();
        }
    }

    pub async fn increment_messages_sent(&self, sign_id: SignId) {
        if let Some(tracking) = self.active_requests.write().await.get_mut(&sign_id) {
            tracking.messages_sent += 1;
            tracking.last_action = Instant::now();
        }
    }

    pub async fn increment_messages_received(&self, sign_id: SignId) {
        if let Some(tracking) = self.active_requests.write().await.get_mut(&sign_id) {
            tracking.messages_received += 1;
            tracking.last_action = Instant::now();
        }
    }

    pub async fn complete_request(&self, sign_id: SignId) {
        if let Some(tracking) = self.active_requests.write().await.remove(&sign_id) {
            let total_time_ms = tracking.started.elapsed().as_millis() as u64;
            let completed = CompletedSignRequestView {
                sign_id,
                sign_request_type: tracking.sign_request_type,
                total_time_ms,
                messages_sent: tracking.messages_sent,
                messages_received: tracking.messages_received,
            };
            self.completed_requests.write().await.push(completed);
        }
    }

    pub async fn get_active_requests(&self) -> Vec<SignRequestView> {
        let now = Instant::now();
        self.active_requests
            .read()
            .await
            .values()
            .map(|tracking| SignRequestView {
                sign_id: tracking.sign_id,
                sign_request_type: tracking.sign_request_type.clone(),
                status: tracking.status.clone(),
                time_in_status_ms: tracking.status_timestamp.elapsed().as_millis() as u64,
                time_since_last_action_ms: tracking.last_action.elapsed().as_millis() as u64,
                messages_sent: tracking.messages_sent,
                messages_received: tracking.messages_received,
            })
            .collect()
    }

    pub async fn get_completed_requests(&self) -> Vec<CompletedSignRequestView> {
        self.completed_requests.read().await.clone()
    }

    pub async fn clear_completed_requests(&self) {
        self.completed_requests.write().await.clear();
    }
}
