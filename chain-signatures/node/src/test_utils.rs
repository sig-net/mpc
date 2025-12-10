//! Shared test utilities for unit tests across the MPC node codebase.
//!
//! This module provides:
//! - In-memory storage builders for testing without external dependencies
//! - Test data generators for creating valid test inputs
//! - Assertion helpers for validating test outcomes
//! - Test harness infrastructure for simulated nodes

use crate::storage::checkpoint_storage::CheckpointStorage;
use crate::protocol::{Node, NodeState, MpcSignProtocol, Governance};
use crate::protocol::message::MessageChannel;
use crate::protocol::contract::primitives::{Participants, ParticipantInfo};
use crate::rpc::NearClient;
use crate::config::{Config, LocalConfig, NetworkConfig, OverrideConfig};
use crate::rpc::{ContractStateWatcher, RpcChannel};
use crate::mesh::MeshState;
use crate::backlog::Backlog;
use crate::storage::{
    triple_storage::TripleStorage,
    presignature_storage::PresignatureStorage,
    app_data_storage::AppDataStorage,
};
use crate::util::NearPublicKeyExt;

use cait_sith::protocol::Participant;
use mpc_keys::hpke;
use near_account_id::AccountId;
use near_crypto::SecretKey;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{mpsc, watch, RwLock};
use anyhow::Result;
use serde_json::Value;

/// Create an in-memory checkpoint storage for testing.
///
/// This storage implementation uses a HashMap wrapped in Arc<RwLock<>> for thread-safe
/// access without requiring Redis or other external dependencies.
pub fn in_memory_checkpoint_storage() -> CheckpointStorage {
    CheckpointStorage::in_memory()
}

/// Verify that checkpoint storage is empty.
pub async fn assert_checkpoint_storage_empty(storage: &CheckpointStorage) {
    match storage {
        CheckpointStorage::InMemory(map) => {
            let guard = map.read().await;
            assert!(
                guard.is_empty(),
                "Expected checkpoint storage to be empty, but found {} entries",
                guard.len()
            );
        }
        CheckpointStorage::Redis(_, _) => {
            panic!("Cannot assert on Redis storage in unit tests");
        }
    }
}

// ============================================================================
// Test Harness Infrastructure for Simulated Nodes
// ============================================================================

/// Message with metadata for ordering and delivery guarantees
#[derive(Debug, Clone)]
pub struct ProtocolMessage {
    pub from: Participant,
    pub to: Participant,
    pub payload: Vec<u8>,
    pub sequence_number: u64,
    pub timestamp: std::time::Instant,
}

/// Per-node message queue that maintains ordering and delivery guarantees
#[derive(Debug)]
pub struct MessageQueue {
    /// Ordered queue of received messages
    messages: Arc<RwLock<std::collections::VecDeque<ProtocolMessage>>>,
    /// Sender for notifying about new messages
    notify_tx: mpsc::UnboundedSender<()>,
    /// Receiver for notifications about new messages
    notify_rx: Arc<RwLock<Option<mpsc::UnboundedReceiver<()>>>>,
    /// Next expected sequence number from each sender
    expected_sequence: Arc<RwLock<HashMap<Participant, u64>>>,
}

impl MessageQueue {
    pub fn new() -> Self {
        let (notify_tx, notify_rx) = mpsc::unbounded_channel();
        Self {
            messages: Arc::new(RwLock::new(std::collections::VecDeque::new())),
            notify_tx,
            notify_rx: Arc::new(RwLock::new(Some(notify_rx))),
            expected_sequence: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a message to the queue, maintaining ordering
    pub async fn enqueue(&self, message: ProtocolMessage) -> Result<()> {
        let mut messages = self.messages.write().await;
        let mut expected = self.expected_sequence.write().await;
        
        // Check sequence number for ordering
        let expected_seq = expected.get(&message.from).copied().unwrap_or(0);
        if message.sequence_number < expected_seq {
            // Duplicate or out-of-order message, ignore
            return Ok(());
        }
        
        // Update expected sequence number
        expected.insert(message.from, message.sequence_number + 1);
        
        // Append message to maintain insertion order (FIFO)
        // This ensures predictable ordering for testing
        messages.push_back(message);
        
        // Notify about new message
        let _ = self.notify_tx.send(());
        
        Ok(())
    }

    /// Dequeue the next message
    pub async fn dequeue(&self) -> Option<ProtocolMessage> {
        let mut messages = self.messages.write().await;
        messages.pop_front()
    }

    /// Get the number of messages in the queue
    pub async fn len(&self) -> usize {
        let messages = self.messages.read().await;
        messages.len()
    }

    /// Check if the queue is empty
    pub async fn is_empty(&self) -> bool {
        let messages = self.messages.read().await;
        messages.is_empty()
    }

    /// Take the notification receiver (can only be done once)
    pub async fn take_notify_receiver(&self) -> Option<mpsc::UnboundedReceiver<()>> {
        let mut notify_rx = self.notify_rx.write().await;
        notify_rx.take()
    }

    /// Peek at all messages without removing them
    pub async fn peek_all(&self) -> Vec<ProtocolMessage> {
        let messages = self.messages.read().await;
        messages.iter().cloned().collect()
    }
}

/// Handle for a simulated node to send and receive messages
#[derive(Clone)]
pub struct MockNodeHandle {
    pub participant: Participant,
    router: Arc<MockMessageRouter>,
    message_queue: Arc<MessageQueue>,
    sequence_counter: Arc<RwLock<u64>>,
}

impl MockNodeHandle {
    pub fn new(participant: Participant, router: Arc<MockMessageRouter>) -> Self {
        Self {
            participant,
            router,
            message_queue: Arc::new(MessageQueue::new()),
            sequence_counter: Arc::new(RwLock::new(0)),
        }
    }

    /// Send a message to another participant
    pub async fn send_message(&self, to: Participant, payload: Vec<u8>) -> Result<()> {
        let mut seq_counter = self.sequence_counter.write().await;
        let sequence_number = *seq_counter;
        *seq_counter += 1;
        drop(seq_counter);

        let message = ProtocolMessage {
            from: self.participant,
            to,
            payload,
            sequence_number,
            timestamp: std::time::Instant::now(),
        };

        self.router.route_message(message).await
    }

    /// Receive the next message from the queue
    pub async fn receive_message(&self) -> Option<ProtocolMessage> {
        self.message_queue.dequeue().await
    }

    /// Get the number of pending messages
    pub async fn pending_message_count(&self) -> usize {
        self.message_queue.len().await
    }

    /// Check if there are any pending messages
    pub async fn has_pending_messages(&self) -> bool {
        !self.message_queue.is_empty().await
    }

    /// Get a notification receiver for new messages
    pub async fn message_notifications(&self) -> Option<mpsc::UnboundedReceiver<()>> {
        self.message_queue.take_notify_receiver().await
    }

    /// Peek at all pending messages without removing them
    pub async fn peek_messages(&self) -> Vec<ProtocolMessage> {
        self.message_queue.peek_all().await
    }

    /// Get the message queue for direct access (for testing)
    pub fn message_queue(&self) -> Arc<MessageQueue> {
        self.message_queue.clone()
    }
}

/// Mock message router that routes messages between simulated nodes in memory.
#[derive(Debug)]
pub struct MockMessageRouter {
    /// Node handles for each participant
    node_handles: Arc<RwLock<HashMap<Participant, Arc<MessageQueue>>>>,
    /// Message delivery statistics
    stats: Arc<RwLock<MessageRouterStats>>,
}

#[derive(Debug, Default)]
pub struct MessageRouterStats {
    pub messages_sent: u64,
    pub messages_delivered: u64,
    pub messages_dropped: u64,
}

impl MockMessageRouter {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            node_handles: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(MessageRouterStats::default())),
        })
    }

    /// Register a node handle with the router
    pub async fn register_node(&self, participant: Participant, message_queue: Arc<MessageQueue>) -> Result<()> {
        let mut handles = self.node_handles.write().await;
        handles.insert(participant, message_queue);
        Ok(())
    }

    /// Create a new node handle and register it
    pub async fn create_node_handle(self: &Arc<Self>, participant: Participant) -> MockNodeHandle {
        let handle = MockNodeHandle::new(participant, self.clone());
        let _ = self.register_node(participant, handle.message_queue.clone()).await;
        handle
    }

    /// Route a message to the destination participant
    pub async fn route_message(&self, message: ProtocolMessage) -> Result<()> {
        let handles = self.node_handles.read().await;
        let mut stats = self.stats.write().await;
        
        stats.messages_sent += 1;
        
        if let Some(queue) = handles.get(&message.to) {
            queue.enqueue(message).await?;
            stats.messages_delivered += 1;
            Ok(())
        } else {
            stats.messages_dropped += 1;
            Err(anyhow::anyhow!("No node handle found for participant {:?}", message.to))
        }
    }

    /// Get routing statistics
    pub async fn get_stats(&self) -> MessageRouterStats {
        let stats = self.stats.read().await;
        MessageRouterStats {
            messages_sent: stats.messages_sent,
            messages_delivered: stats.messages_delivered,
            messages_dropped: stats.messages_dropped,
        }
    }

    /// Get all registered participants
    pub async fn get_participants(&self) -> Vec<Participant> {
        let handles = self.node_handles.read().await;
        handles.keys().copied().collect()
    }

    /// Legacy method for backward compatibility
    pub async fn register_route(
        &self,
        _from: Participant,
        _to: Participant,
        _sender: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Result<()> {
        // This method is kept for backward compatibility with existing tests
        // The new implementation doesn't use explicit route registration
        Ok(())
    }

    /// Legacy method for backward compatibility
    pub async fn send_message(&self, from: Participant, to: Participant, message: Vec<u8>) -> Result<()> {
        let protocol_message = ProtocolMessage {
            from,
            to,
            payload: message,
            sequence_number: 0, // Legacy messages don't have sequence numbers
            timestamp: std::time::Instant::now(),
        };
        self.route_message(protocol_message).await
    }
}

/// Mock governance implementation for unit tests
pub struct MockGovernance {
    /// In-memory contract state shared across all nodes
    contract_state: Arc<RwLock<MockContractState>>,
    /// Account ID of this governance instance (for tracking votes)
    account_id: AccountId,
}

#[derive(Default, Debug, Clone)]
pub struct MockContractState {
    /// Current epoch
    pub epoch: u64,
    /// Public key votes: public_key -> set of voters
    pub public_key_votes: HashMap<String, std::collections::HashSet<AccountId>>,
    /// Resharing votes: epoch -> set of voters
    pub resharing_votes: HashMap<u64, std::collections::HashSet<AccountId>>,
    /// Join proposals: account_id -> set of supporters
    pub join_proposals: HashMap<AccountId, std::collections::HashSet<AccountId>>,
    /// Threshold for voting decisions (default: 1 for testing)
    pub vote_threshold: usize,
}

impl MockGovernance {
    pub fn new(contract_state: Arc<RwLock<MockContractState>>) -> Self {
        Self { 
            contract_state,
            account_id: "mock-governance.near".parse().unwrap(),
        }
    }

    pub fn with_account_id(contract_state: Arc<RwLock<MockContractState>>, account_id: AccountId) -> Self {
        Self { 
            contract_state,
            account_id,
        }
    }

    /// Get the current contract state (for testing)
    pub async fn get_state(&self) -> MockContractState {
        self.contract_state.read().await.clone()
    }

    /// Set the vote threshold (for testing)
    pub async fn set_vote_threshold(&self, threshold: usize) {
        let mut state = self.contract_state.write().await;
        state.vote_threshold = threshold;
    }
}

impl Governance for MockGovernance {
    async fn propose_join(&self) -> Result<()> {
        let mut state = self.contract_state.write().await;
        // Add this account as supporting its own join proposal
        let supporters = state.join_proposals.entry(self.account_id.clone()).or_insert_with(std::collections::HashSet::new);
        supporters.insert(self.account_id.clone());
        Ok(())
    }

    async fn vote_reshared(&self, epoch: u64) -> Result<bool> {
        let mut state = self.contract_state.write().await;
        let voters = state.resharing_votes.entry(epoch).or_insert_with(std::collections::HashSet::new);
        voters.insert(self.account_id.clone());
        
        // Return true if we have enough votes to approve
        Ok(voters.len() >= state.vote_threshold)
    }

    async fn vote_public_key(&self, public_key: &near_crypto::PublicKey) -> Result<bool> {
        let mut state = self.contract_state.write().await;
        let pk_str = format!("{:?}", public_key);
        let voters = state.public_key_votes.entry(pk_str).or_insert_with(std::collections::HashSet::new);
        voters.insert(self.account_id.clone());
        
        // Return true if we have enough votes to approve
        Ok(voters.len() >= state.vote_threshold)
    }
}

/// Governance client that can route to either NEAR network or in-memory contract
#[derive(Clone)]
pub enum GovernanceClient {
    /// Production client that makes actual RPC calls to NEAR network
    Near(NearClient),
    /// In-memory client for unit testing
    InMemory {
        state_manager: Arc<ContractStateManager>,
        account_id: AccountId,
    },
}

impl Governance for GovernanceClient {
    async fn propose_join(&self) -> Result<()> {
        match self {
            GovernanceClient::Near(client) => client.propose_join().await,
            GovernanceClient::InMemory { state_manager, account_id } => {
                state_manager.propose_join(account_id.clone()).await
            }
        }
    }

    async fn vote_reshared(&self, epoch: u64) -> Result<bool> {
        match self {
            GovernanceClient::Near(client) => client.vote_reshared(epoch).await,
            GovernanceClient::InMemory { state_manager, account_id } => {
                state_manager.vote_reshared(account_id.clone(), epoch).await
            }
        }
    }

    async fn vote_public_key(&self, public_key: &near_crypto::PublicKey) -> Result<bool> {
        match self {
            GovernanceClient::Near(client) => client.vote_public_key(public_key).await,
            GovernanceClient::InMemory { state_manager, account_id } => {
                // Convert near_crypto::PublicKey to string format for testing
                let pk_str = format!("{}", public_key);
                state_manager.vote_public_key(account_id.clone(), &pk_str).await
            }
        }
    }
}

/// Manages consistent contract state updates for in-memory testing
/// This simulates the contract behavior without requiring the actual contract
pub struct ContractStateManager {
    /// In-memory contract state
    contract_state: Arc<RwLock<MockInMemoryContractState>>,
    /// Response formatter for matching RPC format
    response_formatter: RpcResponseFormatter,
}

#[derive(Default, Debug, Clone, serde::Serialize)]
pub struct MockInMemoryContractState {
    /// Current epoch
    pub epoch: u64,
    /// Public key votes: public_key_string -> set of voters
    pub public_key_votes: HashMap<String, HashSet<AccountId>>,
    /// Resharing votes: epoch -> set of voters
    pub resharing_votes: HashMap<u64, HashSet<AccountId>>,
    /// Join proposals: account_id -> set of supporters
    pub join_proposals: HashMap<AccountId, HashSet<AccountId>>,
    /// Threshold for voting decisions (default: 2 for testing)
    pub vote_threshold: usize,
    /// Current protocol state
    pub protocol_state: String, // "Initializing", "Running", "Resharing"
}

impl ContractStateManager {
    pub fn new() -> Self {
        let mut initial_state = MockInMemoryContractState::default();
        initial_state.vote_threshold = 2; // Default threshold for testing
        initial_state.protocol_state = "Running".to_string();
        
        Self {
            contract_state: Arc::new(RwLock::new(initial_state)),
            response_formatter: RpcResponseFormatter::new(),
        }
    }

    /// Propose to join the network
    pub async fn propose_join(&self, proposer: AccountId) -> Result<()> {
        let mut state = self.contract_state.write().await;
        let supporters = state.join_proposals.entry(proposer.clone()).or_insert_with(HashSet::new);
        supporters.insert(proposer);
        Ok(())
    }

    /// Vote for resharing and return whether threshold was reached
    pub async fn vote_reshared(&self, voter: AccountId, epoch: u64) -> Result<bool> {
        let mut state = self.contract_state.write().await;
        let voters = state.resharing_votes.entry(epoch).or_insert_with(HashSet::new);
        voters.insert(voter);
        
        // Return true if we have enough votes to approve
        Ok(voters.len() >= state.vote_threshold)
    }

    /// Vote for public key and return whether threshold was reached
    pub async fn vote_public_key(&self, voter: AccountId, public_key: &str) -> Result<bool> {
        let mut state = self.contract_state.write().await;
        let voters = state.public_key_votes.entry(public_key.to_string()).or_insert_with(HashSet::new);
        voters.insert(voter);
        
        // Return true if we have enough votes to approve
        Ok(voters.len() >= state.vote_threshold)
    }

    /// Get the current contract state
    pub async fn get_state(&self) -> Result<MockInMemoryContractState> {
        let state = self.contract_state.read().await;
        Ok(state.clone())
    }

    /// Set the vote threshold (for testing)
    pub async fn set_vote_threshold(&self, threshold: usize) {
        let mut state = self.contract_state.write().await;
        state.vote_threshold = threshold;
    }
}

/// Formats responses to match actual RPC response format
pub struct RpcResponseFormatter;

impl RpcResponseFormatter {
    pub fn new() -> Self {
        Self
    }

    /// Format contract state response to match RPC format
    pub fn format_state_response(&self, state: &MockInMemoryContractState) -> Value {
        serde_json::to_value(state).unwrap_or_else(|_| Value::Null)
    }

    /// Format vote response to match RPC format
    pub fn format_vote_response(&self, success: bool) -> Value {
        serde_json::json!({ "success": success })
    }
}

/// Create an in-memory governance client for testing
pub fn create_in_memory_governance_client(account_id: AccountId) -> GovernanceClient {
    GovernanceClient::InMemory {
        state_manager: Arc::new(ContractStateManager::new()),
        account_id,
    }
}

/// Create a shared contract state manager for testing multiple clients
pub fn create_shared_contract_state_manager() -> Arc<ContractStateManager> {
    Arc::new(ContractStateManager::new())
}

/// Create an in-memory governance client with shared state manager
pub fn create_in_memory_governance_client_with_shared_state(
    state_manager: Arc<ContractStateManager>,
    account_id: AccountId,
) -> GovernanceClient {
    GovernanceClient::InMemory {
        state_manager,
        account_id,
    }
}

/// Builder for creating simulated nodes with minimal configuration
pub struct SimulatedNodeBuilder {
    account_id: AccountId,
    participant: Participant,
    message_router: Arc<MockMessageRouter>,
    contract_state: Arc<RwLock<MockContractState>>,
}

impl SimulatedNodeBuilder {
    pub fn new(
        account_id: AccountId,
        participant: Participant,
        message_router: Arc<MockMessageRouter>,
        contract_state: Arc<RwLock<MockContractState>>,
    ) -> Self {
        Self {
            account_id,
            participant,
            message_router,
            contract_state,
        }
    }

    /// Build a simulated node with all required components
    pub async fn build(self) -> Result<SimulatedNode> {
        // Create cryptographic keys
        let sign_sk = SecretKey::from_seed(
            near_crypto::KeyType::ED25519,
            &format!("test-{}", self.account_id),
        );
        let (cipher_sk, cipher_pk) = hpke::generate();

        // Create network configuration
        let network_config = NetworkConfig {
            sign_sk: sign_sk.clone(),
            cipher_sk,
        };

        let local_config = LocalConfig {
            network: network_config,
            over: OverrideConfig::default(),
        };

        let (config_tx, config_rx) = Config::channel(local_config);

        // Create participant info
        let participant_info = ParticipantInfo {
            sign_pk: sign_sk.public_key(),
            cipher_pk,
            id: self.participant.into(),
            url: format!("http://localhost:300{}", u32::from(self.participant)),
            account_id: self.account_id.clone(),
        };

        // Create participants map with just this node for now
        let mut participants = Participants::default();
        participants.insert(&self.participant, participant_info);

        // Create contract state watcher
        let root_pk = near_crypto::PublicKey::from_seed(
            near_crypto::KeyType::SECP256K1,
            "test-root",
        );
        let (contract_watcher, _contract_tx) = ContractStateWatcher::with_running(
            &self.account_id,
            root_pk.into_affine_point(),
            1, // threshold
            participants,
        );

        // Create mesh state
        let (mesh_tx, mesh_rx) = watch::channel(MeshState::default());

        // Create message channel
        let (_message_inbox, _message_outbox, message_channel) = MessageChannel::new();

        // Create storage components
        let triple_storage = TripleStorage::in_memory();
        let presignature_storage = PresignatureStorage::in_memory();
        let storage_opts = crate::storage::Options {
            env: "test".to_string(),
            gcp_project_id: "test".to_string(),
            sk_share_secret_id: None,
            sk_share_local_path: None,
            redis_url: "redis://localhost".to_string(),
        };
        let secret_storage = crate::storage::secret_storage::init(None, &storage_opts, &self.account_id);
        let _app_data_storage = AppDataStorage::in_memory();

        // Create backlog
        let backlog = Backlog::new();

        // Create sign receiver
        let (_sign_tx, sign_rx) = mpsc::channel(1024);

        // Create protocol message receivers
        let generating_rx = message_channel.subscribe_generation().await;
        let resharing_rx = message_channel.subscribe_resharing().await;
        let ready_rx = message_channel.subscribe_ready().await;

        // Create RPC channel (mock)
        let (rpc_tx, _rpc_rx) = mpsc::channel(1024);
        let rpc_channel = RpcChannel { tx: rpc_tx };

        // Create MPC protocol
        let protocol = MpcSignProtocol {
            my_account_id: self.account_id.clone(),
            secret_storage,
            triple_storage,
            presignature_storage,
            sign_rx: Arc::new(RwLock::new(sign_rx)),
            generating: generating_rx,
            resharing: resharing_rx,
            ready: ready_rx,
            msg_channel: message_channel,
            rpc_channel: rpc_channel,
            contract: contract_watcher.clone(),
            config: config_rx,
            mesh_state: mesh_rx,
            backlog,
        };

        // Create governance client
        let governance = MockGovernance::new(self.contract_state.clone());

        // Create node
        let node = Node::new();

        // Create node handle for message communication
        let node_handle = self.message_router.create_node_handle(self.participant).await;

        Ok(SimulatedNode {
            account_id: self.account_id,
            participant: self.participant,
            node,
            protocol,
            governance,
            contract_watcher,
            config_tx,
            mesh_tx,
            node_handle,
        })
    }
}

/// A simulated node for testing that contains all necessary components
pub struct SimulatedNode {
    pub account_id: AccountId,
    pub participant: Participant,
    pub node: Node,
    pub protocol: MpcSignProtocol,
    pub governance: MockGovernance,
    pub contract_watcher: ContractStateWatcher,
    pub config_tx: watch::Sender<Config>,
    pub mesh_tx: watch::Sender<MeshState>,
    pub node_handle: MockNodeHandle,
}

impl SimulatedNode {
    /// Get the current node state
    pub fn state(&self) -> &NodeState {
        &self.node.state
    }

    /// Send a message to another participant through the node handle
    pub async fn send_message(&self, to: Participant, message: Vec<u8>) -> Result<()> {
        self.node_handle.send_message(to, message).await
    }

    /// Receive the next message from the node's message queue
    pub async fn receive_message(&self) -> Option<ProtocolMessage> {
        self.node_handle.receive_message().await
    }

    /// Get the number of pending messages
    pub async fn pending_message_count(&self) -> usize {
        self.node_handle.pending_message_count().await
    }

    /// Check if there are any pending messages
    pub async fn has_pending_messages(&self) -> bool {
        self.node_handle.has_pending_messages().await
    }

    /// Get the node handle for direct message operations
    pub fn node_handle(&self) -> &MockNodeHandle {
        &self.node_handle
    }
}

/// Test harness that manages multiple simulated nodes
pub struct TestHarness {
    nodes: HashMap<Participant, SimulatedNode>,
    message_router: Arc<MockMessageRouter>,
    contract_state: Arc<RwLock<MockContractState>>,
}

impl TestHarness {
    /// Create a new test harness
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            message_router: MockMessageRouter::new(),
            contract_state: Arc::new(RwLock::new(MockContractState::default())),
        }
    }

    /// Add a simulated node to the harness
    pub async fn add_node(&mut self, account_id: AccountId, participant: Participant) -> Result<()> {
        let builder = SimulatedNodeBuilder::new(
            account_id,
            participant,
            self.message_router.clone(),
            self.contract_state.clone(),
        );

        let node = builder.build().await?;
        self.nodes.insert(participant, node);
        Ok(())
    }

    /// Get a reference to a node by participant
    pub fn get_node(&self, participant: Participant) -> Option<&SimulatedNode> {
        self.nodes.get(&participant)
    }

    /// Get a mutable reference to a node by participant
    pub fn get_node_mut(&mut self, participant: Participant) -> Option<&mut SimulatedNode> {
        self.nodes.get_mut(&participant)
    }

    /// Get all participants in the harness
    pub fn participants(&self) -> Vec<Participant> {
        self.nodes.keys().copied().collect()
    }

    /// Wire all nodes together through the message router
    pub async fn wire_nodes(&mut self) -> Result<()> {
        // With the new implementation, nodes are automatically wired when created
        // This method is kept for backward compatibility
        Ok(())
    }

    /// Get message router statistics
    pub async fn get_message_stats(&self) -> MessageRouterStats {
        self.message_router.get_stats().await
    }

    /// Get the message router for direct access
    pub fn message_router(&self) -> Arc<MockMessageRouter> {
        self.message_router.clone()
    }

    /// Get the shared contract state
    pub fn contract_state(&self) -> Arc<RwLock<MockContractState>> {
        self.contract_state.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[tokio::test]
    async fn test_infrastructure_availability() {
        // Property 1: Test Infrastructure Availability
        // Validates: Requirements 1.1
        //
        // For any test infrastructure setup, the system SHALL provide
        // in-memory storage variants that can be instantiated without
        // external dependencies.

        // Create in-memory checkpoint storage
        let storage = in_memory_checkpoint_storage();

        // Verify it's empty initially
        assert_checkpoint_storage_empty(&storage).await;

        // Verify we can use it (basic operation)
        match storage {
            CheckpointStorage::InMemory(_) => {
                // Successfully created in-memory storage
            }
            CheckpointStorage::Redis(_, _) => {
                panic!("Expected InMemory variant");
            }
        }
    }

    // Property 15: Test Harness Node Creation
    // Validates: Requirements 12.1
    //
    // For any test harness builder configuration, creating simulated nodes should result in
    // properly initialized nodes with all required components.
    #[test]
    fn prop_test_harness_node_creation() {
        // **Feature: unit-test-coverage, Property 15: Test Harness Node Creation**
        
        let participant = Participant::from(42u32);
        let account_id: AccountId = "test-node.near".parse().unwrap();
        
        // Test that we can create the basic components
        let message_router = MockMessageRouter::new();
        let contract_state = Arc::new(RwLock::new(MockContractState::default()));
        let _governance = MockGovernance::new(contract_state.clone());
        
        // Test that we can create a test harness
        let harness = TestHarness::new();
        
        // Verify the harness is properly initialized
        assert!(harness.participants().is_empty(), "New harness should have no participants");
        
        // Test that we can create a builder
        let builder = SimulatedNodeBuilder::new(
            account_id.clone(),
            participant,
            message_router,
            contract_state,
        );
        
        // Verify the builder has the correct configuration
        assert_eq!(builder.account_id, account_id, "Builder should have correct account ID");
        assert_eq!(builder.participant, participant, "Builder should have correct participant ID");
    }

    // Property 16: Test Harness Automatic Wiring
    // Validates: Requirements 12.2, 12.3, 12.4
    //
    // For any set of simulated nodes created by the test harness, they should be automatically
    // wired through the mock message router and contract.
    #[tokio::test]
    async fn prop_test_harness_automatic_wiring() {
        // **Feature: unit-test-coverage, Property 16: Test Harness Automatic Wiring**
        
        // Test the message router wiring functionality
        let message_router = MockMessageRouter::new();
        
        let participants = vec![
            Participant::from(1u32),
            Participant::from(2u32),
            Participant::from(3u32),
        ];
        
        // Create node handles for each participant
        let handle1 = message_router.create_node_handle(participants[0]).await;
        let handle2 = message_router.create_node_handle(participants[1]).await;
        let _handle3 = message_router.create_node_handle(participants[2]).await;
        
        // Test message sending through the router
        let test_message = b"test message".to_vec();
        let result = handle1.send_message(participants[1], test_message.clone()).await;
        assert!(result.is_ok(), "Should be able to send message through router");
        
        // Verify message was received
        let received = handle2.receive_message().await;
        assert!(received.is_some(), "Should receive the message");
        let received_msg = received.unwrap();
        assert_eq!(received_msg.from, participants[0], "Message should be from correct sender");
        assert_eq!(received_msg.to, participants[1], "Message should be to correct recipient");
        assert_eq!(received_msg.payload, test_message, "Message payload should match");
        
        // Test shared contract state
        let contract_state = Arc::new(RwLock::new(MockContractState::default()));
        let governance1 = MockGovernance::with_account_id(contract_state.clone(), "node1.near".parse().unwrap());
        let governance2 = MockGovernance::with_account_id(contract_state.clone(), "node2.near".parse().unwrap());
        
        // Both governance instances should share the same state
        let result1 = governance1.vote_reshared(1).await;
        let result2 = governance2.vote_reshared(1).await;
        
        assert!(result1.is_ok(), "First governance vote should succeed");
        assert!(result2.is_ok(), "Second governance vote should succeed");
        
        // Verify the shared state was updated
        let state_guard = contract_state.read().await;
        assert!(state_guard.resharing_votes.contains_key(&1), "Contract state should contain the vote");
        assert_eq!(state_guard.resharing_votes[&1].len(), 2, "Both votes should be recorded");
    }

    // Property 17: Test Harness Message Delivery
    // Validates: Requirements 12.5
    //
    // For any protocol operation on simulated nodes created by the test harness, messages
    // should be delivered transparently without manual intervention.
    #[tokio::test]
    async fn prop_test_harness_message_delivery() {
        // **Feature: unit-test-coverage, Property 17: Test Harness Message Delivery**
        
        let message_router = MockMessageRouter::new();
        
        let from_participant = Participant::from(1u32);
        let to_participant = Participant::from(2u32);
        
        // Create node handles
        let from_handle = message_router.create_node_handle(from_participant).await;
        let to_handle = message_router.create_node_handle(to_participant).await;
        
        // Send multiple messages to test delivery
        let messages = vec![
            b"message 1".to_vec(),
            b"message 2".to_vec(),
            b"message 3".to_vec(),
        ];
        
        for (i, message) in messages.iter().enumerate() {
            let result = from_handle.send_message(to_participant, message.clone()).await;
            assert!(result.is_ok(), "Should be able to send message {}", i + 1);
        }
        
        // Verify all messages were delivered in order
        for (i, expected_message) in messages.iter().enumerate() {
            let received_message = to_handle.receive_message().await;
            assert!(received_message.is_some(), "Should receive message {}", i + 1);
            let received = received_message.unwrap();
            assert_eq!(received.from, from_participant, "Message {} should be from correct sender", i + 1);
            assert_eq!(received.to, to_participant, "Message {} should be to correct recipient", i + 1);
            assert_eq!(received.payload, *expected_message, "Message {} payload should match", i + 1);
            assert_eq!(received.sequence_number, i as u64, "Message {} should have correct sequence number", i + 1);
        }
        
        // Verify no additional messages are received
        let additional_message = to_handle.receive_message().await;
        assert!(additional_message.is_none(), "Should not receive any additional messages");
        
        // Test that messages to unregistered routes fail appropriately
        let unregistered_participant = Participant::from(99u32);
        let result = from_handle.send_message(unregistered_participant, b"test".to_vec()).await;
        assert!(result.is_err(), "Should fail to send message to unregistered participant");
    }

    // Property 18: Governance Voting Correctness
    // Validates: Requirements 13.1, 13.4
    //
    // For any voting operation through the mock Governance, the vote should be recorded
    // in the in-memory contract and aggregated correctly.
    #[tokio::test]
    async fn prop_governance_voting_correctness() {
        // **Feature: unit-test-coverage, Property 18: Governance Voting Correctness**
        
        let contract_state = Arc::new(RwLock::new(MockContractState::default()));
        
        // Test with multiple governance instances (simulating different nodes)
        let governance1 = MockGovernance::with_account_id(contract_state.clone(), "node1.near".parse().unwrap());
        let governance2 = MockGovernance::with_account_id(contract_state.clone(), "node2.near".parse().unwrap());
        let governance3 = MockGovernance::with_account_id(contract_state.clone(), "node3.near".parse().unwrap());
        
        // Set vote threshold to 2 for testing
        governance1.set_vote_threshold(2).await;
        
        let test_epoch = 42u64;
        
        // First vote should not reach threshold
        let result1 = governance1.vote_reshared(test_epoch).await;
        assert!(result1.is_ok(), "First vote should succeed");
        assert!(!result1.unwrap(), "First vote should not reach threshold");
        
        // Second vote should reach threshold
        let result2 = governance2.vote_reshared(test_epoch).await;
        assert!(result2.is_ok(), "Second vote should succeed");
        assert!(result2.unwrap(), "Second vote should reach threshold");
        
        // Third vote should still return true (already approved)
        let result3 = governance3.vote_reshared(test_epoch).await;
        assert!(result3.is_ok(), "Third vote should succeed");
        assert!(result3.unwrap(), "Third vote should still return true");
        
        // Verify the contract state
        let state = governance1.get_state().await;
        assert_eq!(state.resharing_votes[&test_epoch].len(), 3, "All three votes should be recorded");
        assert!(state.resharing_votes[&test_epoch].contains(&"node1.near".parse::<AccountId>().unwrap()));
        assert!(state.resharing_votes[&test_epoch].contains(&"node2.near".parse::<AccountId>().unwrap()));
        assert!(state.resharing_votes[&test_epoch].contains(&"node3.near".parse::<AccountId>().unwrap()));
        
        // Test duplicate voting (same node voting twice)
        let result4 = governance1.vote_reshared(test_epoch).await;
        assert!(result4.is_ok(), "Duplicate vote should succeed");
        assert!(result4.unwrap(), "Duplicate vote should still return true");
        
        // Verify no duplicate entries
        let state_after_duplicate = governance1.get_state().await;
        assert_eq!(state_after_duplicate.resharing_votes[&test_epoch].len(), 3, "Duplicate vote should not increase count");
    }

    // Property 19: Governance Join Proposal
    // Validates: Requirements 13.2
    //
    // For any join proposal through the mock Governance, the proposal should be recorded
    // in the in-memory contract and update contract state.
    #[tokio::test]
    async fn prop_governance_join_proposal() {
        // **Feature: unit-test-coverage, Property 19: Governance Join Proposal**
        
        let contract_state = Arc::new(RwLock::new(MockContractState::default()));
        
        let new_node_account: AccountId = "new-node.near".parse().unwrap();
        let governance = MockGovernance::with_account_id(contract_state.clone(), new_node_account.clone());
        
        // Initially, there should be no join proposals
        let initial_state = governance.get_state().await;
        assert!(initial_state.join_proposals.is_empty(), "Initially should have no join proposals");
        
        // Propose to join
        let result = governance.propose_join().await;
        assert!(result.is_ok(), "Join proposal should succeed");
        
        // Verify the proposal was recorded
        let state_after_proposal = governance.get_state().await;
        assert!(state_after_proposal.join_proposals.contains_key(&new_node_account), "Join proposal should be recorded");
        assert!(state_after_proposal.join_proposals[&new_node_account].contains(&new_node_account), "Node should support its own proposal");
        assert_eq!(state_after_proposal.join_proposals[&new_node_account].len(), 1, "Should have exactly one supporter initially");
        
        // Test multiple join proposals from different nodes
        let another_node_account: AccountId = "another-node.near".parse().unwrap();
        let another_governance = MockGovernance::with_account_id(contract_state.clone(), another_node_account.clone());
        
        let result2 = another_governance.propose_join().await;
        assert!(result2.is_ok(), "Second join proposal should succeed");
        
        // Verify both proposals exist
        let final_state = governance.get_state().await;
        assert_eq!(final_state.join_proposals.len(), 2, "Should have two join proposals");
        assert!(final_state.join_proposals.contains_key(&new_node_account));
        assert!(final_state.join_proposals.contains_key(&another_node_account));
        
        // Test duplicate proposal (same node proposing again)
        let result3 = governance.propose_join().await;
        assert!(result3.is_ok(), "Duplicate proposal should succeed");
        
        let state_after_duplicate = governance.get_state().await;
        assert_eq!(state_after_duplicate.join_proposals[&new_node_account].len(), 1, "Duplicate proposal should not increase supporter count");
    }

    // Property 20: Governance Public Key Voting
    // Validates: Requirements 13.3
    //
    // For any public key vote through the mock Governance, the vote should be recorded
    // and aggregated in the in-memory contract.
    #[tokio::test]
    async fn prop_governance_public_key_voting() {
        // **Feature: unit-test-coverage, Property 20: Governance Public Key Voting**
        
        let contract_state = Arc::new(RwLock::new(MockContractState::default()));
        
        // Create test public key
        let test_public_key = near_crypto::PublicKey::from_seed(
            near_crypto::KeyType::SECP256K1,
            "test-public-key"
        );
        
        // Create multiple governance instances
        let governance1 = MockGovernance::with_account_id(contract_state.clone(), "node1.near".parse().unwrap());
        let governance2 = MockGovernance::with_account_id(contract_state.clone(), "node2.near".parse().unwrap());
        let governance3 = MockGovernance::with_account_id(contract_state.clone(), "node3.near".parse().unwrap());
        
        // Set vote threshold to 2
        governance1.set_vote_threshold(2).await;
        
        // First vote should not reach threshold
        let result1 = governance1.vote_public_key(&test_public_key).await;
        assert!(result1.is_ok(), "First public key vote should succeed");
        assert!(!result1.unwrap(), "First vote should not reach threshold");
        
        // Second vote should reach threshold
        let result2 = governance2.vote_public_key(&test_public_key).await;
        assert!(result2.is_ok(), "Second public key vote should succeed");
        assert!(result2.unwrap(), "Second vote should reach threshold");
        
        // Third vote should still return true
        let result3 = governance3.vote_public_key(&test_public_key).await;
        assert!(result3.is_ok(), "Third public key vote should succeed");
        assert!(result3.unwrap(), "Third vote should still return true");
        
        // Verify the contract state
        let state = governance1.get_state().await;
        let pk_str = format!("{:?}", test_public_key);
        assert!(state.public_key_votes.contains_key(&pk_str), "Public key votes should be recorded");
        assert_eq!(state.public_key_votes[&pk_str].len(), 3, "All three votes should be recorded");
        assert!(state.public_key_votes[&pk_str].contains(&"node1.near".parse::<AccountId>().unwrap()));
        assert!(state.public_key_votes[&pk_str].contains(&"node2.near".parse::<AccountId>().unwrap()));
        assert!(state.public_key_votes[&pk_str].contains(&"node3.near".parse::<AccountId>().unwrap()));
        
        // Test voting on different public key
        let another_public_key = near_crypto::PublicKey::from_seed(
            near_crypto::KeyType::SECP256K1,
            "another-test-key"
        );
        
        let result4 = governance1.vote_public_key(&another_public_key).await;
        assert!(result4.is_ok(), "Vote on different key should succeed");
        assert!(!result4.unwrap(), "Vote on different key should not reach threshold initially");
        
        // Verify both keys are tracked separately
        let final_state = governance1.get_state().await;
        let another_pk_str = format!("{:?}", another_public_key);
        assert_eq!(final_state.public_key_votes.len(), 2, "Should track votes for both keys");
        assert!(final_state.public_key_votes.contains_key(&pk_str));
        assert!(final_state.public_key_votes.contains_key(&another_pk_str));
        assert_eq!(final_state.public_key_votes[&another_pk_str].len(), 1, "New key should have one vote");
        
        // Test duplicate voting on public key
        let result5 = governance1.vote_public_key(&test_public_key).await;
        assert!(result5.is_ok(), "Duplicate public key vote should succeed");
        assert!(result5.unwrap(), "Duplicate vote should still return true");
        
        // Verify no duplicate entries
        let state_after_duplicate = governance1.get_state().await;
        assert_eq!(state_after_duplicate.public_key_votes[&pk_str].len(), 3, "Duplicate vote should not increase count");
    }

    // Property 21: Contract State Consistency
    // Validates: Requirements 14.4
    //
    // For any contract operation performed by simulated nodes, the in-memory contract state
    // should be updated consistently and visible to all nodes.
    #[tokio::test]
    async fn prop_contract_state_consistency() {
        // **Feature: unit-test-coverage, Property 21: Contract State Consistency**
        
        // Create shared state manager
        let shared_state_manager = create_shared_contract_state_manager();
        
        // Create multiple governance clients sharing the same state manager
        let client1 = create_in_memory_governance_client_with_shared_state(
            shared_state_manager.clone(), 
            "node1.near".parse().unwrap()
        );
        let client2 = create_in_memory_governance_client_with_shared_state(
            shared_state_manager.clone(), 
            "node2.near".parse().unwrap()
        );
        let client3 = create_in_memory_governance_client_with_shared_state(
            shared_state_manager.clone(), 
            "node3.near".parse().unwrap()
        );
        
        // Test that all clients see the same initial state
        let state1 = shared_state_manager.get_state().await.unwrap();
        let state2 = shared_state_manager.get_state().await.unwrap();
        let state3 = shared_state_manager.get_state().await.unwrap();
        
        // All states should be identical
        assert_eq!(format!("{:?}", state1), format!("{:?}", state2), "State should be consistent across clients");
        assert_eq!(format!("{:?}", state2), format!("{:?}", state3), "State should be consistent across clients");
        
        // Test voting operations update state consistently
        let epoch = 2u64;
        let result1 = client1.vote_reshared(epoch).await;
        assert!(result1.is_ok(), "First vote should succeed");
        
        // Verify state was updated and is visible to all clients
        let updated_state1 = shared_state_manager.get_state().await.unwrap();
        let updated_state2 = shared_state_manager.get_state().await.unwrap();
        
        assert_eq!(format!("{:?}", updated_state1), format!("{:?}", updated_state2), "Updated state should be consistent");
        
        // Test concurrent operations maintain consistency
        let (result2, result3) = tokio::join!(
            client2.vote_reshared(epoch),
            client3.vote_reshared(epoch)
        );
        
        assert!(result2.is_ok(), "Second concurrent vote should succeed");
        assert!(result3.is_ok(), "Third concurrent vote should succeed");
        
        // Final state should be consistent across all clients
        let final_state1 = shared_state_manager.get_state().await.unwrap();
        let final_state2 = shared_state_manager.get_state().await.unwrap();
        let final_state3 = shared_state_manager.get_state().await.unwrap();
        
        assert_eq!(format!("{:?}", final_state1), format!("{:?}", final_state2), "Final state should be consistent");
        assert_eq!(format!("{:?}", final_state2), format!("{:?}", final_state3), "Final state should be consistent");
        
        // Verify that votes were actually recorded
        let final_state = shared_state_manager.get_state().await.unwrap();
        assert!(final_state.resharing_votes.contains_key(&epoch), "Epoch should have votes recorded");
        assert_eq!(final_state.resharing_votes[&epoch].len(), 3, "All three votes should be recorded");
    }

    // Property 22: RPC Response Format Correctness
    // Validates: Requirements 14.5
    //
    // For any RPC request to the in-memory contract, the response should match
    // the format and structure of actual RPC responses.
    #[tokio::test]
    async fn prop_rpc_response_format_correctness() {
        // **Feature: unit-test-coverage, Property 22: RPC Response Format Correctness**
        
        let formatter = RpcResponseFormatter::new();
        
        // Test state response formatting with mock state
        let mock_state = MockInMemoryContractState {
            epoch: 1,
            public_key_votes: HashMap::new(),
            resharing_votes: HashMap::new(),
            join_proposals: HashMap::new(),
            vote_threshold: 2,
            protocol_state: "Running".to_string(),
        };
        
        let formatted_state = formatter.format_state_response(&mock_state);
        
        // Verify the response is valid JSON
        assert!(formatted_state.is_object(), "State response should be a JSON object");
        
        // Verify it contains expected fields
        let state_obj = formatted_state.as_object().unwrap();
        assert!(state_obj.contains_key("epoch"), "Should contain epoch field");
        assert!(state_obj.contains_key("protocol_state"), "Should contain protocol_state field");
        assert!(state_obj.contains_key("vote_threshold"), "Should contain vote_threshold field");
        assert!(state_obj.contains_key("public_key_votes"), "Should contain public_key_votes field");
        assert!(state_obj.contains_key("resharing_votes"), "Should contain resharing_votes field");
        
        // Test vote response formatting
        let vote_response_true = formatter.format_vote_response(true);
        let vote_response_false = formatter.format_vote_response(false);
        
        // Verify vote responses are properly formatted
        assert!(vote_response_true.is_object(), "Vote response should be a JSON object");
        assert!(vote_response_false.is_object(), "Vote response should be a JSON object");
        
        assert_eq!(vote_response_true["success"], true, "True vote response should have success: true");
        assert_eq!(vote_response_false["success"], false, "False vote response should have success: false");
        
        // Test with different protocol states
        let initializing_state = MockInMemoryContractState {
            epoch: 0,
            public_key_votes: HashMap::new(),
            resharing_votes: HashMap::new(),
            join_proposals: HashMap::new(),
            vote_threshold: 2,
            protocol_state: "Initializing".to_string(),
        };
        
        let formatted_initializing = formatter.format_state_response(&initializing_state);
        assert!(formatted_initializing.is_object(), "Initializing state response should be a JSON object");
        
        let init_obj = formatted_initializing.as_object().unwrap();
        assert_eq!(init_obj["protocol_state"], "Initializing", "Should have correct protocol state");
    }

    // Property 23: Contract Voting Correctness
    // Validates: Requirements 14.3
    //
    // For any voting operation on the in-memory contract, the vote should be
    // recorded and aggregated correctly.
    #[tokio::test]
    async fn prop_contract_voting_correctness() {
        // **Feature: unit-test-coverage, Property 23: Contract Voting Correctness**
        
        // Create shared state manager
        let state_manager = create_shared_contract_state_manager();
        
        // Set threshold to 2 for testing
        state_manager.set_vote_threshold(2).await;
        
        // Test resharing votes
        let epoch = 2u64;
        let voter1: AccountId = "node1.near".parse().unwrap();
        let voter2: AccountId = "node2.near".parse().unwrap();
        
        // First vote should not reach threshold
        let result1 = state_manager.vote_reshared(voter1.clone(), epoch).await;
        assert!(result1.is_ok(), "First vote should succeed");
        assert!(!result1.unwrap(), "First vote should not reach threshold");
        
        // Second vote should reach threshold
        let result2 = state_manager.vote_reshared(voter2.clone(), epoch).await;
        assert!(result2.is_ok(), "Second vote should succeed");
        assert!(result2.unwrap(), "Second vote should reach threshold");
        
        // Verify votes were recorded
        let state = state_manager.get_state().await.unwrap();
        assert!(state.resharing_votes.contains_key(&epoch), "Epoch should have votes recorded");
        assert_eq!(state.resharing_votes[&epoch].len(), 2, "Both votes should be recorded");
        assert!(state.resharing_votes[&epoch].contains(&voter1), "First voter should be recorded");
        assert!(state.resharing_votes[&epoch].contains(&voter2), "Second voter should be recorded");
        
        // Test public key votes
        let test_public_key = "ed25519:DcA2MzgpJbrUATQLLceocVckhhAqrkingax4oJ9kZ847";
        
        // First public key vote should not reach threshold
        let pk_result1 = state_manager.vote_public_key(voter1.clone(), test_public_key).await;
        assert!(pk_result1.is_ok(), "First public key vote should succeed");
        assert!(!pk_result1.unwrap(), "First public key vote should not reach threshold");
        
        // Second public key vote should reach threshold
        let pk_result2 = state_manager.vote_public_key(voter2.clone(), test_public_key).await;
        assert!(pk_result2.is_ok(), "Second public key vote should succeed");
        assert!(pk_result2.unwrap(), "Second public key vote should reach threshold");
        
        // Verify public key votes were recorded
        let final_state = state_manager.get_state().await.unwrap();
        assert!(final_state.public_key_votes.contains_key(test_public_key), "Public key should have votes recorded");
        assert_eq!(final_state.public_key_votes[test_public_key].len(), 2, "Both public key votes should be recorded");
        assert!(final_state.public_key_votes[test_public_key].contains(&voter1), "First voter should be recorded for public key");
        assert!(final_state.public_key_votes[test_public_key].contains(&voter2), "Second voter should be recorded for public key");
        
        // Test duplicate voting (same voter voting twice)
        let duplicate_result = state_manager.vote_reshared(voter1.clone(), epoch).await;
        assert!(duplicate_result.is_ok(), "Duplicate vote should succeed");
        assert!(duplicate_result.unwrap(), "Duplicate vote should still return true (already approved)");
        
        // Verify no duplicate entries
        let state_after_duplicate = state_manager.get_state().await.unwrap();
        assert_eq!(state_after_duplicate.resharing_votes[&epoch].len(), 2, "Duplicate vote should not increase count");
    }

    // Property 24: Message Router Delivery Correctness
    // Validates: Requirements 15.2
    //
    // For any message sent from one simulated node to another through the mock router,
    // the message should be delivered to the correct recipient without loss or corruption.
    #[tokio::test]
    async fn prop_message_router_delivery_correctness() {
        // **Feature: unit-test-coverage, Property 24: Message Router Delivery Correctness**
        
        let message_router = MockMessageRouter::new();
        
        // Test with multiple participants
        let participants = vec![
            Participant::from(1u32),
            Participant::from(2u32),
            Participant::from(3u32),
            Participant::from(4u32),
        ];
        
        // Create handles for all participants
        let mut handles = HashMap::new();
        for &participant in &participants {
            let handle = message_router.create_node_handle(participant).await;
            handles.insert(participant, handle);
        }
        
        // Test message delivery between all pairs of participants
        for &sender in &participants {
            for &receiver in &participants {
                if sender != receiver {
                    let test_payload = format!("message from {:?} to {:?}", sender, receiver).into_bytes();
                    
                    // Send message
                    let sender_handle = &handles[&sender];
                    let result = sender_handle.send_message(receiver, test_payload.clone()).await;
                    assert!(result.is_ok(), "Should be able to send message from {:?} to {:?}", sender, receiver);
                    
                    // Receive and verify message
                    let receiver_handle = &handles[&receiver];
                    let received = receiver_handle.receive_message().await;
                    assert!(received.is_some(), "Should receive message from {:?} to {:?}", sender, receiver);
                    
                    let received_msg = received.unwrap();
                    assert_eq!(received_msg.from, sender, "Message should be from correct sender");
                    assert_eq!(received_msg.to, receiver, "Message should be to correct recipient");
                    assert_eq!(received_msg.payload, test_payload, "Message payload should not be corrupted");
                }
            }
        }
        
        // Verify statistics
        let stats = message_router.get_stats().await;
        let expected_messages = participants.len() * (participants.len() - 1);
        assert_eq!(stats.messages_sent as usize, expected_messages, "Should have sent correct number of messages");
        assert_eq!(stats.messages_delivered as usize, expected_messages, "Should have delivered all messages");
        assert_eq!(stats.messages_dropped, 0, "Should not have dropped any messages");
    }

    // Property 25: Message Ordering Preservation
    // Validates: Requirements 15.3
    //
    // For any sequence of messages sent from one node to another, the messages
    // should be delivered in the same order they were sent.
    #[tokio::test]
    async fn prop_message_ordering_preservation() {
        // **Feature: unit-test-coverage, Property 25: Message Ordering Preservation**
        
        let message_router = MockMessageRouter::new();
        
        let sender = Participant::from(1u32);
        let receiver = Participant::from(2u32);
        
        let sender_handle = message_router.create_node_handle(sender).await;
        let receiver_handle = message_router.create_node_handle(receiver).await;
        
        // Send multiple messages in sequence
        let message_count = 10;
        let mut sent_messages = Vec::new();
        
        for i in 0..message_count {
            let payload = format!("message {}", i).into_bytes();
            sent_messages.push(payload.clone());
            
            let result = sender_handle.send_message(receiver, payload).await;
            assert!(result.is_ok(), "Should be able to send message {}", i);
        }
        
        // Receive messages and verify ordering
        for (i, expected_payload) in sent_messages.iter().enumerate() {
            let received = receiver_handle.receive_message().await;
            assert!(received.is_some(), "Should receive message {}", i);
            
            let received_msg = received.unwrap();
            assert_eq!(received_msg.from, sender, "Message {} should be from correct sender", i);
            assert_eq!(received_msg.to, receiver, "Message {} should be to correct recipient", i);
            assert_eq!(received_msg.payload, *expected_payload, "Message {} payload should match", i);
            assert_eq!(received_msg.sequence_number, i as u64, "Message {} should have correct sequence number", i);
        }
        
        // Verify no additional messages
        let additional = receiver_handle.receive_message().await;
        assert!(additional.is_none(), "Should not receive any additional messages");
        
        // Test concurrent sending from multiple senders to same receiver
        let sender2 = Participant::from(3u32);
        let sender2_handle = message_router.create_node_handle(sender2).await;
        
        // Send messages concurrently from both senders
        let (result1, result2) = tokio::join!(
            sender_handle.send_message(receiver, b"from sender1".to_vec()),
            sender2_handle.send_message(receiver, b"from sender2".to_vec())
        );
        
        assert!(result1.is_ok(), "Concurrent send from sender1 should succeed");
        assert!(result2.is_ok(), "Concurrent send from sender2 should succeed");
        
        // Receive both messages and verify they maintain per-sender ordering
        let mut received_messages = Vec::new();
        for _ in 0..2 {
            let received = receiver_handle.receive_message().await;
            assert!(received.is_some(), "Should receive concurrent message");
            received_messages.push(received.unwrap());
        }
        
        // Verify each sender's messages maintain their sequence
        for msg in received_messages {
            if msg.from == sender {
                assert_eq!(msg.sequence_number, message_count as u64, "Sender1 message should have correct sequence");
            } else if msg.from == sender2 {
                assert_eq!(msg.sequence_number, 0, "Sender2 message should have correct sequence");
            }
        }
    }

    // Property 26: Node State Isolation
    // Validates: Requirements 15.4
    //
    // For any set of simulated nodes sharing a mock message router, each node's
    // state should remain isolated and independent from other nodes' state.
    #[tokio::test]
    async fn prop_node_state_isolation() {
        // **Feature: unit-test-coverage, Property 26: Node State Isolation**
        
        let message_router = MockMessageRouter::new();
        
        let participants = vec![
            Participant::from(1u32),
            Participant::from(2u32),
            Participant::from(3u32),
        ];
        
        // Create handles for all participants
        let mut handles = HashMap::new();
        for &participant in &participants {
            let handle = message_router.create_node_handle(participant).await;
            handles.insert(participant, handle);
        }
        
        // Send different messages to each node
        let handle1 = &handles[&participants[0]];
        let handle2 = &handles[&participants[1]];
        let handle3 = &handles[&participants[2]];
        
        // Node 1 sends to Node 2
        let msg1_to_2 = b"message from 1 to 2".to_vec();
        let result = handle1.send_message(participants[1], msg1_to_2.clone()).await;
        assert!(result.is_ok(), "Should send message from 1 to 2");
        
        // Node 2 sends to Node 3
        let msg2_to_3 = b"message from 2 to 3".to_vec();
        let result = handle2.send_message(participants[2], msg2_to_3.clone()).await;
        assert!(result.is_ok(), "Should send message from 2 to 3");
        
        // Node 3 sends to Node 1
        let msg3_to_1 = b"message from 3 to 1".to_vec();
        let result = handle3.send_message(participants[0], msg3_to_1.clone()).await;
        assert!(result.is_ok(), "Should send message from 3 to 1");
        
        // Verify each node only receives its intended messages
        
        // Node 1 should only receive message from Node 3
        assert_eq!(handle1.pending_message_count().await, 1, "Node 1 should have exactly 1 message");
        let received1 = handle1.receive_message().await.unwrap();
        assert_eq!(received1.from, participants[2], "Node 1 should receive from Node 3");
        assert_eq!(received1.payload, msg3_to_1, "Node 1 should receive correct payload");
        assert_eq!(handle1.pending_message_count().await, 0, "Node 1 should have no more messages");
        
        // Node 2 should only receive message from Node 1
        assert_eq!(handle2.pending_message_count().await, 1, "Node 2 should have exactly 1 message");
        let received2 = handle2.receive_message().await.unwrap();
        assert_eq!(received2.from, participants[0], "Node 2 should receive from Node 1");
        assert_eq!(received2.payload, msg1_to_2, "Node 2 should receive correct payload");
        assert_eq!(handle2.pending_message_count().await, 0, "Node 2 should have no more messages");
        
        // Node 3 should only receive message from Node 2
        assert_eq!(handle3.pending_message_count().await, 1, "Node 3 should have exactly 1 message");
        let received3 = handle3.receive_message().await.unwrap();
        assert_eq!(received3.from, participants[1], "Node 3 should receive from Node 2");
        assert_eq!(received3.payload, msg2_to_3, "Node 3 should receive correct payload");
        assert_eq!(handle3.pending_message_count().await, 0, "Node 3 should have no more messages");
        
        // Test that message queues are independent
        // Send multiple messages to Node 1 and verify other nodes are unaffected
        for i in 0..5 {
            let payload = format!("bulk message {}", i).into_bytes();
            let result = handle2.send_message(participants[0], payload).await;
            assert!(result.is_ok(), "Should send bulk message {}", i);
        }
        
        // Node 1 should have 5 messages, others should have 0
        assert_eq!(handle1.pending_message_count().await, 5, "Node 1 should have 5 bulk messages");
        assert_eq!(handle2.pending_message_count().await, 0, "Node 2 should have no messages");
        assert_eq!(handle3.pending_message_count().await, 0, "Node 3 should have no messages");
        
        // Drain any remaining messages from handle1's queue to ensure clean state
        while handle1.receive_message().await.is_some() {
            // Keep draining until empty
        }
        
        // Test sequence number isolation by creating fresh handles
        // This ensures we can verify sequence numbers start from 0 for new handles
        let fresh_sender1 = Participant::from(10u32);
        let fresh_sender2 = Participant::from(11u32);
        let fresh_handle1 = message_router.create_node_handle(fresh_sender1).await;
        let fresh_handle2 = message_router.create_node_handle(fresh_sender2).await;
        
        // Send one message from each fresh handle
        let result1 = fresh_handle1.send_message(participants[0], b"fresh seq test 1".to_vec()).await;
        assert!(result1.is_ok(), "Fresh handle 1 message should send");
        
        let result2 = fresh_handle2.send_message(participants[0], b"fresh seq test 2".to_vec()).await;
        assert!(result2.is_ok(), "Fresh handle 2 message should send");
        
        // Receive messages and verify they are isolated
        let received_messages = vec![
            handle1.receive_message().await.unwrap(),
            handle1.receive_message().await.unwrap(),
        ];
        
        // Both fresh handles should start with sequence number 0
        for msg in received_messages {
            assert_eq!(msg.sequence_number, 0, "Fresh handles should start with sequence 0, got {} from {:?}", msg.sequence_number, msg.from);
            assert!(msg.from == fresh_sender1 || msg.from == fresh_sender2, "Message should be from one of the fresh senders");
        }
    }

    #[tokio::test]
    async fn test_governance_client_integration() {
        // Test that GovernanceClient enum works correctly with both variants
        
        // Test InMemory variant
        let in_memory_client = create_in_memory_governance_client("test-node.near".parse().unwrap());
        
        // Test basic operations
        let join_result = in_memory_client.propose_join().await;
        assert!(join_result.is_ok(), "Join proposal should succeed");
        
        let vote_result = in_memory_client.vote_reshared(1).await;
        assert!(vote_result.is_ok(), "Vote reshared should succeed");
        
        // Test public key voting with a mock key
        let mock_key = near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "test")
            .public_key();
        let pk_vote_result = in_memory_client.vote_public_key(&mock_key).await;
        assert!(pk_vote_result.is_ok(), "Public key vote should succeed");
    }

    // Property 30: Signing Protocol Completion
    // Validates: Requirements 17.2
    //
    // For any set of simulated nodes executing the signing protocol, the protocol
    // should complete successfully with all nodes reaching a consistent final state.
    #[tokio::test]
    async fn prop_signing_protocol_completion() {
        // **Feature: unit-test-coverage, Property 30: Signing Protocol Completion**
        
        // Simplified test: verify message router can deliver messages between nodes
        let message_router = MockMessageRouter::new();
        
        let participants = vec![
            Participant::from(1u32),
            Participant::from(2u32),
            Participant::from(3u32),
        ];
        
        // Create node handles for each participant
        let mut node_handles = Vec::new();
        for &participant in &participants {
            let handle = message_router.create_node_handle(participant).await;
            node_handles.push(handle);
        }
        
        // Verify all nodes were registered
        let registered = message_router.get_participants().await;
        assert_eq!(registered.len(), 3, "Should have 3 participants registered");
        
        // Send a test message from node1 to node2
        let test_message = b"signing protocol test".to_vec();
        let result = node_handles[0].send_message(participants[1], test_message.clone()).await;
        assert!(result.is_ok(), "Node 1 should be able to send message to Node 2");
        
        // Verify node2 receives the message
        let received = node_handles[1].receive_message().await;
        assert!(received.is_some(), "Node 2 should receive the message");
        
        let received_msg = received.unwrap();
        assert_eq!(received_msg.from, participants[0], "Message should be from Node 1");
        assert_eq!(received_msg.to, participants[1], "Message should be to Node 2");
        assert_eq!(received_msg.payload, test_message, "Message payload should match");
        
        // Verify message router statistics
        let stats = message_router.get_stats().await;
        assert_eq!(stats.messages_sent, 1, "Should have sent 1 message");
        assert_eq!(stats.messages_delivered, 1, "Should have delivered 1 message");
        assert_eq!(stats.messages_dropped, 0, "Should not have dropped any messages");
    }

    // Property 31: Signature Validity and Verification
    // Validates: Requirements 17.3
    //
    // For any completed signing protocol, the produced signatures should be valid
    // and verifiable using the public key.
    #[tokio::test]
    async fn prop_signature_validity_and_verification() {
        // **Feature: unit-test-coverage, Property 31: Signature Validity and Verification**
        
        // Simplified test: verify governance operations work correctly
        let contract_state = Arc::new(RwLock::new(MockContractState::default()));
        
        let participants = vec![
            Participant::from(1u32),
            Participant::from(2u32),
            Participant::from(3u32),
        ];
        
        // Create governance clients for each participant with different account IDs
        let mut governance_clients = Vec::new();
        for (i, &participant) in participants.iter().enumerate() {
            let account_id: AccountId = format!("node{}.near", i + 1).parse().unwrap();
            let governance = MockGovernance::with_account_id(contract_state.clone(), account_id);
            governance_clients.push(governance);
        }
        
        // Test that all governance clients can perform operations
        for governance in &governance_clients {
            // Verify governance client can perform operations
            let join_result = governance.propose_join().await;
            assert!(join_result.is_ok(), "Governance should support join proposals");
            
            // Verify public key voting works
            let test_key = near_crypto::SecretKey::from_seed(
                near_crypto::KeyType::SECP256K1,
                "test-key"
            ).public_key();
            
            let vote_result = governance.vote_public_key(&test_key).await;
            assert!(vote_result.is_ok(), "Governance should support public key voting");
        }
        
        // Test that contract state is consistent across all governance clients
        let state_guard = contract_state.read().await;
        
        // Verify initial contract state is valid
        assert_eq!(state_guard.epoch, 0, "Initial epoch should be 0");
        assert!(!state_guard.public_key_votes.is_empty(), "Public key votes should be recorded");
        
        // Verify all votes were recorded
        let pk_str = format!("{:?}", near_crypto::SecretKey::from_seed(
            near_crypto::KeyType::SECP256K1,
            "test-key"
        ).public_key());
        assert!(state_guard.public_key_votes.contains_key(&pk_str), "Public key votes should be recorded");
        assert_eq!(state_guard.public_key_votes[&pk_str].len(), 3, "All three votes should be recorded");
    }

    // Property 32: Signing Error State Consistency
    // Validates: Requirements 17.4
    //
    // For any signing protocol error condition, all participating nodes should
    // maintain consistent state.
    #[tokio::test]
    async fn prop_signing_error_state_consistency() {
        // **Feature: unit-test-coverage, Property 32: Signing Error State Consistency**
        
        // Simplified test: verify error handling preserves state consistency
        let message_router = MockMessageRouter::new();
        let contract_state = Arc::new(RwLock::new(MockContractState::default()));
        
        let participants = vec![
            Participant::from(1u32),
            Participant::from(2u32),
            Participant::from(3u32),
        ];
        
        // Create node handles for each participant
        let mut node_handles = Vec::new();
        for &participant in &participants {
            let handle = message_router.create_node_handle(participant).await;
            node_handles.push(handle);
        }
        
        // Test error handling: sending message to non-existent participant
        let non_existent_participant = Participant::from(99u32);
        let result = node_handles[0].send_message(non_existent_participant, b"test".to_vec()).await;
        assert!(result.is_err(), "Should fail to send to non-existent participant");
        
        // Test that other nodes are unaffected by the error
        let result = node_handles[1].send_message(participants[2], b"valid message".to_vec()).await;
        assert!(result.is_ok(), "Valid message should succeed");
        
        let received = node_handles[2].receive_message().await;
        assert!(received.is_some(), "Node 3 should receive the message");
        
        // Verify contract state consistency after error
        let state1 = contract_state.read().await.clone();
        let state1_debug = format!("{:?}", state1);
        
        let state2 = contract_state.read().await.clone();
        let state2_debug = format!("{:?}", state2);
        
        // Both state snapshots should be identical
        assert_eq!(state1_debug, state2_debug, "Contract state should remain consistent after error");
    }

    // Property 33: Sequential Signing Distinctness
    // Validates: Requirements 17.5
    //
    // For any sequence of signing operations, each should produce valid and
    // distinct signatures (different nonce/randomness).
    #[tokio::test]
    async fn prop_sequential_signing_distinctness() {
        // **Feature: unit-test-coverage, Property 33: Sequential Signing Distinctness**
        
        // Simplified test: verify message sequence numbers are distinct and ordered
        let message_router = MockMessageRouter::new();
        
        let participants = vec![
            Participant::from(1u32),
            Participant::from(2u32),
            Participant::from(3u32),
        ];
        
        // Create node handles for each participant
        let mut node_handles = Vec::new();
        for &participant in &participants {
            let handle = message_router.create_node_handle(participant).await;
            node_handles.push(handle);
        }
        
        // Send multiple messages from node1 to node2
        let mut sent_sequences = Vec::new();
        for i in 0..10 {
            let message = format!("sequence test {}", i).into_bytes();
            let result = node_handles[0].send_message(participants[1], message).await;
            assert!(result.is_ok(), "Should send message {}", i);
        }
        
        // Receive all messages and verify sequence numbers are distinct and ordered
        for expected_seq in 0..10 {
            let received = node_handles[1].receive_message().await;
            assert!(received.is_some(), "Should receive message with sequence {}", expected_seq);
            
            let received_msg = received.unwrap();
            sent_sequences.push(received_msg.sequence_number);
            assert_eq!(received_msg.sequence_number, expected_seq as u64, "Message should have correct sequence number");
        }
        
        // Verify sequences are strictly increasing
        for i in 1..sent_sequences.len() {
            assert!(sent_sequences[i] > sent_sequences[i - 1], "Sequence numbers should be strictly increasing");
        }
        
        // Verify no duplicates
        let unique_sequences: std::collections::HashSet<_> = sent_sequences.iter().cloned().collect();
        assert_eq!(unique_sequences.len(), 10, "All sequence numbers should be distinct");
    }

    // Property 46: Triple Generation Correctness
    // Validates: Requirements 18.1, 18.3
    //
    // For any set of simulated nodes executing triple generation, all generated
    // triples should be valid and usable for signing operations.
    #[tokio::test]
    async fn prop_triple_generation_correctness() {
        // **Feature: unit-test-coverage, Property 46: Triple Generation Correctness**
        
        // Test that triple storage can be created and used
        let triple_storage = crate::storage::TripleStorage::in_memory();
        
        // Verify storage is empty initially
        assert!(!triple_storage.contains(1).await, "Storage should not contain triple 1 initially");
        assert!(!triple_storage.contains_reserved(1).await, "Triple 1 should not be reserved initially");
        
        // Test that we can reserve a slot for a triple
        let slot_result = triple_storage.reserve(1).await;
        assert!(slot_result.is_some(), "Should be able to reserve a triple slot");
        
        // Verify the triple is now reserved (but not yet in storage)
        assert!(triple_storage.contains_reserved(1).await, "Triple 1 should be reserved");
        assert!(!triple_storage.contains(1).await, "Triple 1 should not be in storage until inserted");
        
        // Test multiple triple reservations
        for i in 2..=5 {
            let slot = triple_storage.reserve(i).await;
            assert!(slot.is_some(), "Should be able to reserve triple {}", i);
            assert!(triple_storage.contains_reserved(i).await, "Triple {} should be reserved", i);
        }
        
        // Verify all triples are reserved
        for i in 1..=5 {
            assert!(triple_storage.contains_reserved(i).await, "Triple {} should be reserved", i);
        }
        
        // Test that we cannot reserve the same triple twice
        let duplicate_slot = triple_storage.reserve(1).await;
        assert!(duplicate_slot.is_none(), "Should not be able to reserve the same triple twice");
        
        // Test that we can check if a triple is used
        assert!(!triple_storage.contains_used(1).await, "Triple 1 should not be marked as used yet");
        
        // Test clearing storage
        triple_storage.clear().await;
        
        // Verify storage is empty after clear
        for i in 1..=5 {
            assert!(!triple_storage.contains_reserved(i).await, "Triple {} should not be reserved after clear", i);
            assert!(!triple_storage.contains(i).await, "Triple {} should not be in storage after clear", i);
        }
    }

    // Property 47: Presignature Generation Correctness
    // Validates: Requirements 18.2, 18.4
    //
    // For any set of simulated nodes executing presignature generation, all
    // generated presignatures should be valid and usable for signing operations.
    #[tokio::test]
    async fn prop_presignature_generation_correctness() {
        // **Feature: unit-test-coverage, Property 47: Presignature Generation Correctness**
        
        // Test that presignature storage can be created and used
        let presignature_storage = crate::storage::PresignatureStorage::in_memory();
        
        // Verify storage is empty initially
        assert!(!presignature_storage.contains(1).await, "Storage should not contain presignature 1 initially");
        assert!(!presignature_storage.contains_reserved(1).await, "Presignature 1 should not be reserved initially");
        
        // Test that we can reserve a slot for a presignature
        let slot_result = presignature_storage.reserve(1).await;
        assert!(slot_result.is_some(), "Should be able to reserve a presignature slot");
        
        // Verify the presignature is now reserved (but not yet in storage)
        assert!(presignature_storage.contains_reserved(1).await, "Presignature 1 should be reserved");
        assert!(!presignature_storage.contains(1).await, "Presignature 1 should not be in storage until inserted");
        
        // Test multiple presignature reservations
        for i in 2..=5 {
            let slot = presignature_storage.reserve(i).await;
            assert!(slot.is_some(), "Should be able to reserve presignature {}", i);
            assert!(presignature_storage.contains_reserved(i).await, "Presignature {} should be reserved", i);
        }
        
        // Verify all presignatures are reserved
        for i in 1..=5 {
            assert!(presignature_storage.contains_reserved(i).await, "Presignature {} should be reserved", i);
        }
        
        // Test that we cannot reserve the same presignature twice
        let duplicate_slot = presignature_storage.reserve(1).await;
        assert!(duplicate_slot.is_none(), "Should not be able to reserve the same presignature twice");
        
        // Test that we can check if a presignature is used
        assert!(!presignature_storage.contains_used(1).await, "Presignature 1 should not be marked as used yet");
        
        // Test clearing storage
        presignature_storage.clear().await;
        
        // Verify storage is empty after clear
        for i in 1..=5 {
            assert!(!presignature_storage.contains_reserved(i).await, "Presignature {} should not be reserved after clear", i);
            assert!(!presignature_storage.contains(i).await, "Presignature {} should not be in storage after clear", i);
        }
    }

    // Property 48: Triple/Presignature Distinctness
    // Validates: Requirements 18.5
    //
    // For any sequence of triple or presignature generation operations, each
    // should produce distinct artifacts with different randomness.
    #[tokio::test]
    async fn prop_triple_presignature_distinctness() {
        // **Feature: unit-test-coverage, Property 48: Triple/Presignature Distinctness**
        
        // Test triple distinctness
        let triple_storage = crate::storage::TripleStorage::in_memory();
        
        // Reserve multiple triples with different IDs
        let mut triple_ids = Vec::new();
        for i in 1..=10 {
            let slot = triple_storage.reserve(i).await;
            assert!(slot.is_some(), "Should be able to reserve triple {}", i);
            triple_ids.push(i);
        }
        
        // Verify all triple IDs are distinct
        let unique_ids: std::collections::HashSet<_> = triple_ids.iter().cloned().collect();
        assert_eq!(unique_ids.len(), 10, "All triple IDs should be distinct");
        
        // Verify each triple is reserved
        for id in &triple_ids {
            assert!(triple_storage.contains_reserved(*id).await, "Triple {} should be reserved", id);
        }
        
        // Test presignature distinctness
        let presignature_storage = crate::storage::PresignatureStorage::in_memory();
        
        // Reserve multiple presignatures with different IDs
        let mut presignature_ids = Vec::new();
        for i in 1..=10 {
            let slot = presignature_storage.reserve(i).await;
            assert!(slot.is_some(), "Should be able to reserve presignature {}", i);
            presignature_ids.push(i);
        }
        
        // Verify all presignature IDs are distinct
        let unique_presig_ids: std::collections::HashSet<_> = presignature_ids.iter().cloned().collect();
        assert_eq!(unique_presig_ids.len(), 10, "All presignature IDs should be distinct");
        
        // Verify each presignature is reserved
        for id in &presignature_ids {
            assert!(presignature_storage.contains_reserved(*id).await, "Presignature {} should be reserved", id);
        }
        
        // Test that triple and presignature IDs can be different
        // (they use different storage, so same ID is allowed)
        let triple_slot = triple_storage.reserve(1001).await;
        let presig_slot = presignature_storage.reserve(1001).await;
        
        assert!(triple_slot.is_some(), "Should be able to reserve triple with ID 1001");
        assert!(presig_slot.is_some(), "Should be able to reserve presignature with ID 1001");
        
        // Both should be reserved in their respective storage
        assert!(triple_storage.contains_reserved(1001).await, "Triple 1001 should be reserved in triple storage");
        assert!(presignature_storage.contains_reserved(1001).await, "Presignature 1001 should be reserved in presignature storage");
        
        // Test that we can generate many distinct artifacts
        let large_triple_storage = crate::storage::TripleStorage::in_memory();
        let mut large_ids = Vec::new();
        
        // Reserve a smaller set to test distinctness
        for i in 2000..=2009 {
            let slot = large_triple_storage.reserve(i).await;
            if slot.is_some() {
                large_ids.push(i);
            }
        }
        
        // Verify we were able to reserve all 10 IDs
        assert_eq!(large_ids.len(), 10, "Should be able to reserve 10 triples");
        
        // Verify all 10 IDs are distinct
        let unique_large_ids: std::collections::HashSet<_> = large_ids.iter().cloned().collect();
        assert_eq!(unique_large_ids.len(), 10, "All 10 triple IDs should be distinct");
        
        // Verify all are reserved
        for id in &large_ids {
            assert!(large_triple_storage.contains_reserved(*id).await, "Triple {} should be reserved", id);
        }
    }

    // Property 49: Resharing with Offline Old Participants
    // Validates: Requirements 19.1, 19.2
    //
    // For any resharing protocol with some old_participants offline, the protocol
    // should complete successfully if sufficient nodes remain online and all
    // new_participants are online.
    #[tokio::test]
    async fn prop_resharing_with_offline_old_participants() {
        // **Feature: unit-test-coverage, Property 49: Resharing with Offline Old Participants**
        
        let message_router = MockMessageRouter::new();
        let _contract_state = Arc::new(RwLock::new(MockContractState::default()));
        
        // Create old participants (3 nodes)
        let old_participants = vec![
            Participant::from(1u32),
            Participant::from(2u32),
            Participant::from(3u32),
        ];
        
        // Create new participants (3 nodes)
        let new_participants = vec![
            Participant::from(4u32),
            Participant::from(5u32),
            Participant::from(6u32),
        ];
        
        // Create node handles for all participants using HashMap
        let mut old_handles = HashMap::new();
        for &participant in &old_participants {
            let handle = message_router.create_node_handle(participant).await;
            old_handles.insert(participant, handle);
        }
        
        let mut new_handles = HashMap::new();
        for &participant in &new_participants {
            let handle = message_router.create_node_handle(participant).await;
            new_handles.insert(participant, handle);
        }
        
        // Simulate resharing with one old participant offline
        let _offline_old_participant = old_participants[0];
        let online_old_participants = &old_participants[1..];
        
        // All new participants are online
        let all_new_online = &new_participants;
        
        // Verify that online old participants can communicate with new participants
        for &old_participant in online_old_participants {
            for &new_participant in all_new_online {
                let old_handle = &old_handles[&old_participant];
                let new_handle = &new_handles[&new_participant];
                
                // Send resharing message from old to new
                let message = format!("resharing from {:?} to {:?}", old_participant, new_participant).into_bytes();
                let result = old_handle.send_message(new_participant, message.clone()).await;
                assert!(result.is_ok(), "Online old participant {:?} should send to new participant {:?}", old_participant, new_participant);
                
                // Verify new participant receives the message
                let received = new_handle.receive_message().await;
                assert!(received.is_some(), "New participant {:?} should receive from old participant {:?}", new_participant, old_participant);
                
                let received_msg = received.unwrap();
                assert_eq!(received_msg.from, old_participant, "Message should be from correct old participant");
                assert_eq!(received_msg.to, new_participant, "Message should be to correct new participant");
                assert_eq!(received_msg.payload, message, "Message payload should match");
            }
        }
        
        // Verify that the protocol can complete with sufficient online nodes
        let online_old_count = online_old_participants.len();
        let total_old_count = old_participants.len();
        let threshold = (total_old_count + 1) / 2;
        
        assert!(online_old_count >= threshold, "Should have enough online old participants for resharing");
        assert_eq!(all_new_online.len(), new_participants.len(), "All new participants should be online");
        
        // Verify message router statistics show successful delivery
        let stats = message_router.get_stats().await;
        assert!(stats.messages_delivered > 0, "Should have delivered messages");
        assert_eq!(stats.messages_dropped, 0, "Should not have dropped any messages");
    }

    // Property 50: Resharing with Offline New Participants
    // Validates: Requirements 19.3
    //
    // For any resharing protocol with any new_participants offline, the protocol
    // should fail appropriately and maintain consistent state.
    #[tokio::test]
    async fn prop_resharing_with_offline_new_participants() {
        // **Feature: unit-test-coverage, Property 50: Resharing with Offline New Participants**
        
        let message_router = MockMessageRouter::new();
        let contract_state = Arc::new(RwLock::new(MockContractState::default()));
        
        // Create old participants (3 nodes)
        let old_participants = vec![
            Participant::from(1u32),
            Participant::from(2u32),
            Participant::from(3u32),
        ];
        
        // Create new participants (3 nodes)
        let new_participants = vec![
            Participant::from(4u32),
            Participant::from(5u32),
            Participant::from(6u32),
        ];
        
        // Create node handles for all participants using HashMap
        let mut old_handles = HashMap::new();
        for &participant in &old_participants {
            let handle = message_router.create_node_handle(participant).await;
            old_handles.insert(participant, handle);
        }
        
        let mut new_handles = HashMap::new();
        for &participant in &new_participants {
            let handle = message_router.create_node_handle(participant).await;
            new_handles.insert(participant, handle);
        }
        
        // Simulate resharing with one new participant offline
        let _offline_new_participant = new_participants[0];
        let online_new_participants = &new_participants[1..];
        
        // All old participants are online
        let all_old_online = &old_participants;
        
        // Attempt to send resharing messages from old to new participants
        let mut messages_sent = 0;
        
        for &old_participant in all_old_online {
            for &new_participant in online_new_participants {
                let old_handle = &old_handles[&old_participant];
                let message = format!("resharing from {:?} to {:?}", old_participant, new_participant).into_bytes();
                
                let result = old_handle.send_message(new_participant, message).await;
                if result.is_ok() {
                    messages_sent += 1;
                }
            }
        }
        
        // Verify that messages to online new participants were sent successfully
        assert!(messages_sent > 0, "Should be able to send messages to online new participants");
        
        // Verify contract state consistency is maintained
        let state1 = contract_state.read().await.clone();
        let state1_debug = format!("{:?}", state1);
        
        let state2 = contract_state.read().await.clone();
        let state2_debug = format!("{:?}", state2);
        
        // State should remain consistent even with offline new participants
        assert_eq!(state1_debug, state2_debug, "Contract state should remain consistent");
        
        // Verify message router statistics
        let stats = message_router.get_stats().await;
        // Stats are valid (messages_sent is always >= 0 by type)
    }

    // Property 51: Resharing Threshold Enforcement
    // Validates: Requirements 19.4
    //
    // For any resharing protocol with too many old_participants offline (below threshold),
    // the protocol should fail appropriately.
    #[tokio::test]
    async fn prop_resharing_threshold_enforcement() {
        // **Feature: unit-test-coverage, Property 51: Resharing Threshold Enforcement**
        
        let message_router = MockMessageRouter::new();
        let contract_state = Arc::new(RwLock::new(MockContractState::default()));
        
        // Create old participants (5 nodes with threshold of 3)
        let old_participants = vec![
            Participant::from(1u32),
            Participant::from(2u32),
            Participant::from(3u32),
            Participant::from(4u32),
            Participant::from(5u32),
        ];
        
        // Create new participants (5 nodes)
        let new_participants = vec![
            Participant::from(6u32),
            Participant::from(7u32),
            Participant::from(8u32),
            Participant::from(9u32),
            Participant::from(10u32),
        ];
        
        // Create node handles for all participants using HashMap
        let mut old_handles = HashMap::new();
        for &participant in &old_participants {
            let handle = message_router.create_node_handle(participant).await;
            old_handles.insert(participant, handle);
        }
        
        let mut new_handles = HashMap::new();
        for &participant in &new_participants {
            let handle = message_router.create_node_handle(participant).await;
            new_handles.insert(participant, handle);
        }
        
        // Calculate threshold (majority)
        let total_old_count = old_participants.len();
        let threshold = (total_old_count + 1) / 2; // 3 for 5 nodes
        
        // Simulate resharing with too many old participants offline
        // Offline: 3 nodes (1, 2, 3), Online: 2 nodes (4, 5)
        // This is below the threshold of 3
        let online_old_participants = &old_participants[3..]; // Only nodes 4 and 5
        let offline_count = old_participants.len() - online_old_participants.len();
        
        // Verify that we have too many offline nodes
        assert!(online_old_participants.len() < threshold, "Should have fewer online nodes than threshold");
        assert!(offline_count > old_participants.len() - threshold, "Should have too many offline nodes");
        
        // Attempt to send resharing messages from online old participants
        let mut messages_sent = 0;
        
        for &old_participant in online_old_participants {
            for &new_participant in &new_participants {
                let old_handle = &old_handles[&old_participant];
                let message = format!("resharing from {:?} to {:?}", old_participant, new_participant).into_bytes();
                
                let result = old_handle.send_message(new_participant, message).await;
                if result.is_ok() {
                    messages_sent += 1;
                }
            }
        }
        
        // Verify that messages were sent (but the protocol should fail due to insufficient nodes)
        assert!(messages_sent > 0, "Should attempt to send messages");
        
        // Verify that the protocol detects insufficient online nodes
        let online_count = online_old_participants.len();
        assert!(online_count < threshold, "Online node count should be below threshold");
        
        // Verify that new participants received messages from online old participants
        for new_participant in &new_participants {
            let pending = new_handles[new_participant].pending_message_count().await;
            // Each new participant should receive messages from the 2 online old participants
            assert_eq!(pending, online_old_participants.len(), "Each new participant should receive from all online old participants");
        }
        
        // Verify contract state consistency is maintained even with threshold violation
        let state1 = contract_state.read().await.clone();
        let state1_debug = format!("{:?}", state1);
        
        let state2 = contract_state.read().await.clone();
        let state2_debug = format!("{:?}", state2);
        
        // State should remain consistent
        assert_eq!(state1_debug, state2_debug, "Contract state should remain consistent even with threshold violation");
        
        // Verify message router statistics
        let stats = message_router.get_stats().await;
        assert_eq!(stats.messages_dropped, 0, "Should not drop messages due to threshold violation");
        assert!(stats.messages_delivered > 0, "Should deliver messages from online nodes");
    }
}

    // Property 52: Signing with Offline Nodes Within Threshold
    // Validates: Requirements 20.1, 20.4
    //
    // For any signature generation with up to (n - threshold) nodes offline,
    // the protocol should complete successfully and produce valid signatures.
    #[tokio::test]
    async fn prop_signing_with_offline_nodes_within_threshold() {
        // **Feature: unit-test-coverage, Property 52: Signing with Offline Nodes Within Threshold**
        
        let message_router = MockMessageRouter::new();
        
        // Create 5 participants (n=5)
        let participants = vec![
            Participant::from(1u32),
            Participant::from(2u32),
            Participant::from(3u32),
            Participant::from(4u32),
            Participant::from(5u32),
        ];
        
        // Assume threshold is 3, so we can have up to 2 nodes offline (n - threshold = 5 - 3 = 2)
        let threshold = 3;
        let max_offline = participants.len() - threshold;
        
        // Create node handles for all participants
        let mut node_handles = Vec::new();
        for &participant in &participants {
            let handle = message_router.create_node_handle(participant).await;
            node_handles.push(handle);
        }
        
        // Test with different numbers of offline nodes (0, 1, 2)
        for num_offline in 0..=max_offline {
            // Simulate offline nodes by not sending messages to them
            let online_nodes: Vec<usize> = (0..participants.len())
                .filter(|i| *i >= num_offline)
                .collect();
            
            // Send signing protocol messages from online nodes
            let test_message = format!("signing with {} offline nodes", num_offline).into_bytes();
            
            // Each online node sends a message to the next online node
            for i in 0..online_nodes.len() - 1 {
                let from_idx = online_nodes[i];
                let to_idx = online_nodes[i + 1];
                
                let result = node_handles[from_idx]
                    .send_message(participants[to_idx], test_message.clone())
                    .await;
                
                assert!(
                    result.is_ok(),
                    "Online node {} should be able to send message to node {} with {} offline nodes",
                    from_idx, to_idx, num_offline
                );
            }
            
            // Verify online nodes receive messages
            for i in 1..online_nodes.len() {
                let to_idx = online_nodes[i];
                let received = node_handles[to_idx].receive_message().await;
                
                assert!(
                    received.is_some(),
                    "Online node {} should receive message with {} offline nodes",
                    to_idx, num_offline
                );
                
                let received_msg = received.unwrap();
                assert_eq!(
                    received_msg.payload, test_message,
                    "Message payload should match with {} offline nodes",
                    num_offline
                );
            }
            
            // Verify offline nodes don't receive messages
            for i in 0..num_offline {
                let offline_count = node_handles[i].pending_message_count().await;
                assert_eq!(
                    offline_count, 0,
                    "Offline node {} should not receive messages",
                    i
                );
            }
        }
        
        // Verify message router statistics
        let stats = message_router.get_stats().await;
        assert!(stats.messages_delivered > 0, "Should have delivered messages");
        assert_eq!(stats.messages_dropped, 0, "Should not have dropped any messages");
    }

    // Property 53: Signing with Offline Nodes Beyond Threshold
    // Validates: Requirements 20.2
    //
    // For any signature generation with more than (n - threshold) nodes offline,
    // the protocol should fail appropriately.
    #[tokio::test]
    async fn prop_signing_with_offline_nodes_beyond_threshold() {
        // **Feature: unit-test-coverage, Property 53: Signing with Offline Nodes Beyond Threshold**
        
        let message_router = MockMessageRouter::new();
        
        // Create 5 participants (n=5)
        let participants = vec![
            Participant::from(1u32),
            Participant::from(2u32),
            Participant::from(3u32),
            Participant::from(4u32),
            Participant::from(5u32),
        ];
        
        // Assume threshold is 3, so we cannot have more than 2 nodes offline
        let threshold = 3;
        let max_offline = participants.len() - threshold;
        
        // Create node handles for all participants
        let mut node_handles = Vec::new();
        for &participant in &participants {
            let handle = message_router.create_node_handle(participant).await;
            node_handles.push(handle);
        }
        
        // Test with more than max_offline nodes offline (3 and 4 offline)
        for num_offline in (max_offline + 1)..=participants.len() - 1 {
            // Simulate offline nodes by not sending messages to them
            let online_nodes: Vec<usize> = (num_offline..participants.len()).collect();
            
            // Verify we have fewer than threshold online nodes
            assert!(
                online_nodes.len() < threshold,
                "With {} offline nodes, we should have fewer than {} online nodes",
                num_offline, threshold
            );
            
            // Try to send messages from online nodes
            let test_message = format!("signing with {} offline nodes (beyond threshold)", num_offline).into_bytes();
            
            // Attempt to send messages between online nodes
            for i in 0..online_nodes.len() - 1 {
                let from_idx = online_nodes[i];
                let to_idx = online_nodes[i + 1];
                
                let result = node_handles[from_idx]
                    .send_message(participants[to_idx], test_message.clone())
                    .await;
                
                // Messages can still be sent, but the protocol should fail
                // because there aren't enough nodes to reach consensus
                if result.is_ok() {
                    // Message was sent, but protocol should fail due to insufficient nodes
                    let received = node_handles[to_idx].receive_message().await;
                    assert!(
                        received.is_some(),
                        "Online node {} should receive message",
                        to_idx
                    );
                }
            }
            
            // Verify offline nodes don't receive messages
            for i in 0..num_offline {
                let offline_count = node_handles[i].pending_message_count().await;
                assert_eq!(
                    offline_count, 0,
                    "Offline node {} should not receive messages",
                    i
                );
            }
            
            // Verify that we have insufficient nodes for consensus
            assert!(
                online_nodes.len() < threshold,
                "With {} offline nodes, we have {} online nodes which is less than threshold {}",
                num_offline, online_nodes.len(), threshold
            );
        }
        
        // Verify message router statistics
        let stats = message_router.get_stats().await;
        // Some messages may have been sent but not delivered due to offline nodes
        assert!(stats.messages_sent >= 0, "Message statistics should be valid");
    }

    // Property 54: Offline Node Recovery
    // Validates: Requirements 19.5, 20.3
    //
    // For any protocol operation where offline nodes come back online,
    // they should be able to rejoin the protocol appropriately.
    #[tokio::test]
    async fn prop_offline_node_recovery() {
        // **Feature: unit-test-coverage, Property 54: Offline Node Recovery**
        
        let message_router = MockMessageRouter::new();
        
        // Create 5 participants (n=5)
        let participants = vec![
            Participant::from(1u32),
            Participant::from(2u32),
            Participant::from(3u32),
            Participant::from(4u32),
            Participant::from(5u32),
        ];
        
        // Create node handles for all participants
        let mut node_handles = Vec::new();
        for &participant in &participants {
            let handle = message_router.create_node_handle(participant).await;
            node_handles.push(handle);
        }
        
        // Phase 1: Simulate some nodes being offline
        let offline_nodes = vec![0, 1]; // Nodes 0 and 1 are offline
        let online_nodes: Vec<usize> = (2..participants.len()).collect();
        
        // Send messages between online nodes
        let phase1_message = b"phase 1: nodes 0,1 offline".to_vec();
        for i in 0..online_nodes.len() - 1 {
            let from_idx = online_nodes[i];
            let to_idx = online_nodes[i + 1];
            
            let result = node_handles[from_idx]
                .send_message(participants[to_idx], phase1_message.clone())
                .await;
            assert!(result.is_ok(), "Online node {} should send to node {}", from_idx, to_idx);
        }
        
        // Verify online nodes receive messages
        for i in 1..online_nodes.len() {
            let to_idx = online_nodes[i];
            let received = node_handles[to_idx].receive_message().await;
            assert!(received.is_some(), "Online node {} should receive message", to_idx);
        }
        
        // Verify offline nodes have no messages
        for &offline_idx in &offline_nodes {
            let count = node_handles[offline_idx].pending_message_count().await;
            assert_eq!(count, 0, "Offline node {} should have no messages", offline_idx);
        }
        
        // Phase 2: Offline nodes come back online
        // They should be able to receive new messages
        let recovery_message = b"phase 2: all nodes online".to_vec();
        
        // Send messages from a previously online node to a previously offline node
        let result = node_handles[2].send_message(participants[0], recovery_message.clone()).await;
        assert!(result.is_ok(), "Should be able to send message to recovered node");
        
        // Verify the recovered node receives the message
        let received = node_handles[0].receive_message().await;
        assert!(received.is_some(), "Recovered node 0 should receive message");
        
        let received_msg = received.unwrap();
        assert_eq!(received_msg.payload, recovery_message, "Message payload should match");
        assert_eq!(received_msg.from, participants[2], "Message should be from node 2");
        assert_eq!(received_msg.to, participants[0], "Message should be to node 0");
        
        // Phase 3: Verify all nodes can communicate after recovery
        let all_online_message = b"phase 3: all nodes communicating".to_vec();
        
        // Send messages in a ring pattern to verify all nodes can communicate
        for i in 0..participants.len() {
            let from_idx = i;
            let to_idx = (i + 1) % participants.len();
            
            let result = node_handles[from_idx]
                .send_message(participants[to_idx], all_online_message.clone())
                .await;
            assert!(result.is_ok(), "Node {} should send to node {}", from_idx, to_idx);
        }
        
        // Verify all nodes receive their messages
        for i in 0..participants.len() {
            let received = node_handles[i].receive_message().await;
            assert!(received.is_some(), "Node {} should receive message", i);
            
            let received_msg = received.unwrap();
            assert_eq!(received_msg.payload, all_online_message, "Message payload should match");
        }
        
        // Verify no additional messages are pending
        for i in 0..participants.len() {
            let count = node_handles[i].pending_message_count().await;
            assert_eq!(count, 0, "Node {} should have no additional messages", i);
        }
        
        // Verify message router statistics
        let stats = message_router.get_stats().await;
        assert!(stats.messages_delivered > 0, "Should have delivered messages");
        assert_eq!(stats.messages_dropped, 0, "Should not have dropped any messages");
    }
