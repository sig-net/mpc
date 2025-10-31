use crate::protocol::Chain;
use crate::sign_bidirectional::{BidirectionalTx, PendingRequestStatus};
use mpc_primitives::SignId;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct PendingRequests {
    requests: HashMap<SignId, BidirectionalTx>,
    /// Queue of transaction IDs waiting to be published
    pending_publish: VecDeque<SignId>,
    /// The highest block height that has been processed for this chain
    processed_block_height: Option<u64>,
}

impl Default for PendingRequests {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingRequests {
    /// Creates a new empty PendingRequests container
    pub fn new() -> Self {
        Self {
            requests: HashMap::new(),
            pending_publish: VecDeque::new(),
            processed_block_height: None,
        }
    }

    /// Inserts a sign-respond transaction into the pending requests map
    /// Returns Some(old_value) if the key was already present
    fn insert(&mut self, id: SignId, tx: BidirectionalTx) -> Option<BidirectionalTx> {
        self.requests.insert(id, tx)
    }

    /// Removes a sign-respond transaction from the pending requests map
    /// Returns Some(value) if the key was present
    fn remove(&mut self, id: &SignId) -> Option<BidirectionalTx> {
        self.requests.remove(id)
    }

    /// Gets a clone of a sign-respond transaction from the pending requests map
    /// Returns Some(value) if the key is present
    fn get(&self, id: &SignId) -> Option<BidirectionalTx> {
        self.requests.get(id).cloned()
    }

    /// Returns the number of pending requests
    fn len(&self) -> usize {
        self.requests.len()
    }

    /// Returns all sign-respond transactions with a specific status
    pub fn get_by_status(&self, status: PendingRequestStatus) -> HashMap<SignId, BidirectionalTx> {
        self.requests
            .iter()
            .filter(|(_, tx)| tx.status == status)
            .map(|(id, tx)| (*id, tx.clone()))
            .collect()
    }

    /// Add a transaction ID to the pending publish queue
    pub fn push_pending_publish(&mut self, id: SignId) {
        self.pending_publish.push_back(id);
    }

    /// Pop the next transaction ID from the pending publish queue
    /// Returns the transaction if found
    pub fn pop_pending_publish(&mut self) -> Option<(SignId, BidirectionalTx)> {
        let id = self.pending_publish.pop_front()?;
        let tx = self.get(&id)?;
        Some((id, tx))
    }

    /// Get the number of transactions waiting to be published
    fn pending_publish_count(&self) -> usize {
        self.pending_publish.len()
    }

    /// Get all pending transaction IDs and their transactions
    fn pending_execution(&self) -> Vec<(SignId, BidirectionalTx)> {
        self.pending_publish
            .iter()
            .filter_map(|id| self.get(id).map(|tx| (*id, tx)))
            .collect()
    }

    /// Get the processed block height for this chain
    fn processed_block_height(&self) -> Option<u64> {
        self.processed_block_height
    }

    /// Set the processed block height for this chain
    fn set_processed_block(&mut self, height: u64) {
        self.processed_block_height = Some(height);
    }
}

/// Backlog manages pending sign-respond requests across multiple chains.
/// Each chain has its own isolated set of pending requests with their own
/// publish queues.
#[derive(Debug, Clone)]
pub struct Backlog {
    requests: Arc<RwLock<HashMap<Chain, PendingRequests>>>,
}

impl Default for Backlog {
    fn default() -> Self {
        Self::new()
    }
}

impl Backlog {
    pub fn new() -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn insert(
        &self,
        chain: Chain,
        id: SignId,
        tx: BidirectionalTx,
    ) -> Option<BidirectionalTx> {
        self.requests
            .write()
            .await
            .entry(chain)
            .or_insert_with(PendingRequests::new)
            .insert(id, tx)
    }

    pub async fn remove(&self, chain: Chain, id: &SignId) -> Option<BidirectionalTx> {
        self.requests
            .write()
            .await
            .entry(chain)
            .or_insert_with(PendingRequests::new)
            .remove(id)
    }

    pub async fn get(&self, chain: Chain, id: &SignId) -> Option<BidirectionalTx> {
        self.requests
            .read()
            .await
            .get(&chain)
            .and_then(|pending_requests| pending_requests.get(id))
    }

    /// Returns the number of pending requests in total
    pub async fn len(&self) -> usize {
        self.requests
            .read()
            .await
            .values()
            .map(|requests| requests.len())
            .sum()
    }

    /// Returns true if there are no pending requests
    pub async fn is_empty(&self) -> bool {
        self.requests.read().await.is_empty()
    }

    /// Returns all sign-respond transactions with a specific status
    pub async fn get_by_status(
        &self,
        chain: Chain,
        status: PendingRequestStatus,
    ) -> HashMap<SignId, BidirectionalTx> {
        self.requests
            .read()
            .await
            .get(&chain)
            .map(|requests| requests.get_by_status(status))
            .unwrap_or_default()
    }

    pub async fn len_by_chain(&self, chain: Chain) -> usize {
        self.requests
            .read()
            .await
            .get(&chain)
            .map(|requests| requests.len())
            .unwrap_or(0)
    }

    /// Mark a request as published (success or failure)
    pub async fn mark_published(
        &self,
        _chain: Chain,
        _id: &SignId,
        _success: bool,
    ) -> Result<(), BacklogError> {
        // TODO: implement
        Ok(())
    }

    /// Get the number of transactions waiting to be published for a specific chain
    pub async fn pending_publish_count(&self, chain: Chain) -> usize {
        self.requests
            .read()
            .await
            .get(&chain)
            .map(|pr| pr.pending_publish_count())
            .unwrap_or(0)
    }

    /// Get all pending transactions for a specific chain
    pub async fn pending_execution(&self, chain: Chain) -> Vec<(SignId, BidirectionalTx)> {
        self.requests
            .read()
            .await
            .get(&chain)
            .map(|pr| pr.pending_execution())
            .unwrap_or_default()
    }

    /// Get the processed block height for a specific chain
    pub async fn processed_block(&self, chain: Chain) -> Option<u64> {
        self.requests
            .read()
            .await
            .get(&chain)
            .and_then(|pr| pr.processed_block_height())
    }

    /// Set the processed block height for a specific chain
    pub async fn set_processed_block(&self, chain: Chain, height: u64) {
        let mut map = self.requests.write().await;
        let pending_requests = map.entry(chain).or_default();
        pending_requests.set_processed_block(height);
        tracing::debug!(?chain, height, "updated processed block height");
    }
}

/// Errors that can occur when working with Backlog
#[derive(Debug, thiserror::Error)]
pub enum BacklogError {
    #[error("request not found for chain {chain:?} with id {id:?}")]
    NotFound { chain: Chain, id: SignId },
    #[error("chain not initialized: {chain:?}")]
    ChainNotInitialized { chain: Chain },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign_bidirectional::{BidirectionalTx, BidirectionalTxId, PendingRequestStatus};
    use alloy::primitives::{Address, B256};
    use anchor_lang::prelude::Pubkey;
    use mpc_primitives::SignId;

    fn create_test_tx(id: u8, status: PendingRequestStatus) -> BidirectionalTx {
        BidirectionalTx {
            id: BidirectionalTxId(B256::from([id; 32])),
            sender: Pubkey::new_unique(),
            serialized_transaction: vec![1, 2, 3],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: "test_caip2_id".to_string(),
            key_version: 1,
            deposit: 1000,
            path: "test_path".to_string(),
            algo: "ECDSA".to_string(),
            dest: "0x1234567890123456789012345678901234567890".to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: vec![],
            request_id: [id; 32],
            from_address: Address::ZERO,
            nonce: 0,
            participants: vec![],
            status,
        }
    }

    #[tokio::test]
    async fn test_backlog_chain_isolation() {
        let backlog = Backlog::new();

        let tx_eth = create_test_tx(1, PendingRequestStatus::PendingExecution);
        let tx_sol = create_test_tx(2, PendingRequestStatus::PendingExecution);
        let tx_near = create_test_tx(3, PendingRequestStatus::PendingExecution);

        let sign_id_eth = SignId::new(tx_eth.request_id);
        let sign_id_sol = SignId::new(tx_sol.request_id);
        let sign_id_near = SignId::new(tx_near.request_id);

        // Insert into different chains
        backlog
            .insert(Chain::Ethereum, sign_id_eth, tx_eth.clone())
            .await;
        backlog
            .insert(Chain::Solana, sign_id_sol, tx_sol.clone())
            .await;
        backlog
            .insert(Chain::NEAR, sign_id_near, tx_near.clone())
            .await;

        // Verify correct transactions in each chain
        assert!(backlog.get(Chain::Ethereum, &sign_id_eth).await.is_some());
        assert!(backlog.get(Chain::Ethereum, &sign_id_sol).await.is_none());
        assert!(backlog.get(Chain::Solana, &sign_id_sol).await.is_some());
        assert!(backlog.get(Chain::Solana, &sign_id_eth).await.is_none());
        assert!(backlog.get(Chain::NEAR, &sign_id_near).await.is_some());
        assert!(backlog.get(Chain::NEAR, &sign_id_eth).await.is_none());
    }

    #[tokio::test]
    async fn test_backlog_filter_by_status() {
        let backlog = Backlog::new();

        // Add transactions with different statuses to Ethereum
        let tx1 = create_test_tx(1, PendingRequestStatus::PendingExecution);
        let tx2 = create_test_tx(2, PendingRequestStatus::Success);
        let tx3 = create_test_tx(3, PendingRequestStatus::PendingExecution);

        backlog
            .insert(Chain::Ethereum, SignId::new(tx1.request_id), tx1)
            .await;
        backlog
            .insert(Chain::Ethereum, SignId::new(tx2.request_id), tx2)
            .await;
        backlog
            .insert(Chain::Ethereum, SignId::new(tx3.request_id), tx3)
            .await;

        // Add transactions to Solana
        let tx4 = create_test_tx(4, PendingRequestStatus::PendingExecution);
        backlog
            .insert(Chain::Solana, SignId::new(tx4.request_id), tx4)
            .await;

        // Filter Ethereum by Pending
        let eth_pending = backlog
            .get_by_status(Chain::Ethereum, PendingRequestStatus::PendingExecution)
            .await;
        assert_eq!(eth_pending.len(), 2);

        // Filter Ethereum by Success
        let eth_success = backlog
            .get_by_status(Chain::Ethereum, PendingRequestStatus::Success)
            .await;
        assert_eq!(eth_success.len(), 1);

        // Filter Solana by Pending
        let sol_pending = backlog
            .get_by_status(Chain::Solana, PendingRequestStatus::PendingExecution)
            .await;
        assert_eq!(sol_pending.len(), 1);

        // Filter non-existent chain returns empty
        let near_pending = backlog
            .get_by_status(Chain::NEAR, PendingRequestStatus::PendingExecution)
            .await;
        assert_eq!(near_pending.len(), 0);
    }

    #[tokio::test]
    async fn test_backlog_concurrent_access() {
        let backlog = Backlog::new();
        let mut handles = vec![];

        // Spawn multiple tasks that insert concurrently to different chains
        for i in 0..5 {
            let backlog = backlog.clone();
            let handle = tokio::spawn(async move {
                let tx = create_test_tx(i, PendingRequestStatus::PendingExecution);
                let sign_id = SignId::new(tx.request_id);
                backlog.insert(Chain::Ethereum, sign_id, tx).await;
            });
            handles.push(handle);
        }

        for i in 5..10 {
            let backlog = backlog.clone();
            let handle = tokio::spawn(async move {
                let tx = create_test_tx(i, PendingRequestStatus::PendingExecution);
                let sign_id = SignId::new(tx.request_id);
                backlog.insert(Chain::Solana, sign_id, tx).await;
            });
            handles.push(handle);
        }

        // Wait for all insertions and verify all were inserted
        for handle in handles {
            handle.await.unwrap();
        }
        assert_eq!(backlog.len_by_chain(Chain::Ethereum).await, 5);
        assert_eq!(backlog.len_by_chain(Chain::Solana).await, 5);

        // Spawn multiple tasks that remove concurrently
        let mut handles = vec![];
        for i in 0..5 {
            let backlog = backlog.clone();
            let handle = tokio::spawn(async move {
                let id = SignId::new([i; 32]);
                backlog.remove(Chain::Ethereum, &id).await
            });
            handles.push(handle);
        }

        // Wait for all removals
        for handle in handles {
            let removed = handle.await.unwrap();
            assert!(removed.is_some());
        }

        // Verify Ethereum chain is now empty, but Solana still has data
        assert_eq!(backlog.len_by_chain(Chain::Ethereum).await, 0);
        assert_eq!(backlog.len_by_chain(Chain::Solana).await, 5);
    }
}
