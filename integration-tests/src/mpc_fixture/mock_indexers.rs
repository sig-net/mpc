//! Generic mock indexer for testing CheckpointManager integration

use alloy::primitives::{Address, B256};
use k256::Scalar;
use mpc_node::checkpoint::CheckpointManager;
use mpc_node::protocol::{Chain, IndexedSignRequest, SignRequestType};
use mpc_node::read_respond::ReadRespondedTx;
use mpc_node::sign_respond_tx::{SignRespondTx, SignRespondTxId, SignRespondTxStatus};
use mpc_primitives::{SignArgs, SignId};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::interval;

/// Generic mock indexer that simulates blockchain indexing with checkpoint integration
pub struct MockIndexer {
    chain: Chain,
    checkpoint_manager: Arc<CheckpointManager>,
    sign_request_tx: mpsc::Sender<IndexedSignRequest>,
    mock_tx_counter: u64,
}

impl MockIndexer {
    /// Create a new mock indexer for the specified chain
    pub fn new(
        chain: Chain,
        checkpoint_manager: Arc<CheckpointManager>,
        sign_request_tx: mpsc::Sender<IndexedSignRequest>,
    ) -> Self {
        Self {
            chain,
            checkpoint_manager,
            sign_request_tx,
            mock_tx_counter: 0,
        }
    }

    /// Create a mock indexer for Ethereum
    pub fn ethereum(
        checkpoint_manager: Arc<CheckpointManager>,
        sign_request_tx: mpsc::Sender<IndexedSignRequest>,
    ) -> Self {
        Self::new(Chain::Ethereum, checkpoint_manager, sign_request_tx)
    }

    /// Create a mock indexer for Solana
    pub fn solana(
        checkpoint_manager: Arc<CheckpointManager>,
        sign_request_tx: mpsc::Sender<IndexedSignRequest>,
    ) -> Self {
        Self::new(Chain::Solana, checkpoint_manager, sign_request_tx)
    }

    /// Create a mock indexer for NEAR
    pub fn near(
        checkpoint_manager: Arc<CheckpointManager>,
        sign_request_tx: mpsc::Sender<IndexedSignRequest>,
    ) -> Self {
        Self::new(Chain::NEAR, checkpoint_manager, sign_request_tx)
    }

    /// Start the mock indexer process
    pub fn start(
        chain: Chain,
        checkpoint_manager: Arc<CheckpointManager>,
        sign_request_tx: mpsc::Sender<IndexedSignRequest>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let interval_ms = Self::get_interval_for_chain(&chain);
            let mut interval = interval(Duration::from_millis(interval_ms));
            let mut block_height = 1u64;

            loop {
                interval.tick().await;

                // Simulate getting pending transactions from checkpoint manager
                let pending_txs = checkpoint_manager.get_pending_sign_respond_txs(chain).await;

                // Process each pending transaction
                for (tx_id, _tx) in pending_txs {
                    tracing::info!(
                        "MockIndexer({:?}): Processing transaction {:?} at block {}",
                        chain,
                        tx_id,
                        block_height
                    );

                    // Simulate transaction success/failure with chain-specific rates
                    let success = Self::simulate_success(&chain, block_height, &tx_id);

                    if let Some(sign_id) = checkpoint_manager.get_sign_id_from_tx_id(&tx_id).await {
                        if success {
                            checkpoint_manager.found_tx_output(chain, &sign_id).await;
                        }

                        // Create a mock sign request for the completed transaction
                        if success {
                            let mock_request = Self::create_mock_read_respond_request(
                                sign_id,
                                chain,
                                block_height,
                            );
                            let _ = sign_request_tx.send(mock_request).await;
                        }
                    }
                }

                block_height += 1;

                // Stop after processing 100 blocks to avoid infinite loop in tests
                if block_height > 100 {
                    break;
                }
            }
        })
    }

    /// Simulate adding a new transaction to be tracked
    pub async fn add_mock_transaction(&mut self, sign_id: SignId) -> SignRespondTxId {
        let tx_id = SignRespondTxId(B256::from_slice(&[self.mock_tx_counter as u8; 32]));
        self.mock_tx_counter += 1;

        // Create a mock SignRespondTx with chain-specific parameters
        let mock_tx = self.create_mock_sign_respond_tx(sign_id, tx_id);

        // Store the transaction in checkpoint manager
        self.checkpoint_manager
            .published_signed_transaction(&self.chain, &sign_id, tx_id, mock_tx)
            .await;

        tx_id
    }

    /// Get the chain this indexer is configured for
    pub fn chain(&self) -> Chain {
        self.chain
    }

    /// Get a clone of the sign request sender
    pub fn sign_request_tx(&self) -> mpsc::Sender<IndexedSignRequest> {
        self.sign_request_tx.clone()
    }

    /// Get interval in milliseconds for different chains
    fn get_interval_for_chain(chain: &Chain) -> u64 {
        match chain {
            Chain::Ethereum => 500, // ~12 second blocks, check every 500ms
            Chain::Solana => 600,   // ~400ms slots, check every 600ms
            Chain::NEAR => 800,     // ~1 second blocks, check every 800ms
        }
    }

    /// Simulate transaction success with chain-specific rates
    fn simulate_success(chain: &Chain, block_height: u64, tx_id: &SignRespondTxId) -> bool {
        let seed = block_height + tx_id.0.as_slice()[0] as u64;
        match chain {
            Chain::Ethereum => seed % 10 != 0, // 90% success rate
            Chain::Solana => seed % 7 != 0,    // 85% success rate
            Chain::NEAR => seed % 20 != 0,     // 95% success rate
        }
    }

    /// Create a mock SignRespondTx with chain-specific parameters
    fn create_mock_sign_respond_tx(
        &self,
        sign_id: SignId,
        tx_id: SignRespondTxId,
    ) -> SignRespondTx {
        let (slip44_chain_id, algo, dest) = match self.chain {
            Chain::Ethereum => (
                60,
                "secp256k1".to_string(),
                "0x1234567890123456789012345678901234567890".to_string(),
            ),
            Chain::Solana => (
                501,
                "ed25519".to_string(),
                "11111111111111111111111111111112".to_string(), // System Program ID
            ),
            Chain::NEAR => (397, "ed25519".to_string(), "system.near".to_string()),
        };

        SignRespondTx {
            id: tx_id,
            sender: anchor_lang::prelude::Pubkey::default(),
            transaction_data: vec![0u8; 32],
            slip44_chain_id,
            key_version: 1,
            deposit: 1000000,
            path: "mock_path".to_string(),
            algo,
            dest,
            params: "{}".to_string(),
            explorer_deserialization_format: 1,
            explorer_deserialization_schema: vec![],
            callback_serialization_format: 1,
            callback_serialization_schema: vec![],
            request_id: sign_id.request_id,
            from_address: Address::ZERO,
            nonce: self.mock_tx_counter,
            participants: vec![],
            status: SignRespondTxStatus::Pending,
        }
    }

    /// Create a mock read respond request for testing
    fn create_mock_read_respond_request(
        sign_id: SignId,
        chain: Chain,
        block_height: u64,
    ) -> IndexedSignRequest {
        // Convert request_id to u64 by taking first 8 bytes
        let request_id_as_u64 =
            u64::from_le_bytes(sign_id.request_id[0..8].try_into().unwrap_or([0u8; 8]));

        // Create chain-specific mock output
        let output = match chain {
            Chain::Ethereum => {
                format!("0x{:x}", block_height * 1000 + request_id_as_u64).into_bytes()
            }
            Chain::Solana => format!("{}", block_height * 2000 + request_id_as_u64).into_bytes(),
            Chain::NEAR => format!("near_{}", block_height * 3000 + request_id_as_u64).into_bytes(),
        };

        let mock_tx = ReadRespondedTx {
            tx_id: SignRespondTxId(B256::from_slice(&sign_id.request_id)),
            output,
        };

        // Create mock SignArgs
        let mock_args = SignArgs {
            entropy: sign_id.request_id,
            epsilon: Scalar::from(1u32),
            payload: Scalar::from(2u32),
            path: "mock_path".to_string(),
            key_version: 1,
        };

        IndexedSignRequest {
            id: sign_id,
            args: mock_args,
            chain,
            unix_timestamp_indexed: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            timestamp_sign_queue: Some(Instant::now()),
            total_timeout: Duration::from_secs(300),
            sign_request_type: SignRequestType::ReadRespond(mock_tx),
            participants: None,
        }
    }
}

// Type aliases for backwards compatibility and convenience
pub type MockEthereumIndexer = MockIndexer;
pub type MockSolanaIndexer = MockIndexer;
