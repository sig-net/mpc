use crate::protocol::Chain;

use anyhow::Context;
use deadpool_redis::Pool;
use mpc_primitives::Checkpoint;
use near_account_id::AccountId;
use redis::AsyncCommands;
use tokio::sync::RwLock;

use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub enum CheckpointStorage {
    Redis(Pool, AccountId),
    InMemory(Arc<RwLock<HashMap<Chain, Checkpoint>>>),
}

impl Default for CheckpointStorage {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl CheckpointStorage {
    pub fn in_memory() -> Self {
        Self::InMemory(Arc::new(RwLock::new(HashMap::new())))
    }

    fn checkpoint_key(&self, chain: Chain) -> String {
        match self {
            CheckpointStorage::Redis(_, account_id) => {
                format!("{account_id}:checkpoint:latest:{chain}")
            }
            CheckpointStorage::InMemory(_) => format!("checkpoint:latest:{chain}"),
        }
    }

    pub async fn persist(&self, checkpoint: &Checkpoint) -> anyhow::Result<()> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let value = serde_json::to_string(checkpoint)
                    .context("failed to serialize checkpoint persistence")?;
                conn.set::<_, _, ()>(self.checkpoint_key(checkpoint.chain), value)
                    .await
                    .context("failed to set checkpoint in redis")?;
            }
            CheckpointStorage::InMemory(storage) => {
                storage
                    .write()
                    .await
                    .insert(checkpoint.chain, checkpoint.clone());
            }
        }
        Ok(())
    }

    pub async fn load_latest(&self, chain: Chain) -> anyhow::Result<Option<Checkpoint>> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let value: Option<String> = conn
                    .get(self.checkpoint_key(chain))
                    .await
                    .context("failed to get checkpoint from redis")?;
                match value {
                    Some(v) => {
                        let checkpoint: Checkpoint =
                            serde_json::from_str(&v).context("failed to deserialize checkpoint")?;
                        Ok(Some(checkpoint))
                    }
                    None => Ok(None),
                }
            }
            CheckpointStorage::InMemory(storage) => Ok(storage.read().await.get(&chain).cloned()),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use mpc_primitives::{Chain, Checkpoint, PendingTx, SignId};

    // Helper function to generate arbitrary chain
    fn arbitrary_chain() -> impl Strategy<Value = Chain> {
        prop_oneof![
            Just(Chain::NEAR),
            Just(Chain::Ethereum),
            Just(Chain::Solana),
        ]
    }

    // Helper function to generate arbitrary checkpoint
    fn arbitrary_checkpoint() -> impl Strategy<Value = Checkpoint> {
        (
            arbitrary_chain(),
            0u64..1000000u64, // block_height
        ).prop_map(|(chain, block_height)| {
            Checkpoint {
                chain,
                block_height,
                pending_requests: Vec::new(), // Empty for simplicity
            }
        })
    }

    // Helper function to generate arbitrary SignId
    fn arbitrary_sign_id() -> impl Strategy<Value = SignId> {
        prop::collection::vec(any::<u8>(), 32..=32)
            .prop_map(|bytes| {
                let mut request_id = [0u8; 32];
                request_id.copy_from_slice(&bytes);
                SignId::new(request_id)
            })
    }

    // Helper function to generate arbitrary pending transaction
    fn arbitrary_pending_tx() -> impl Strategy<Value = PendingTx> {
        (
            arbitrary_sign_id(),
            prop::collection::vec(any::<u8>(), 0..100), // transaction bytes
        ).prop_map(|(sign_id, transaction)| {
            PendingTx {
                sign_id,
                transaction,
            }
        })
    }

    // Helper function to generate arbitrary checkpoint with pending requests
    fn arbitrary_checkpoint_with_requests() -> impl Strategy<Value = Checkpoint> {
        (
            arbitrary_chain(),
            0u64..1000000u64, // block_height
            prop::collection::vec(arbitrary_pending_tx(), 0..5), // 0-5 pending requests
        ).prop_map(|(chain, block_height, pending_requests)| {
            Checkpoint {
                chain,
                block_height,
                pending_requests,
            }
        })
    }

    proptest! {
        /// Property 108: Checkpoint Storage Correctness
        /// *For any* checkpoint data, storing and loading should preserve all checkpoint
        /// information including chain, block height, and pending requests.
        /// **Feature: unit-test-coverage, Property 108: Checkpoint Storage Correctness**
        /// **Validates: Requirements 33.3**
        #[test]
        fn prop_checkpoint_storage_correctness(
            checkpoint in arbitrary_checkpoint_with_requests()
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                // Create in-memory checkpoint storage
                let storage = CheckpointStorage::in_memory();
                
                // Store the checkpoint
                let persist_result = storage.persist(&checkpoint).await;
                prop_assert!(persist_result.is_ok(), "Persist operation should succeed");
                
                // Load the checkpoint
                let load_result = storage.load_latest(checkpoint.chain).await;
                prop_assert!(load_result.is_ok(), "Load operation should succeed");
                
                let loaded = load_result.unwrap();
                prop_assert!(loaded.is_some(), "Loaded checkpoint should exist");
                
                let restored = loaded.unwrap();
                
                // Verify all fields are correctly preserved
                prop_assert_eq!(
                    restored.chain, 
                    checkpoint.chain,
                    "Chain should be preserved"
                );
                prop_assert_eq!(
                    restored.block_height, 
                    checkpoint.block_height,
                    "Block height should be preserved"
                );
                prop_assert_eq!(
                    restored.pending_requests.len(), 
                    checkpoint.pending_requests.len(),
                    "Pending requests count should be preserved"
                );
                
                // Verify each pending request is preserved
                for (i, (original, restored_req)) in checkpoint.pending_requests.iter()
                    .zip(restored.pending_requests.iter())
                    .enumerate() 
                {
                    prop_assert_eq!(
                        original.sign_id, 
                        restored_req.sign_id,
                        "Pending request {} sign_id should be preserved", i
                    );
                    prop_assert_eq!(
                        &original.transaction, 
                        &restored_req.transaction,
                        "Pending request {} transaction should be preserved", i
                    );
                }
                
                Ok(())
            })?;
        }

        /// Test checkpoint storage with multiple chains
        /// Verifies that checkpoints for different chains are stored and retrieved independently
        #[test]
        fn prop_checkpoint_storage_multi_chain(
            near_checkpoint in arbitrary_checkpoint().prop_filter("NEAR chain", |c| c.chain == Chain::NEAR),
            eth_checkpoint in arbitrary_checkpoint().prop_filter("Ethereum chain", |c| c.chain == Chain::Ethereum),
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let storage = CheckpointStorage::in_memory();
                
                // Create checkpoints for different chains
                let near_cp = Checkpoint {
                    chain: Chain::NEAR,
                    block_height: near_checkpoint.block_height,
                    pending_requests: Vec::new(),
                };
                
                let eth_cp = Checkpoint {
                    chain: Chain::Ethereum,
                    block_height: eth_checkpoint.block_height,
                    pending_requests: Vec::new(),
                };
                
                // Store both checkpoints
                storage.persist(&near_cp).await.unwrap();
                storage.persist(&eth_cp).await.unwrap();
                
                // Load and verify each chain's checkpoint independently
                let loaded_near = storage.load_latest(Chain::NEAR).await.unwrap().unwrap();
                let loaded_eth = storage.load_latest(Chain::Ethereum).await.unwrap().unwrap();
                
                prop_assert_eq!(loaded_near.chain, Chain::NEAR);
                prop_assert_eq!(loaded_near.block_height, near_cp.block_height);
                
                prop_assert_eq!(loaded_eth.chain, Chain::Ethereum);
                prop_assert_eq!(loaded_eth.block_height, eth_cp.block_height);
                
                // Verify Solana returns None (not stored)
                let loaded_sol = storage.load_latest(Chain::Solana).await.unwrap();
                prop_assert!(loaded_sol.is_none(), "Solana checkpoint should not exist");
                
                Ok(())
            })?;
        }

        /// Test checkpoint update/overwrite behavior
        /// Verifies that storing a new checkpoint for the same chain overwrites the old one
        #[test]
        fn prop_checkpoint_storage_update(
            initial_height in 0u64..500000u64,
            updated_height in 500001u64..1000000u64,
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let storage = CheckpointStorage::in_memory();
                
                // Store initial checkpoint
                let initial_cp = Checkpoint {
                    chain: Chain::NEAR,
                    block_height: initial_height,
                    pending_requests: Vec::new(),
                };
                storage.persist(&initial_cp).await.unwrap();
                
                // Verify initial checkpoint
                let loaded1 = storage.load_latest(Chain::NEAR).await.unwrap().unwrap();
                prop_assert_eq!(loaded1.block_height, initial_height);
                
                // Store updated checkpoint (should overwrite)
                let updated_cp = Checkpoint {
                    chain: Chain::NEAR,
                    block_height: updated_height,
                    pending_requests: Vec::new(),
                };
                storage.persist(&updated_cp).await.unwrap();
                
                // Verify updated checkpoint
                let loaded2 = storage.load_latest(Chain::NEAR).await.unwrap().unwrap();
                prop_assert_eq!(loaded2.block_height, updated_height);
                
                Ok(())
            })?;
        }
    }

    #[tokio::test]
    async fn test_checkpoint_storage_basic_operations() {
        let storage = CheckpointStorage::in_memory();
        
        // Initially empty
        let initial = storage.load_latest(Chain::NEAR).await.unwrap();
        assert!(initial.is_none());
        
        // Create and store checkpoint
        let checkpoint = Checkpoint {
            chain: Chain::NEAR,
            block_height: 12345,
            pending_requests: Vec::new(),
        };
        storage.persist(&checkpoint).await.unwrap();
        
        // Load and verify
        let loaded = storage.load_latest(Chain::NEAR).await.unwrap().unwrap();
        assert_eq!(loaded.chain, Chain::NEAR);
        assert_eq!(loaded.block_height, 12345);
    }

    #[tokio::test]
    async fn test_checkpoint_storage_empty_checkpoint() {
        let storage = CheckpointStorage::in_memory();
        
        // Store empty checkpoint
        let checkpoint = Checkpoint::empty(Chain::Ethereum);
        storage.persist(&checkpoint).await.unwrap();
        
        // Load and verify
        let loaded = storage.load_latest(Chain::Ethereum).await.unwrap().unwrap();
        assert_eq!(loaded.chain, Chain::Ethereum);
        assert_eq!(loaded.block_height, 0);
        assert!(loaded.pending_requests.is_empty());
    }

    #[tokio::test]
    async fn test_checkpoint_key_generation() {
        let storage = CheckpointStorage::in_memory();
        
        // Test key generation for different chains
        let near_key = storage.checkpoint_key(Chain::NEAR);
        let eth_key = storage.checkpoint_key(Chain::Ethereum);
        let sol_key = storage.checkpoint_key(Chain::Solana);
        
        // Keys should be different for different chains
        assert_ne!(near_key, eth_key);
        assert_ne!(eth_key, sol_key);
        assert_ne!(near_key, sol_key);
        
        // Keys should contain chain identifier
        assert!(near_key.contains("NEAR"));
        assert!(eth_key.contains("Ethereum"));
        assert!(sol_key.contains("Solana"));
    }
}
