#[cfg(test)]
mod tests {
    use crate::checkpoint::{CheckpointManager, PendingTxStatus};
    use mpc_primitives::SignId;
    use std::collections::HashMap;
    use tokio::sync::RwLock;
    use std::sync::Arc;
    use crate::sign_respond_tx::SignRespondTxId;
    use alloy::primitives::B256;

    #[tokio::test]
    async fn test_checkpoint_manager_basic_flow() {
        let sign_respond_tx_map = Arc::new(RwLock::new(HashMap::new()));
        let checkpoint_manager = CheckpointManager::new(sign_respond_tx_map);

        let sign_id = SignId::new([1; 32]);
        let chain_id = "ethereum".to_string();
        let block_height = 100;
        let tx_id = SignRespondTxId(B256::from_slice(&[2; 32]));

        // Test 1: New sign and respond request
        checkpoint_manager
            .new_sign_and_respond_request(chain_id.clone(), sign_id, block_height)
            .await;

        let checkpoint = checkpoint_manager.get_chain_checkpoint(&chain_id).await;
        assert!(checkpoint.is_some());
        let checkpoint = checkpoint.unwrap();
        assert_eq!(checkpoint.processed_block_height, block_height);
        
        // Check that request was added to pending_tx map
        let pending_tx = checkpoint.pending_tx.get(&sign_id);
        assert!(pending_tx.is_some());
        assert_eq!(pending_tx.unwrap().status, PendingTxStatus::PendingSignAndRespond);

        // Test 2: Published signed transaction
        let updated = checkpoint_manager
            .published_signed_transaction(&chain_id, &sign_id, tx_id)
            .await;
        assert!(updated);

        let checkpoint = checkpoint_manager.get_chain_checkpoint(&chain_id).await;
        assert!(checkpoint.is_some());
        let checkpoint = checkpoint.unwrap();
        let pending_tx = checkpoint.pending_tx.get(&sign_id);
        assert!(pending_tx.is_some());
        assert_eq!(pending_tx.unwrap().status, PendingTxStatus::PendingExecuteRespond);

        // Test 3: Found transaction output
        checkpoint_manager
            .found_tx_output(&chain_id, &sign_id)
            .await;

        let checkpoint = checkpoint_manager.get_chain_checkpoint(&chain_id).await;
        assert!(checkpoint.is_some());
        let checkpoint = checkpoint.unwrap();
        let pending_tx = checkpoint.pending_tx.get(&sign_id);
        assert!(pending_tx.is_some());
        assert_eq!(pending_tx.unwrap().status, PendingTxStatus::PendingRespond);

        // Test 4: Published signed output (final step)
        checkpoint_manager
            .published_signed_output(&chain_id, &sign_id)
            .await;

        let checkpoint = checkpoint_manager.get_chain_checkpoint(&chain_id).await;
        assert!(checkpoint.is_some());
        let checkpoint = checkpoint.unwrap();
        
        // After completion, request should be removed from pending_tx
        let pending_tx = checkpoint.pending_tx.get(&sign_id);
        assert!(pending_tx.is_none());
    }

    #[tokio::test]
    async fn test_checkpoint_manager_multiple_chains() {
        let sign_respond_tx_map = Arc::new(RwLock::new(HashMap::new()));
        let checkpoint_manager = CheckpointManager::new(sign_respond_tx_map);

        let sign_id1 = SignId::new([1; 32]);
        let sign_id2 = SignId::new([2; 32]);
        let eth_chain = "ethereum".to_string();
        let sol_chain = "solana".to_string();

        // Add requests for different chains
        checkpoint_manager
            .new_sign_and_respond_request(eth_chain.clone(), sign_id1, 100)
            .await;
        
        checkpoint_manager
            .new_sign_and_respond_request(sol_chain.clone(), sign_id2, 200)
            .await;

        // Verify both checkpoints exist
        let eth_checkpoint = checkpoint_manager.get_chain_checkpoint(&eth_chain).await;
        let sol_checkpoint = checkpoint_manager.get_chain_checkpoint(&sol_chain).await;
        
        assert!(eth_checkpoint.is_some());
        assert!(sol_checkpoint.is_some());
        
        assert_eq!(eth_checkpoint.unwrap().processed_block_height, 100);
        assert_eq!(sol_checkpoint.unwrap().processed_block_height, 200);
    }

    #[tokio::test]
    async fn test_checkpoint_manager_cross_chain_dependency() {
        let sign_respond_tx_map = Arc::new(RwLock::new(HashMap::new()));
        let checkpoint_manager = CheckpointManager::new(sign_respond_tx_map);

        let sign_id = SignId::new([1; 32]);
        let source_chain = "ethereum".to_string();
        let target_chain = "near".to_string();

        // Add request to source chain
        checkpoint_manager
            .new_sign_and_respond_request(source_chain.clone(), sign_id, 100)
            .await;

        // Add dependency for target chain
        checkpoint_manager
            .new_sign_and_respond_request(target_chain.clone(), sign_id, 50)
            .await;

        // Verify both checkpoints exist
        let source_checkpoint = checkpoint_manager.get_chain_checkpoint(&source_chain).await;
        let target_checkpoint = checkpoint_manager.get_chain_checkpoint(&target_chain).await;
        
        assert!(source_checkpoint.is_some());
        assert!(target_checkpoint.is_some());
        
        // Verify that both have the same request with appropriate dependencies
        let source_checkpoint = source_checkpoint.unwrap();
        let target_checkpoint = target_checkpoint.unwrap();
        let source_pending = source_checkpoint.pending_tx.get(&sign_id);
        let target_pending = target_checkpoint.pending_tx.get(&sign_id);
        
        assert!(source_pending.is_some());
        assert!(target_pending.is_some());
    }
}
