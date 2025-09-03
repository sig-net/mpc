#[cfg(test)]
mod tests {
    use crate::checkpoint::{CheckpointManager, PendingTxStatus};
    use mpc_primitives::SignId;
    use crate::sign_respond_tx::{SignRespondTxId, SignRespondTx, SignRespondTxStatus};
    use alloy::primitives::{B256, Address};
    use anchor_lang::prelude::Pubkey;

    fn create_mock_sign_respond_tx(tx_id: SignRespondTxId, request_id: [u8; 32]) -> SignRespondTx {
        SignRespondTx {
            id: tx_id,
            sender: Pubkey::new_unique(),
            transaction_data: vec![0u8; 32],
            slip44_chain_id: 60, // Ethereum
            key_version: 1,
            deposit: 1000000,
            path: "test_path".to_string(),
            algo: "secp256k1".to_string(),
            dest: "0x1234567890123456789012345678901234567890".to_string(),
            params: "{}".to_string(),
            explorer_deserialization_format: 1,
            explorer_deserialization_schema: vec![],
            callback_serialization_format: 1,
            callback_serialization_schema: vec![],
            request_id,
            from_address: Address::ZERO,
            nonce: 1,
            participants: vec![],
            status: SignRespondTxStatus::Pending,
        }
    }

    #[tokio::test]
    async fn test_checkpoint_manager_basic_flow() {
        let checkpoint_manager = CheckpointManager::new();

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
        let mock_tx = create_mock_sign_respond_tx(tx_id, sign_id.request_id);
        let updated = checkpoint_manager
            .published_signed_transaction(&chain_id, &sign_id, tx_id, mock_tx)
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
        let checkpoint_manager = CheckpointManager::new();

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
    async fn test_checkpoint_manager_dependencies() {
        let checkpoint_manager = CheckpointManager::new();

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
