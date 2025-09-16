use integration_tests::cluster;

#[test_log::test(tokio::test)]
async fn test_solana_sandbox() {
    let solana = cluster::spawn().spawn_solana().await;
    solana.deploy_contract().await.unwrap();
    let signature = solana
        .sign_with_params([42u8; 32], "test/path", 1)
        .await
        .unwrap();
    println!("✅ Solana sign transaction successful: {}", signature);
}

#[test_log::test(tokio::test)]
async fn test_solana_cluster_sign() {
    // Test the nodes.sign().sol() functionality that uses cluster's Solana instance
    let cluster = cluster::spawn().sol().await.unwrap();

    // Test the new Solana sign functionality with custom parameters
    let payload = [42u8; 32]; // Custom test payload
    let result = cluster
        .sign()
        .payload(payload)
        .path("test/integration/path")
        .sol()
        .await
        .unwrap();

    // Verify the result
    println!("  Transaction signature: {}", result.transaction_signature);
    println!("  Request ID: {}", hex::encode(result.request_id));

    // Verify that we got a valid transaction signature
    assert!(!result.transaction_signature.is_empty());
    assert_eq!(result.request_id, alloy::primitives::keccak256(payload).0);
}
