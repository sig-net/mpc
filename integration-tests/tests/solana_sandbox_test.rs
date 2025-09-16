use integration_tests::cluster;

#[test_log::test(tokio::test)]
async fn test_solana_sandbox() {
    let solana = cluster::spawn().spawn_solana().await;
    solana.deploy_contract().await.unwrap();
    let signature = solana.sign().await.unwrap();
    println!("✅ Solana sign transaction successful: {}", signature);
}

#[test_log::test(tokio::test)]
async fn test_solana_cluster_sign() {
    // Test the nodes.sign().sol() functionality that uses cluster's Solana instance
    let cluster = cluster::spawn()
        .sol()
        .nodes(3)
        .threshold(2)
        .disable_wait_running() // Disable waiting for nodes to be fully running
        .disable_prestockpile() // Disable prestockpiling to avoid timeout
        .await
        .unwrap();

    // Test the new Solana sign functionality with custom parameters
    let payload = [42u8; 32]; // Custom test payload
    let result = cluster
        .sign()
        .payload(payload)
        .path("test/integration/path")
        .key_version(1)
        .sol()
        .await
        .unwrap();

    // Verify the result
    println!("✅ Cluster Solana sign call successful:");
    println!("  Transaction signature: {}", result.transaction_signature);
    println!("  Request ID: {}", hex::encode(result.request_id));

    // Verify that we got a valid transaction signature
    assert!(!result.transaction_signature.is_empty());
    assert_eq!(result.request_id, alloy::primitives::keccak256(payload).0);
}
