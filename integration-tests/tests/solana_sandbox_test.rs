use integration_tests::cluster;

#[test_log::test(tokio::test)]
async fn test_solana_sandbox_spawn_with_deployed_contract() -> anyhow::Result<()> {
    // Test that we can spawn a cluster with Solana sandbox and deploy contracts
    let cluster = cluster::spawn()
        .sol()
        .nodes(3)
        .threshold(2)
        .disable_wait_running() // Disable waiting for nodes to be fully running
        .disable_prestockpile() // Disable prestockpiling to avoid timeout
        .await?;

    // Verify that the SolConfig is properly set
    assert!(cluster.cfg.sol.is_some());
    let sol_config = cluster.cfg.sol.as_ref().unwrap();

    // Verify the configuration parameters - program address should be deployed contract
    assert!(!sol_config.program_address.is_empty());
    assert_ne!(
        sol_config.program_address,
        "11111111111111111111111111111112"
    ); // Should not be system program
    assert!(!sol_config.account_sk.is_empty());

    println!("✅ Solana sandbox with deployed contract successful:");
    println!("  RPC HTTP URL: {}", sol_config.rpc_http_url);
    println!("  RPC WS URL: {}", sol_config.rpc_ws_url);
    println!("  Program Address: {}", sol_config.program_address);
    println!("  Total Timeout: {}s", sol_config.total_timeout);
    println!("  Account SK configured: ✅");

    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_solana_sandbox_spawn_with_custom_program() -> anyhow::Result<()> {
    // Test that we can spawn a cluster with Solana sandbox and custom program address
    let cluster = cluster::spawn()
        .sol()
        .program_address("11111111111111111111111111111112".to_string()) // System program ID for testing
        .nodes(3)
        .threshold(2)
        .disable_wait_running() // Disable waiting for nodes to be fully running
        .disable_prestockpile() // Disable prestockpiling to avoid timeout
        .await?;

    // Verify that the SolConfig is properly set
    assert!(cluster.cfg.sol.is_some());
    let sol_config = cluster.cfg.sol.as_ref().unwrap();

    // Verify the configuration parameters
    assert_eq!(
        sol_config.program_address,
        "11111111111111111111111111111112"
    );
    assert!(!sol_config.account_sk.is_empty());

    println!("✅ Solana sandbox with custom program successful:");
    println!("  RPC HTTP URL: {}", sol_config.rpc_http_url);
    println!("  RPC WS URL: {}", sol_config.rpc_ws_url);
    println!("  Program Address: {}", sol_config.program_address);
    println!("  Total Timeout: {}s", sol_config.total_timeout);
    println!("  Account SK configured: ✅");

    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_solana_sign_call() -> anyhow::Result<()> {
    // Test that we can call nodes.sign().sol().await to make a sign call to Solana contract
    let cluster = cluster::spawn()
        .sol()
        .nodes(3)
        .threshold(2)
        .disable_wait_running() // Disable waiting for nodes to be fully running
        .disable_prestockpile() // Disable prestockpiling to avoid timeout
        .await?;

    // Verify that the SolConfig is properly set
    assert!(cluster.cfg.sol.is_some());
    let sol_config = cluster.cfg.sol.as_ref().unwrap();
    println!(
        "✅ Solana sandbox configured with program: {}",
        sol_config.program_address
    );

    // Test the new Solana sign functionality
    let payload = [1u8; 32]; // Test payload

    // This calls the Solana contract's sign function directly (not the MPC respond function)
    let result = cluster
        .sign()
        .payload(payload)
        .path("test/path")
        .key_version(0)
        .sol()
        .await?;

    // Verify the result
    println!("✅ Solana sign call successful:");
    println!("  Transaction signature: {}", result.transaction_signature);
    println!("  Request ID: {}", hex::encode(result.request_id));

    // Verify that we got a valid transaction signature
    assert!(!result.transaction_signature.is_empty());
    assert_eq!(result.request_id, alloy::primitives::keccak256(payload).0);

    Ok(())
}
