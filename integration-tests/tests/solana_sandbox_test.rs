use integration_tests::cluster;

#[test_log::test(tokio::test)]
async fn test_solana_sandbox_spawn() -> anyhow::Result<()> {
    // Test that we can spawn a cluster with Solana sandbox
    let cluster = cluster::spawn()
        .sol()
        .program_address("11111111111111111111111111111112".to_string()) // System program ID for testing
        .total_timeout(30)
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

    println!("✅ Solana sandbox configuration successful:");
    println!("  RPC HTTP URL: {}", sol_config.rpc_http_url);
    println!("  RPC WS URL: {}", sol_config.rpc_ws_url);
    println!("  Program Address: {}", sol_config.program_address);
    println!("  Total Timeout: {}s", sol_config.total_timeout);
    println!("  Account SK configured: ✅");

    Ok(())
}
