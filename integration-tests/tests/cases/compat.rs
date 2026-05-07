use integration_tests::cluster;
use test_log::test;

/// Test that testnet production binary can cooperate with our latest code.
/// Ensures backward compatibility during deployments.
#[test(tokio::test)]
#[ignore = "should be ran manually for now until we have compatibility"]
async fn test_testnet_compatibility() -> anyhow::Result<()> {
    // Spawn a cluster with 1 testnet node and 1 current code node
    // Threshold is 2, so both nodes must work together to sign
    let nodes = cluster::spawn()
        .nodes(1)
        .testnet_nodes(1)
        .threshold(2)
        .await?;

    // Verify we have 2 nodes
    assert_eq!(nodes.len(), 2, "should have 2 nodes total");

    nodes.wait().signable().await?;
    let _ = nodes.sign().await?;
    tracing::info!("testnet successfully cooperates with current code");

    Ok(())
}

/// Test that mainnet production binary can cooperate with our latest code.
/// Ensures backward compatibility during deployments.
#[test(tokio::test)]
#[ignore = "should be ran manually for now until we have compatibility"]
async fn test_mainnet_compatibility() -> anyhow::Result<()> {
    // Spawn a cluster with 1 mainnet node and 1 current code node
    // Threshold is 2, so both nodes must work together to sign
    let nodes = cluster::spawn()
        .nodes(1)
        .mainnet_nodes(1)
        .threshold(2)
        .await?;

    // Verify we have 2 nodes
    assert_eq!(nodes.len(), 2, "should have 2 nodes total");

    nodes.wait().signable().await?;
    let _ = nodes.sign().await?;
    tracing::info!("mainnet successfully cooperates with current code");

    Ok(())
}
