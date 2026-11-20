use integration_tests::cluster;
use test_log::test;

/// Test that the latest release binary can cooperate with our latest code.
/// Ensures backward compatibility during rolling deployments.
#[test(tokio::test)]
#[ignore = "needs the release binary from `just build compat`; run via `just test-compat`"]
async fn test_latest_release_compatibility() -> anyhow::Result<()> {
    // Spawn a cluster with 1 latest release node and 1 current code node.
    // Threshold is 2, so both nodes must work together to sign.
    let nodes = cluster::spawn()
        .nodes(1)
        .latest_release_nodes(1)
        .threshold(2)
        .await?;

    assert_eq!(nodes.len(), 2, "should have 2 nodes total");

    nodes.wait().signable().await?;
    let _ = nodes.sign().await?;
    tracing::info!("latest release successfully cooperates with current code");

    Ok(())
}
