use integration_tests::cluster;
use test_log::test;

/// Test that the latest release binary can cooperate with our latest code.
/// Ensures backward compatibility during rolling deployments.
#[test(tokio::test)]
#[ignore = "needs the release binary from `just build compat`; run via `just test-compat`"]
async fn test_latest_release_compatibility() -> anyhow::Result<()> {
    // One node on the current code among two on the latest release: the first
    // step of a rolling upgrade. The threshold is every node, so no version can
    // sign without the other.
    let nodes = cluster::spawn()
        .nodes(1)
        .latest_release_nodes(2)
        .threshold(3)
        .await?;

    assert_eq!(nodes.len(), 3, "should have 3 nodes total");

    // A change both versions run differently can still agree on some requests,
    // as a different proposer election does on half of them. Ten requests catch
    // it almost surely, where one catches it half the time.
    for idx in 0..10 {
        tracing::info!(idx, "producing signature");
        nodes.wait().signable().await?;
        nodes.sign().await?;
    }
    tracing::info!("latest release successfully cooperates with current code");

    Ok(())
}
