/// Example of how to use the visualizer with integration tests.
/// 
/// This is commented out by default since integration tests are long-running.
/// To actually test this, uncomment the test and run:
/// ```
/// RUST_LOG=info,workspaces=warn cargo test --test visualizer_example --nocapture -- --show-output
/// ```

/*
use integration_tests::cluster;

#[tokio::test]
async fn example_with_visualizer() -> anyhow::Result<()> {
    // Spawn a cluster with the visualizer enabled
    let cluster = cluster::spawn()
        .nodes(3)
        .visualize()  // This enables the visualizer!
        .await?;

    tracing::info!("Cluster started with visualizer at http://localhost:8080/ui");
    tracing::info!("Open your browser to see the real-time sign request lifecycle");

    // Run some sign operations
    // The visualizer will display them in real-time
    let sign_result = cluster
        .sign()
        .payload([1u8; 32])
        .await?;

    tracing::info!("Signed payload: {:?}", sign_result);

    // Keep the test running for a bit to view the visualizer
    tracing::info!("Keeping cluster alive for 30 seconds...");
    tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

    Ok(())
}
*/

// Placeholder test to make the file valid
#[test]
fn visualizer_documentation() {
    // See the commented example above for usage
}
