use test_log::test;

use integration_tests::cluster;

#[test(tokio::test)]
#[ignore = "This is triggered by the nightly Github Actions pipeline"]
async fn test_nightly_signature_production() -> anyhow::Result<()> {
    const SIGNATURE_AMOUNT: usize = 1000;
    const NODES: usize = 8;
    const THRESHOLD: usize = 4;
    const MIN_T_PAIRS_PER_NODE: u32 = 10;
    const MAX_T_PAIRS_PER_NETWORK: u32 = 2 * NODES as u32 * MIN_T_PAIRS_PER_NODE;

    let nodes = cluster::spawn()
        .with_config(|config| {
            config.nodes = NODES;
            config.threshold = THRESHOLD;
            config.protocol.triple.min_triple_pairs_per_node = MIN_T_PAIRS_PER_NODE;
            config.protocol.triple.max_triple_pairs_per_network = MAX_T_PAIRS_PER_NETWORK;
        })
        .await?;

    for i in 0..SIGNATURE_AMOUNT {
        if let Err(err) = nodes.wait().signable().await {
            tracing::error!(?err, "Failed to be ready to sign");
            continue;
        }

        tracing::info!(at_signature = i, "Producing signature...");
        if let Err(err) = nodes.sign().await {
            tracing::error!(?err, "Failed to produce signature");
        }
    }

    Ok(())
}
