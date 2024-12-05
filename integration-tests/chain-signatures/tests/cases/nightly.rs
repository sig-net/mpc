use test_log::test;

use crate::cluster;

#[test(tokio::test)]
#[ignore = "This is triggered by the nightly Github Actions pipeline"]
async fn test_nightly_signature_production() -> anyhow::Result<()> {
    const SIGNATURE_AMOUNT: usize = 1000;
    const NODES: usize = 8;
    const THRESHOLD: usize = 4;
    const MIN_TRIPLES: u32 = 10;
    const MAX_TRIPLES: u32 = 2 * NODES as u32 * MIN_TRIPLES;

    let nodes = cluster::spawn()
        .with_config(|config| {
            config.nodes = NODES;
            config.threshold = THRESHOLD;
            config.protocol.triple.min_triples = MIN_TRIPLES;
            config.protocol.triple.max_triples = MAX_TRIPLES;
        })
        .wait_for_running()
        .await?;

    for i in 0..SIGNATURE_AMOUNT {
        if let Err(err) = nodes.wait().ready_to_sign().await {
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
