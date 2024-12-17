use near_sdk::NearToken;
use test_log::test;

use crate::cluster;

#[test(tokio::test)]
#[ignore = "This is triggered by the nightly Github Actions pipeline"]
async fn test_nightly_signature_production() -> anyhow::Result<()> {
    const SIGNATURE_AMOUNT: usize = 100;
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

    let tasks = (0..SIGNATURE_AMOUNT)
        .map(|_| async { nodes.sign().deposit(NearToken::from_near(1)).await });
    let outcomes = futures::future::join_all(tasks).await;

    for outcome in outcomes {
        println!("produce signature {outcome:?}");
    }

    Ok(())
}
