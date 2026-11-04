use integration_tests::redis_harness::{RedisHarness, RedisHarnessConfig};
use std::time::Duration;

#[tokio::test]
async fn mixed_pipeline_uses_independent_node_pools() -> anyhow::Result<()> {
    let harness = RedisHarness::new(RedisHarnessConfig::new(3).with_pool_size(Some(1))).await?;

    // Holding one node's only connection must not prevent another node from connecting.
    let first = harness.participants[0].pool.get().await?;
    let second =
        tokio::time::timeout(Duration::from_secs(2), harness.participants[1].pool.get()).await??;
    drop((first, second));

    let results = harness.bench_mixed_pipeline(2).await?;
    assert_eq!(results.len(), 7);
    for result in results {
        let expected = match result.op_name.as_str() {
            "mixed_insert_triple"
            | "mixed_presig_peek_triple"
            | "mixed_presig_commit_triple"
            | "mixed_insert_presig" => 6,
            "mixed_sign_peek_presig" | "mixed_sign_commit_presig" => 4,
            "mixed_sign_take_presig" => 2,
            name => panic!("unexpected operation: {name}"),
        };
        assert_eq!(result.count, expected, "{}", result.op_name);
        assert_eq!(result.failures, 0, "{}", result.op_name);
    }
    Ok(())
}
