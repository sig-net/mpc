use deadpool_redis::redis;
use integration_tests::cluster::spawner::ClusterSpawner;
use integration_tests::containers;
use test_log::test;

#[test(tokio::test)]
async fn test_mpc_store_commands() -> anyhow::Result<()> {
    let spawner = ClusterSpawner::default()
        .network("test-mpc-store-commands")
        .init_network()
        .await?;
    let redis = containers::Redis::run(&spawner).await;
    let pool = redis.pool();
    let mut conn = pool.get().await?;

    let artifact_id = "test-artifact-1";
    let artifact_key = "test-artifacts";
    let owner_key = "owner-1";
    let owner_keys = "all-owners";
    let artifact_payload = b"artifact-data-1";
    let holders = vec!["holder-1", "holder-2"];

    // 1. Insert
    redis::cmd("mpc.artifact.insert")
        .arg(artifact_key)
        .arg(owner_keys)
        .arg(owner_key)
        .arg(artifact_id)
        .arg(artifact_payload)
        .arg(&holders)
        .query_async::<()>(&mut conn)
        .await?;

    // 2. Contains
    let exists: bool = redis::cmd("mpc.artifact.contains")
        .arg(artifact_key)
        .arg(artifact_id)
        .query_async(&mut conn)
        .await?;
    assert!(exists);

    // 3. Fetch Owned
    let owned: Vec<String> = redis::cmd("mpc.artifact.fetch_owned")
        .arg(owner_key)
        .query_async(&mut conn)
        .await?;
    assert_eq!(owned, vec![artifact_id]);

    // 4. Take
    let (taken_payload, taken_holders): (Vec<u8>, Vec<String>) = redis::cmd("mpc.artifact.take")
        .arg(artifact_key)
        .arg(owner_key)
        .arg(artifact_id)
        .query_async(&mut conn)
        .await?;
    assert_eq!(taken_payload, artifact_payload);
    assert_eq!(taken_holders, holders);

    // 5. Contains (0)
    let exists_after: bool = redis::cmd("mpc.artifact.contains")
        .arg(artifact_key)
        .arg(artifact_id)
        .query_async(&mut conn)
        .await?;
    assert!(!exists_after);

    // 6. Checkpoint persist/load
    let checkpoint_key = "checkpoint-1";
    let checkpoint_json = "{\"data\": \"value\"}";
    redis::cmd("mpc.checkpoint.persist")
        .arg(checkpoint_key)
        .arg(checkpoint_json)
        .query_async::<()>(&mut conn)
        .await?;

    let loaded: Option<String> = redis::cmd("mpc.checkpoint.load")
        .arg(checkpoint_key)
        .query_async(&mut conn)
        .await?;
    assert_eq!(loaded, Some(checkpoint_json.to_string()));

    Ok(())
}
