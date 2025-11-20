use integration_tests::cluster::spawner::ClusterSpawner;
use test_log::test;

// Ensure that when `parallel` feature is enabled, multiple spawners return the same
// redis instance (global) and worker (sandbox) references.
#[test(tokio::test)]
async fn test_shared_redis_and_worker() -> anyhow::Result<()> {
    // Two separate spawners in same process
    let mut spawner1 = ClusterSpawner::default().init_network().await?;
    let mut spawner2 = ClusterSpawner::default().init_network().await?;

    // prespawn/syncronize for spawner1
    let redis1 = spawner1.prespawn_redis().await.clone();
    let worker1 = spawner1.prespawn_sandbox().await?.clone();

    // spawn using spawner2 - should return the same instances (or at least have same endpoint)
    let redis2 = spawner2.spawn_redis().await;
    let worker2 = spawner2.take_worker().await;

    assert_eq!(redis1.internal_address, redis2.internal_address);
    assert_eq!(worker1.rpc_addr(), worker2.rpc_addr());

    Ok(())
}
