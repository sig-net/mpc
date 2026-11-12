use integration_tests::redis_harness::participant::ChurnState;
use integration_tests::redis_harness::RedisDiagnosticsClient;
use integration_tests::redis_harness::{ArtifactKind, RedisHarness, RedisHarnessConfig};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

async fn wait_for_blocked_ping(
    probe: &mut deadpool_redis::Connection,
    on_block: impl FnOnce(),
) -> anyhow::Result<Duration> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut on_block = Some(on_block);
        loop {
            let start = Instant::now();
            let cmd = deadpool_redis::redis::cmd("PING");
            let ping = cmd.query_async::<()>(&mut *probe);
            tokio::pin!(ping);
            tokio::select! {
                result = &mut ping => result?,
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    on_block.take().unwrap()();
                    ping.await?;
                    return Ok::<_, anyhow::Error>(start.elapsed());
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await?
}

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
            "mixed_sign_take_presig" => 4,
            name => panic!("unexpected operation: {name}"),
        };
        assert_eq!(result.count, expected, "{}", result.op_name);
        assert_eq!(result.failures, 0, "{}", result.op_name);
        assert_eq!(result.indeterminate, 0, "{}", result.op_name);
    }

    let results = harness.bench_checkpoint_contention(4, 100).await?;
    assert_eq!(results.len(), 6);
    for result in results {
        assert!(result.count > 0, "{}", result.op_name);
        assert_eq!(result.failures, 0, "{}", result.op_name);
        assert_eq!(result.indeterminate, 0, "{}", result.op_name);
    }

    let results = harness.bench_presignature_stockpile(16, 2, 3).await?;
    assert_eq!(results[0].count + results[0].indeterminate, 6);
    assert!(results[1].count > 0);
    assert_eq!(results[1].failures, 0);

    harness
        .populate(ArtifactKind::Presignatures, 0, 900_000_000, 32)
        .await?;
    let state = Arc::new(ChurnState::default());
    let barrier = Arc::new(tokio::sync::Barrier::new(9));
    let mut tasks = Vec::new();
    for i in 0..8 {
        tasks.push(tokio::spawn(
            harness.participants[0].clone().run_proposer_churn(
                barrier.clone(),
                i,
                1,
                0,
                500,
                state.clone(),
            ),
        ));
    }
    barrier.wait().await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while state.pending.load(Ordering::Relaxed) < 4 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    for task in tasks {
        let (metrics, _, _) = task.await?;
        assert_eq!(metrics[0].latencies.len(), 1);
        assert_eq!(metrics[1].latencies.len(), 1);
    }
    assert!(state.peak_pending.load(Ordering::Relaxed) >= 4);
    assert_eq!(state.pending.load(Ordering::Relaxed), 0);

    // All five items are excluded by the proposer scenario: empty peeks are
    // indeterminate, not successful latency samples or known Redis errors.
    let results = harness.bench_proposer_race(0, 5, 1, 3).await?;
    assert_eq!(results[0].count, 0);
    assert_eq!(results[0].indeterminate, 3);
    assert_eq!(results[0].failures, 0);

    let results = harness.bench_conflicted_take(3, 2).await?;
    assert_eq!(results[0].count, 3);
    assert_eq!(results[0].indeterminate, 3);
    assert_eq!(results[0].failures, 0);

    // A closed pool produces the same Option::None as an empty stockpile.
    let p = harness.participants[0].clone();
    p.pool.close();
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(1));
    let [peek, commit] = p.race_proposals(barrier, 0, 2).await;
    assert_eq!(peek.latencies.len(), 0);
    assert_eq!(peek.indeterminate, 2);
    assert_eq!(commit.latencies.len(), 0);
    Ok(())
}

#[tokio::test]
async fn blocking_spike_delays_other_connections_for_requested_duration() -> anyhow::Result<()> {
    let harness = RedisHarness::new(
        RedisHarnessConfig::new(1)
            .with_pool_size(Some(1))
            .with_pool_timeout(Some(Duration::from_millis(50))),
    )
    .await?;
    harness.client.check_debug_sleep().await?;

    if let Some(redis) = &harness.redis {
        let docker = bollard::Docker::connect_with_defaults()?;
        let info = docker.inspect_container(redis.container.id(), None).await?;
        let ports = info.network_settings.unwrap().ports.unwrap();
        let bindings = ports.get("6379/tcp").unwrap().as_ref().unwrap();
        assert!(!bindings.is_empty());
        assert!(bindings
            .iter()
            .all(|binding| binding.host_ip.as_deref() == Some("127.0.0.1")));
    }
    let mut anonymous_url = url::Url::parse(&harness.redis_url)?;
    anonymous_url.set_password(None).unwrap();
    let anonymous_pool = RedisDiagnosticsClient::build_pool(anonymous_url.as_str(), Some(1), None)?;
    let mut anonymous = anonymous_pool.get().await?;
    assert!(deadpool_redis::redis::cmd("PING")
        .query_async::<()>(&mut anonymous)
        .await
        .is_err());

    // The probe and spike use distinct pools, so the delay is at Redis, not a pool wait.
    let probe_pool = RedisDiagnosticsClient::build_pool(&harness.redis_url, Some(1), None)?;
    let mut probe = probe_pool.get().await?;
    let stop = Arc::new(AtomicBool::new(false));
    let spike = RedisDiagnosticsClient::spawn_intermittent_spike(&harness.redis_url, stop, 250, 1)?
        .expect("nonzero spike should start");
    let probe_elapsed = wait_for_blocked_ping(&mut probe, || {}).await?;
    let intervals = spike.await??;

    assert_eq!(intervals.len(), 1);
    let spike_elapsed = intervals[0].1.duration_since(intervals[0].0);
    assert!(
        spike_elapsed >= Duration::from_millis(250),
        "{spike_elapsed:?}"
    );
    assert!(spike_elapsed < Duration::from_secs(3), "{spike_elapsed:?}");
    assert!(
        probe_elapsed >= Duration::from_millis(100),
        "{probe_elapsed:?}"
    );
    assert!(probe_elapsed < Duration::from_secs(3), "{probe_elapsed:?}");
    let slowlog = harness.client.fetch_slowlog(20).await?;
    let spike_record = slowlog
        .iter()
        .find(|entry| entry.command.starts_with("DEBUG SLEEP 0.250"))
        .expect("the injected spike should be recorded in Redis slowlog");
    assert!(
        spike_record.duration_us >= 240_000,
        "{}",
        spike_record.duration_us
    );
    assert!(
        spike_record.duration_us < 3_000_000,
        "{}",
        spike_record.duration_us
    );

    harness.client.reset_slowlog().await?;
    let stop = Arc::new(AtomicBool::new(false));
    let spike =
        RedisDiagnosticsClient::spawn_intermittent_spike(&harness.redis_url, stop, 250, 10)?
            .expect("nonzero spike should start");
    wait_for_blocked_ping(&mut probe, || drop(spike)).await?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let slowlog = harness.client.fetch_slowlog(20).await?;
    assert_eq!(
        slowlog
            .iter()
            .filter(|e| e.command.starts_with("DEBUG SLEEP 0.250"))
            .count(),
        1
    );
    Ok(())
}
