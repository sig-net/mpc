use std::time::Duration;

use criterion::Criterion;
use integration_tests::stress::{StressAction, StressHarnessBuilder, StressRequestStatus};

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let nodes = env_usize("MPC_STRESS_NODES", 3);
    let threshold = env_usize("MPC_STRESS_THRESHOLD", 2);
    let total_requests = env_usize("MPC_STRESS_TOTAL_REQUESTS", 16);
    let concurrency = env_usize("MPC_STRESS_CONCURRENCY", 8);
    let samples = env_usize("MPC_STRESS_SAMPLES", 10).max(1);
    let latency_ms = env_u64("MPC_STRESS_LATENCY_MS", 0);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let harness = rt
        .block_on(async {
            StressHarnessBuilder::default()
                .nodes(nodes)
                .threshold(threshold)
                .request_timeout(Duration::from_secs(60))
                .with_config(|cfg| {
                    cfg.protocol.triple.min_triples = (total_requests as u32).saturating_mul(2);
                    cfg.protocol.triple.max_triples = (total_requests as u32).saturating_mul(8);
                    cfg.protocol.presignature.min_presignatures = total_requests as u32;
                    cfg.protocol.presignature.max_presignatures = (total_requests as u32).saturating_mul(4);
                })
                .build()
                .await
        })
        .unwrap();

    if latency_ms > 0 {
        rt.block_on(harness.set_global_latency(Duration::from_millis(latency_ms)));
    }

    let mut c = Criterion::default().sample_size(samples);
    c.bench_function(
        &format!("stress/sign_burst/{total_requests}_req/{concurrency}_conc"),
        |b| {
            b.iter(|| {
                let outcomes = rt.block_on(harness.submit_sign_requests(total_requests, concurrency));
                let failures = outcomes
                    .iter()
                    .filter(|outcome| !matches!(outcome.status, StressRequestStatus::Success))
                    .count();
                assert_eq!(failures, 0, "stress sign burst had non-success outcomes");
            })
        },
    );

    let report = rt
        .block_on(harness.run_actions(&[
            StressAction::Snapshot("post-bench".to_string()),
        ]))
        .unwrap();
    println!("post-bench snapshots: {}", report.snapshots.len());
}