use std::time::Duration;

use criterion::Criterion;
use integration_tests::stress::{StressHarnessBuilder, StressScenario, StressSummary};

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

fn env_string(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn main() {
    let scenario = env_string("MPC_STRESS_SCENARIO", "burst");
    let scenario = StressScenario::from_env(&scenario).unwrap_or(StressScenario::Burst);
    let nodes = env_usize("MPC_STRESS_NODES", 3);
    let threshold = env_usize("MPC_STRESS_THRESHOLD", 2);
    let total_requests = env_usize("MPC_STRESS_TOTAL_REQUESTS", 16);
    let concurrency = env_usize("MPC_STRESS_CONCURRENCY", 8);
    let samples = env_usize("MPC_STRESS_SAMPLES", 10).max(1);
    let latency_ms = env_u64("MPC_STRESS_LATENCY_MS", 0);
    let report_path = std::env::var("MPC_STRESS_REPORT_PATH").ok();
    let csv_path = std::env::var("MPC_STRESS_CSV_PATH").ok();

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
        &format!(
            "stress/{}/{total_requests}_req/{concurrency}_conc",
            scenario.as_str()
        ),
        |b| {
            b.iter(|| {
                let report = rt
                    .block_on(harness.run_scenario(scenario, total_requests, concurrency))
                    .unwrap();
                let summary = StressSummary::from_outcomes(&report.requests);
                assert_eq!(summary.timeout + summary.dropped + summary.errors, 0, "stress scenario had non-success outcomes");
            })
        },
    );

    let report = rt
        .block_on(harness.run_scenario(scenario, total_requests, concurrency))
        .unwrap();
    if let Some(path) = &report_path {
        rt.block_on(harness.write_report_json(&report, path)).unwrap();
    }
    if let Some(path) = &csv_path {
        rt.block_on(harness.write_requests_csv(&report, path)).unwrap();
    }
    let summary = StressSummary::from_outcomes(&report.requests);
    println!(
        "scenario={} total={} success={} timeout={} dropped={} errors={} median_ms={:?} p99_ms={:?} snapshots={} batches={}",
        scenario.as_str(),
        summary.total,
        summary.success,
        summary.timeout,
        summary.dropped,
        summary.errors,
        summary.median_latency_ms,
        summary.p99_latency_ms,
        report.snapshots.len(),
        report.batches.len(),
    );

    rt.block_on(async move {
        drop(harness);
    });
}