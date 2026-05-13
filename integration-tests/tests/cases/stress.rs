use std::time::Duration;

use integration_tests::stress::{
    GlobalLatencySweepConfig, LatencySweepStage, SingleNodeStragglerConfig, SteadyOverloadConfig,
    StressHarnessBuilder, StressRunReport,
};
use serial_test::serial;
use test_log::test;

fn assert_all_resolved(report: &StressRunReport) {
    let total = report.requests.len();
    assert!(total > 0, "stress report must contain requests");

    let classified = report
        .requests
        .iter()
        .filter(|outcome| !matches!(outcome.status, integration_tests::stress::StressRequestStatus::Success))
        .count();
    assert!(classified <= total, "all requests must be classified");
}

async fn build_harness() -> anyhow::Result<integration_tests::stress::StressHarness> {
    StressHarnessBuilder::default()
        .nodes(3)
        .threshold(2)
        .request_timeout(Duration::from_secs(45))
        .with_config(|cfg| {
            cfg.protocol.triple.min_triples = 24;
            cfg.protocol.triple.max_triples = 128;
            cfg.protocol.presignature.min_presignatures = 24;
            cfg.protocol.presignature.max_presignatures = 128;
        })
        .build()
        .await
}

#[test(tokio::test)]
#[serial]
async fn test_stress_a1_global_latency_ci() -> anyhow::Result<()> {
    let harness = build_harness().await?;
    let cfg = GlobalLatencySweepConfig {
        stages: vec![
            LatencySweepStage {
                label: "baseline".to_string(),
                latency_ms: 0,
                total_requests: 6,
                concurrency: 3,
            },
            LatencySweepStage {
                label: "medium".to_string(),
                latency_ms: 200,
                total_requests: 6,
                concurrency: 3,
            },
            LatencySweepStage {
                label: "high".to_string(),
                latency_ms: 500,
                total_requests: 6,
                concurrency: 3,
            },
            LatencySweepStage {
                label: "recovery".to_string(),
                latency_ms: 0,
                total_requests: 6,
                concurrency: 3,
            },
        ],
    };

    let report = harness.run_global_latency_sweep(&cfg).await?;
    assert_eq!(report.batches.len(), cfg.stages.len());
    assert_eq!(report.snapshots.len(), cfg.stages.len() * 2);
    assert_all_resolved(&report);

    let baseline = &report.batches[0].summary;
    assert_eq!(baseline.timeout + baseline.dropped + baseline.errors, 0);

    Ok(())
}

#[test(tokio::test)]
#[serial]
async fn test_stress_a2_single_node_straggler_ci() -> anyhow::Result<()> {
    let harness = build_harness().await?;
    let cfg = SingleNodeStragglerConfig {
        node: 1,
        latency_ms: 750,
        total_requests: 12,
        concurrency: 4,
    };

    let report = harness.run_single_node_straggler(&cfg).await?;
    assert_eq!(report.batches.len(), 1);
    assert_eq!(report.snapshots.len(), 3);
    assert_all_resolved(&report);
    assert_eq!(report.batches[0].summary.total, 12);

    Ok(())
}

#[test(tokio::test)]
#[serial]
async fn test_stress_b1_steady_overload_ci() -> anyhow::Result<()> {
    let harness = build_harness().await?;
    let cfg = SteadyOverloadConfig {
        stages: vec![
            integration_tests::stress::OverloadStage {
                label: "c8".to_string(),
                concurrency: 8,
                total_requests: 8,
            },
            integration_tests::stress::OverloadStage {
                label: "c16".to_string(),
                concurrency: 16,
                total_requests: 16,
            },
            integration_tests::stress::OverloadStage {
                label: "c24".to_string(),
                concurrency: 24,
                total_requests: 24,
            },
            integration_tests::stress::OverloadStage {
                label: "recovery".to_string(),
                concurrency: 8,
                total_requests: 8,
            },
        ],
    };

    let report = harness.run_steady_overload(&cfg).await?;
    assert_eq!(report.batches.len(), cfg.stages.len());
    assert_eq!(report.snapshots.len(), cfg.stages.len() * 2);
    assert_all_resolved(&report);

    Ok(())
}