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

    for outcome in &report.requests {
        assert!(outcome.batch_label.is_some(), "each request should retain its batch label");
        if matches!(
            outcome.status,
            integration_tests::stress::StressRequestStatus::Success
        ) {
            assert!(outcome.reason_code.is_none(), "successes should not carry a reason code");
        } else {
            assert!(outcome.reason_code.is_some(), "non-successes must carry a reason code");
            assert!(outcome.detail.is_some(), "non-successes must carry detail");
        }
    }
}

fn assert_snapshot_shape(report: &StressRunReport, nodes: usize) {
    for snapshot in &report.snapshots {
        assert_eq!(snapshot.nodes.len(), nodes, "snapshot must include every node");
        for node in &snapshot.nodes {
            assert!(
                node.metrics.is_some() || node.metrics_error.is_some(),
                "snapshot must contain either metrics or a fetch error"
            );
        }
    }
}

fn assert_batch_totals(report: &StressRunReport) {
    let expected_total: usize = report.batches.iter().map(|batch| batch.summary.total).sum();
    assert_eq!(expected_total, report.requests.len(), "batch totals must match request count");
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
    assert_snapshot_shape(&report, 3);
    assert_batch_totals(&report);

    let baseline = &report.batches[0].summary;
    assert_eq!(baseline.timeout + baseline.dropped + baseline.errors, 0);
    let recovery = report.batches.last().unwrap();
    assert_eq!(recovery.summary.timeout + recovery.summary.dropped + recovery.summary.errors, 0);
    assert!(baseline.median_latency_ms.is_some());

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
    assert_snapshot_shape(&report, 3);
    assert_batch_totals(&report);
    assert_eq!(report.batches[0].summary.total, 12);
    assert!(report.batches[0].summary.p99_latency_ms.is_some());

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
    assert_snapshot_shape(&report, 3);
    assert_batch_totals(&report);

    let first = &report.batches[0].summary;
    let last = &report.batches[report.batches.len() - 1].summary;
    assert_eq!(first.timeout + first.dropped + first.errors, 0);
    assert_eq!(last.timeout + last.dropped + last.errors, 0);

    Ok(())
}