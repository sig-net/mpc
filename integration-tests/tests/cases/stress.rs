use std::time::Duration;

use integration_tests::stress::{
    BurstSpikeConfig, GlobalLatencySweepConfig, LatencySweepStage, SingleNodeStragglerConfig,
    OverloadNodeDegradationConfig, SteadyOverloadConfig, StressHarnessBuilder, StressRunReport,
    PipelineContentionConfig, TripleDepletionConfig,
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
            assert!(node.state.is_some() || node.state_error.is_some(), "snapshot must contain either state or a fetch error");
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

async fn build_triple_depletion_harness() -> anyhow::Result<integration_tests::stress::StressHarness> {
    StressHarnessBuilder::default()
        .nodes(3)
        .threshold(2)
        .disable_prestockpile()
        .request_timeout(Duration::from_secs(90))
        .with_config(|cfg| {
            cfg.protocol.max_concurrent_generation = 1;
            cfg.protocol.max_concurrent_introduction = 1;
            cfg.protocol.triple.min_triples = 1;
            cfg.protocol.triple.max_triples = 2;
            cfg.protocol.presignature.min_presignatures = 2;
            cfg.protocol.presignature.max_presignatures = 4;
        })
        .build()
        .await
}

async fn build_pipeline_contention_harness() -> anyhow::Result<integration_tests::stress::StressHarness> {
    StressHarnessBuilder::default()
        .nodes(3)
        .threshold(2)
        .disable_prestockpile()
        .request_timeout(Duration::from_secs(90))
        .with_config(|cfg| {
            cfg.protocol.max_concurrent_generation = 1;
            cfg.protocol.max_concurrent_introduction = 1;
            cfg.protocol.triple.min_triples = 1;
            cfg.protocol.triple.max_triples = 2;
            cfg.protocol.presignature.min_presignatures = 1;
            cfg.protocol.presignature.max_presignatures = 2;
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
async fn test_stress_b2_burst_spike_ci() -> anyhow::Result<()> {
    let harness = build_harness().await?;
    let cfg = BurstSpikeConfig {
        warmup_total_requests: 6,
        warmup_concurrency: 3,
        spike_total_requests: 18,
        spike_concurrency: 18,
        recovery_total_requests: 6,
        recovery_concurrency: 3,
    };

    let report = harness.run_burst_spike(&cfg).await?;
    assert_eq!(report.batches.len(), 3);
    assert_eq!(report.snapshots.len(), 4);
    assert_all_resolved(&report);
    assert_snapshot_shape(&report, 3);
    assert_batch_totals(&report);

    let warmup = &report.batches[0];
    let spike = &report.batches[1];
    let recovery = &report.batches[2];
    assert_eq!(warmup.label, "warmup");
    assert_eq!(spike.label, "spike");
    assert_eq!(recovery.label, "recovery");
    assert_eq!(warmup.summary.timeout + warmup.summary.dropped + warmup.summary.errors, 0);
    assert_eq!(recovery.summary.timeout + recovery.summary.dropped + recovery.summary.errors, 0);
    assert_eq!(spike.summary.total, 18);
    assert!(spike.summary.p99_latency_ms.is_some());

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

#[test(tokio::test)]
#[serial]
async fn test_stress_c1_triple_depletion_ci() -> anyhow::Result<()> {
    let harness = build_triple_depletion_harness().await?;
    let cfg = TripleDepletionConfig {
        initial_triples_per_node: 1,
        initial_presignatures_per_node: 2,
        active_triple_generators_min: 1,
        recovery_triples_min: 1,
        total_requests: 4,
        concurrency: 2,
        stockpile_timeout: Duration::from_secs(45),
        recovery_timeout: Duration::from_secs(90),
    };

    let report = harness.run_triple_depletion(&cfg).await?;
    assert_eq!(report.batches.len(), 1);
    assert_eq!(report.snapshots.len(), 3);
    assert_all_resolved(&report);
    assert_snapshot_shape(&report, 3);
    assert_batch_totals(&report);

    let batch = &report.batches[0];
    assert_eq!(batch.label, "triple-depletion");
    assert_eq!(batch.summary.timeout + batch.summary.dropped + batch.summary.errors, 0);

    let depleted = &report.snapshots[1];
    let active_refill = depleted
        .nodes
        .iter()
        .filter_map(|node| node.state.as_ref())
        .any(|state| matches!(
            state,
            integration_tests::stress::NodeStateSnapshot::Running {
                triple_count,
                triple_potential_count,
                ..
            } if triple_potential_count > triple_count
        ));
    assert!(
        active_refill,
        "triple generation should be active while requests refill stockpile"
    );

    let recovered = &report.snapshots[2];
    for node in &recovered.nodes {
        let state = node.state.as_ref().expect("recovery snapshot should carry state");
        assert!(
            matches!(
                state,
                integration_tests::stress::NodeStateSnapshot::Running { triple_count, .. }
                    if *triple_count >= cfg.recovery_triples_min as usize
            ),
            "triple stockpile should recover after scenario"
        );
    }

    Ok(())
}

#[test(tokio::test)]
#[serial]
async fn test_stress_b3_overload_node_degradation_ci() -> anyhow::Result<()> {
    let mut harness = build_harness().await?;
    let cfg = OverloadNodeDegradationConfig {
        node: 1,
        warmup_total_requests: 6,
        warmup_concurrency: 3,
        degraded_total_requests: 16,
        degraded_concurrency: 8,
        recovery_total_requests: 6,
        recovery_concurrency: 3,
    };

    let report = harness.run_overload_with_node_restart(&cfg).await?;
    assert_eq!(report.batches.len(), 3);
    assert_eq!(report.snapshots.len(), 4);
    assert_all_resolved(&report);
    assert_batch_totals(&report);

    assert_eq!(report.snapshots[0].nodes.len(), 3);
    assert_eq!(report.snapshots[1].nodes.len(), 2);
    assert_eq!(report.snapshots[2].nodes.len(), 3);
    assert_eq!(report.snapshots[3].nodes.len(), 3);

    let warmup = &report.batches[0];
    let degraded = &report.batches[1];
    let recovery = &report.batches[2];
    assert_eq!(warmup.label, "warmup");
    assert_eq!(degraded.label, "degraded");
    assert_eq!(recovery.label, "recovery");
    assert_eq!(warmup.summary.timeout + warmup.summary.dropped + warmup.summary.errors, 0);
    assert_eq!(recovery.summary.timeout + recovery.summary.dropped + recovery.summary.errors, 0);
    assert_eq!(degraded.summary.total, cfg.degraded_total_requests);

    Ok(())
}

#[test(tokio::test)]
#[serial]
#[ignore = "needs deterministic presignature refill hook under signing load"]
async fn test_stress_c2_pipeline_contention_ci() -> anyhow::Result<()> {
    let harness = build_pipeline_contention_harness().await?;
    let cfg = PipelineContentionConfig {
        initial_triples_per_node: 1,
        initial_presignatures_per_node: 0,
        total_requests: 4,
        concurrency: 2,
        pressure_timeout: Duration::from_secs(45),
        recovery_triples_min: 1,
        recovery_presignatures_min: 1,
    };

    let report = harness.run_pipeline_contention(&cfg).await?;
    assert_eq!(report.batches.len(), 1);
    assert_eq!(report.snapshots.len(), 4);
    assert_all_resolved(&report);
    assert_snapshot_shape(&report, 3);
    assert_batch_totals(&report);

    let triple_pressure_snapshot = &report.snapshots[1];
    let triple_pressure = triple_pressure_snapshot
        .nodes
        .iter()
        .filter_map(|node| node.state.as_ref())
        .any(|state| {
        matches!(
            state,
            integration_tests::stress::NodeStateSnapshot::Running {
                triple_count,
                triple_potential_count,
                ..
            } if triple_potential_count > triple_count
        )
    });
    let presignature_pressure_snapshot = &report.snapshots[2];
    let presignature_pressure = presignature_pressure_snapshot
        .nodes
        .iter()
        .filter_map(|node| node.state.as_ref())
        .any(|state| {
        matches!(
            state,
            integration_tests::stress::NodeStateSnapshot::Running {
                presignature_count,
                presignature_potential_count,
                ..
            } if presignature_potential_count > presignature_count
        )
    });
    assert!(triple_pressure, "triple refill should activate under signing load");
    assert!(presignature_pressure, "presignature refill should activate under signing load");

    Ok(())
}