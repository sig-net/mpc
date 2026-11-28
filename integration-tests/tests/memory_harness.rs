use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use integration_tests::memory_harness::diagnostics::{
    format_bytes, sample_current_process_memory, MemorySnapshot, MemorySummary,
};
use integration_tests::memory_harness::scenarios::deterministic_base_id;
use integration_tests::memory_harness::{
    HighWaterMarkTracker, MemoryHarness, MemoryHarnessConfig, StartingGate,
};

#[tokio::test]
async fn orphan_inbox_accumulation_measures_memory_delta() -> anyhow::Result<()> {
    let config = MemoryHarnessConfig::new(3)
        .with_items_per_batch(60)
        .with_max_allowed_leak(50 * 1024 * 1024);

    let harness = MemoryHarness::new(config).await?;
    let summary = harness.bench_orphan_inbox_accumulation().await?;

    assert_eq!(summary.scenario_name, "orphan_inbox_accumulation");
    assert_eq!(summary.iteration, 1);
    assert!(summary.operations > 0, "operations should be recorded");
    assert!(
        summary.peak_rss >= summary.initial_rss,
        "peak RSS should be at least initial RSS"
    );
    assert!(
        summary.duration.as_millis() > 0,
        "duration should be non-zero"
    );
    assert!(summary.passed_leak_check, "should pass within 50MB budget");

    Ok(())
}

#[tokio::test]
async fn burst_posit_flood_buffers_and_tracks_peak() -> anyhow::Result<()> {
    let config = MemoryHarnessConfig::new(3)
        .with_posit_burst_count(150)
        .with_max_allowed_leak(50 * 1024 * 1024);

    let harness = MemoryHarness::new(config).await?;
    let summary = harness.bench_burst_posit_flood().await?;

    assert_eq!(summary.scenario_name, "burst_posit_flood");
    assert_eq!(summary.iteration, 1);
    assert!(summary.operations > 0, "operations should be recorded");
    assert!(
        summary.peak_rss >= summary.initial_rss,
        "peak RSS should be at least initial RSS"
    );
    assert!(summary.passed_leak_check);

    Ok(())
}

#[tokio::test]
async fn generator_concurrency_surge_with_cait_sith_and_inbox() -> anyhow::Result<()> {
    let config = MemoryHarnessConfig::new(3)
        .with_surge_generators(10)
        .with_max_allowed_leak(50 * 1024 * 1024);

    let harness = MemoryHarness::new(config).await?;
    let summary = harness.bench_generator_concurrency_surge().await?;

    assert_eq!(summary.scenario_name, "generator_concurrency_surge");
    assert_eq!(summary.iteration, 1);
    assert_eq!(summary.operations, 10);
    assert!(summary.peak_rss >= summary.initial_rss);
    assert!(summary.passed_leak_check);

    Ok(())
}

#[tokio::test]
async fn multi_iteration_tracks_cumulative_drift() -> anyhow::Result<()> {
    let config = MemoryHarnessConfig::new(3)
        .with_items_per_batch(30)
        .with_max_allowed_leak(50 * 1024 * 1024);

    let harness = MemoryHarness::new(config).await?;
    let s1 = harness.bench_orphan_inbox_accumulation_iter(1).await?;
    let s2 = harness.bench_orphan_inbox_accumulation_iter(2).await?;

    assert_eq!(s1.iteration, 1);
    assert_eq!(s2.iteration, 2);
    assert_eq!(s1.baseline_rss, harness.baseline_rss);
    assert_eq!(s2.baseline_rss, harness.baseline_rss);
    assert_eq!(
        s1.drift_from_baseline,
        s1.final_rss as i64 - s1.baseline_rss as i64
    );
    assert_eq!(
        s2.drift_from_baseline,
        s2.final_rss as i64 - s2.baseline_rss as i64
    );

    Ok(())
}

#[test]
fn scenario_id_ranges_never_overlap() {
    let seed = 42;
    let mut ranges: Vec<(u64, u64, String)> = Vec::new();

    for scenario_idx in 1..=6 {
        for iteration in 1..=50 {
            for peer_idx in 0..=8 {
                let base = deterministic_base_id(seed, scenario_idx, iteration, peer_idx);
                // Each batch uses up to 100,000 items
                let end = base + 100_000;
                ranges.push((
                    base,
                    end,
                    format!("s{scenario_idx}_i{iteration}_p{peer_idx}"),
                ));
            }
        }
    }

    ranges.sort_by_key(|r| r.0);
    for i in 0..ranges.len() - 1 {
        let (base1, end1, ref label1) = ranges[i];
        let (base2, _, ref label2) = ranges[i + 1];
        assert!(
            end1 <= base2,
            "ID range overlap detected between {label1} [{}, {}] and {label2} [{}]",
            base1,
            end1,
            base2
        );
    }
}

#[test]
fn config_validation_rejects_invalid_inputs() {
    // Insufficient participants (< 2)
    let c1 = MemoryHarnessConfig::new(0);
    assert!(c1.validate().is_err());
    let c2 = MemoryHarnessConfig::new(1);
    assert!(c2.validate().is_err());

    // Threshold = 0
    let c3 = MemoryHarnessConfig::new(3).with_threshold(0);
    assert!(c3.validate().is_err());

    // Threshold > num_participants
    let c4 = MemoryHarnessConfig::new(3).with_threshold(4);
    assert!(c4.validate().is_err());

    // Zero items per batch
    let c5 = MemoryHarnessConfig::new(3).with_items_per_batch(0);
    assert!(c5.validate().is_err());

    // Zero sample interval
    let c6 = MemoryHarnessConfig::new(3).with_sample_interval(Duration::ZERO);
    assert!(c6.validate().is_err());

    // Zero payload_bytes
    let c7 = MemoryHarnessConfig::new(3).with_payload_bytes(0);
    assert!(c7.validate().is_err());

    // Valid configuration
    let c8 = MemoryHarnessConfig::new(4)
        .with_threshold(3)
        .with_items_per_batch(100)
        .with_payload_bytes(4096)
        .with_surge_generators(20);
    assert!(c8.validate().is_ok());

    // Items per batch exceeding 500,000
    let c9 = MemoryHarnessConfig::new(3).with_items_per_batch(500_001);
    assert!(c9.validate().is_err());

    // Posit burst exceeding 500,000
    let c10 = MemoryHarnessConfig::new(3).with_posit_burst_count(500_001);
    assert!(c10.validate().is_err());
}

#[test]
fn leak_detection_flags_exceeded_threshold_deterministically() {
    let initial = MemorySnapshot {
        rss_bytes: 50_000_000,
        virtual_bytes: 100_000_000,
        timestamp: std::time::Instant::now(),
    };
    let final_leak = MemorySnapshot {
        rss_bytes: 55_000_000, // +5 MB retained in this run
        virtual_bytes: 100_000_000,
        timestamp: std::time::Instant::now(),
    };

    // Budget of 2 MB (< 5 MB retained) must fail
    let summary_fail = MemorySummary::calculate(
        "test_leak",
        1,
        50_000_000,
        initial,
        60_000_000,
        final_leak,
        Duration::from_secs(1),
        100,
        2 * 1024 * 1024,
    );
    assert!(
        !summary_fail.passed_leak_check,
        "5MB retained exceeds 2MB budget -> must fail"
    );

    // Budget of 10 MB (> 5 MB retained) must pass
    let summary_pass = MemorySummary::calculate(
        "test_ok",
        1,
        50_000_000,
        initial,
        60_000_000,
        final_leak,
        Duration::from_secs(1),
        100,
        10 * 1024 * 1024,
    );
    assert!(
        summary_pass.passed_leak_check,
        "5MB retained within 10MB budget -> must pass"
    );

    // Cumulative drift is reported accurately and does not falsely fail if retained delta is within budget
    let final_drift = MemorySnapshot {
        rss_bytes: 51_000_000, // +1 MB retained in iteration 3
        virtual_bytes: 100_000_000,
        timestamp: std::time::Instant::now(),
    };
    let summary_drift = MemorySummary::calculate(
        "test_drift_ok",
        3,
        40_000_000, // baseline was 40MB -> cumulative drift is 11MB
        initial,    // initial was 50MB -> isolated retained is 1MB
        60_000_000,
        final_drift,
        Duration::from_secs(1),
        100,
        5 * 1024 * 1024, // 5MB budget
    );
    assert_eq!(summary_drift.retained_rss, 1_000_000);
    assert_eq!(summary_drift.drift_from_baseline, 11_000_000);
    assert!(
        summary_drift.passed_leak_check,
        "1MB retained within 5MB budget must pass"
    );
}

#[test]
fn format_bytes_displays_correct_units() {
    assert_eq!(format_bytes(512), "512 B");
    assert_eq!(format_bytes(1024), "1.00 KB");
    assert_eq!(format_bytes(10 * 1024), "10.00 KB");
    assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
    assert_eq!(format_bytes(50 * 1024 * 1024), "50.00 MB");
    assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    assert_eq!(format_bytes(2 * 1024 * 1024 * 1024), "2.00 GB");
}

#[tokio::test]
async fn starting_gate_synchronizes_workers() {
    let gate = StartingGate::new(3);
    let released = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();

    for _ in 0..3 {
        let barrier = gate.barrier();
        let released_clone = released.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            // Assert that workers only proceed after the orchestrator tripped the gate
            assert!(
                released_clone.load(Ordering::SeqCst),
                "worker released before gate started!"
            );
        }));
    }

    // Ensure workers are waiting at the barrier
    tokio::time::sleep(Duration::from_millis(30)).await;
    released.store(true, Ordering::SeqCst);

    let start_time = gate.start().await;
    for h in handles {
        h.await.unwrap();
    }
    assert!(start_time.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn high_water_mark_tracker_samples_peak() {
    let tracker = HighWaterMarkTracker::start(Duration::from_millis(5));
    let (initial_rss, _) = sample_current_process_memory();
    assert!(initial_rss > 0);

    // Allocate and touch pages across 24 MB to verify tracker records peak
    let mut spike: Vec<u8> = vec![0u8; 24 * 1024 * 1024];
    for chunk in spike.chunks_mut(4096) {
        chunk[0] = 0x42;
    }
    std::hint::black_box(&spike);
    tokio::time::sleep(Duration::from_millis(40)).await;

    let observed_peak = tracker.current_peak();
    assert!(
        observed_peak > initial_rss + 8 * 1024 * 1024,
        "tracker must capture allocation spike: observed_peak ({observed_peak}) > initial_rss ({initial_rss}) + 8MB"
    );

    drop(spike);
    let final_peak = tracker.stop();
    assert!(final_peak >= observed_peak);
}

#[test]
fn memory_summary_csv_and_json_serialization() {
    let initial = MemorySnapshot {
        rss_bytes: 10_000_000,
        virtual_bytes: 50_000_000,
        timestamp: std::time::Instant::now(),
    };
    let final_snap = MemorySnapshot {
        rss_bytes: 12_000_000,
        virtual_bytes: 55_000_000,
        timestamp: std::time::Instant::now(),
    };

    let summary = MemorySummary::calculate(
        "test_scenario",
        2,
        9_000_000,
        initial,
        15_000_000,
        final_snap,
        Duration::from_millis(500),
        1000,
        5_000_000,
    );

    assert_eq!(summary.scenario_name, "test_scenario");
    assert_eq!(summary.iteration, 2);
    assert_eq!(summary.initial_rss, 10_000_000);
    assert_eq!(summary.baseline_rss, 9_000_000);
    assert_eq!(summary.peak_rss, 15_000_000);
    assert_eq!(summary.final_rss, 12_000_000);
    assert_eq!(summary.retained_rss, 2_000_000);
    assert_eq!(summary.drift_from_baseline, 3_000_000);
    assert_eq!(summary.peak_delta, 5_000_000);
    assert_eq!(summary.operations, 1000);
    assert!(summary.ops_per_sec > 1900.0 && summary.ops_per_sec < 2100.0);
    assert!(summary.passed_leak_check);

    // CSV serialization
    let header = MemorySummary::to_csv_header();
    assert!(header.starts_with("scenario_name,iteration,initial_rss_bytes"));
    let row = summary.to_csv_row();
    assert!(row.starts_with("test_scenario,2,10000000,9000000,15000000,12000000,2000000,3000000"));

    // JSON serialization roundtrip
    let json_str = serde_json::to_string_pretty(&summary).unwrap();
    let deserialized: MemorySummary = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.scenario_name, summary.scenario_name);
    assert_eq!(deserialized.iteration, summary.iteration);
    assert_eq!(deserialized.initial_rss, summary.initial_rss);
    assert_eq!(deserialized.baseline_rss, summary.baseline_rss);
    assert_eq!(deserialized.peak_rss, summary.peak_rss);
    assert_eq!(deserialized.retained_rss, summary.retained_rss);
    assert_eq!(
        deserialized.drift_from_baseline,
        summary.drift_from_baseline
    );
    assert!(deserialized.passed_leak_check);
}
