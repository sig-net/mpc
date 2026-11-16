use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use cait_sith::protocol::Participant;
use mpc_node::backlog::{mock::mock_sign_request, BacklogEntry, Checkpoint};
use mpc_node::storage::CheckpointStorage;
use mpc_primitives::{Chain, SignId};

use super::diagnostics::LatencySummary;
use super::gate::StartingGate;
use super::participant::{
    next_id_block, ArtifactKind, ChurnState, MeasuredOp, SimulatedParticipant,
};
use super::RedisHarness;

fn summarize(name: &str, mut metric: MeasuredOp, wall: Duration) -> LatencySummary {
    LatencySummary::calculate_with_outcomes(
        name,
        &mut metric.latencies,
        wall,
        metric.failures,
        metric.indeterminate,
    )
}

fn overlaps(
    (start, end): (Instant, Instant),
    (other_start, other_end): (Instant, Instant),
) -> bool {
    start < other_end && end > other_start
}

async fn collect_task_results(
    tasks: impl IntoIterator<Item = tokio::task::JoinHandle<(Vec<Duration>, usize)>>,
) -> anyhow::Result<(Vec<Duration>, usize)> {
    let mut latencies = Vec::new();
    let mut failures = 0;
    for t in tasks {
        let (lats, f) = t.await?;
        latencies.extend(lats);
        failures += f;
    }
    Ok((latencies, failures))
}

impl RedisHarness {
    /// SCENARIO 1: Concurrent Insert & Take Throughput.
    /// Simulates N participants inserting pairs simultaneously and subsequently taking them.
    pub async fn bench_concurrent_insert_and_take(
        &self,
        items_per_participant: usize,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;
        self.run_concurrent_insert_and_take(items_per_participant)
            .await
    }

    async fn run_concurrent_insert_and_take(
        &self,
        items_per_participant: usize,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        if self.participants.is_empty() || items_per_participant == 0 {
            return Ok(vec![
                LatencySummary::empty("concurrent_insert_triple"),
                LatencySummary::empty("concurrent_take_triple"),
            ]);
        }

        let run_base_id =
            next_id_block((self.participants.len() * items_per_participant) as u64 + 1000);
        let gate = StartingGate::new(self.participants.len());
        let participant_list = self.participant_ids();

        let insert_tasks: Vec<_> = self
            .participants
            .iter()
            .enumerate()
            .map(|(node_idx, p)| {
                let base_id = run_base_id + (node_idx as u64 * items_per_participant as u64);
                tokio::spawn(p.clone().insert_measured(
                    ArtifactKind::Triples,
                    base_id,
                    items_per_participant,
                    participant_list.clone(),
                    gate.barrier(),
                ))
            })
            .collect();

        let overall_start = gate.start().await;

        let (mut all_insert_latencies, insert_failures) =
            collect_task_results(insert_tasks).await?;
        let insert_wall = overall_start.elapsed();

        // Concurrent taking of the inserted items
        let gate = StartingGate::new(self.participants.len());

        let take_tasks: Vec<_> = self
            .participants
            .iter()
            .enumerate()
            .map(|(node_idx, p)| {
                let base_id = run_base_id + (node_idx as u64 * items_per_participant as u64);
                let ids: Vec<u64> = (base_id..base_id + items_per_participant as u64).collect();
                tokio::spawn(p.clone().take_triples(ids, gate.optional_barrier()))
            })
            .collect();

        let take_start = gate.start().await;

        let (mut all_take_latencies, take_indeterminate) = collect_task_results(take_tasks).await?;
        let take_wall = take_start.elapsed();

        let s1 = LatencySummary::calculate_with_failures(
            "concurrent_insert_triple",
            &mut all_insert_latencies,
            insert_wall,
            insert_failures,
        );
        let s2 = LatencySummary::calculate_with_outcomes(
            "concurrent_take_triple",
            &mut all_take_latencies,
            take_wall,
            0,
            take_indeterminate,
        );

        Ok(vec![s1, s2])
    }

    /// SCENARIO 2: Stockpile One-Second Background Polling Contention Comparison.
    /// Runs a write/read workload without vs. with one-second pipelined stock-count polling across all participants,
    /// returning tagged LatencySummary metrics for direct comparison.
    pub async fn bench_polling_contention(
        &self,
        workload_items: usize,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        println!("    Phase A: Workload WITHOUT background polling...");
        self.reset_diagnostics().await?;
        let without_polling = self.run_concurrent_insert_and_take(workload_items).await?;

        println!(
            "    Phase B: Workload WITH one-second stock-count polling across {} participants...",
            self.participants.len()
        );
        self.reset_diagnostics().await?;
        let poller = self.spawn_background_polling(true);
        let with_polling = self.run_concurrent_insert_and_take(workload_items).await;
        poller.stop().await;
        let with_polling = with_polling?;

        let mut combined = Vec::with_capacity(without_polling.len() + with_polling.len());
        combined.extend(without_polling.into_iter().map(|mut r| {
            r.op_name = format!("{}_no_poll", r.op_name);
            r
        }));
        combined.extend(with_polling.into_iter().map(|mut r| {
            r.op_name = format!("{}_with_poll", r.op_name);
            r
        }));

        Ok(combined)
    }

    /// Compare artifact traffic with and without concurrent checkpoint writes and reads.
    pub async fn bench_checkpoint_contention(
        &self,
        requests_per_checkpoint: usize,
        workload_items: usize,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;
        let baseline = self.run_concurrent_insert_and_take(workload_items).await?;
        self.reset_diagnostics().await?;

        if self.participants.is_empty() || workload_items == 0 {
            return Ok(vec![
                LatencySummary::empty("concurrent_insert_triple_no_checkpoint"),
                LatencySummary::empty("concurrent_take_triple_no_checkpoint"),
                LatencySummary::empty("concurrent_insert_triple_with_checkpoint"),
                LatencySummary::empty("concurrent_take_triple_with_checkpoint"),
                LatencySummary::empty("checkpoint_write"),
                LatencySummary::empty("checkpoint_read"),
            ]);
        }

        let mut checkpoint = Checkpoint::empty(Chain::Solana);
        checkpoint.pending_requests = (0..requests_per_checkpoint)
            .map(|i| {
                let mut id = [0; 32];
                id[..8].copy_from_slice(&(i as u64).to_le_bytes());
                let mut request = mock_sign_request(SignId::new(id), Chain::Solana);
                // Approximate the observed ~1.2 kB/request checkpoint payload.
                Arc::get_mut(&mut request).unwrap().args.path = "x".repeat(900);
                BacklogEntry::new(request)
            })
            .collect();
        let mut encoded = Vec::new();
        ciborium::into_writer(&checkpoint, &mut encoded)?;
        println!("   -> Checkpoint payload: {} bytes per node", encoded.len());
        drop(encoded);
        let checkpoint = Arc::new(checkpoint);
        let storages: Vec<_> = self
            .participants
            .iter()
            .map(|p| CheckpointStorage::Redis(p.pool.clone(), p.account_id.clone()))
            .collect();
        futures::future::try_join_all(storages.iter().map(|s| s.persist(&checkpoint))).await?;

        let stop = Arc::new(AtomicBool::new(false));
        let gate = StartingGate::new(self.participants.len() * 2);
        let mut tasks = Vec::new();
        for storage in storages {
            for is_write in [true, false] {
                let storage = storage.clone();
                let checkpoint = checkpoint.clone();
                let stop = stop.clone();
                let barrier = gate.barrier();
                tasks.push(tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                    barrier.wait().await;
                    let mut latencies = Vec::new();
                    let mut failures = 0;
                    let mut intervals = Vec::new();
                    while !stop.load(Ordering::Relaxed) {
                        let start = Instant::now();
                        let success = if is_write {
                            storage.persist(&checkpoint).await.is_ok()
                        } else {
                            matches!(storage.load_latest(Chain::Solana).await,
                                Ok(Some(value)) if value.pending_requests.len() == checkpoint.pending_requests.len())
                        };
                        let end = Instant::now();
                        intervals.push((start, end));
                        if success { latencies.push(end - start); } else { failures += 1; }
                    }
                    (is_write, latencies, failures, intervals)
                })));
            }
        }

        let start = gate.start().await;
        let workload_start = Instant::now();
        let workload = self.run_concurrent_insert_and_take(workload_items).await;
        let workload_end = Instant::now();
        stop.store(true, Ordering::Relaxed);
        let mut writes = Vec::new();
        let mut reads = Vec::new();
        let mut write_failures = 0;
        let mut read_failures = 0;
        let mut write_overlap = false;
        let mut read_overlap = false;
        for task in tasks {
            let (is_write, latencies, failures, intervals) = task.await?;
            let overlapped = intervals
                .into_iter()
                .any(|interval| overlaps(interval, (workload_start, workload_end)));
            if is_write {
                writes.extend(latencies);
                write_failures += failures;
                write_overlap |= overlapped;
            } else {
                reads.extend(latencies);
                read_failures += failures;
                read_overlap |= overlapped;
            }
        }
        let wall = start.elapsed();
        let workload = workload?;
        anyhow::ensure!(write_overlap && read_overlap, "checkpoint reads and writes did not both overlap the artifact workload; increase --items");
        let mut results = Vec::new();
        results.extend(baseline.into_iter().map(|mut result| {
            result.op_name.push_str("_no_checkpoint");
            result
        }));
        results.extend(workload.into_iter().map(|mut result| {
            result.op_name.push_str("_with_checkpoint");
            result
        }));
        results.push(LatencySummary::calculate_with_failures(
            "checkpoint_write",
            &mut writes,
            wall,
            write_failures,
        ));
        results.push(LatencySummary::calculate_with_failures(
            "checkpoint_read",
            &mut reads,
            wall,
            read_failures,
        ));
        Ok(results)
    }

    /// SCENARIO 3: `remove_outdated` Pruning Storm.
    /// Pre-populates owned items across participants, then triggers `remove_outdated` concurrently
    /// across all participants with remaining shares (reproducing the slowlog spike).
    pub async fn bench_remove_outdated_storm(
        &self,
        stockpile_count: usize,
        prune_count: usize,
        rounds: usize,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;

        if self.participants.is_empty() || stockpile_count == 0 || rounds == 0 {
            return Ok(vec![LatencySummary::empty("remove_outdated_storm")]);
        }

        let num_p = self.participants.len();
        let mut all_latencies = Vec::with_capacity(num_p * rounds);
        let mut total_failures = 0;
        let mut storm_wall = Duration::ZERO;

        println!(
            "   -> Running {rounds} rounds of `remove_outdated` pruning storm across {num_p} participants ({stockpile_count} items/participant, {prune_count} pruned/round)..."
        );

        for _ in 0..rounds {
            let run_base_id = next_id_block((num_p * stockpile_count) as u64 + 1000);
            let all_ids = self
                .populate_all_triples(run_base_id, stockpile_count)
                .await?;

            let gate = StartingGate::new(num_p);
            let storm_tasks: Vec<_> = self
                .participants
                .iter()
                .enumerate()
                .map(|(node_idx, p)| {
                    let remaining_shares = all_ids
                        .get(node_idx)
                        .map(|ids| {
                            let prune_idx = prune_count.min(ids.len());
                            ids[prune_idx..].to_vec()
                        })
                        .unwrap_or_default();
                    tokio::spawn(
                        p.clone()
                            .remove_outdated_shares(gate.barrier(), remaining_shares),
                    )
                })
                .collect();

            let storm_start = gate.start().await;
            for task in storm_tasks {
                let (lat, res) = task.await?;
                if res.is_ok() {
                    all_latencies.push(lat);
                } else {
                    total_failures += 1;
                }
            }
            storm_wall += storm_start.elapsed();

            // Untimed cleanup of leftover shares so subsequent rounds measure identical keyspace distributions
            self.clear_triples().await;
        }

        Ok(vec![LatencySummary::calculate_with_failures(
            "remove_outdated_storm",
            &mut all_latencies,
            storm_wall,
            total_failures,
        )])
    }

    /// SCENARIO 4: Proposer Race (`peek_mine` + `commit`).
    /// Multiple concurrent tasks on a single participant storage racing to reserve artifacts with exclusion lists.
    pub async fn bench_proposer_race(
        &self,
        participant_idx: usize,
        initial_stockpile: usize,
        num_racers: usize,
        proposals_per_racer: usize,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;

        if self.participants.is_empty() || num_racers == 0 || proposals_per_racer == 0 {
            return Ok(vec![
                LatencySummary::empty("peek_mine_contended"),
                LatencySummary::empty("commit_proposal"),
            ]);
        }

        let p = self
            .participants
            .get(participant_idx)
            .context("invalid participant index")?;
        println!(
            "   -> Stockpiling {initial_stockpile} triples on participant {participant_idx}..."
        );
        let base_id = next_id_block(initial_stockpile as u64 + 1000);
        self.populate(
            ArtifactKind::Triples,
            participant_idx,
            base_id,
            initial_stockpile,
        )
        .await?;

        let gate = StartingGate::new(num_racers);

        let racer_tasks: Vec<_> = (0..num_racers)
            .map(|_| {
                let racer = p.clone();
                tokio::spawn(racer.race_proposals(gate.barrier(), base_id, proposals_per_racer))
            })
            .collect();

        let race_start = gate.start().await;

        let mut metrics: [MeasuredOp; 2] = Default::default();

        for task in racer_tasks {
            for (total, result) in metrics.iter_mut().zip(task.await?) {
                total.merge(result);
            }
        }
        let wall = race_start.elapsed();
        let [peek, commit] = metrics;
        Ok(vec![
            summarize("peek_mine_contended", peek, wall),
            summarize("commit_proposal", commit, wall),
        ])
    }

    /// SCENARIO 5: Production Cascading Saturation & Head-of-Line Blocking (reproducing 50ms - 6s latencies).
    /// Simulates production conditions:
    /// 1. one-second background stock-count refreshes.
    /// 2. High concurrency (many concurrent tasks competing for connection pool slots).
    /// 3. Intermittent Redis blocking events (simulating long remove_outdated Lua scripts or BGSAVE freezes).
    ///
    /// Measures the resulting queueing delays and tail latencies.
    pub async fn bench_cascading_saturation(
        &self,
        tasks_per_participant: usize,
        items_per_task: usize,
        blocking_spike_ms: u64,
        num_spikes: usize,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        if self.participants.is_empty() || tasks_per_participant == 0 || items_per_task == 0 {
            return Ok(vec![
                LatencySummary::empty("saturated_insert_triple"),
                LatencySummary::empty("saturated_peek_mine"),
                LatencySummary::empty("saturated_take_triple"),
            ]);
        }

        if blocking_spike_ms > 0 && num_spikes > 0 {
            self.client.check_debug_sleep().await?;
        }
        self.reset_diagnostics().await?;

        let pool_status = self.participants[0].pool.status();
        println!(
            "   -> Participant 0 connection pool status: max_size={} (active={}, available={}, waiting={})",
            pool_status.max_size, pool_status.size, pool_status.available, pool_status.waiting
        );

        // 1. One-second stock-count polling across all participants
        let poller = self.spawn_background_polling(true);

        // 2. Intermittent main-thread stalls, spanning insert, peek, and take.
        let spike_stop = Arc::new(AtomicBool::new(false));
        let spike_count = num_spikes.checked_mul(3).context("spike count overflow")?;
        let spike_handle = super::RedisDiagnosticsClient::spawn_intermittent_spike(
            &self.redis_url,
            spike_stop.clone(),
            blocking_spike_ms,
            spike_count,
        )?;
        let workload = async {
            // 3. Phase A: High-concurrency inserts across participants under saturation
            let total_items = self.participants.len() * tasks_per_participant * items_per_task;
            let run_base_id = next_id_block(total_items as u64 + 10_000);
            let insert_gate = StartingGate::new(self.participants.len() * tasks_per_participant);
            let participant_list = self.participant_ids();

            let mut insert_tasks =
                Vec::with_capacity(self.participants.len() * tasks_per_participant);
            let mut task_id_ranges =
                Vec::with_capacity(self.participants.len() * tasks_per_participant);

            for (p_idx, p) in self.participants.iter().enumerate() {
                for t_idx in 0..tasks_per_participant {
                    let task_id = p_idx * tasks_per_participant + t_idx;
                    let base_id = run_base_id + (task_id as u64 * items_per_task as u64);
                    let ids: Vec<u64> = (base_id..base_id + items_per_task as u64).collect();
                    task_id_ranges.push((p.clone(), ids));
                    insert_tasks.push(tokio::spawn(p.clone().insert_measured(
                        ArtifactKind::Triples,
                        base_id,
                        items_per_task,
                        participant_list.clone(),
                        insert_gate.barrier(),
                    )));
                }
            }

            let insert_start = insert_gate.start().await;
            let (mut all_insert_latencies, total_insert_failures) =
                collect_task_results(insert_tasks).await?;
            let insert_wall = insert_start.elapsed();

            // 4. Phase B: Concurrent peek_mine on available stockpile under saturation and blocking stalls
            let peek_gate = StartingGate::new(self.participants.len() * tasks_per_participant);
            let peek_items = items_per_task.min(25);
            let mut peek_tasks =
                Vec::with_capacity(self.participants.len() * tasks_per_participant);
            for p in &self.participants {
                for _ in 0..tasks_per_participant {
                    peek_tasks.push(tokio::spawn(
                        p.clone()
                            .peek_triples_measured(peek_gate.barrier(), peek_items),
                    ));
                }
            }

            let peek_start = peek_gate.start().await;
            let (mut all_peek_latencies, total_peek_indeterminate) =
                collect_task_results(peek_tasks).await?;
            let peek_wall = peek_start.elapsed();

            // 5. Phase C: High-concurrency takes across participants under saturation
            let take_gate = StartingGate::new(self.participants.len() * tasks_per_participant);
            let mut take_tasks =
                Vec::with_capacity(self.participants.len() * tasks_per_participant);
            for (p, ids) in task_id_ranges {
                take_tasks.push(tokio::spawn(
                    p.take_triples(ids, take_gate.optional_barrier()),
                ));
            }

            let take_start = take_gate.start().await;
            let (mut all_take_latencies, total_take_indeterminate) =
                collect_task_results(take_tasks).await?;
            let take_wall = take_start.elapsed();
            let workload_end = Instant::now();

            let insert_summary = LatencySummary::calculate_with_failures(
                "saturated_insert_triple",
                &mut all_insert_latencies,
                insert_wall,
                total_insert_failures,
            );
            let peek_summary = LatencySummary::calculate_with_outcomes(
                "saturated_peek_mine",
                &mut all_peek_latencies,
                peek_wall,
                0,
                total_peek_indeterminate,
            );
            let take_summary = LatencySummary::calculate_with_outcomes(
                "saturated_take_triple",
                &mut all_take_latencies,
                take_wall,
                0,
                total_take_indeterminate,
            );

            Ok::<_, anyhow::Error>((
                vec![insert_summary, peek_summary, take_summary],
                insert_start,
                workload_end,
            ))
        }
        .await;

        spike_stop.store(true, Ordering::Relaxed);
        poller.stop().await;
        let spikes = match spike_handle {
            Some(handle) => Some(handle.await.context("blocking spike task failed")?),
            None => None,
        };
        let (summaries, workload_start, workload_end) = workload?;
        if let Some(spikes) = spikes {
            let intervals = spikes?;
            let overlapping = intervals
                .iter()
                .filter(|interval| overlaps(**interval, (workload_start, workload_end)))
                .count();
            anyhow::ensure!(overlapping > 0, "no DEBUG SLEEP spike overlapped the workload; increase the workload size or disable spikes with --spike-ms 0");
            println!("   -> DEBUG SLEEP: {overlapping} spike(s) overlapped the workload ({} completed total)", intervals.len());
        }
        Ok(summaries)
    }

    /// SCENARIO 6: Mass Epoch Resharing `clear()` Storm.
    /// Simulates network-wide resharing where all nodes simultaneously wipe both triples
    /// and presignatures via `clear()`.
    /// Directly measures execution time of the HKEYS + multi-DEL Lua script, Redis slowlog,
    /// and keyspace drop.
    pub async fn bench_clear_storm(
        &self,
        stockpile_per_participant: usize,
        rounds: usize,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;

        if self.participants.is_empty() || stockpile_per_participant == 0 || rounds == 0 {
            return Ok(vec![
                LatencySummary::empty("clear_triples_storm"),
                LatencySummary::empty("clear_presigs_storm"),
            ]);
        }

        let num_p = self.participants.len();
        let total_items = num_p * stockpile_per_participant;
        let mut all_triple_latencies = Vec::with_capacity(num_p * rounds);
        let mut all_presig_latencies = Vec::with_capacity(num_p * rounds);
        let mut triple_fails = 0;
        let mut presig_fails = 0;
        let mut total_triple_wall = Duration::ZERO;
        let mut total_presig_wall = Duration::ZERO;

        println!(
            "   -> Running {rounds} rounds of mass clear storm across {num_p} participants ({stockpile_per_participant} triples + presignatures/participant/round)..."
        );

        for _ in 0..rounds {
            let triples_base = next_id_block(total_items as u64 + 10_000);
            let presigs_base = next_id_block(total_items as u64 + 10_000);

            self.populate_all_triples(triples_base, stockpile_per_participant)
                .await?;
            self.populate_all_presignatures(presigs_base, stockpile_per_participant)
                .await?;

            let gate = StartingGate::new(num_p * 2);

            let spawn_clear_tasks = |kind: ArtifactKind| {
                self.participants
                    .iter()
                    .map(|p| tokio::spawn(p.clone().clear_measured(kind, gate.barrier())))
                    .collect::<Vec<_>>()
            };

            let triple_tasks = spawn_clear_tasks(ArtifactKind::Triples);
            let presig_tasks = spawn_clear_tasks(ArtifactKind::Presignatures);

            let clear_start = gate.start().await;

            let collect_clear = |tasks: Vec<tokio::task::JoinHandle<(Duration, bool)>>| async move {
                let mut latencies = Vec::with_capacity(num_p);
                let mut fails = 0;
                for t in tasks {
                    let (elapsed, ok) = t.await?;
                    if ok {
                        latencies.push(elapsed);
                    } else {
                        fails += 1;
                    }
                }
                Ok::<_, anyhow::Error>((latencies, fails, clear_start.elapsed()))
            };

            let (
                (round_triple_lats, round_triple_fails, round_triple_wall),
                (round_presig_lats, round_presig_fails, round_presig_wall),
            ) = tokio::try_join!(collect_clear(triple_tasks), collect_clear(presig_tasks),)?;

            all_triple_latencies.extend(round_triple_lats);
            all_presig_latencies.extend(round_presig_lats);
            triple_fails += round_triple_fails;
            presig_fails += round_presig_fails;
            total_triple_wall += round_triple_wall;
            total_presig_wall += round_presig_wall;
        }

        let post_mem = self.client.fetch_memory_snapshot().await?;
        println!(
            "   -> Post-clear keyspace: {} keys remaining in Redis, Memory: {}",
            post_mem.total_keys, post_mem.used_memory_human
        );

        let s1 = LatencySummary::calculate_with_failures(
            "clear_triples_storm",
            &mut all_triple_latencies,
            total_triple_wall,
            triple_fails,
        );
        let s2 = LatencySummary::calculate_with_failures(
            "clear_presigs_storm",
            &mut all_presig_latencies,
            total_presig_wall,
            presig_fails,
        );
        Ok(vec![s1, s2])
    }

    /// SCENARIO 7: Concurrent triple generation, presignature generation, and signing.
    /// Each node shares its own pool across these operations and stock-count refreshes.
    /// Signing excludes newly generated local-only shares because deliberators
    /// hold pre-stocked shares (with t-1 deliberators per signing proposer).
    pub async fn bench_mixed_pipeline(
        &self,
        items_per_participant: usize,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;
        const NAMES: [&str; 7] = [
            "mixed_insert_triple",
            "mixed_presig_peek_triple",
            "mixed_presig_commit_triple",
            "mixed_insert_presig",
            "mixed_sign_peek_presig",
            "mixed_sign_commit_presig",
            "mixed_sign_take_presig",
        ];
        let num_p = self.participants.len();
        if num_p == 0 || items_per_participant == 0 {
            return Ok(NAMES.into_iter().map(LatencySummary::empty).collect());
        }

        let total_items = num_p * items_per_participant;
        let triple_base = next_id_block(total_items as u64 + 10_000);
        let presig_base = next_id_block(total_items as u64 + 10_000);
        let gen_base = next_id_block((total_items * 2) as u64 + 10_000);
        self.populate_all_triples(triple_base, items_per_participant)
            .await?;
        let participant_list = self.participant_ids();

        let threshold = mpc_contract::utils::compute_threshold(num_p);
        let num_deliberators = threshold.saturating_sub(1).min(num_p.saturating_sub(1));
        let proposers: Vec<usize> = (0..num_p).filter(|idx| idx % 2 == 0).collect();

        let mut pop_tasks = Vec::new();
        for &p_idx in &proposers {
            let owner = self.participants[p_idx].participant;
            let base = presig_base + (p_idx * items_per_participant) as u64;
            pop_tasks.push(self.participants[p_idx].clone().populate_owned_by(
                ArtifactKind::Presignatures,
                base,
                items_per_participant,
                participant_list.clone(),
                owner,
            ));
            for k in 1..=num_deliberators {
                let d_idx = (p_idx + k) % num_p;
                pop_tasks.push(self.participants[d_idx].clone().populate_owned_by(
                    ArtifactKind::Presignatures,
                    base,
                    items_per_participant,
                    participant_list.clone(),
                    owner,
                ));
            }
        }
        futures::future::try_join_all(pop_tasks).await?;

        let poller = self.spawn_background_polling(true);
        let gate = StartingGate::new(num_p * 2 + proposers.len() + num_p);
        let mut triple_tasks = Vec::new();
        let mut presig_tasks = Vec::new();
        let mut sign_tasks = Vec::new();

        let mut senders = Vec::with_capacity(num_p);
        let mut receivers = Vec::with_capacity(num_p);
        for _ in 0..num_p {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            senders.push(tx);
            receivers.push(rx);
        }

        for (idx, p) in self.participants.iter().enumerate() {
            let base = gen_base + (idx * items_per_participant * 2) as u64;
            triple_tasks.push(tokio::spawn(p.clone().insert_measured(
                ArtifactKind::Triples,
                base,
                items_per_participant,
                participant_list.clone(),
                gate.barrier(),
            )));
            presig_tasks.push(tokio::spawn(p.clone().generate_presignatures_measured(
                gate.barrier(),
                base + items_per_participant as u64,
                items_per_participant,
                participant_list.clone(),
            )));
        }

        for &p_idx in &proposers {
            let p = self.participants[p_idx].clone();
            let barrier = gate.barrier();
            let base = gen_base + (p_idx * items_per_participant * 2) as u64;
            // Newly generated shares are local to this simulated node; only
            // pre-stocked shares have matching copies at the deliberators.
            let excluded: Vec<_> = (0..items_per_participant)
                .map(|i| base + items_per_participant as u64 + i as u64)
                .collect();
            let mut proposer_deliberators = Vec::with_capacity(num_deliberators);
            for k in 1..=num_deliberators {
                let d_idx = (p_idx + k) % num_p;
                proposer_deliberators.push(senders[d_idx].clone());
            }
            sign_tasks.push(tokio::spawn(async move {
                let [peek, commit] = p
                    .sign_measured(
                        barrier,
                        items_per_participant,
                        excluded,
                        proposer_deliberators,
                    )
                    .await;
                [peek, commit, MeasuredOp::default()]
            }));
        }
        drop(senders);

        for (p, rx) in self.participants.iter().zip(receivers) {
            let p = p.clone();
            let barrier = gate.barrier();
            sign_tasks.push(tokio::spawn(async move {
                let take = p.sign_deliberator_measured(barrier, rx).await;
                [MeasuredOp::default(), MeasuredOp::default(), take]
            }));
        }

        let start = gate.start().await;
        let mut metrics: [MeasuredOp; 7] = Default::default();
        for task in triple_tasks {
            let (latencies, failures) = task.await?;
            metrics[0].latencies.extend(latencies);
            metrics[0].failures += failures;
        }
        for task in presig_tasks {
            for (target, result) in metrics[1..4].iter_mut().zip(task.await?) {
                target.merge(result);
            }
        }
        for task in sign_tasks {
            for (target, result) in metrics[4..7].iter_mut().zip(task.await?) {
                target.merge(result);
            }
        }
        let wall = start.elapsed();
        poller.stop().await;
        Ok(NAMES
            .into_iter()
            .zip(metrics)
            .map(|(name, metric)| summarize(name, metric, wall))
            .collect())
    }

    /// SCENARIO 8: State Sync Peer Drop & Pruning (`remove_holder_and_prune`).
    /// Simulates a peer drop or desync during state sync (as seen in `sync/mod.rs`),
    /// where surviving participants batch-prune missing IDs through the Lua script.
    pub async fn bench_sync_prune_storm(
        &self,
        items_per_participant: usize,
        rounds: usize,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;

        if self.participants.is_empty() || items_per_participant == 0 || rounds == 0 {
            return Ok(vec![
                LatencySummary::empty("sync_update_triples"),
                LatencySummary::empty("sync_update_presigs"),
                LatencySummary::empty("sync_prune_triples"),
                LatencySummary::empty("sync_prune_presigs"),
            ]);
        }

        let num_p = self.participants.len();
        let total_items = num_p * items_per_participant;
        let participant_list = self.participant_ids();
        let target_peer = participant_list[0];
        let second_peer = participant_list[1 % num_p];
        let threshold_update = (num_p / 2).min(num_p.saturating_sub(1));
        let threshold_prune = num_p;

        let mut all_update_triple_latencies = Vec::with_capacity(num_p * rounds);
        let mut all_update_presig_latencies = Vec::with_capacity(num_p * rounds);
        let mut all_prune_triple_latencies = Vec::with_capacity(num_p * rounds);
        let mut all_prune_presig_latencies = Vec::with_capacity(num_p * rounds);
        let mut update_triple_fails = 0;
        let mut update_presig_fails = 0;
        let mut prune_triple_fails = 0;
        let mut prune_presig_fails = 0;
        let mut total_update_wall = Duration::ZERO;
        let mut total_prune_wall = Duration::ZERO;

        println!(
            "   -> Running {rounds} rounds of state sync peer drop & prune storm across {num_p} participants ({items_per_participant} items/participant/round)..."
        );

        for _ in 0..rounds {
            let triples_base = next_id_block(total_items as u64 + 10_000);
            let presigs_base = next_id_block(total_items as u64 + 10_000);

            let triple_ids_by_p = self
                .populate_all_triples(triples_base, items_per_participant)
                .await?;
            let presig_ids_by_p = self
                .populate_all_presignatures(presigs_base, items_per_participant)
                .await?;

            // Phase 1: Holder update without prune (count >= threshold, standard sync update path)
            let update_gate = StartingGate::new(num_p);
            let update_tasks: Vec<_> = self
                .participants
                .iter()
                .enumerate()
                .map(|(node_idx, p)| {
                    let my_triple_ids = triple_ids_by_p.get(node_idx).cloned().unwrap_or_default();
                    let my_presig_ids = presig_ids_by_p.get(node_idx).cloned().unwrap_or_default();
                    tokio::spawn(p.clone().prune_artifacts(
                        update_gate.barrier(),
                        target_peer,
                        threshold_update,
                        my_triple_ids,
                        my_presig_ids,
                    ))
                })
                .collect();

            let update_start = update_gate.start().await;
            let mut round_updated_triples = 0;
            let mut round_updated_presigs = 0;
            let mut round_update_triple_errors = 0;
            let mut round_update_presig_errors = 0;

            for t in update_tasks {
                let (t_lat, t_res, p_lat, p_res) = t.await?;
                match t_res {
                    Ok((_, t_upd)) => {
                        round_updated_triples += t_upd.len();
                        if t_upd.len() == items_per_participant {
                            all_update_triple_latencies.push(t_lat);
                        } else {
                            update_triple_fails += 1;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to update holder triples in S8: {e:#}");
                        update_triple_fails += 1;
                        round_update_triple_errors += 1;
                    }
                }
                match p_res {
                    Ok((_, p_upd)) => {
                        round_updated_presigs += p_upd.len();
                        if p_upd.len() == items_per_participant {
                            all_update_presig_latencies.push(p_lat);
                        } else {
                            update_presig_fails += 1;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to update holder presignatures in S8: {e:#}");
                        update_presig_fails += 1;
                        round_update_presig_errors += 1;
                    }
                }
            }
            total_update_wall += update_start.elapsed();

            if round_update_triple_errors == 0 && round_updated_triples != total_items {
                tracing::warn!(
                    "Incomplete triple holder update in S8 round: expected {total_items}, updated {round_updated_triples}"
                );
            }
            if round_update_presig_errors == 0 && round_updated_presigs != total_items {
                tracing::warn!(
                    "Incomplete presignature holder update in S8 round: expected {total_items}, updated {round_updated_presigs}"
                );
            }

            // Phase 2: Below-threshold prune (count < threshold, items removed from Redis)
            let prune_gate = StartingGate::new(num_p);
            let prune_tasks: Vec<_> = self
                .participants
                .iter()
                .enumerate()
                .map(|(node_idx, p)| {
                    let my_triple_ids = triple_ids_by_p.get(node_idx).cloned().unwrap_or_default();
                    let my_presig_ids = presig_ids_by_p.get(node_idx).cloned().unwrap_or_default();
                    tokio::spawn(p.clone().prune_artifacts(
                        prune_gate.barrier(),
                        second_peer,
                        threshold_prune,
                        my_triple_ids,
                        my_presig_ids,
                    ))
                })
                .collect();

            let prune_start = prune_gate.start().await;
            let mut round_pruned_triples = 0;
            let mut round_pruned_presigs = 0;
            let mut round_prune_triple_errors = 0;
            let mut round_prune_presig_errors = 0;

            for t in prune_tasks {
                let (t_lat, t_res, p_lat, p_res) = t.await?;
                match t_res {
                    Ok((t_rem, _)) => {
                        round_pruned_triples += t_rem.len();
                        if t_rem.len() == items_per_participant {
                            all_prune_triple_latencies.push(t_lat);
                        } else {
                            prune_triple_fails += 1;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to prune triples in S8: {e:#}");
                        prune_triple_fails += 1;
                        round_prune_triple_errors += 1;
                    }
                }
                match p_res {
                    Ok((p_rem, _)) => {
                        round_pruned_presigs += p_rem.len();
                        if p_rem.len() == items_per_participant {
                            all_prune_presig_latencies.push(p_lat);
                        } else {
                            prune_presig_fails += 1;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to prune presignatures in S8: {e:#}");
                        prune_presig_fails += 1;
                        round_prune_presig_errors += 1;
                    }
                }
            }
            total_prune_wall += prune_start.elapsed();

            if round_prune_triple_errors == 0 && round_pruned_triples != total_items {
                tracing::warn!(
                    "Incomplete triple prune in S8 round: expected {total_items}, pruned {round_pruned_triples}"
                );
            }
            if round_prune_presig_errors == 0 && round_pruned_presigs != total_items {
                tracing::warn!(
                    "Incomplete presignature prune in S8 round: expected {total_items}, pruned {round_pruned_presigs}"
                );
            }
        }

        let s1 = LatencySummary::calculate_with_failures(
            "sync_update_triples",
            &mut all_update_triple_latencies,
            total_update_wall,
            update_triple_fails,
        );
        let s2 = LatencySummary::calculate_with_failures(
            "sync_update_presigs",
            &mut all_update_presig_latencies,
            total_update_wall,
            update_presig_fails,
        );
        let s3 = LatencySummary::calculate_with_failures(
            "sync_prune_triples",
            &mut all_prune_triple_latencies,
            total_prune_wall,
            prune_triple_fails,
        );
        let s4 = LatencySummary::calculate_with_failures(
            "sync_prune_presigs",
            &mut all_prune_presig_latencies,
            total_prune_wall,
            prune_presig_fails,
        );
        Ok(vec![s1, s2, s3, s4])
    }

    /// SCENARIO 9: Connection Drop & Reconnection Shock (`CLIENT KILL`).
    /// Simulates cloud network blips, pod restarts, or proxy TCP resets (as seen in devnet/testnet
    /// with ConnectionResetByPeer / Timeout(Create)).
    /// While participants are actively performing inserts and takes, background task triggers
    /// `CLIENT KILL TYPE normal SKIPME yes` to sever all client connections.
    /// Measures how many operations fail or recover, and the resulting latency tail.
    pub async fn bench_client_kill(
        &self,
        items_per_participant: usize,
        kill_delay_ms: u64,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;

        if self.participants.is_empty() || items_per_participant == 0 {
            return Ok(vec![
                LatencySummary::empty("insert_under_client_kill"),
                LatencySummary::empty("take_under_client_kill"),
                LatencySummary::empty("take_post_reconnect"),
            ]);
        }

        let num_p = self.participants.len();
        let run_base_id = next_id_block((num_p * items_per_participant) as u64 + 10_000);
        let gate = StartingGate::new(num_p + 1);
        let participant_list = self.participant_ids();

        println!(
            "   -> Launching {num_p} participant workers ({items_per_participant} items each) with mid-flight CLIENT KILL shock at +{kill_delay_ms}ms...",
        );

        // 1. Killer task that severs all client connections using client helper
        let killer_task = self
            .client
            .spawn_client_killer(gate.barrier(), kill_delay_ms);

        // 2. Active participant tasks (Phase A: mid-insert CLIENT KILL)
        let worker_tasks: Vec<_> = self
            .participants
            .iter()
            .enumerate()
            .map(|(node_idx, p)| {
                let base_id = run_base_id + (node_idx as u64 * items_per_participant as u64);
                tokio::spawn(p.clone().insert_triples_tracked(
                    base_id,
                    items_per_participant,
                    participant_list.clone(),
                    gate.barrier(),
                ))
            })
            .collect();

        let overall_start = gate.start().await;
        let killed_connections = killer_task.await?;

        let mut all_insert_latencies = Vec::with_capacity(num_p * items_per_participant);
        let mut all_success_ids = Vec::with_capacity(num_p);
        let mut total_insert_failures = 0;

        for (node_idx, t) in worker_tasks.into_iter().enumerate() {
            let (lats, s_ids, f) = t.await?;
            all_insert_latencies.extend(lats);
            all_success_ids.push((node_idx, s_ids));
            total_insert_failures += f;
        }
        let insert_wall = overall_start.elapsed();

        let total_inserts = num_p * items_per_participant;
        let total_success_inserts: usize = all_success_ids.iter().map(|(_, ids)| ids.len()).sum();

        println!(
            "   -> Insert outcome: {}/{} successful, {} failed/aborted (Severed {} connections)",
            total_success_inserts, total_inserts, total_insert_failures, killed_connections
        );

        // 3. Phase B: Mid-take CLIENT KILL shock (killing connections mid-take)
        let num_take_workers = all_success_ids.len();
        let take_gate = StartingGate::new(num_take_workers + 1);
        let take_killer_task = self
            .client
            .spawn_client_killer(take_gate.barrier(), kill_delay_ms);

        let mut kill_take_tasks = Vec::with_capacity(num_take_workers);
        let mut post_take_batches = Vec::with_capacity(num_take_workers);

        for (node_idx, ids) in all_success_ids {
            let p = self.participants[node_idx].clone();
            let mid = ids.len() / 2;
            let (first_half, second_half) = ids.split_at(mid);
            kill_take_tasks.push(tokio::spawn(
                p.clone()
                    .take_triples(first_half.to_vec(), take_gate.optional_barrier()),
            ));
            post_take_batches.push((p, second_half.to_vec()));
        }

        let take_kill_start = take_gate.start().await;
        let _ = take_killer_task.await?;
        let (mut all_kill_take_latencies, total_kill_take_indeterminate) =
            collect_task_results(kill_take_tasks).await?;
        let take_kill_wall = take_kill_start.elapsed();

        // 4. Phase C: Post-kill verification: take remaining items to measure pool recovery
        let post_take_start = Instant::now();
        let mut post_take_tasks = Vec::with_capacity(num_p);
        for (p, ids) in post_take_batches {
            post_take_tasks.push(tokio::spawn(p.take_triples(ids, None)));
        }

        let (mut all_post_take_latencies, total_post_take_indeterminate) =
            collect_task_results(post_take_tasks).await?;
        let post_take_wall = post_take_start.elapsed();

        let s1 = LatencySummary::calculate_with_failures(
            "insert_under_client_kill",
            &mut all_insert_latencies,
            insert_wall,
            total_insert_failures,
        );
        let s2 = LatencySummary::calculate_with_outcomes(
            "take_under_client_kill",
            &mut all_kill_take_latencies,
            take_kill_wall,
            0,
            total_kill_take_indeterminate,
        );
        let s3 = LatencySummary::calculate_with_outcomes(
            "take_post_reconnect",
            &mut all_post_take_latencies,
            post_take_wall,
            0,
            total_post_take_indeterminate,
        );
        Ok(vec![s1, s2, s3])
    }

    /// SCENARIO 10: Large Stockpile Deep-Seek (`peek_mine` with large exclusion sets).
    /// Pre-populates a large stockpile (e.g. 2,000–10,000 items) and tests `peek_mine`
    /// when nodes pass large exclusion lists accumulated from repeated round reorgs.
    /// Reproduces the single-threaded Lua O(N) iteration spike that causes 50ms - 6s tail latency.
    pub async fn bench_deep_stockpile_seek(
        &self,
        stockpile_size: usize,
        num_seekers: usize,
        exclusions_count: usize,
        seeks_per_worker: usize,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;

        if self.participants.is_empty() || stockpile_size == 0 || num_seekers == 0 {
            return Ok(vec![
                LatencySummary::empty("deep_peek_mine"),
                LatencySummary::empty("deep_commit"),
            ]);
        }

        let p = &self.participants[0];
        let base_id = next_id_block(stockpile_size as u64 + 10_000);

        println!(
            "   -> Pre-populating large stockpile of {stockpile_size} items on participant 0..."
        );
        self.populate(ArtifactKind::Triples, 0, base_id, stockpile_size)
            .await?;

        let coverage = (exclusions_count as f64 / stockpile_size as f64) * 100.0;
        println!(
            "   -> Launching {num_seekers} concurrent seekers across {stockpile_size} items with {exclusions_count} exclusions ({coverage:.1}% coverage - near-exhaustion tail)..."
        );
        let gate = StartingGate::new(num_seekers);

        let tasks: Vec<_> = (0..num_seekers)
            .map(|_| {
                let seeker = p.clone();
                tokio::spawn(seeker.seek_deep_stockpile(
                    gate.barrier(),
                    base_id,
                    seeks_per_worker,
                    exclusions_count,
                ))
            })
            .collect();

        let overall_start = gate.start().await;

        let mut metrics: [MeasuredOp; 2] = Default::default();
        for task in tasks {
            for (total, result) in metrics.iter_mut().zip(task.await?) {
                total.merge(result);
            }
        }
        let wall = overall_start.elapsed();
        let [peek, commit] = metrics;
        Ok(vec![
            summarize("deep_peek_mine", peek, wall),
            summarize("deep_commit", commit, wall),
        ])
    }

    /// Measure signing proposer operations against a large owned presignature stockpile.
    pub async fn bench_presignature_stockpile(
        &self,
        stockpile_size: usize,
        num_seekers: usize,
        seeks_per_worker: usize,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;
        if self.participants.is_empty()
            || stockpile_size == 0
            || num_seekers == 0
            || seeks_per_worker == 0
        {
            return Ok(vec![
                LatencySummary::empty("presig_stockpile_peek"),
                LatencySummary::empty("presig_stockpile_commit"),
            ]);
        }
        let base_id = next_id_block(stockpile_size as u64 + 10_000);
        self.populate(ArtifactKind::Presignatures, 0, base_id, stockpile_size)
            .await?;
        let p = &self.participants[0];
        let gate = StartingGate::new(num_seekers);
        let tasks: Vec<_> = (0..num_seekers)
            .map(|_| {
                tokio::spawn(
                    p.clone()
                        .seek_presignatures(gate.barrier(), seeks_per_worker),
                )
            })
            .collect();
        let start = gate.start().await;
        let mut metrics: [MeasuredOp; 2] = Default::default();
        for task in tasks {
            for (total, result) in metrics.iter_mut().zip(task.await?) {
                total.merge(result);
            }
        }
        let wall = start.elapsed();
        let [peek, commit] = metrics;
        Ok(vec![
            summarize("presig_stockpile_peek", peek, wall),
            summarize("presig_stockpile_commit", commit, wall),
        ])
    }

    /// SCENARIO 11: Proposer Churn & Aborted Reservation Storm.
    /// Simulates deliberation timeouts and reject reorgs seen in production logs:
    /// proposers peek presignatures, hold them for simulated deliberation, and a portion
    /// aborts/drops without commit, while concurrent proposers race to re-peek and commit.
    pub async fn bench_reservation_churn_abort(
        &self,
        initial_stockpile: usize,
        num_proposers: usize,
        rounds_per_proposer: usize,
        abort_percent: u8,
        deliberation_delay_ms: u64,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;

        if self.participants.is_empty() || initial_stockpile == 0 || num_proposers == 0 {
            return Ok(vec![
                LatencySummary::empty("churn_peek_mine"),
                LatencySummary::empty("churn_commit"),
            ]);
        }

        let p = &self.participants[0];
        let base_id = next_id_block(initial_stockpile as u64 + 10_000);

        println!("   -> Pre-stockpiling {initial_stockpile} presignatures on participant 0...");
        self.populate(ArtifactKind::Presignatures, 0, base_id, initial_stockpile)
            .await?;

        println!(
            "   -> Simulating {num_proposers} proposers with {abort_percent}% deliberation timeout/abort rate across {rounds_per_proposer} rounds (deliberation hold: {deliberation_delay_ms}ms)..."
        );
        let gate = StartingGate::new(num_proposers);
        let state = Arc::new(ChurnState::default());

        let tasks: Vec<_> = (0..num_proposers)
            .map(|proposer_id| {
                let proposer = p.clone();
                tokio_util::task::AbortOnDropHandle::new(tokio::spawn(proposer.run_proposer_churn(
                    gate.barrier(),
                    proposer_id,
                    rounds_per_proposer,
                    abort_percent,
                    deliberation_delay_ms,
                    state.clone(),
                )))
            })
            .collect();

        let overall_start = gate.start().await;

        let mut metrics: [MeasuredOp; 2] = Default::default();
        let mut total_deliberations = 0;
        let mut total_aborts = 0;
        for task in tasks {
            let (results, deliberation, aborted) = task.await?;
            for (total, result) in metrics.iter_mut().zip(results) {
                total.merge(result);
            }
            total_deliberations += deliberation;
            total_aborts += aborted;
        }
        let wall = overall_start.elapsed();
        println!(
            "   -> Churn outcome: {} committed, {} indeterminate commits, {total_aborts} dropped on timeout/reject",
            metrics[1].latencies.len(), metrics[1].indeterminate,
        );
        println!(
            "   -> Peak pending reservations: {}; simulated deliberations: {} (target {deliberation_delay_ms}ms)",
            state.peak_pending.load(Ordering::Relaxed), total_deliberations,
        );
        let [peek, commit] = metrics;
        Ok(vec![
            summarize("churn_peek_mine", peek, wall),
            summarize("churn_commit", commit, wall),
        ])
    }

    /// SCENARIO 12: Conflicted Double-Take Race Storm.
    /// Uses independent handles for the same node's keys to exercise concurrent
    /// attempts to take the same artifact IDs. This is a synthetic stress test.
    pub async fn bench_conflicted_take(
        &self,
        num_items: usize,
        contenders_per_item: usize,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;

        if self.participants.is_empty() || num_items == 0 || contenders_per_item == 0 {
            return Ok(vec![LatencySummary::empty("take_contended")]);
        }

        let owner = &self.participants[0];
        let owner_participant = owner.participant;
        let base_id = next_id_block(num_items as u64 + 10_000);

        println!("   -> Pre-populating {num_items} items on owner participant...");
        let target_ids = self
            .populate(ArtifactKind::Triples, 0, base_id, num_items)
            .await?;

        println!(
            "   -> Launching {contenders_per_item} parallel tasks racing to take each item (reproducing 'not owned by this owner' Lua errors)..."
        );
        let gate = StartingGate::new(contenders_per_item);

        let tasks: Vec<_> = (0..contenders_per_item)
            .map(|contender_idx| {
                // Independent handles intentionally force a synthetic same-key take race.
                let contender = Participant::from(contender_idx as u32);
                let p_contender =
                    SimulatedParticipant::new(&owner.pool, &owner.account_id, contender);
                let ids = target_ids.clone();
                tokio::spawn(p_contender.race_take_conflicted(
                    gate.barrier(),
                    ids,
                    owner_participant,
                ))
            })
            .collect();

        let overall_start = gate.start().await;

        let mut total = MeasuredOp::default();
        for task in tasks {
            total.merge(task.await?);
        }
        let wall = overall_start.elapsed();
        println!(
            "   -> Take outcomes: {} successful, {} indeterminate (unavailable or storage error)",
            total.latencies.len(),
            total.indeterminate,
        );
        Ok(vec![summarize("take_contended", total, wall)])
    }

    /// SCENARIO 13: Large-Batch & ARGV Outdated Pruning (>4,096 items Lua unpack limit stress).
    /// Pre-populates a large stockpile (>4,096 items) and exercises `remove_outdated`:
    /// 1. `large_argv_sync`: Passes >4,096 IDs in ARGV to stress Lua argument table conversion and existence checks.
    /// 2. `large_outdated_prune`: Prunes >4,096 items to stress Redis Lua's 4,096-item batch unpack (`unpack(outdated)`) and tail cleanup.
    pub async fn bench_large_batch_prune(
        &self,
        batch_size: usize,
        rounds: usize,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;

        if self.participants.is_empty() || batch_size == 0 || rounds == 0 {
            return Ok(vec![
                LatencySummary::empty("large_argv_sync"),
                LatencySummary::empty("large_outdated_prune"),
            ]);
        }

        anyhow::ensure!(
            batch_size > 4096,
            "Scenario 13 batch_size must be > 4096 to stress Lua unpack limits, got {batch_size}"
        );

        let active_nodes = self.participants.len().min(2);
        let keep_count = (batch_size / 25).max(10);
        let prune_target = batch_size - keep_count;

        println!(
            "   -> Testing {rounds} rounds of large batch pruning across {active_nodes} participants ({batch_size} items/participant, {prune_target} pruned > 4,096 unpack threshold)..."
        );

        let mut all_argv_latencies = Vec::with_capacity(rounds * active_nodes);
        let mut all_prune_latencies = Vec::with_capacity(rounds * active_nodes);
        let mut argv_failures = 0;
        let mut prune_failures = 0;
        let mut total_argv_wall = Duration::ZERO;
        let mut total_prune_wall = Duration::ZERO;

        for _ in 0..rounds {
            for node_idx in 0..active_nodes {
                let p = &self.participants[node_idx];
                let _ = p.triples.clear().await;

                let base_id = next_id_block(batch_size as u64 + 1000);
                let all_ids = self
                    .populate(ArtifactKind::Triples, node_idx, base_id, batch_size)
                    .await?;

                // Phase 1: Large ARGV sync (passing all >4,096 IDs in ARGV; 0 outdated)
                let t_argv_start = Instant::now();
                let argv_res = p.triples.remove_outdated(p.participant, &all_ids).await;
                let argv_lat = t_argv_start.elapsed();
                total_argv_wall += argv_lat;

                match argv_res {
                    Ok(res) => {
                        all_argv_latencies.push(argv_lat);
                        if !res.not_found.is_empty() {
                            tracing::warn!(
                                "Unexpected not_found items in large ARGV sync: {}",
                                res.not_found.len()
                            );
                            argv_failures += 1;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed large ARGV sync: {e:#}");
                        argv_failures += 1;
                    }
                }

                // Phase 2: Large outdated prune (keeping only keep_count; pruning >4,096 items to hit Lua unpack)
                let remaining_ids = &all_ids[..keep_count];
                let t_prune_start = Instant::now();
                let prune_res = p
                    .triples
                    .remove_outdated(p.participant, remaining_ids)
                    .await;
                let prune_lat = t_prune_start.elapsed();
                total_prune_wall += prune_lat;

                match prune_res {
                    Ok(_) => {
                        all_prune_latencies.push(prune_lat);
                        let remaining_in_redis = p.triples.len_by_owner(p.participant).await;
                        if remaining_in_redis != keep_count {
                            tracing::warn!(
                                "Incomplete large prune: expected {keep_count} remaining, found {remaining_in_redis}"
                            );
                            prune_failures += 1;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed large outdated prune: {e:#}");
                        prune_failures += 1;
                    }
                }

                // Untimed cleanup
                let _ = p.triples.clear().await;
            }
        }

        let s1 = LatencySummary::calculate_with_failures(
            "large_argv_sync",
            &mut all_argv_latencies,
            total_argv_wall,
            argv_failures,
        );
        let s2 = LatencySummary::calculate_with_failures(
            "large_outdated_prune",
            &mut all_prune_latencies,
            total_prune_wall,
            prune_failures,
        );

        Ok(vec![s1, s2])
    }

    /// SCENARIO 14: Real AOF & BGSAVE Disk Persistence Stalls vs In-Memory Execution.
    /// Evaluates filesystem write overhead and background snapshot fork stalls:
    /// 1. `in_memory_insert`: Pure RAM baseline insert latency (`appendonly no`).
    /// 2. `aof_fsync_insert`: Real disk-persisted insert with `appendonly yes` and `appendfsync always`.
    /// 3. `bgsave_concurrent_take`: Concurrent takes running while `BGSAVE` background snapshot flushes to disk.
    pub async fn bench_disk_persistence_stall(
        &self,
        items_per_participant: usize,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;

        if self.participants.is_empty() || items_per_participant == 0 {
            return Ok(vec![
                LatencySummary::empty("in_memory_insert"),
                LatencySummary::empty("aof_fsync_insert"),
                LatencySummary::empty("bgsave_concurrent_take"),
            ]);
        }

        let num_p = self.participants.len();
        let participant_list = self.participant_ids();

        println!(
            "   -> Running Scenario 14: AOF & BGSAVE Disk Persistence Stalls ({num_p} participants, {items_per_participant} items/participant)..."
        );

        // Phase 1: Pure in-memory insert baseline
        self.client.configure_persistence(false, "no").await?;
        let base_id_1 = next_id_block((num_p * items_per_participant) as u64 + 10_000);
        let gate_1 = StartingGate::new(num_p);

        let tasks_1: Vec<_> = self
            .participants
            .iter()
            .enumerate()
            .map(|(node_idx, p)| {
                let p_base = base_id_1 + (node_idx as u64 * items_per_participant as u64);
                tokio::spawn(p.clone().insert_measured(
                    ArtifactKind::Triples,
                    p_base,
                    items_per_participant,
                    participant_list.clone(),
                    gate_1.barrier(),
                ))
            })
            .collect();

        let t_start_1 = gate_1.start().await;
        let (mut mem_latencies, mem_fails) = collect_task_results(tasks_1).await?;
        let mem_wall = t_start_1.elapsed();

        // Phase 2: Real AOF fsync disk writes (appendonly yes, appendfsync always)
        self.client.configure_persistence(true, "always").await?;
        let base_id_2 = next_id_block((num_p * items_per_participant) as u64 + 10_000);
        let gate_2 = StartingGate::new(num_p);

        let tasks_2: Vec<_> = self
            .participants
            .iter()
            .enumerate()
            .map(|(node_idx, p)| {
                let p_base = base_id_2 + (node_idx as u64 * items_per_participant as u64);
                tokio::spawn(p.clone().insert_measured(
                    ArtifactKind::Triples,
                    p_base,
                    items_per_participant,
                    participant_list.clone(),
                    gate_2.barrier(),
                ))
            })
            .collect();

        let t_start_2 = gate_2.start().await;
        let (mut aof_latencies, aof_fails) = collect_task_results(tasks_2).await?;
        let aof_wall = t_start_2.elapsed();

        // Phase 3: BGSAVE snapshot fork under concurrent takes
        self.client.trigger_bgsave().await?;
        let gate_3 = StartingGate::new(num_p);

        let tasks_3: Vec<_> = self
            .participants
            .iter()
            .enumerate()
            .map(|(node_idx, p)| {
                let p_base = base_id_2 + (node_idx as u64 * items_per_participant as u64);
                let ids: Vec<u64> = (p_base..p_base + items_per_participant as u64).collect();
                tokio::spawn(p.clone().take_triples(ids, gate_3.optional_barrier()))
            })
            .collect();

        let t_start_3 = gate_3.start().await;
        let (mut bgsave_latencies, bgsave_indeterminate) = collect_task_results(tasks_3).await?;
        let bgsave_wall = t_start_3.elapsed();

        // Cleanup: disable AOF and reset keys
        self.client.configure_persistence(false, "no").await?;
        self.clear_triples().await;

        let s1 = LatencySummary::calculate_with_failures(
            "in_memory_insert",
            &mut mem_latencies,
            mem_wall,
            mem_fails,
        );
        let s2 = LatencySummary::calculate_with_failures(
            "aof_fsync_insert",
            &mut aof_latencies,
            aof_wall,
            aof_fails,
        );
        let s3 = LatencySummary::calculate_with_outcomes(
            "bgsave_concurrent_take",
            &mut bgsave_latencies,
            bgsave_wall,
            0,
            bgsave_indeterminate,
        );

        Ok(vec![s1, s2, s3])
    }
}

#[cfg(test)]
mod tests {
    use super::overlaps;
    use std::time::{Duration, Instant};

    #[test]
    fn spike_overlaps_even_when_it_ends_after_the_workload() {
        let start = Instant::now();
        let at = |ms| start + Duration::from_millis(ms);
        assert!(overlaps((at(5), at(30)), (at(10), at(20))));
        assert!(overlaps((at(15), at(30)), (at(10), at(20))));
        assert!(!overlaps((at(20), at(30)), (at(10), at(20))));
        assert!(!overlaps((at(0), at(10)), (at(10), at(20))));
    }
}
