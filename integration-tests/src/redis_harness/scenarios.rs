use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use cait_sith::protocol::Participant;
use mpc_node::storage::triple_storage::TriplePair;
use mpc_node::storage::TripleStorage;
use tokio::sync::Barrier;

use super::diagnostics::{partition_wall_3, partition_wall_by_active_time, LatencySummary};
use super::participant::{next_id_block, SimulatedParticipant, StockpileKind};
use super::RedisHarness;

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
        let barrier = Arc::new(Barrier::new(self.participants.len()));
        let overall_start = Instant::now();
        let participant_list = self.participant_ids();

        let insert_tasks: Vec<_> = self
            .participants
            .iter()
            .enumerate()
            .map(|(node_idx, p)| {
                let base_id = run_base_id + (node_idx as u64 * items_per_participant as u64);
                tokio::spawn(p.clone().insert_measured(
                    StockpileKind::Triples,
                    base_id,
                    items_per_participant,
                    participant_list.clone(),
                    barrier.clone(),
                ))
            })
            .collect();

        let (mut all_insert_latencies, insert_failures) =
            collect_task_results(insert_tasks).await?;
        let insert_wall = overall_start.elapsed();

        // Concurrent taking of the inserted items
        let barrier = Arc::new(Barrier::new(self.participants.len()));
        let take_start = Instant::now();

        let take_tasks: Vec<_> = self
            .participants
            .iter()
            .enumerate()
            .map(|(node_idx, p)| {
                let base_id = run_base_id + (node_idx as u64 * items_per_participant as u64);
                let ids: Vec<u64> = (base_id..base_id + items_per_participant as u64).collect();
                tokio::spawn(p.clone().take_triples(ids, Some(barrier.clone())))
            })
            .collect();

        let (mut all_take_latencies, take_failures) = collect_task_results(take_tasks).await?;
        let take_wall = take_start.elapsed();

        let s1 = LatencySummary::calculate_with_failures(
            "concurrent_insert_triple",
            &mut all_insert_latencies,
            insert_wall,
            insert_failures,
        );
        let s2 = LatencySummary::calculate_with_failures(
            "concurrent_take_triple",
            &mut all_take_latencies,
            take_wall,
            take_failures,
        );

        Ok(vec![s1, s2])
    }

    /// SCENARIO 2: Stockpile 100ms Background Polling Contention.
    /// Runs a write/read workload with vs. without 100ms background polling (HLEN / SCARD) across all participants.
    pub async fn bench_polling_contention(
        &self,
        workload_items: usize,
        enable_polling: bool,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;

        let poller = enable_polling.then(|| self.spawn_background_polling(false));
        let res = self.run_concurrent_insert_and_take(workload_items).await;
        if let Some(p) = poller {
            p.stop().await;
        }

        res
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
            self.reset_reservations().await;
            let run_base_id = next_id_block((num_p * stockpile_count) as u64 + 1000);
            let all_ids = self
                .populate_all_triples(run_base_id, stockpile_count)
                .await?;

            let barrier = Arc::new(Barrier::new(num_p));
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
                            .remove_outdated_shares(barrier.clone(), remaining_shares),
                    )
                })
                .collect();

            let storm_start = Instant::now();
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
                LatencySummary::empty("commit_winner_success"),
                LatencySummary::empty("commit_conflict_rejected"),
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
            StockpileKind::Triples,
            participant_idx,
            base_id,
            initial_stockpile,
        )
        .await?;

        let barrier = Arc::new(Barrier::new(num_racers));
        let race_start = Instant::now();

        let racer_tasks: Vec<_> = (0..num_racers)
            .map(|_| {
                // Each racer gets an independent storage handle with its own `reserved` RwLock,
                // matching production where distinct nodes do not share in-memory reservation maps.
                let racer = SimulatedParticipant::new(&self.client.pool, &p.account_id, p.participant);
                tokio::spawn(racer.race_proposals(
                    barrier.clone(),
                    base_id,
                    proposals_per_racer,
                ))
            })
            .collect();

        let mut all_peek = Vec::new();
        let mut all_commit_wins = Vec::new();
        let mut all_commit_losses = Vec::new();

        for task in racer_tasks {
            let (peek, wins, losses) = task.await?;
            all_peek.extend(peek);
            all_commit_wins.extend(wins);
            all_commit_losses.extend(losses);
        }
        let wall = race_start.elapsed();
        let (peek_wall, win_wall, loss_wall) =
            partition_wall_3(wall, &all_peek, &all_commit_wins, &all_commit_losses);

        let s1 = LatencySummary::calculate("peek_mine_contended", &mut all_peek, peek_wall);
        let s2 =
            LatencySummary::calculate("commit_winner_success", &mut all_commit_wins, win_wall);
        let s3 = LatencySummary::calculate(
            "commit_conflict_rejected",
            &mut all_commit_losses,
            loss_wall,
        );

        Ok(vec![s1, s2, s3])
    }

    /// SCENARIO 5: Production Cascading Saturation & Head-of-Line Blocking (reproducing 50ms - 6s latencies).
    /// Simulates production conditions:
    /// 1. 100ms background stockpile polling storms (continuous HLEN/SCARD).
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
        self.reset_diagnostics().await?;

        if self.participants.is_empty() || tasks_per_participant == 0 || items_per_task == 0 {
            return Ok(vec![
                LatencySummary::empty("saturated_insert_triple"),
                LatencySummary::empty("saturated_peek_mine"),
                LatencySummary::empty("saturated_take_triple"),
            ]);
        }

        let pool_status = self.client.status();
        println!(
            "   -> Connection pool status: max_size={} (active={}, available={}, waiting={})",
            pool_status.max_size, pool_status.size, pool_status.available, pool_status.waiting
        );

        // 1. Continuous 100ms polling across all participants
        let poller = self.spawn_background_polling(false);

        // 2. Intermittent blocking spikes on Redis main thread (simulating large Lua scripts or BGSAVE stalls)
        // Spans insert, peek, and take phases
        let spike_stop = Arc::new(AtomicBool::new(false));
        let spike_handle =
            self.client.spawn_intermittent_spike(spike_stop.clone(), blocking_spike_ms, num_spikes * 3);

        // 3. Phase A: High-concurrency inserts across participants under saturation
        let total_items = self.participants.len() * tasks_per_participant * items_per_task;
        let run_base_id = next_id_block(total_items as u64 + 10_000);
        let insert_barrier = Arc::new(Barrier::new(
            self.participants.len() * tasks_per_participant,
        ));
        let participant_list = self.participant_ids();

        let mut insert_tasks = Vec::with_capacity(self.participants.len() * tasks_per_participant);
        let mut task_id_ranges = Vec::with_capacity(self.participants.len() * tasks_per_participant);

        for (p_idx, p) in self.participants.iter().enumerate() {
            for t_idx in 0..tasks_per_participant {
                let task_id = p_idx * tasks_per_participant + t_idx;
                let base_id = run_base_id + (task_id as u64 * items_per_task as u64);
                let ids: Vec<u64> = (base_id..base_id + items_per_task as u64).collect();
                task_id_ranges.push((p.clone(), ids));
                insert_tasks.push(tokio::spawn(p.clone().insert_measured(
                    StockpileKind::Triples,
                    base_id,
                    items_per_task,
                    participant_list.clone(),
                    insert_barrier.clone(),
                )));
            }
        }

        let insert_start = Instant::now();
        let (mut all_insert_latencies, total_insert_failures) =
            collect_task_results(insert_tasks).await?;
        let insert_wall = insert_start.elapsed();

        // 4. Phase B: Concurrent peek_mine on available stockpile under saturation and blocking stalls
        let peek_barrier = Arc::new(Barrier::new(
            self.participants.len() * tasks_per_participant,
        ));
        let peek_items = items_per_task.min(25);
        let mut peek_tasks = Vec::with_capacity(self.participants.len() * tasks_per_participant);
        for p in &self.participants {
            for _ in 0..tasks_per_participant {
                peek_tasks.push(tokio::spawn(p.clone().peek_triples_measured(
                    peek_barrier.clone(),
                    peek_items,
                )));
            }
        }

        let peek_start = Instant::now();
        let (mut all_peek_latencies, total_peek_failures) =
            collect_task_results(peek_tasks).await?;
        let peek_wall = peek_start.elapsed();
        self.reset_reservations().await;

        // 5. Phase C: High-concurrency takes across participants under saturation
        let take_barrier = Arc::new(Barrier::new(
            self.participants.len() * tasks_per_participant,
        ));
        let mut take_tasks = Vec::with_capacity(self.participants.len() * tasks_per_participant);
        for (p, ids) in task_id_ranges {
            take_tasks.push(tokio::spawn(p.take_triples(
                ids,
                Some(take_barrier.clone()),
            )));
        }

        let take_start = Instant::now();
        let (mut all_take_latencies, total_take_failures) =
            collect_task_results(take_tasks).await?;
        let take_wall = take_start.elapsed();

        poller.stop().await;
        if let Some(h) = spike_handle {
            spike_stop.store(true, Ordering::Relaxed);
            let _ = h.await;
        }

        let insert_summary = LatencySummary::calculate_with_failures(
            "saturated_insert_triple",
            &mut all_insert_latencies,
            insert_wall,
            total_insert_failures,
        );
        let peek_summary = LatencySummary::calculate_with_failures(
            "saturated_peek_mine",
            &mut all_peek_latencies,
            peek_wall,
            total_peek_failures,
        );
        let take_summary = LatencySummary::calculate_with_failures(
            "saturated_take_triple",
            &mut all_take_latencies,
            take_wall,
            total_take_failures,
        );

        Ok(vec![insert_summary, peek_summary, take_summary])
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
            self.reset_reservations().await;
            let triples_base = next_id_block(total_items as u64 + 10_000);
            let presigs_base = next_id_block(total_items as u64 + 10_000);

            self.populate_all_triples(triples_base, stockpile_per_participant)
                .await?;
            self.populate_all_presignatures(presigs_base, stockpile_per_participant)
                .await?;

            let barrier = Arc::new(Barrier::new(num_p * 2));
            let clear_start = Instant::now();

            let spawn_clear_tasks = |kind: StockpileKind| {
                self.participants
                    .iter()
                    .map(|p| tokio::spawn(p.clone().clear_measured(kind, barrier.clone())))
                    .collect::<Vec<_>>()
            };

            let collect_clear = |tasks: Vec<tokio::task::JoinHandle<(Duration, bool)>>| async {
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
            ) = tokio::try_join!(
                collect_clear(spawn_clear_tasks(StockpileKind::Triples)),
                collect_clear(spawn_clear_tasks(StockpileKind::Presignatures)),
            )?;

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

    /// SCENARIO 7: Realistic Mixed MPC Pipeline Contention.
    /// Simulates production node conditions where a single connection pool is shared
    /// across concurrent triple generation, presignature generation, sign requests
    /// (taking 1 triple + 1 presignature), and background 100ms stockpile polling.
    pub async fn bench_mixed_pipeline(
        &self,
        items_per_participant: usize,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;

        if self.participants.is_empty() || items_per_participant == 0 {
            return Ok(vec![
                LatencySummary::empty("mixed_insert_triple"),
                LatencySummary::empty("mixed_insert_presig"),
                LatencySummary::empty("mixed_take_triple"),
                LatencySummary::empty("mixed_take_presig"),
            ]);
        }

        let participant_list = self.participant_ids();
        let num_p = self.participants.len();
        let total_items = num_p * items_per_participant;

        let stockpile_triples_base = next_id_block(total_items as u64 + 10_000);
        let stockpile_presigs_base = next_id_block(total_items as u64 + 10_000);
        let gen_base = next_id_block((total_items * 2) as u64 + 10_000);

        println!(
            "   -> Pre-stockpiling {items_per_participant} triples & presignatures per node across {num_p} participants..."
        );
        let triple_stockpile_ids = self
            .populate_all_triples(stockpile_triples_base, items_per_participant)
            .await?;
        let presig_stockpile_ids = self
            .populate_all_presignatures(stockpile_presigs_base, items_per_participant)
            .await?;

        // 1. Background 100ms polling for all participants (both triples and presignatures)
        let poller = self.spawn_background_polling(true);

        // 2. Launch concurrent workers:
        // - Generators creating new triples
        // - Generators creating new presignatures
        // - Signers taking 1 triple + 1 presignature
        let barrier = Arc::new(Barrier::new(num_p * 3));
        let overall_start = Instant::now();

        let triple_gen_tasks: Vec<_> = self
            .participants
            .iter()
            .enumerate()
            .map(|(node_idx, p)| {
                let base_id = gen_base + (node_idx as u64 * items_per_participant as u64 * 2);
                tokio::spawn(p.clone().insert_measured(
                    StockpileKind::Triples,
                    base_id,
                    items_per_participant,
                    participant_list.clone(),
                    barrier.clone(),
                ))
            })
            .collect();

        let presig_gen_tasks: Vec<_> = self
            .participants
            .iter()
            .enumerate()
            .map(|(node_idx, p)| {
                let base_id = gen_base
                    + (node_idx as u64 * items_per_participant as u64 * 2)
                    + items_per_participant as u64;
                tokio::spawn(p.clone().insert_measured(
                    StockpileKind::Presignatures,
                    base_id,
                    items_per_participant,
                    participant_list.clone(),
                    barrier.clone(),
                ))
            })
            .collect();

        let signer_tasks: Vec<_> = self
            .participants
            .iter()
            .enumerate()
            .map(|(node_idx, p)| {
                let my_triple_ids = triple_stockpile_ids
                    .get(node_idx)
                    .cloned()
                    .unwrap_or_default();
                let my_presig_ids = presig_stockpile_ids
                    .get(node_idx)
                    .cloned()
                    .unwrap_or_default();
                tokio::spawn(p.clone().take_triple_and_presig_pairs(
                    barrier.clone(),
                    my_triple_ids,
                    my_presig_ids,
                ))
            })
            .collect();

        let triple_gen = async {
            let (all, fails) = collect_task_results(triple_gen_tasks).await?;
            Ok::<_, anyhow::Error>((all, fails, overall_start.elapsed()))
        };

        let presig_gen = async {
            let (all, fails) = collect_task_results(presig_gen_tasks).await?;
            Ok::<_, anyhow::Error>((all, fails, overall_start.elapsed()))
        };

        let signers = async {
            let mut all_t = Vec::with_capacity(num_p * items_per_participant);
            let mut all_p = Vec::with_capacity(num_p * items_per_participant);
            let mut fails_t = 0;
            let mut fails_p = 0;
            for t in signer_tasks {
                let (tt, ft, tp, fp) = t.await?;
                all_t.extend(tt);
                fails_t += ft;
                all_p.extend(tp);
                fails_p += fp;
            }
            Ok::<_, anyhow::Error>((all_t, fails_t, all_p, fails_p, overall_start.elapsed()))
        };

        let (
            (mut all_insert_triples, triple_fails, triple_wall),
            (mut all_insert_presigs, presig_fails, presig_wall),
            (mut all_take_triples, take_triple_fails, mut all_take_presigs, take_presig_fails, signer_wall),
        ) = tokio::try_join!(triple_gen, presig_gen, signers)?;

        poller.stop().await;

        let (take_triple_wall, take_presig_wall) =
            partition_wall_by_active_time(signer_wall, &all_take_triples, &all_take_presigs);

        let s1 = LatencySummary::calculate_with_failures(
            "mixed_insert_triple",
            &mut all_insert_triples,
            triple_wall,
            triple_fails,
        );
        let s2 = LatencySummary::calculate_with_failures(
            "mixed_insert_presig",
            &mut all_insert_presigs,
            presig_wall,
            presig_fails,
        );
        let s3 = LatencySummary::calculate_with_failures(
            "mixed_take_triple",
            &mut all_take_triples,
            take_triple_wall,
            take_triple_fails,
        );
        let s4 = LatencySummary::calculate_with_failures(
            "mixed_take_presig",
            &mut all_take_presigs,
            take_presig_wall,
            take_presig_fails,
        );

        Ok(vec![s1, s2, s3, s4])
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
            self.reset_reservations().await;
            let triples_base = next_id_block(total_items as u64 + 10_000);
            let presigs_base = next_id_block(total_items as u64 + 10_000);

            let triple_ids_by_p = self
                .populate_all_triples(triples_base, items_per_participant)
                .await?;
            let presig_ids_by_p = self
                .populate_all_presignatures(presigs_base, items_per_participant)
                .await?;

            // Phase 1: Holder update without prune (count >= threshold, standard sync update path)
            let update_barrier = Arc::new(Barrier::new(num_p));
            let update_tasks: Vec<_> = self
                .participants
                .iter()
                .enumerate()
                .map(|(node_idx, p)| {
                    let my_triple_ids = triple_ids_by_p.get(node_idx).cloned().unwrap_or_default();
                    let my_presig_ids = presig_ids_by_p.get(node_idx).cloned().unwrap_or_default();
                    tokio::spawn(p.clone().prune_artifacts(
                        update_barrier.clone(),
                        target_peer,
                        threshold_update,
                        my_triple_ids,
                        my_presig_ids,
                    ))
                })
                .collect();

            let update_start = Instant::now();
            let mut round_updated_triples = 0;
            let mut round_updated_presigs = 0;
            let mut round_update_triple_errors = 0;
            let mut round_update_presig_errors = 0;

            for t in update_tasks {
                let (t_lat, t_res, p_lat, p_res) = t.await?;
                match t_res {
                    Ok((_, t_upd)) => {
                        round_updated_triples += t_upd.len();
                        all_update_triple_latencies.push(t_lat);
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
                        all_update_presig_latencies.push(p_lat);
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
                update_triple_fails += 1;
            }
            if round_update_presig_errors == 0 && round_updated_presigs != total_items {
                tracing::warn!(
                    "Incomplete presignature holder update in S8 round: expected {total_items}, updated {round_updated_presigs}"
                );
                update_presig_fails += 1;
            }

            // Phase 2: Below-threshold prune (count < threshold, items removed from Redis)
            let prune_barrier = Arc::new(Barrier::new(num_p));
            let prune_tasks: Vec<_> = self
                .participants
                .iter()
                .enumerate()
                .map(|(node_idx, p)| {
                    let my_triple_ids = triple_ids_by_p.get(node_idx).cloned().unwrap_or_default();
                    let my_presig_ids = presig_ids_by_p.get(node_idx).cloned().unwrap_or_default();
                    tokio::spawn(p.clone().prune_artifacts(
                        prune_barrier.clone(),
                        second_peer,
                        threshold_prune,
                        my_triple_ids,
                        my_presig_ids,
                    ))
                })
                .collect();

            let prune_start = Instant::now();
            let mut round_pruned_triples = 0;
            let mut round_pruned_presigs = 0;
            let mut round_prune_triple_errors = 0;
            let mut round_prune_presig_errors = 0;

            for t in prune_tasks {
                let (t_lat, t_res, p_lat, p_res) = t.await?;
                match t_res {
                    Ok((t_rem, _)) => {
                        round_pruned_triples += t_rem.len();
                        all_prune_triple_latencies.push(t_lat);
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
                        all_prune_presig_latencies.push(p_lat);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to prune presignatures in S8: {e:#}");
                        prune_presig_fails += 1;
                        round_prune_presig_errors += 1;
                    }
                }
            }
            total_prune_wall += prune_start.elapsed();

            // Soft-failure tracking consistent with S3/S6 to avoid aborting multi-scenario runs on partial prunes
            if round_prune_triple_errors == 0 && round_pruned_triples != total_items {
                tracing::warn!(
                    "Incomplete triple prune in S8 round: expected {total_items}, pruned {round_pruned_triples}"
                );
                prune_triple_fails += 1;
            }
            if round_prune_presig_errors == 0 && round_pruned_presigs != total_items {
                tracing::warn!(
                    "Incomplete presignature prune in S8 round: expected {total_items}, pruned {round_pruned_presigs}"
                );
                prune_presig_fails += 1;
            }
        }

        let (update_triple_wall, update_presig_wall) =
            partition_wall_by_active_time(total_update_wall, &all_update_triple_latencies, &all_update_presig_latencies);
        let (prune_triple_wall, prune_presig_wall) =
            partition_wall_by_active_time(total_prune_wall, &all_prune_triple_latencies, &all_prune_presig_latencies);

        let s1 = LatencySummary::calculate_with_failures(
            "sync_update_triples",
            &mut all_update_triple_latencies,
            update_triple_wall,
            update_triple_fails,
        );
        let s2 = LatencySummary::calculate_with_failures(
            "sync_update_presigs",
            &mut all_update_presig_latencies,
            update_presig_wall,
            update_presig_fails,
        );
        let s3 = LatencySummary::calculate_with_failures(
            "sync_prune_triples",
            &mut all_prune_triple_latencies,
            prune_triple_wall,
            prune_triple_fails,
        );
        let s4 = LatencySummary::calculate_with_failures(
            "sync_prune_presigs",
            &mut all_prune_presig_latencies,
            prune_presig_wall,
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
        let barrier = Arc::new(Barrier::new(num_p + 1));
        let participant_list = self.participant_ids();

        println!(
            "   -> Launching {num_p} participant workers ({items_per_participant} items each) with mid-flight CLIENT KILL shock at +{kill_delay_ms}ms...",
        );

        // 1. Killer task that severs all client connections using client helper
        let killer_task = self.client.spawn_client_killer(barrier.clone(), kill_delay_ms);

        // 2. Active participant tasks (Phase A: mid-insert CLIENT KILL)
        let overall_start = Instant::now();

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
                    barrier.clone(),
                ))
            })
            .collect();

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
        let take_barrier = Arc::new(Barrier::new(num_p + 1));
        let take_killer_task = self.client.spawn_client_killer(take_barrier.clone(), kill_delay_ms);

        let mut kill_take_tasks = Vec::with_capacity(num_p);
        let mut post_take_batches = Vec::with_capacity(num_p);

        for (node_idx, ids) in all_success_ids {
            let p = self.participants[node_idx].clone();
            let mid = ids.len() / 2;
            let (first_half, second_half) = ids.split_at(mid);
            kill_take_tasks.push(tokio::spawn(p.clone().take_triples(
                first_half.to_vec(),
                Some(take_barrier.clone()),
            )));
            post_take_batches.push((p, second_half.to_vec()));
        }

        let take_kill_start = Instant::now();
        let _ = take_killer_task.await?;
        let (mut all_kill_take_latencies, total_kill_take_failures) =
            collect_task_results(kill_take_tasks).await?;
        let take_kill_wall = take_kill_start.elapsed();

        // 4. Phase C: Post-kill verification: take remaining items to measure pool recovery
        let post_take_start = Instant::now();
        let mut post_take_tasks = Vec::with_capacity(num_p);
        for (p, ids) in post_take_batches {
            post_take_tasks.push(tokio::spawn(p.take_triples(ids, None)));
        }

        let (mut all_post_take_latencies, total_post_take_failures) =
            collect_task_results(post_take_tasks).await?;
        let post_take_wall = post_take_start.elapsed();

        let s1 = LatencySummary::calculate_with_failures(
            "insert_under_client_kill",
            &mut all_insert_latencies,
            insert_wall,
            total_insert_failures,
        );
        let s2 = LatencySummary::calculate_with_failures(
            "take_under_client_kill",
            &mut all_kill_take_latencies,
            take_kill_wall,
            total_kill_take_failures,
        );
        let s3 = LatencySummary::calculate_with_failures(
            "take_post_reconnect",
            &mut all_post_take_latencies,
            post_take_wall,
            total_post_take_failures,
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
                LatencySummary::empty("deep_commit_winner"),
                LatencySummary::empty("deep_commit_conflict"),
            ]);
        }

        let p = &self.participants[0];
        let base_id = next_id_block(stockpile_size as u64 + 10_000);

        println!(
            "   -> Pre-populating large stockpile of {stockpile_size} items on participant 0..."
        );
        self.populate(StockpileKind::Triples, 0, base_id, stockpile_size)
            .await?;

        let coverage = (exclusions_count as f64 / stockpile_size as f64) * 100.0;
        println!(
            "   -> Launching {num_seekers} concurrent seekers across {stockpile_size} items with {exclusions_count} exclusions ({coverage:.1}% coverage - near-exhaustion tail)..."
        );
        let barrier = Arc::new(Barrier::new(num_seekers));
        let overall_start = Instant::now();

        let tasks: Vec<_> = (0..num_seekers)
            .map(|_| {
                // Each seeker gets an independent storage handle with its own `reserved` RwLock,
                // matching production where distinct nodes do not share in-memory reservation maps.
                let seeker = SimulatedParticipant::new(&self.client.pool, &p.account_id, p.participant);
                tokio::spawn(seeker.seek_deep_stockpile(
                    barrier.clone(),
                    base_id,
                    seeks_per_worker,
                    exclusions_count,
                ))
            })
            .collect();

        let mut all_peek = Vec::new();
        let mut all_commit_wins = Vec::new();
        let mut all_commit_losses = Vec::new();

        for t in tasks {
            let (peek, wins, losses) = t.await?;
            all_peek.extend(peek);
            all_commit_wins.extend(wins);
            all_commit_losses.extend(losses);
        }
        let wall = overall_start.elapsed();
        let (peek_wall, win_wall, loss_wall) =
            partition_wall_3(wall, &all_peek, &all_commit_wins, &all_commit_losses);

        let s1 = LatencySummary::calculate("deep_peek_mine", &mut all_peek, peek_wall);
        let s2 =
            LatencySummary::calculate("deep_commit_winner", &mut all_commit_wins, win_wall);
        let s3 = LatencySummary::calculate(
            "deep_commit_conflict",
            &mut all_commit_losses,
            loss_wall,
        );
        Ok(vec![s1, s2, s3])
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
                LatencySummary::empty("churn_commit_winner"),
                LatencySummary::empty("churn_commit_conflict"),
                LatencySummary::empty("churn_simulated_deliberation"),
            ]);
        }

        let p = &self.participants[0];
        let base_id = next_id_block(initial_stockpile as u64 + 10_000);

        println!("   -> Pre-stockpiling {initial_stockpile} triples on participant 0...");
        self.populate(StockpileKind::Triples, 0, base_id, initial_stockpile)
            .await?;

        println!(
            "   -> Simulating {num_proposers} proposers with {abort_percent}% deliberation timeout/abort rate across {rounds_per_proposer} rounds (deliberation hold: {deliberation_delay_ms}ms)..."
        );
        let barrier = Arc::new(Barrier::new(num_proposers));
        let overall_start = Instant::now();

        let tasks: Vec<_> = (0..num_proposers)
            .map(|proposer_id| {
                // Each proposer gets an independent storage handle with its own `reserved` RwLock,
                // matching production where distinct nodes do not share in-memory reservation maps.
                let proposer = SimulatedParticipant::new(&self.client.pool, &p.account_id, p.participant);
                tokio::spawn(proposer.run_proposer_churn(
                    barrier.clone(),
                    proposer_id,
                    rounds_per_proposer,
                    abort_percent,
                    deliberation_delay_ms,
                ))
            })
            .collect();

        let mut all_peek = Vec::new();
        let mut all_commit_wins = Vec::new();
        let mut all_commit_losses = Vec::new();
        let mut all_deliberation = Vec::new();
        let mut total_aborts = 0;
        let mut total_commits = 0;

        for t in tasks {
            let (peek, wins, losses, deliberation, aborted, committed) = t.await?;
            all_peek.extend(peek);
            all_commit_wins.extend(wins);
            all_commit_losses.extend(losses);
            all_deliberation.extend(deliberation);
            total_aborts += aborted;
            total_commits += committed;
        }
        let total_wall = overall_start.elapsed();

        // Calculate active Redis time (excluding simulated node deliberation sleep)
        // so Redis command throughput accurately reflects database performance.
        let total_deliberation_time: Duration = all_deliberation.iter().copied().sum();
        let effective_redis_wall = if num_proposers > 0 {
            let avg_deliberation = total_deliberation_time / num_proposers as u32;
            total_wall.saturating_sub(avg_deliberation)
        } else {
            total_wall
        };

        let (peek_wall, win_wall, loss_wall) = partition_wall_3(
            effective_redis_wall,
            &all_peek,
            &all_commit_wins,
            &all_commit_losses,
        );

        println!(
            "   -> Churn outcome: {total_commits} successfully committed, {} rejected on conflict, {total_aborts} dropped back to pool on timeout/reject",
            all_commit_losses.len()
        );
        println!(
            "   -> Deliberation hold time: {deliberation_delay_ms}ms per round (reported separately from Redis command throughput)"
        );

        let s1 = LatencySummary::calculate("churn_peek_mine", &mut all_peek, peek_wall);
        let s2 =
            LatencySummary::calculate("churn_commit_winner", &mut all_commit_wins, win_wall);
        let s3 = LatencySummary::calculate(
            "churn_commit_conflict",
            &mut all_commit_losses,
            loss_wall,
        );
        let s4 = LatencySummary::calculate(
            "churn_simulated_deliberation",
            &mut all_deliberation,
            total_deliberation_time,
        );
        Ok(vec![s1, s2, s3, s4])
    }

    /// SCENARIO 12: Conflicted Double-Take Race Storm.
    /// Simulates concurrent attempts by multiple nodes to `take` the exact same artifact IDs,
    /// reproducing the "WARN: artifact X is not owned by this owner" Lua failure path.
    pub async fn bench_conflicted_take(
        &self,
        num_items: usize,
        contenders_per_item: usize,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;

        if self.participants.is_empty() || num_items == 0 || contenders_per_item == 0 {
            return Ok(vec![
                LatencySummary::empty("take_winner_success"),
                LatencySummary::empty("take_conflict_rejected"),
            ]);
        }

        let owner = &self.participants[0];
        let owner_participant = owner.participant;
        let base_id = next_id_block(num_items as u64 + 10_000);

        println!("   -> Pre-populating {num_items} items on owner participant...");
        let target_ids = self
            .populate(StockpileKind::Triples, 0, base_id, num_items)
            .await?;

        println!(
            "   -> Launching {contenders_per_item} parallel tasks racing to take each item (reproducing 'not owned by this owner' Lua errors)..."
        );
        let barrier = Arc::new(Barrier::new(contenders_per_item));
        let overall_start = Instant::now();

        let tasks: Vec<_> = (0..contenders_per_item)
            .map(|contender_idx| {
                // Each contender gets an independent storage handle with its own `reserved` RwLock,
                // matching production where distinct nodes do not share in-memory reservation maps.
                let contender = Participant::from(contender_idx as u32);
                let triples = TriplePair::storage(&self.client.pool, &owner.account_id);
                triples.set_me(contender);
                let ids = target_ids.clone();
                tokio::spawn(Self::race_take_conflicted(
                    triples,
                    barrier.clone(),
                    ids,
                    owner_participant,
                ))
            })
            .collect();

        let mut all_wins = Vec::new();
        let mut all_conflicts = Vec::new();
        let mut total_wins = 0;
        let mut total_conflicts = 0;

        for t in tasks {
            let (wins, conflicts, w_count, c_count) = t.await?;
            all_wins.extend(wins);
            all_conflicts.extend(conflicts);
            total_wins += w_count;
            total_conflicts += c_count;
        }
        let wall = overall_start.elapsed();
        let (win_wall, conflict_wall) =
            partition_wall_by_active_time(wall, &all_wins, &all_conflicts);

        println!(
            "   -> Conflict outcome: {total_wins} successful takes, {total_conflicts} rejected (SREM == 0 Lua conflict errors)"
        );

        let s1 = LatencySummary::calculate("take_winner_success", &mut all_wins, win_wall);
        let s2 =
            LatencySummary::calculate("take_conflict_rejected", &mut all_conflicts, conflict_wall);
        Ok(vec![s1, s2])
    }

    /// Helper task for racing contenders to take artifacts concurrently over Redis.
    pub async fn race_take_conflicted(
        triples: TripleStorage,
        barrier: Arc<Barrier>,
        target_ids: Vec<u64>,
        owner: Participant,
    ) -> (Vec<Duration>, Vec<Duration>, usize, usize) {
        barrier.wait().await;
        let mut win_latencies = Vec::new();
        let mut conflict_latencies = Vec::new();
        let mut wins = 0;
        let mut conflicts = 0;

        for id in target_ids {
            let t0 = Instant::now();
            let res = triples.take(id, owner).await;
            let elapsed = t0.elapsed();

            if res.is_some() {
                win_latencies.push(elapsed);
                wins += 1;
            } else {
                conflict_latencies.push(elapsed);
                conflicts += 1;
            }
        }

        (win_latencies, conflict_latencies, wins, conflicts)
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
                p.triples.reset_reservations().await;
                let _ = p.triples.clear().await;

                let base_id = next_id_block(batch_size as u64 + 1000);
                let all_ids = self
                    .populate(StockpileKind::Triples, node_idx, base_id, batch_size)
                    .await?;

                // Phase 1: Large ARGV sync (passing all >4,096 IDs in ARGV; 0 outdated)
                let t_argv_start = Instant::now();
                let argv_res = p
                    .triples
                    .remove_outdated(p.participant, &all_ids)
                    .await;
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
        let barrier_1 = Arc::new(Barrier::new(num_p));

        let tasks_1: Vec<_> = self
            .participants
            .iter()
            .enumerate()
            .map(|(node_idx, p)| {
                let p_base = base_id_1 + (node_idx as u64 * items_per_participant as u64);
                tokio::spawn(p.clone().insert_measured(
                    StockpileKind::Triples,
                    p_base,
                    items_per_participant,
                    participant_list.clone(),
                    barrier_1.clone(),
                ))
            })
            .collect();

        let t_start_1 = Instant::now();
        let (mut mem_latencies, mem_fails) = collect_task_results(tasks_1).await?;
        let mem_wall = t_start_1.elapsed();

        // Phase 2: Real AOF fsync disk writes (appendonly yes, appendfsync always)
        self.client.configure_persistence(true, "always").await?;
        let base_id_2 = next_id_block((num_p * items_per_participant) as u64 + 10_000);
        let barrier_2 = Arc::new(Barrier::new(num_p));

        let tasks_2: Vec<_> = self
            .participants
            .iter()
            .enumerate()
            .map(|(node_idx, p)| {
                let p_base = base_id_2 + (node_idx as u64 * items_per_participant as u64);
                tokio::spawn(p.clone().insert_measured(
                    StockpileKind::Triples,
                    p_base,
                    items_per_participant,
                    participant_list.clone(),
                    barrier_2.clone(),
                ))
            })
            .collect();

        let t_start_2 = Instant::now();
        let (mut aof_latencies, aof_fails) = collect_task_results(tasks_2).await?;
        let aof_wall = t_start_2.elapsed();

        // Phase 3: BGSAVE snapshot fork under concurrent takes
        self.client.trigger_bgsave().await?;
        let barrier_3 = Arc::new(Barrier::new(num_p));

        let tasks_3: Vec<_> = self
            .participants
            .iter()
            .enumerate()
            .map(|(node_idx, p)| {
                let p_base = base_id_2 + (node_idx as u64 * items_per_participant as u64);
                let ids: Vec<u64> = (p_base..p_base + items_per_participant as u64).collect();
                tokio::spawn(p.clone().take_triples(ids, Some(barrier_3.clone())))
            })
            .collect();

        let t_start_3 = Instant::now();
        let (mut bgsave_latencies, bgsave_fails) = collect_task_results(tasks_3).await?;
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
        let s3 = LatencySummary::calculate_with_failures(
            "bgsave_concurrent_take",
            &mut bgsave_latencies,
            bgsave_wall,
            bgsave_fails,
        );

        Ok(vec![s1, s2, s3])
    }
}

