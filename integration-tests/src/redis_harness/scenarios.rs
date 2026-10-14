use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use cait_sith::protocol::Participant;
use deadpool_redis::redis::cmd;
use deadpool_redis::Pool;
use mpc_node::storage::triple_storage::TriplePair;
use mpc_node::storage::TripleStorage;
use tokio::sync::Barrier;

use super::diagnostics::{partition_wall_by_active_time, LatencySummary, RedisDiagnostics};
use super::participant::{next_id_block, SimulatedParticipant};
use super::RedisHarness;

impl RedisHarness {
    /// Helper task for disconnecting clients after a given delay.
    pub async fn run_client_killer(pool: Pool, barrier: Arc<Barrier>, kill_delay_ms: u64) -> i64 {
        barrier.wait().await;
        tokio::time::sleep(Duration::from_millis(kill_delay_ms)).await;

        match Self::kill_client_connections_on_pool(&pool).await {
            Ok(count) => {
                println!("   [CLIENT KILL] Severed {count} active Redis client connections!");
                count
            }
            Err(e) => {
                tracing::warn!("CLIENT KILL failed: {e:#}");
                0
            }
        }
    }

    /// Sever all client connections to Redis using `CLIENT KILL TYPE normal SKIPME yes`.
    pub async fn kill_client_connections_on_pool(pool: &Pool) -> anyhow::Result<i64> {
        let mut conn = pool.get().await.context("failed to get connection")?;
        let count: i64 = cmd("CLIENT")
            .arg("KILL")
            .arg("TYPE")
            .arg("normal")
            .arg("SKIPME")
            .arg("yes")
            .query_async(&mut conn)
            .await
            .context("failed to kill client connections")?;
        Ok(count)
    }

    /// Sever all client connections to Redis using `CLIENT KILL TYPE normal SKIPME yes`.
    pub async fn kill_client_connections(&self) -> anyhow::Result<i64> {
        Self::kill_client_connections_on_pool(&self.pool).await
    }

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
                tokio::spawn(p.clone().insert_triples_measured(
                    base_id,
                    items_per_participant,
                    participant_list.clone(),
                    barrier.clone(),
                ))
            })
            .collect();

        let mut all_insert_latencies =
            Vec::with_capacity(self.participants.len() * items_per_participant);
        let mut insert_failures = 0;
        for task in insert_tasks {
            let (lat, fails) = task.await?;
            all_insert_latencies.extend(lat);
            insert_failures += fails;
        }
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

        let mut all_take_latencies =
            Vec::with_capacity(self.participants.len() * items_per_participant);
        let mut take_failures = 0;
        for task in take_tasks {
            let (lat, fails) = task.await?;
            all_take_latencies.extend(lat);
            take_failures += fails;
        }
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

    /// SCENARIO 2: `remove_outdated` Pruning Storm.
    /// Pre-populates owned items across participants, then triggers `remove_outdated` concurrently
    /// across all participants with remaining shares (reproducing the slowlog spike).
    pub async fn bench_remove_outdated_storm(
        &self,
        stockpile_count: usize,
        prune_count: usize,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;

        if self.participants.is_empty() || stockpile_count == 0 {
            return Ok(vec![LatencySummary::empty("remove_outdated_storm")]);
        }

        let run_base_id = next_id_block((self.participants.len() * stockpile_count) as u64 + 1000);

        // 1. Populate items concurrently across participants
        println!("   -> Pre-populating {stockpile_count} triples per participant across {} participants...", self.participants.len());
        let all_ids = self
            .populate_all_triples(run_base_id, stockpile_count)
            .await;

        // 2. Prepare remaining shares (simulating that `prune_count` items were consumed/outdated)
        let barrier = Arc::new(Barrier::new(self.participants.len()));
        let storm_start = Instant::now();

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

        let mut latencies = Vec::new();
        for task in storm_tasks {
            let (lat, res) = task.await?;
            assert!(res.is_ok(), "remove_outdated should succeed");
            latencies.push(lat);
        }
        let wall = storm_start.elapsed();

        Ok(vec![LatencySummary::calculate(
            "remove_outdated_storm",
            &mut latencies,
            wall,
        )])
    }

    /// SCENARIO 3: Stockpile 100ms Background Polling Contention.
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
        let participant_list = self.participant_ids();

        println!(
            "   -> Stockpiling {initial_stockpile} triples on participant {participant_idx}..."
        );
        let base_id = next_id_block(initial_stockpile as u64 + 1000);
        p.clone()
            .populate_triples(base_id, initial_stockpile, participant_list)
            .await;

        let barrier = Arc::new(Barrier::new(num_racers));
        let race_start = Instant::now();

        let racer_tasks: Vec<_> = (0..num_racers)
            .map(|_| {
                // Each racer gets an independent storage handle with its own `reserved` RwLock,
                // matching production where distinct nodes do not share in-memory reservation maps.
                let racer = SimulatedParticipant::new(&self.pool, &p.account_id, p.participant);
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
        let (peek_wall, commit_wall) =
            partition_wall_by_active_time(wall, &all_peek, &all_commit_wins);
        let (win_wall, loss_wall) =
            partition_wall_by_active_time(commit_wall, &all_commit_wins, &all_commit_losses);

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
                LatencySummary::empty("saturated_take_triple"),
            ]);
        }

        let pool_status = self.pool.status();
        println!(
            "   -> Connection pool status: max_size={} (active={}, available={}, waiting={})",
            pool_status.max_size, pool_status.size, pool_status.available, pool_status.waiting
        );

        // 1. Continuous 100ms polling across all participants
        let poller = self.spawn_background_polling(false);

        // 2. Intermittent blocking spikes on Redis main thread (simulating large Lua scripts or BGSAVE stalls)
        // Spans both insert and take phases
        let spike_stop = Arc::new(AtomicBool::new(false));
        let spike_handle =
            self.spawn_intermittent_spike(spike_stop.clone(), blocking_spike_ms, num_spikes * 2);

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
                insert_tasks.push(tokio::spawn(p.clone().insert_triples_measured(
                    base_id,
                    items_per_task,
                    participant_list.clone(),
                    insert_barrier.clone(),
                )));
            }
        }

        let insert_start = Instant::now();
        let mut all_insert_latencies = Vec::new();
        let mut total_insert_failures = 0;
        for task in insert_tasks {
            let (lat, fails) = task.await?;
            all_insert_latencies.extend(lat);
            total_insert_failures += fails;
        }
        let insert_wall = insert_start.elapsed();

        // 4. Phase B: High-concurrency takes across participants under saturation
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
        let mut all_take_latencies = Vec::new();
        let mut total_take_failures = 0;
        for task in take_tasks {
            let (lat, fails) = task.await?;
            all_take_latencies.extend(lat);
            total_take_failures += fails;
        }
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
        let take_summary = LatencySummary::calculate_with_failures(
            "saturated_take_triple",
            &mut all_take_latencies,
            take_wall,
            total_take_failures,
        );

        Ok(vec![insert_summary, take_summary])
    }

    /// SCENARIO 6: Mass Epoch Resharing `clear()` Storm.
    /// Simulates network-wide resharing where all nodes simultaneously wipe both triples
    /// and presignatures via `clear()`.
    /// Directly measures execution time of the HKEYS + multi-DEL Lua script, Redis slowlog,
    /// and keyspace drop.
    pub async fn bench_clear_storm(
        &self,
        stockpile_per_participant: usize,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;

        if self.participants.is_empty() || stockpile_per_participant == 0 {
            return Ok(vec![
                LatencySummary::empty("clear_triples_storm"),
                LatencySummary::empty("clear_presigs_storm"),
            ]);
        }

        let num_p = self.participants.len();
        let total_items = num_p * stockpile_per_participant;
        let triples_base = next_id_block(total_items as u64 + 10_000);
        let presigs_base = next_id_block(total_items as u64 + 10_000);

        println!(
            "   -> Pre-populating {stockpile_per_participant} triples AND {stockpile_per_participant} presignatures across {num_p} participants..."
        );
        self.populate_all_triples(triples_base, stockpile_per_participant)
            .await;
        self.populate_all_presignatures(presigs_base, stockpile_per_participant)
            .await;

        let pre_mem = RedisDiagnostics::fetch_memory_snapshot(&self.pool).await?;
        println!(
            "   -> Pre-clear keyspace: {} keys in Redis, Memory: {}",
            pre_mem.total_keys, pre_mem.used_memory_human
        );

        let barrier = Arc::new(Barrier::new(num_p * 2));
        let clear_start = Instant::now();

        let clear_triple_tasks: Vec<_> = self
            .participants
            .iter()
            .map(|p| tokio::spawn(p.clone().clear_triples(barrier.clone())))
            .collect();

        let clear_presig_tasks: Vec<_> = self
            .participants
            .iter()
            .map(|p| tokio::spawn(p.clone().clear_presignatures(barrier.clone())))
            .collect();

        let clear_triples = async {
            let mut latencies = Vec::with_capacity(num_p);
            for t in clear_triple_tasks {
                let (elapsed, ok) = t.await?;
                assert!(ok, "triples clear should succeed");
                latencies.push(elapsed);
            }
            Ok::<_, anyhow::Error>((latencies, clear_start.elapsed()))
        };

        let clear_presigs = async {
            let mut latencies = Vec::with_capacity(num_p);
            for t in clear_presig_tasks {
                let (elapsed, ok) = t.await?;
                assert!(ok, "presignatures clear should succeed");
                latencies.push(elapsed);
            }
            Ok::<_, anyhow::Error>((latencies, clear_start.elapsed()))
        };

        let ((mut triple_latencies, triple_wall), (mut presig_latencies, presig_wall)) =
            tokio::try_join!(clear_triples, clear_presigs)?;

        let post_mem = RedisDiagnostics::fetch_memory_snapshot(&self.pool).await?;
        println!(
            "   -> Post-clear keyspace: {} keys remaining in Redis, Memory: {}",
            post_mem.total_keys, post_mem.used_memory_human
        );

        let s1 =
            LatencySummary::calculate("clear_triples_storm", &mut triple_latencies, triple_wall);
        let s2 =
            LatencySummary::calculate("clear_presigs_storm", &mut presig_latencies, presig_wall);
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
            .await;
        let presig_stockpile_ids = self
            .populate_all_presignatures(stockpile_presigs_base, items_per_participant)
            .await;

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
                tokio::spawn(p.clone().insert_triples_measured(
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
                tokio::spawn(p.clone().insert_presignatures_measured(
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
            let mut all = Vec::with_capacity(num_p * items_per_participant);
            let mut fails = 0;
            for t in triple_gen_tasks {
                let (lats, f) = t.await?;
                all.extend(lats);
                fails += f;
            }
            Ok::<_, anyhow::Error>((all, fails, overall_start.elapsed()))
        };

        let presig_gen = async {
            let mut all = Vec::with_capacity(num_p * items_per_participant);
            let mut fails = 0;
            for t in presig_gen_tasks {
                let (lats, f) = t.await?;
                all.extend(lats);
                fails += f;
            }
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
            signer_wall,
            take_triple_fails,
        );
        let s4 = LatencySummary::calculate_with_failures(
            "mixed_take_presig",
            &mut all_take_presigs,
            signer_wall,
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
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;

        if self.participants.is_empty() || items_per_participant == 0 {
            return Ok(vec![
                LatencySummary::empty("sync_prune_triples"),
                LatencySummary::empty("sync_prune_presigs"),
            ]);
        }

        let num_p = self.participants.len();
        let total_items = num_p * items_per_participant;
        let triples_base = next_id_block(total_items as u64 + 10_000);
        let presigs_base = next_id_block(total_items as u64 + 10_000);
        let participant_list = self.participant_ids();
        let target_peer = participant_list[0];

        println!(
            "   -> Pre-populating {items_per_participant} triples and presignatures across {num_p} participants..."
        );
        let triple_ids_by_p = self
            .populate_all_triples(triples_base, items_per_participant)
            .await;
        let presig_ids_by_p = self
            .populate_all_presignatures(presigs_base, items_per_participant)
            .await;

        // Threshold = num_p ensures removing target_peer drops remaining holders from num_p to (num_p - 1),
        // which falls strictly below threshold and executes the actual HDEL/DEL/SREM pruning path in Lua.
        let threshold = num_p;
        let barrier = Arc::new(Barrier::new(num_p));
        let prune_start = Instant::now();

        let tasks: Vec<_> = self
            .participants
            .iter()
            .enumerate()
            .map(|(node_idx, p)| {
                let my_triple_ids = triple_ids_by_p.get(node_idx).cloned().unwrap_or_default();
                let my_presig_ids = presig_ids_by_p.get(node_idx).cloned().unwrap_or_default();
                tokio::spawn(p.clone().prune_artifacts(
                    barrier.clone(),
                    target_peer,
                    threshold,
                    my_triple_ids,
                    my_presig_ids,
                ))
            })
            .collect();

        let mut all_triple_latencies = Vec::with_capacity(num_p);
        let mut all_presig_latencies = Vec::with_capacity(num_p);
        let mut total_pruned_triples = 0;
        let mut total_pruned_presigs = 0;

        for t in tasks {
            let (t_lat, t_res, p_lat, p_res) = t.await?;
            let (t_removed, _t_updated) =
                t_res.context("triples remove_holder_and_prune should succeed")?;
            let (p_removed, _p_updated) =
                p_res.context("presignatures remove_holder_and_prune should succeed")?;
            total_pruned_triples += t_removed.len();
            total_pruned_presigs += p_removed.len();
            all_triple_latencies.push(t_lat);
            all_presig_latencies.push(p_lat);
        }
        let wall = prune_start.elapsed();

        assert_eq!(
            total_pruned_triples, total_items,
            "all triples should be pruned when falling below threshold"
        );
        assert_eq!(
            total_pruned_presigs, total_items,
            "all presignatures should be pruned when falling below threshold"
        );

        let (triple_wall, presig_wall) =
            partition_wall_by_active_time(wall, &all_triple_latencies, &all_presig_latencies);

        let s1 =
            LatencySummary::calculate("sync_prune_triples", &mut all_triple_latencies, triple_wall);
        let s2 =
            LatencySummary::calculate("sync_prune_presigs", &mut all_presig_latencies, presig_wall);
        Ok(vec![s1, s2])
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

        // 1. Killer task that severs all client connections using shared pool helper
        let killer_task = tokio::spawn(Self::run_client_killer(
            self.pool.clone(),
            barrier.clone(),
            kill_delay_ms,
        ));

        // 2. Active participant tasks
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

        // 3. Post-kill verification: take the successfully inserted items to measure pool recovery
        let take_start = Instant::now();

        let take_tasks: Vec<_> = all_success_ids
            .into_iter()
            .map(|(node_idx, ids)| {
                let p = self.participants[node_idx].clone();
                tokio::spawn(p.take_triples(ids, None))
            })
            .collect();

        let mut all_take_latencies = Vec::new();
        let mut total_take_failures = 0;
        for t in take_tasks {
            let (lats, fails) = t.await?;
            all_take_latencies.extend(lats);
            total_take_failures += fails;
        }
        let take_wall = take_start.elapsed();

        let s1 = LatencySummary::calculate_with_failures(
            "insert_under_client_kill",
            &mut all_insert_latencies,
            insert_wall,
            total_insert_failures,
        );
        let s2 = LatencySummary::calculate_with_failures(
            "take_post_reconnect",
            &mut all_take_latencies,
            take_wall,
            total_take_failures,
        );
        Ok(vec![s1, s2])
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
        let participant_list = self.participant_ids();
        let base_id = next_id_block(stockpile_size as u64 + 10_000);

        println!(
            "   -> Pre-populating large stockpile of {stockpile_size} items on participant 0..."
        );
        p.clone()
            .populate_triples(base_id, stockpile_size, participant_list)
            .await;

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
                let seeker = SimulatedParticipant::new(&self.pool, &p.account_id, p.participant);
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
        let (peek_wall, commit_wall) =
            partition_wall_by_active_time(wall, &all_peek, &all_commit_wins);
        let (win_wall, loss_wall) =
            partition_wall_by_active_time(commit_wall, &all_commit_wins, &all_commit_losses);

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
        let participant_list = self.participant_ids();
        let base_id = next_id_block(initial_stockpile as u64 + 10_000);

        println!("   -> Pre-stockpiling {initial_stockpile} triples on participant 0...");
        p.clone()
            .populate_triples(base_id, initial_stockpile, participant_list)
            .await;

        println!(
            "   -> Simulating {num_proposers} proposers with {abort_percent}% deliberation timeout/abort rate across {rounds_per_proposer} rounds (deliberation hold: {deliberation_delay_ms}ms)..."
        );
        let barrier = Arc::new(Barrier::new(num_proposers));
        let overall_start = Instant::now();

        let tasks: Vec<_> = (0..num_proposers)
            .map(|proposer_id| {
                // Each proposer gets an independent storage handle with its own `reserved` RwLock,
                // matching production where distinct nodes do not share in-memory reservation maps.
                let proposer = SimulatedParticipant::new(&self.pool, &p.account_id, p.participant);
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

        let (peek_wall, commit_wall) =
            partition_wall_by_active_time(effective_redis_wall, &all_peek, &all_commit_wins);
        let (win_wall, loss_wall) =
            partition_wall_by_active_time(commit_wall, &all_commit_wins, &all_commit_losses);

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
        let participant_list = self.participant_ids();
        let base_id = next_id_block(num_items as u64 + 10_000);

        println!("   -> Pre-populating {num_items} items on owner participant...");
        let target_ids = owner
            .clone()
            .populate_triples(base_id, num_items, participant_list)
            .await;

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
                let triples = TriplePair::storage(&self.pool, &owner.account_id);
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
}
