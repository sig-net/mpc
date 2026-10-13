use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use cait_sith::protocol::Participant;
use cait_sith::triples::{TriplePub, TripleShare};
use cait_sith::PresignOutput;
use elliptic_curve::CurveArithmetic;
use k256::Secp256k1;
use mpc_node::protocol::presignature::Presignature;
use mpc_node::protocol::triple::Triple;
use mpc_node::storage::triple_storage::TriplePair;
use mpc_node::storage::{PresignatureStorage, TripleStorage};
use near_account_id::AccountId;
use tokio::sync::Barrier;

use crate::cluster::spawner::ClusterSpawner;
use crate::containers::Redis;

/// Diagnostics and telemetry fetched directly from Redis.
#[derive(Debug, Clone)]
pub struct SlowlogRecord {
    pub id: i64,
    pub timestamp: i64,
    pub duration_us: i64,
    pub command: String,
    pub client_addr: String,
}

#[derive(Debug, Clone)]
pub struct LatencyRecord {
    pub event: String,
    pub timestamp: i64,
    pub latest_latency_ms: i64,
    pub max_latency_ms: i64,
}

#[derive(Debug, Clone)]
pub struct CommandStat {
    pub calls: u64,
    pub usec: u64,
    pub usec_per_call: f64,
}

#[derive(Debug, Clone)]
pub struct MemorySnapshot {
    pub used_memory_human: String,
    pub used_memory_rss_human: String,
    pub fragmentation_ratio: f64,
    pub total_keys: i64,
}

pub struct RedisDiagnostics;

impl RedisDiagnostics {
    /// Configure Redis to log all commands slower than `slowlog_threshold_us` (e.g. 1000us = 1ms)
    /// and enable latency monitoring threshold `latency_threshold_ms`.
    pub async fn setup(
        pool: &deadpool_redis::Pool,
        slowlog_threshold_us: i64,
        latency_threshold_ms: i64,
    ) -> anyhow::Result<()> {
        let mut conn = pool.get().await.context("failed to get connection")?;
        deadpool_redis::redis::cmd("CONFIG")
            .arg("SET")
            .arg("slowlog-log-slower-than")
            .arg(slowlog_threshold_us)
            .query_async::<()>(&mut conn)
            .await
            .context("failed to set slowlog threshold")?;

        deadpool_redis::redis::cmd("CONFIG")
            .arg("SET")
            .arg("slowlog-max-len")
            .arg(1024)
            .query_async::<()>(&mut conn)
            .await
            .context("failed to set slowlog max-len")?;

        deadpool_redis::redis::cmd("CONFIG")
            .arg("SET")
            .arg("latency-monitor-threshold")
            .arg(latency_threshold_ms)
            .query_async::<()>(&mut conn)
            .await
            .context("failed to set latency-monitor-threshold")?;

        deadpool_redis::redis::cmd("SLOWLOG")
            .arg("RESET")
            .query_async::<()>(&mut conn)
            .await
            .context("failed to reset slowlog")?;

        Ok(())
    }

    /// Reset the Redis slow log.
    pub async fn reset_slowlog(pool: &deadpool_redis::Pool) -> anyhow::Result<()> {
        let mut conn = pool.get().await.context("failed to get connection")?;
        deadpool_redis::redis::cmd("SLOWLOG")
            .arg("RESET")
            .query_async::<()>(&mut conn)
            .await
            .context("failed to reset slowlog")?;
        Ok(())
    }

    /// Fetch entries from Redis SLOWLOG.
    pub async fn fetch_slowlog(
        pool: &deadpool_redis::Pool,
        count: usize,
    ) -> anyhow::Result<Vec<SlowlogRecord>> {
        let mut conn = pool.get().await.context("failed to get connection")?;
        let raw: deadpool_redis::redis::Value = deadpool_redis::redis::cmd("SLOWLOG")
            .arg("GET")
            .arg(count)
            .query_async(&mut conn)
            .await
            .context("failed to query slowlog")?;

        let mut records = Vec::new();
        if let deadpool_redis::redis::Value::Array(entries) = raw {
            for entry in entries {
                if let deadpool_redis::redis::Value::Array(fields) = entry {
                    if fields.len() >= 4 {
                        let id = match &fields[0] {
                            deadpool_redis::redis::Value::Int(val) => *val,
                            _ => 0,
                        };
                        let timestamp = match &fields[1] {
                            deadpool_redis::redis::Value::Int(val) => *val,
                            _ => 0,
                        };
                        let duration_us = match &fields[2] {
                            deadpool_redis::redis::Value::Int(val) => *val,
                            _ => 0,
                        };
                        let command = match &fields[3] {
                            deadpool_redis::redis::Value::Array(cmd_parts) => cmd_parts
                                .iter()
                                .take(4)
                                .map(|p| match p {
                                    deadpool_redis::redis::Value::BulkString(bytes) => {
                                        String::from_utf8_lossy(bytes).to_string()
                                    }
                                    other => format!("{other:?}"),
                                })
                                .collect::<Vec<_>>()
                                .join(" "),
                            _ => "unknown".to_string(),
                        };
                        let client_addr = if fields.len() >= 5 {
                            match &fields[4] {
                                deadpool_redis::redis::Value::BulkString(bytes) => {
                                    String::from_utf8_lossy(bytes).to_string()
                                }
                                _ => "".to_string(),
                            }
                        } else {
                            "".to_string()
                        };

                        records.push(SlowlogRecord {
                            id,
                            timestamp,
                            duration_us,
                            command,
                            client_addr,
                        });
                    }
                }
            }
        }
        Ok(records)
    }

    /// Fetch latest latency spikes reported by Redis LATENCY LATEST.
    pub async fn fetch_latency_latest(
        pool: &deadpool_redis::Pool,
    ) -> anyhow::Result<Vec<LatencyRecord>> {
        let mut conn = pool.get().await.context("failed to get connection")?;
        let raw: deadpool_redis::redis::Value = deadpool_redis::redis::cmd("LATENCY")
            .arg("LATEST")
            .query_async(&mut conn)
            .await
            .context("failed to query latency latest")?;

        let mut records = Vec::new();
        if let deadpool_redis::redis::Value::Array(entries) = raw {
            for entry in entries {
                if let deadpool_redis::redis::Value::Array(fields) = entry {
                    if fields.len() >= 4 {
                        let event = match &fields[0] {
                            deadpool_redis::redis::Value::BulkString(bytes) => {
                                String::from_utf8_lossy(bytes).to_string()
                            }
                            _ => "unknown".to_string(),
                        };
                        let timestamp = match &fields[1] {
                            deadpool_redis::redis::Value::Int(val) => *val,
                            _ => 0,
                        };
                        let latest_latency_ms = match &fields[2] {
                            deadpool_redis::redis::Value::Int(val) => *val,
                            _ => 0,
                        };
                        let max_latency_ms = match &fields[3] {
                            deadpool_redis::redis::Value::Int(val) => *val,
                            _ => 0,
                        };
                        records.push(LatencyRecord {
                            event,
                            timestamp,
                            latest_latency_ms,
                            max_latency_ms,
                        });
                    }
                }
            }
        }
        Ok(records)
    }

    /// Query INFO commandstats.
    pub async fn fetch_commandstats(
        pool: &deadpool_redis::Pool,
    ) -> anyhow::Result<HashMap<String, CommandStat>> {
        let mut conn = pool.get().await.context("failed to get connection")?;
        let raw: String = deadpool_redis::redis::cmd("INFO")
            .arg("commandstats")
            .query_async(&mut conn)
            .await
            .context("failed to query commandstats")?;

        let mut stats = HashMap::new();
        for line in raw.lines() {
            if let Some(rest) = line.strip_prefix("cmdstat_") {
                if let Some((cmd, values)) = rest.split_once(':') {
                    let mut calls = 0;
                    let mut usec = 0;
                    let mut usec_per_call = 0.0;
                    for part in values.split(',') {
                        if let Some((k, v)) = part.split_once('=') {
                            match k {
                                "calls" => calls = v.parse().unwrap_or(0),
                                "usec" => usec = v.parse().unwrap_or(0),
                                "usec_per_call" => usec_per_call = v.parse().unwrap_or(0.0),
                                _ => {}
                            }
                        }
                    }
                    stats.insert(
                        cmd.to_string(),
                        CommandStat {
                            calls,
                            usec,
                            usec_per_call,
                        },
                    );
                }
            }
        }
        Ok(stats)
    }

    /// Query memory snapshot and dbsize.
    pub async fn fetch_memory_snapshot(
        pool: &deadpool_redis::Pool,
    ) -> anyhow::Result<MemorySnapshot> {
        let mut conn = pool.get().await.context("failed to get connection")?;
        let raw: String = deadpool_redis::redis::cmd("INFO")
            .arg("memory")
            .query_async(&mut conn)
            .await
            .context("failed to query memory")?;

        let mut used_memory_human = String::new();
        let mut used_memory_rss_human = String::new();
        let mut fragmentation_ratio = 1.0;

        for line in raw.lines() {
            if let Some((k, v)) = line.split_once(':') {
                match k.trim() {
                    "used_memory_human" => used_memory_human = v.trim().to_string(),
                    "used_memory_rss_human" => used_memory_rss_human = v.trim().to_string(),
                    "mem_fragmentation_ratio" => {
                        fragmentation_ratio = v.trim().parse().unwrap_or(1.0)
                    }
                    _ => {}
                }
            }
        }

        let total_keys: i64 = deadpool_redis::redis::cmd("DBSIZE")
            .query_async(&mut conn)
            .await
            .unwrap_or(0);

        Ok(MemorySnapshot {
            used_memory_human,
            used_memory_rss_human,
            fragmentation_ratio,
            total_keys,
        })
    }
}

/// Computes statistical latency distribution.
#[derive(Debug, Clone)]
pub struct LatencySummary {
    pub op_name: String,
    pub count: usize,
    pub min_ms: f64,
    pub mean_ms: f64,
    pub p50_ms: f64,
    pub p90_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    pub throughput_ops_sec: f64,
}

impl LatencySummary {
    pub fn calculate(op_name: impl Into<String>, samples: &mut [Duration], total_wall_time: Duration) -> Self {
        let op_name = op_name.into();
        if samples.is_empty() {
            return Self {
                op_name,
                count: 0,
                min_ms: 0.0,
                mean_ms: 0.0,
                p50_ms: 0.0,
                p90_ms: 0.0,
                p95_ms: 0.0,
                p99_ms: 0.0,
                max_ms: 0.0,
                throughput_ops_sec: 0.0,
            };
        }

        samples.sort();
        let count = samples.len();
        let total_ms: f64 = samples.iter().map(|s| s.as_secs_f64() * 1000.0).sum();
        let min_ms = samples.first().unwrap().as_secs_f64() * 1000.0;
        let max_ms = samples.last().unwrap().as_secs_f64() * 1000.0;
        let mean_ms = total_ms / count as f64;

        let percentile = |p: f64| -> f64 {
            let idx = ((count as f64 * p).ceil() as usize).saturating_sub(1);
            samples[idx.min(count - 1)].as_secs_f64() * 1000.0
        };

        let p50_ms = percentile(0.50);
        let p90_ms = percentile(0.90);
        let p95_ms = percentile(0.95);
        let p99_ms = percentile(0.99);

        let wall_sec = total_wall_time.as_secs_f64().max(0.0001);
        let throughput_ops_sec = count as f64 / wall_sec;

        Self {
            op_name,
            count,
            min_ms,
            mean_ms,
            p50_ms,
            p90_ms,
            p95_ms,
            p99_ms,
            max_ms,
            throughput_ops_sec,
        }
    }

    pub fn print_row(&self) {
        println!(
            "{:<24} | {:>7} | {:>7.2}ms | {:>7.2}ms | {:>7.2}ms | {:>7.2}ms | {:>7.2}ms | {:>8.1}",
            self.op_name,
            self.count,
            self.p50_ms,
            self.p90_ms,
            self.p95_ms,
            self.p99_ms,
            self.max_ms,
            self.throughput_ops_sec,
        );
    }
}

pub fn print_summary_header() {
    println!("{:-<105}", "");
    println!(
        "{:<24} | {:>7} | {:>9} | {:>9} | {:>9} | {:>9} | {:>9} | {:>8}",
        "Operation", "Samples", "p50", "p90", "p95", "p99", "Max", "Ops/Sec"
    );
    println!("{:-<105}", "");
}

/// Simulated node actor in the Redis test cluster.
pub struct NodeActor {
    pub participant: Participant,
    pub account_id: AccountId,
    pub triples: TripleStorage,
    pub presignatures: PresignatureStorage,
}

/// Test Cluster that simulates N nodes interacting with Redis.
pub struct RedisHarnessCluster {
    _redis_container: Option<Redis>,
    pub redis_url: String,
    pub pool: deadpool_redis::Pool,
    pub nodes: Vec<NodeActor>,
    pub participants: Vec<Participant>,
}

impl RedisHarnessCluster {
    /// Spawn a fresh Redis container via testcontainers and prepare N simulated nodes.
    pub async fn spawn(num_nodes: usize) -> anyhow::Result<Self> {
        let spawner = ClusterSpawner::default()
            .network("bench-redis-harness")
            .init_network()
            .await
            .context("failed to init docker network")?;

        let redis = spawner.spawn_redis().await;
        let pool = redis.pool();
        let redis_url = redis.internal_address.clone();

        Self::init_with_pool(Some(redis), redis_url, pool, num_nodes).await
    }

    /// Connect to an existing Redis instance at the given URL (e.g. redis://127.0.0.1:6379).
    pub async fn from_url(redis_url: &str, num_nodes: usize) -> anyhow::Result<Self> {
        let parsed_url = url::Url::parse(redis_url).context("invalid redis url")?;
        let cfg = deadpool_redis::Config::from_url(parsed_url);
        let pool = cfg
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .context("failed to create redis pool")?;

        Self::init_with_pool(None, redis_url.to_string(), pool, num_nodes).await
    }

    async fn init_with_pool(
        redis_container: Option<Redis>,
        redis_url: String,
        pool: deadpool_redis::Pool,
        num_nodes: usize,
    ) -> anyhow::Result<Self> {
        RedisDiagnostics::setup(&pool, 1000, 1).await?;

        let mut nodes = Vec::new();
        let mut participants = Vec::new();

        for i in 0..num_nodes {
            let participant = Participant::from(i as u32);
            let account_id: AccountId = format!("node-{i}.testnet").parse().unwrap();

            let triples = TriplePair::storage(&pool, &account_id);
            triples.set_me(participant);

            let presignatures = Presignature::storage(&pool, &account_id);
            presignatures.set_me(participant);

            nodes.push(NodeActor {
                participant,
                account_id,
                triples,
                presignatures,
            });
            participants.push(participant);
        }

        Ok(Self {
            _redis_container: redis_container,
            redis_url,
            pool,
            nodes,
            participants,
        })
    }

    /// Reset slowlog before running a test case.
    pub async fn reset_diagnostics(&self) -> anyhow::Result<()> {
        RedisDiagnostics::reset_slowlog(&self.pool).await
    }

    /// Print slowlog entries and memory stats captured during the last run.
    pub async fn print_diagnostics(&self) -> anyhow::Result<()> {
        let slowlog = RedisDiagnostics::fetch_slowlog(&self.pool, 10).await?;
        println!("\n  [Redis Diagnostics]");
        if slowlog.is_empty() {
            println!("   Slowlog (>=1ms): None recorded (all commands executed under 1ms)");
        } else {
            println!("   Slowlog (top {} operations >=1ms):", slowlog.len());
            for s in slowlog {
                println!(
                    "     * ID {}: {:>7.2}ms | Cmd: {}",
                    s.id,
                    s.duration_us as f64 / 1000.0,
                    s.command
                );
            }
        }

        let mem = RedisDiagnostics::fetch_memory_snapshot(&self.pool).await?;
        println!(
            "   Memory: used={} rss={} frag_ratio={:.2} total_keys={}",
            mem.used_memory_human, mem.used_memory_rss_human, mem.fragmentation_ratio, mem.total_keys
        );
        Ok(())
    }

    /// SCENARIO 1: Concurrent Insert & Take Throughput.
    /// Simulates N nodes inserting pairs and presignatures simultaneously.
    pub async fn bench_concurrent_insert_and_take(
        &self,
        items_per_node: usize,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;

        let barrier = Arc::new(Barrier::new(self.nodes.len()));
        let mut insert_tasks = Vec::new();
        let overall_start = Instant::now();

        for (node_idx, node) in self.nodes.iter().enumerate() {
            let triples = node.triples.clone();
            let me = node.participant;
            let barrier = barrier.clone();
            let participants = self.participants.clone();

            insert_tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                let mut insert_triple_latencies = Vec::with_capacity(items_per_node);
                let base_id = (node_idx as u64) * 1_000_000;

                for i in 0..items_per_node {
                    let id = base_id + (i as u64);
                    let pair = dummy_pair(id, &participants);

                    let t0 = Instant::now();
                    let mut slot = triples.create_slot(id, me).await.expect("slot created");
                    slot.insert(pair, me).await;
                    insert_triple_latencies.push(t0.elapsed());
                }

                insert_triple_latencies
            }));
        }

        let mut all_insert_latencies = Vec::new();
        for task in insert_tasks {
            all_insert_latencies.extend(task.await?);
        }
        let insert_wall = overall_start.elapsed();

        // Now test concurrent taking of the inserted items
        let barrier = Arc::new(Barrier::new(self.nodes.len()));
        let mut take_tasks = Vec::new();
        let take_start = Instant::now();

        for (node_idx, node) in self.nodes.iter().enumerate() {
            let triples = node.triples.clone();
            let me = node.participant;
            let barrier = barrier.clone();

            take_tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                let mut take_latencies = Vec::with_capacity(items_per_node);
                let base_id = (node_idx as u64) * 1_000_000;

                for i in 0..items_per_node {
                    let id = base_id + (i as u64);
                    let t0 = Instant::now();
                    triples.take(id, me).await;
                    take_latencies.push(t0.elapsed());
                }

                take_latencies
            }));
        }

        let mut all_take_latencies = Vec::new();
        for task in take_tasks {
            all_take_latencies.extend(task.await?);
        }
        let take_wall = take_start.elapsed();

        let s1 = LatencySummary::calculate("concurrent_insert_triple", &mut all_insert_latencies, insert_wall);
        let s2 = LatencySummary::calculate("concurrent_take_triple", &mut all_take_latencies, take_wall);

        Ok(vec![s1, s2])
    }

    /// SCENARIO 2: `remove_outdated` Pruning Storm.
    /// Pre-populates owned items across all nodes, then triggers `remove_outdated` concurrently
    /// across all nodes with `batch_size` owner shares (reproducing the 110ms slowlog spike).
    pub async fn bench_remove_outdated_storm(
        &self,
        stockpile_count: usize,
        prune_count: usize,
    ) -> anyhow::Result<LatencySummary> {
        self.reset_diagnostics().await?;

        // 1. Populate items on all nodes
        println!("   -> Pre-populating {stockpile_count} triples per node across {} nodes...", self.nodes.len());
        for (node_idx, node) in self.nodes.iter().enumerate() {
            let base_id = (node_idx as u64) * 10_000_000;
            for i in 0..stockpile_count {
                let id = base_id + (i as u64);
                let pair = dummy_pair(id, &self.participants);
                if let Some(mut slot) = node.triples.create_slot(id, node.participant).await {
                    slot.insert(pair, node.participant).await;
                }
            }
        }

        // 2. Prepare remaining shares (simulating that `prune_count` items were consumed/outdated)
        let barrier = Arc::new(Barrier::new(self.nodes.len()));
        let mut storm_tasks = Vec::new();
        let storm_start = Instant::now();

        for (node_idx, node) in self.nodes.iter().enumerate() {
            let triples = node.triples.clone();
            let me = node.participant;
            let barrier = barrier.clone();
            let base_id = (node_idx as u64) * 10_000_000;

            // owner_shares contains only the items that the owner STILL HAS (from prune_count..stockpile_count)
            let remaining_shares: Vec<u64> = (prune_count..stockpile_count)
                .map(|i| base_id + (i as u64))
                .collect();

            storm_tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                let t0 = Instant::now();
                let res = triples.remove_outdated(me, &remaining_shares).await;
                (t0.elapsed(), res)
            }));
        }

        let mut latencies = Vec::new();
        for task in storm_tasks {
            let (lat, res) = task.await?;
            assert!(res.is_ok(), "remove_outdated should succeed");
            latencies.push(lat);
        }
        let wall = storm_start.elapsed();

        Ok(LatencySummary::calculate("remove_outdated_storm", &mut latencies, wall))
    }

    /// SCENARIO 3: Stockpile 100ms Background Polling Contention.
    /// Runs a write/read workload with vs. without 100ms background polling (HLEN / SCARD) across all nodes.
    pub async fn bench_polling_contention(
        &self,
        workload_items: usize,
        enable_polling: bool,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;

        let stop_flag = Arc::new(AtomicBool::new(false));
        let mut poller_handles = Vec::new();

        if enable_polling {
            for node in &self.nodes {
                let triples = node.triples.clone();
                let me = node.participant;
                let stop = stop_flag.clone();

                poller_handles.push(tokio::spawn(async move {
                    let mut interval = tokio::time::interval(Duration::from_millis(100));
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                    while !stop.load(Ordering::Relaxed) {
                        interval.tick().await;
                        // Emulate the 4 queries in triple.rs stockpile loop
                        let _ = triples.len_generated().await; // HLEN
                        let _ = triples.len_by_owner(me).await; // SCARD
                        let _ = triples.len_by_owner(me).await; // SCARD
                        let _ = triples.len_generated().await; // HLEN
                    }
                }));
            }
        }

        // Run active inserts and takes under this polling condition
        let summaries = self.bench_concurrent_insert_and_take(workload_items).await?;

        if enable_polling {
            stop_flag.store(true, Ordering::Relaxed);
            for h in poller_handles {
                let _ = h.await;
            }
        }

        Ok(summaries)
    }

    /// SCENARIO 4: Proposer Race (`peek_mine` + `commit`).
    /// Multiple concurrent tasks on a single node racing to reserve artifacts with exclusion lists.
    pub async fn bench_proposer_race(
        &self,
        node_idx: usize,
        initial_stockpile: usize,
        num_racers: usize,
        proposals_per_racer: usize,
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;

        let node = &self.nodes[node_idx];
        let me = node.participant;
        let triples = node.triples.clone();

        println!("   -> Stockpiling {initial_stockpile} triples on node {node_idx}...");
        let base_id = 50_000_000u64;
        for i in 0..initial_stockpile {
            let id = base_id + (i as u64);
            let pair = dummy_pair(id, &self.participants);
            if let Some(mut slot) = triples.create_slot(id, me).await {
                slot.insert(pair, me).await;
            }
        }

        let barrier = Arc::new(Barrier::new(num_racers));
        let mut racer_tasks = Vec::new();
        let race_start = Instant::now();

        for racer_id in 0..num_racers {
            let triples = triples.clone();
            let barrier = barrier.clone();

            racer_tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                let mut peek_latencies = Vec::new();
                let mut commit_latencies = Vec::new();

                let excluded: Vec<u64> = (0..50).map(|x| base_id + (x as u64) + (racer_id as u64 * 100)).collect();

                for _ in 0..proposals_per_racer {
                    let t0 = Instant::now();
                    let reservation = triples.peek_mine(&excluded).await;
                    peek_latencies.push(t0.elapsed());

                    if let Some(reservation) = reservation {
                        let t1 = Instant::now();
                        let taken = reservation.commit().await;
                        commit_latencies.push(t1.elapsed());
                        if taken.is_none() {
                            tracing::debug!("lost reservation race on commit, as expected in concurrent proposers");
                        }
                    }
                }

                (peek_latencies, commit_latencies)
            }));
        }

        let mut all_peek = Vec::new();
        let mut all_commit = Vec::new();

        for task in racer_tasks {
            let (peek, commit) = task.await?;
            all_peek.extend(peek);
            all_commit.extend(commit);
        }
        let wall = race_start.elapsed();

        let s1 = LatencySummary::calculate("peek_mine_contended", &mut all_peek, wall);
        let s2 = LatencySummary::calculate("commit_reservation", &mut all_commit, wall);

        Ok(vec![s1, s2])
    }
}

pub fn dummy_presignature(id: u64, participants: &[Participant]) -> Presignature {
    Presignature {
        id,
        output: PresignOutput {
            big_r: <Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            k: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
            sigma: <Secp256k1 as CurveArithmetic>::Scalar::ONE,
        },
        participants: participants.to_vec(),
        holders: Some(participants.to_vec()),
    }
}

pub fn dummy_pair(id: u64, participants: &[Participant]) -> TriplePair {
    TriplePair {
        id,
        triple0: dummy_triple(participants),
        triple1: dummy_triple(participants),
        holders: Some(participants.to_vec()),
    }
}

pub fn dummy_triple(participants: &[Participant]) -> Triple {
    Triple {
        share: TripleShare {
            a: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
            b: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
            c: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
        },
        public: TriplePub {
            big_a: <k256::Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            big_b: <k256::Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            big_c: <k256::Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            participants: participants.to_vec(),
            threshold: (participants.len() * 2 / 3).max(1),
        },
    }
}
