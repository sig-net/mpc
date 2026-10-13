use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

static GLOBAL_ID_COUNTER: AtomicU64 = AtomicU64::new(10_000_000);

pub fn next_id_block(count: u64) -> u64 {
    GLOBAL_ID_COUNTER.fetch_add(count, Ordering::Relaxed)
}

use anyhow::Context as _;
use cait_sith::protocol::Participant;
use cait_sith::triples::{TriplePub, TripleShare};
use cait_sith::PresignOutput;
pub use deadpool_redis::redis;
use deadpool_redis::{Config as RedisPoolConfig, Pool, Runtime as RedisRuntime};
use elliptic_curve::CurveArithmetic;
use k256::Secp256k1;
use mpc_node::protocol::presignature::Presignature;
use mpc_node::protocol::triple::Triple;
use mpc_node::storage::protocol_storage::RemoveOutdatedResult;
use mpc_node::storage::triple_storage::TriplePair;
use mpc_node::storage::{PresignatureStorage, TripleStorage};
use near_account_id::AccountId;
use redis::{cmd, Script, Value};
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
pub struct MemorySnapshot {
    pub used_memory_human: String,
    pub used_memory_rss_human: String,
    pub fragmentation_ratio: f64,
    pub total_keys: i64,
}

pub struct RedisDiagnostics;

impl RedisDiagnostics {
    /// Configure Redis to log all commands slower than `slowlog_threshold_us` (e.g. 1000us = 1ms).
    pub async fn setup(pool: &Pool, slowlog_threshold_us: i64) -> anyhow::Result<()> {
        let mut conn = pool.get().await.context("failed to get connection")?;
        cmd("CONFIG")
            .arg("SET")
            .arg("slowlog-log-slower-than")
            .arg(slowlog_threshold_us)
            .query_async::<()>(&mut conn)
            .await
            .context("failed to set slowlog threshold")?;

        cmd("CONFIG")
            .arg("SET")
            .arg("slowlog-max-len")
            .arg(1024)
            .query_async::<()>(&mut conn)
            .await
            .context("failed to set slowlog max-len")?;

        cmd("SLOWLOG")
            .arg("RESET")
            .query_async::<()>(&mut conn)
            .await
            .context("failed to reset slowlog")?;

        Ok(())
    }

    /// Reset the Redis slow log.
    pub async fn reset_slowlog(pool: &Pool) -> anyhow::Result<()> {
        let mut conn = pool.get().await.context("failed to get connection")?;
        cmd("SLOWLOG")
            .arg("RESET")
            .query_async::<()>(&mut conn)
            .await
            .context("failed to reset slowlog")?;
        Ok(())
    }

    /// Flush the Redis database (FLUSHDB).
    pub async fn flush_db(pool: &Pool) -> anyhow::Result<()> {
        let mut conn = pool.get().await.context("failed to get connection")?;
        cmd("FLUSHDB")
            .query_async::<()>(&mut conn)
            .await
            .context("failed to flush database")?;
        Ok(())
    }

    /// Fetch entries from Redis SLOWLOG.
    pub async fn fetch_slowlog(pool: &Pool, count: usize) -> anyhow::Result<Vec<SlowlogRecord>> {
        let mut conn = pool.get().await.context("failed to get connection")?;
        let raw: Value = cmd("SLOWLOG")
            .arg("GET")
            .arg(count)
            .query_async(&mut conn)
            .await
            .context("failed to query slowlog")?;

        let Value::Array(entries) = raw else {
            return Ok(Vec::new());
        };

        Ok(entries
            .into_iter()
            .filter_map(parse_slowlog_entry)
            .collect())
    }

    /// Query memory snapshot and dbsize.
    pub async fn fetch_memory_snapshot(pool: &Pool) -> anyhow::Result<MemorySnapshot> {
        let mut conn = pool.get().await.context("failed to get connection")?;
        let raw: String = cmd("INFO")
            .arg("memory")
            .query_async(&mut conn)
            .await
            .context("failed to query memory")?;

        let mut used_memory_human = String::new();
        let mut used_memory_rss_human = String::new();
        let mut fragmentation_ratio = 1.0;

        for line in raw.lines() {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            match k.trim() {
                "used_memory_human" => used_memory_human = v.trim().to_string(),
                "used_memory_rss_human" => used_memory_rss_human = v.trim().to_string(),
                "mem_fragmentation_ratio" => fragmentation_ratio = v.trim().parse().unwrap_or(1.0),
                _ => {}
            }
        }

        let total_keys: i64 = cmd("DBSIZE").query_async(&mut conn).await.unwrap_or(0);

        Ok(MemorySnapshot {
            used_memory_human,
            used_memory_rss_human,
            fragmentation_ratio,
            total_keys,
        })
    }
}

fn parse_slowlog_entry(entry: Value) -> Option<SlowlogRecord> {
    let Value::Array(fields) = entry else {
        return None;
    };
    if fields.len() < 4 {
        return None;
    }
    let id = match fields[0] {
        Value::Int(val) => val,
        _ => 0,
    };
    let timestamp = match fields[1] {
        Value::Int(val) => val,
        _ => 0,
    };
    let duration_us = match fields[2] {
        Value::Int(val) => val,
        _ => 0,
    };
    let command = match &fields[3] {
        Value::Array(cmd_parts) => cmd_parts
            .iter()
            .take(4)
            .map(|p| match p {
                Value::BulkString(bytes) => String::from_utf8_lossy(bytes).to_string(),
                other => format!("{other:?}"),
            })
            .collect::<Vec<_>>()
            .join(" "),
        _ => "unknown".to_string(),
    };
    let client_addr = if fields.len() >= 5 {
        match &fields[4] {
            Value::BulkString(bytes) => String::from_utf8_lossy(bytes).to_string(),
            _ => String::new(),
        }
    } else {
        String::new()
    };

    Some(SlowlogRecord {
        id,
        timestamp,
        duration_us,
        command,
        client_addr,
    })
}

/// Computes statistical latency distribution.
#[derive(Debug, Clone)]
pub struct LatencySummary {
    pub op_name: String,
    pub count: usize,
    pub failures: usize,
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
    pub fn empty(op_name: impl Into<String>) -> Self {
        Self {
            op_name: op_name.into(),
            count: 0,
            failures: 0,
            min_ms: 0.0,
            mean_ms: 0.0,
            p50_ms: 0.0,
            p90_ms: 0.0,
            p95_ms: 0.0,
            p99_ms: 0.0,
            max_ms: 0.0,
            throughput_ops_sec: 0.0,
        }
    }

    pub fn calculate(
        op_name: impl Into<String>,
        samples: &mut [Duration],
        total_wall_time: Duration,
    ) -> Self {
        Self::calculate_with_failures(op_name, samples, total_wall_time, 0)
    }

    pub fn calculate_with_failures(
        op_name: impl Into<String>,
        samples: &mut [Duration],
        total_wall_time: Duration,
        failures: usize,
    ) -> Self {
        let op_name = op_name.into();
        if samples.is_empty() {
            let mut summary = Self::empty(op_name);
            summary.failures = failures;
            return summary;
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
            failures,
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
            "{:<24} | {:>7} | {:>8} | {:>7.2}ms | {:>7.2}ms | {:>7.2}ms | {:>7.2}ms | {:>7.2}ms | {:>8.1}",
            self.op_name,
            self.count,
            self.failures,
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
    println!("{:-<116}", "");
    println!(
        "{:<24} | {:>7} | {:>8} | {:>9} | {:>9} | {:>9} | {:>9} | {:>9} | {:>8}",
        "Operation", "Samples", "Failures", "p50", "p90", "p95", "p99", "Max", "Ops/Sec"
    );
    println!("{:-<116}", "");
}

/// Partitions a combined wall duration between two interleaved operations
/// proportionally according to the total active time measured for each operation.
pub fn partition_wall_by_active_time(
    wall: Duration,
    op1_samples: &[Duration],
    op2_samples: &[Duration],
) -> (Duration, Duration) {
    let t1: Duration = op1_samples.iter().copied().sum();
    let t2: Duration = op2_samples.iter().copied().sum();
    let total = t1 + t2;
    if total > Duration::ZERO {
        let r1 = t1.as_secs_f64() / total.as_secs_f64();
        (wall.mul_f64(r1), wall.mul_f64(1.0 - r1))
    } else {
        (wall, wall)
    }
}

/// Simulated participant storage handles in the isolated Redis harness.
#[derive(Clone)]
pub struct SimulatedParticipant {
    pub participant: Participant,
    pub account_id: AccountId,
    pub triples: TripleStorage,
    pub presignatures: PresignatureStorage,
}

impl SimulatedParticipant {
    /// Populate a sequential range of triples starting at `base_id`.
    pub async fn populate_triples(
        self,
        base_id: u64,
        count: usize,
        participants: Vec<Participant>,
    ) -> Vec<u64> {
        let mut ids = Vec::with_capacity(count);
        for i in 0..count {
            let id = base_id + i as u64;
            let pair = dummy_pair(id, &participants);
            let Some(mut slot) = self.triples.create_slot(id, self.participant).await else {
                continue;
            };
            if slot.insert(pair, self.participant).await {
                ids.push(id);
            }
        }
        ids
    }

    /// Populate a sequential range of presignatures starting at `base_id`.
    pub async fn populate_presignatures(
        self,
        base_id: u64,
        count: usize,
        participants: Vec<Participant>,
    ) -> Vec<u64> {
        let mut ids = Vec::with_capacity(count);
        for i in 0..count {
            let id = base_id + i as u64;
            let presig = dummy_presignature(id, &participants);
            let Some(mut slot) = self.presignatures.create_slot(id, self.participant).await else {
                continue;
            };
            if slot.insert(presig, self.participant).await {
                ids.push(id);
            }
        }
        ids
    }

    /// Run the 100ms background stockpile polling loop until stopped.
    pub async fn run_polling_loop(self, stop: Arc<AtomicBool>, include_presignatures: bool) {
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        while !stop.load(Ordering::Relaxed) {
            interval.tick().await;
            let _ = self.triples.len_generated().await;
            let _ = self.triples.len_by_owner(self.participant).await;
            if include_presignatures {
                let _ = self.presignatures.len_generated().await;
                let _ = self.presignatures.len_by_owner(self.participant).await;
            }
        }
    }

    /// Concurrently insert a range of triples, measuring latency per insert and tracking failures.
    pub async fn insert_triples_measured(
        self,
        base_id: u64,
        count: usize,
        participants: Vec<Participant>,
        barrier: Arc<Barrier>,
    ) -> (Vec<Duration>, usize) {
        barrier.wait().await;
        let mut latencies = Vec::with_capacity(count);
        let mut failures = 0;

        for i in 0..count {
            let id = base_id + i as u64;
            let pair = dummy_pair(id, &participants);

            let t0 = Instant::now();
            let success = match self.triples.create_slot(id, self.participant).await {
                Some(mut slot) => slot.insert(pair, self.participant).await,
                None => false,
            };
            if success {
                latencies.push(t0.elapsed());
            } else {
                failures += 1;
            }
        }

        (latencies, failures)
    }

    /// Concurrently take a list of triple IDs, measuring latency for each take and tracking failures.
    pub async fn take_triples(
        self,
        ids: Vec<u64>,
        barrier: Option<Arc<Barrier>>,
    ) -> (Vec<Duration>, usize) {
        if let Some(b) = barrier {
            b.wait().await;
        }
        let mut latencies = Vec::with_capacity(ids.len());
        let mut failures = 0;
        for id in ids {
            let t0 = Instant::now();
            if self.triples.take(id, self.participant).await.is_some() {
                latencies.push(t0.elapsed());
            } else {
                failures += 1;
            }
        }
        (latencies, failures)
    }

    /// Concurrently invoke remove_outdated on triples storage.
    pub async fn remove_outdated_shares(
        self,
        barrier: Arc<Barrier>,
        remaining_shares: Vec<u64>,
    ) -> (Duration, anyhow::Result<RemoveOutdatedResult<u64>>) {
        barrier.wait().await;
        let t0 = Instant::now();
        let res = self
            .triples
            .remove_outdated(self.participant, &remaining_shares)
            .await;
        (t0.elapsed(), res.map_err(anyhow::Error::from))
    }

    /// Concurrently clear all triples storage.
    pub async fn clear_triples(self, barrier: Arc<Barrier>) -> (Duration, bool) {
        barrier.wait().await;
        let t0 = Instant::now();
        let ok = self.triples.clear().await;
        (t0.elapsed(), ok)
    }

    /// Concurrently clear all presignatures storage.
    pub async fn clear_presignatures(self, barrier: Arc<Barrier>) -> (Duration, bool) {
        barrier.wait().await;
        let t0 = Instant::now();
        let ok = self.presignatures.clear().await;
        (t0.elapsed(), ok)
    }

    /// Concurrently invoke remove_holder_and_prune across both triples and presignatures.
    pub async fn prune_artifacts(
        self,
        barrier: Arc<Barrier>,
        target_peer: Participant,
        threshold: usize,
        triple_ids: Vec<u64>,
        presig_ids: Vec<u64>,
    ) -> (
        Duration,
        anyhow::Result<(Vec<u64>, Vec<u64>)>,
        Duration,
        anyhow::Result<(Vec<u64>, Vec<u64>)>,
    ) {
        barrier.wait().await;
        let t0 = Instant::now();
        let triple_res = self
            .triples
            .remove_holder_and_prune(target_peer, threshold, &triple_ids)
            .await;
        let triple_elapsed = t0.elapsed();

        let t1 = Instant::now();
        let presig_res = self
            .presignatures
            .remove_holder_and_prune(target_peer, threshold, &presig_ids)
            .await;
        let presig_elapsed = t1.elapsed();

        (
            triple_elapsed,
            triple_res.map_err(anyhow::Error::from),
            presig_elapsed,
            presig_res.map_err(anyhow::Error::from),
        )
    }

    /// Concurrently insert a range of presignatures, measuring latency per insert and tracking failures.
    pub async fn insert_presignatures_measured(
        self,
        base_id: u64,
        count: usize,
        participants: Vec<Participant>,
        barrier: Arc<Barrier>,
    ) -> (Vec<Duration>, usize) {
        barrier.wait().await;
        let mut latencies = Vec::with_capacity(count);
        let mut failures = 0;

        for i in 0..count {
            let id = base_id + i as u64;
            let presig = dummy_presignature(id, &participants);

            let t0 = Instant::now();
            let success = match self.presignatures.create_slot(id, self.participant).await {
                Some(mut slot) => slot.insert(presig, self.participant).await,
                None => false,
            };
            if success {
                latencies.push(t0.elapsed());
            } else {
                failures += 1;
            }
        }

        (latencies, failures)
    }

    /// Concurrently take pairs of (triple, presignature), measuring latency for each and tracking failures.
    pub async fn take_triple_and_presig_pairs(
        self,
        barrier: Arc<Barrier>,
        triple_ids: Vec<u64>,
        presig_ids: Vec<u64>,
    ) -> (Vec<Duration>, usize, Vec<Duration>, usize) {
        barrier.wait().await;
        let count = triple_ids.len().min(presig_ids.len());
        let mut take_triple_latencies = Vec::with_capacity(count);
        let mut take_presig_latencies = Vec::with_capacity(count);
        let mut triple_failures = 0;
        let mut presig_failures = 0;

        for i in 0..count {
            let triple_id = triple_ids[i];
            let presig_id = presig_ids[i];

            let t0 = Instant::now();
            if self.triples.take(triple_id, self.participant).await.is_some() {
                take_triple_latencies.push(t0.elapsed());
            } else {
                triple_failures += 1;
            }

            let t1 = Instant::now();
            if self.presignatures.take(presig_id, self.participant).await.is_some() {
                take_presig_latencies.push(t1.elapsed());
            } else {
                presig_failures += 1;
            }
        }

        (
            take_triple_latencies,
            triple_failures,
            take_presig_latencies,
            presig_failures,
        )
    }

    /// Concurrently peek and commit reservations in a proposer race.
    pub async fn race_proposals(
        self,
        barrier: Arc<Barrier>,
        base_id: u64,
        racer_id: usize,
        proposals_per_racer: usize,
    ) -> (Vec<Duration>, Vec<Duration>) {
        barrier.wait().await;
        let mut peek_latencies = Vec::with_capacity(proposals_per_racer);
        let mut commit_latencies = Vec::with_capacity(proposals_per_racer);

        let excluded: Vec<u64> = (0..50)
            .map(|x| base_id + (x as u64) + (racer_id as u64 * 100))
            .collect();

        for _ in 0..proposals_per_racer {
            let t0 = Instant::now();
            let reservation = self.triples.peek_mine(&excluded).await;
            peek_latencies.push(t0.elapsed());

            let Some(reservation) = reservation else {
                continue;
            };
            let t1 = Instant::now();
            let taken = reservation.commit().await;
            commit_latencies.push(t1.elapsed());
            if taken.is_none() {
                tracing::debug!(
                    "lost reservation race on commit, as expected in concurrent proposers"
                );
            }
        }

        (peek_latencies, commit_latencies)
    }

    /// Concurrently insert triples and track successful IDs vs failures (e.g. during client kill tests).
    pub async fn insert_triples_tracked(
        self,
        base_id: u64,
        count: usize,
        participants: Vec<Participant>,
        barrier: Arc<Barrier>,
    ) -> (Vec<Duration>, Vec<u64>, usize) {
        barrier.wait().await;
        let mut latencies = Vec::with_capacity(count);
        let mut success_ids = Vec::with_capacity(count);
        let mut failure_count = 0;

        for i in 0..count {
            let id = base_id + (i as u64);
            let pair = dummy_pair(id, &participants);

            let t0 = Instant::now();
            let success = match self.triples.create_slot(id, self.participant).await {
                Some(mut slot) => slot.insert(pair, self.participant).await,
                None => false,
            };

            if success {
                success_ids.push(id);
            } else {
                failure_count += 1;
            }
            latencies.push(t0.elapsed());
        }

        (latencies, success_ids, failure_count)
    }

    /// Concurrently peek available artifacts from a large stockpile with an exclusion list.
    pub async fn seek_deep_stockpile(
        self,
        barrier: Arc<Barrier>,
        base_id: u64,
        worker_id: usize,
        seeks_count: usize,
        exclusions_count: usize,
    ) -> (Vec<Duration>, Vec<Duration>) {
        barrier.wait().await;
        let mut peek_latencies = Vec::with_capacity(seeks_count);
        let mut commit_latencies = Vec::with_capacity(seeks_count);

        // Exclusion list simulates accumulated rejected / timed-out IDs from prior reorg rounds
        let excluded: Vec<u64> = (0..exclusions_count)
            .map(|x| base_id + (x as u64) + (worker_id as u64 * 100))
            .collect();

        for _ in 0..seeks_count {
            let t0 = Instant::now();
            let reservation = self.triples.peek_mine(&excluded).await;
            peek_latencies.push(t0.elapsed());

            let Some(reservation) = reservation else {
                continue;
            };
            let t1 = Instant::now();
            let taken = reservation.commit().await;
            commit_latencies.push(t1.elapsed());
            if taken.is_none() {
                tracing::debug!("lost reservation race on commit in deep stockpile seek");
            }
        }

        (peek_latencies, commit_latencies)
    }

    /// Concurrently simulate proposer deliberation with partial timeout / reject drops.
    pub async fn run_proposer_churn(
        self,
        barrier: Arc<Barrier>,
        proposer_id: usize,
        rounds: usize,
        abort_percent: u8,
        deliberation_delay_ms: u64,
    ) -> (Vec<Duration>, Vec<Duration>, usize, usize) {
        barrier.wait().await;
        let mut peek_latencies = Vec::with_capacity(rounds);
        let mut commit_latencies = Vec::with_capacity(rounds);
        let mut aborted_count = 0;
        let mut committed_count = 0;

        let mut local_excluded: Vec<u64> = Vec::new();

        for round_idx in 0..rounds {
            let t0 = Instant::now();
            let reservation = self.triples.peek_mine(&local_excluded).await;
            peek_latencies.push(t0.elapsed());

            let Some(reservation) = reservation else {
                continue;
            };

            if deliberation_delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(deliberation_delay_ms)).await;
            }

            let should_abort =
                ((proposer_id * 17 + round_idx * 31) % 100) < (abort_percent as usize);
            if should_abort {
                let id = reservation.id;
                // Dropping reservation aborts pending state without commit, returning item to Redis pool
                drop(reservation);
                local_excluded.push(id);
                aborted_count += 1;
            } else {
                let t1 = Instant::now();
                if reservation.commit().await.is_some() {
                    committed_count += 1;
                }
                commit_latencies.push(t1.elapsed());
            }
        }

        (
            peek_latencies,
            commit_latencies,
            aborted_count,
            committed_count,
        )
    }
}

/// Guard managing background polling tasks. Automatically stops and joins tasks on `.stop().await`.
pub struct BackgroundPollerGuard {
    stop_flag: Arc<AtomicBool>,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl BackgroundPollerGuard {
    pub async fn stop(self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        for h in self.handles {
            let _ = h.await;
        }
    }
}

/// Standalone Redis benchmark harness.
///
/// Spawns ONLY an isolated Redis container (zero MPC node processes, zero NEAR
/// sandbox, zero smart contracts, and zero external chains).
/// Interfaces with Redis purely through `redis.triple_storage(...)` and `redis.presignature_storage(...)`.
pub struct RedisHarness {
    pub redis: Option<Redis>,
    pub redis_url: String,
    pub pool: Pool,
    pub participants: Vec<SimulatedParticipant>,
    pub flush_between: bool,
}

pub type RedisHarnessCluster = RedisHarness;

impl RedisHarness {
    /// Spawn a fresh Redis container via testcontainers and prepare N simulated participants.
    /// Notice: No MPC node processes, no NEAR sandbox, and no blockchains are spawned.
    pub async fn spawn(num_participants: usize) -> anyhow::Result<Self> {
        Self::spawn_with_pool_config(num_participants, None, None).await
    }

    /// Spawn a fresh Redis container with custom connection pool constraints (matching production deadpool settings).
    pub async fn spawn_with_pool_config(
        num_participants: usize,
        max_pool_size: Option<usize>,
        timeout: Option<Duration>,
    ) -> anyhow::Result<Self> {
        let spawner = ClusterSpawner::default()
            .network("bench-redis-harness")
            .init_network()
            .await
            .context("failed to init docker network")?;

        let redis = crate::containers::Redis::run(&spawner).await;
        let redis_url = redis.internal_address.clone();
        let pool = Self::build_pool(&redis_url, max_pool_size, timeout)?;

        Self::init(Some(redis), redis_url, pool, num_participants).await
    }

    pub fn build_pool(
        redis_url: &str,
        max_pool_size: Option<usize>,
        timeout: Option<Duration>,
    ) -> anyhow::Result<Pool> {
        let parsed_url = url::Url::parse(redis_url).context("invalid redis url")?;
        let mut builder = RedisPoolConfig::from_url(parsed_url)
            .builder()?
            .runtime(RedisRuntime::Tokio1);

        if let Some(size) = max_pool_size {
            builder = builder.max_size(size);
        }
        if let Some(to) = timeout {
            builder = builder
                .wait_timeout(Some(to))
                .create_timeout(Some(to))
                .recycle_timeout(Some(to));
        }
        Ok(builder.build()?)
    }

    /// Construct harness from an existing `Redis` container handle.
    pub async fn from_redis(redis: Redis, num_participants: usize) -> anyhow::Result<Self> {
        let pool = redis.pool();
        let redis_url = redis.internal_address.clone();
        Self::init(Some(redis), redis_url, pool, num_participants).await
    }

    /// Connect to an existing external Redis instance at the given URL (e.g. redis://127.0.0.1:6379).
    pub async fn from_url(redis_url: &str, num_participants: usize) -> anyhow::Result<Self> {
        let parsed_url = url::Url::parse(redis_url).context("invalid redis url")?;
        let cfg = RedisPoolConfig::from_url(parsed_url);
        let pool = cfg
            .create_pool(Some(RedisRuntime::Tokio1))
            .context("failed to create redis pool")?;

        Self::init(None, redis_url.to_string(), pool, num_participants).await
    }

    async fn init(
        redis: Option<Redis>,
        redis_url: String,
        pool: Pool,
        num_participants: usize,
    ) -> anyhow::Result<Self> {
        RedisDiagnostics::setup(&pool, 1000).await?;

        let mut participants = Vec::new();

        for i in 0..num_participants {
            let participant = Participant::from(i as u32);
            let account_id: AccountId = format!("node-{i}.testnet").parse().unwrap();

            // Directly use redis.triple_storage and redis.presignature_storage when available
            let (triples, presignatures) = if let Some(ref r) = redis {
                (
                    r.triple_storage(&account_id, participant),
                    r.presignature_storage(&account_id, participant),
                )
            } else {
                let t = TriplePair::storage(&pool, &account_id);
                t.set_me(participant);
                let p = Presignature::storage(&pool, &account_id);
                p.set_me(participant);
                (t, p)
            };

            participants.push(SimulatedParticipant {
                participant,
                account_id,
                triples,
                presignatures,
            });
        }

        Ok(Self {
            redis,
            redis_url,
            pool,
            participants,
            flush_between: true,
        })
    }

    pub fn participant_ids(&self) -> Vec<Participant> {
        self.participants.iter().map(|p| p.participant).collect()
    }

    /// Enable or disable FLUSHDB between benchmark scenarios (default: true).
    pub fn set_flush_between(&mut self, flush: bool) {
        self.flush_between = flush;
    }

    /// Flush the Redis database (FLUSHDB).
    pub async fn flush_db(&self) -> anyhow::Result<()> {
        RedisDiagnostics::flush_db(&self.pool).await
    }

    /// Fetch memory snapshot and total key count (DBSIZE) from Redis.
    pub async fn memory_snapshot(&self) -> anyhow::Result<MemorySnapshot> {
        RedisDiagnostics::fetch_memory_snapshot(&self.pool).await
    }

    /// Reset slowlog (and optionally FLUSHDB if flush_between is enabled) before running a test case,
    /// logging the pre-run keyspace and memory state.
    pub async fn reset_diagnostics(&self) -> anyhow::Result<()> {
        if self.flush_between {
            self.flush_db().await?;
        }
        RedisDiagnostics::reset_slowlog(&self.pool).await?;
        let mem = self.memory_snapshot().await?;
        println!(
            "   -> Keyspace pre-run: {} keys in Redis (DBSIZE), Memory: {}",
            mem.total_keys, mem.used_memory_human
        );
        Ok(())
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
            "   Keyspace post-run: {} keys in Redis (DBSIZE) | Memory: used={} rss={} frag_ratio={:.2}",
            mem.total_keys,
            mem.used_memory_human,
            mem.used_memory_rss_human,
            mem.fragmentation_ratio
        );
        Ok(())
    }

    /// Helper to print scenario summary table and diagnostics.
    pub async fn report_results(&self, results: &[LatencySummary]) -> anyhow::Result<()> {
        print_summary_header();
        for r in results {
            r.print_row();
        }
        self.print_diagnostics().await
    }

    async fn populate_all<F, Fut>(&self, base_id: u64, count: usize, f: F) -> Vec<Vec<u64>>
    where
        F: Fn(SimulatedParticipant, u64, usize, Vec<Participant>) -> Fut,
        Fut: std::future::Future<Output = Vec<u64>> + Send + 'static,
    {
        let participant_list = self.participant_ids();
        let handles: Vec<_> = self
            .participants
            .iter()
            .enumerate()
            .map(|(idx, p)| {
                let p_base = base_id + (idx as u64 * count as u64);
                tokio::spawn(f(p.clone(), p_base, count, participant_list.clone()))
            })
            .collect();

        let mut results = Vec::with_capacity(handles.len());
        for h in handles {
            results.push(h.await.unwrap_or_default());
        }
        results
    }

    /// Populate `count` triples on all participants concurrently.
    /// Returns the list of generated triple IDs grouped by participant index.
    pub async fn populate_all_triples(&self, base_id: u64, count: usize) -> Vec<Vec<u64>> {
        self.populate_all(base_id, count, SimulatedParticipant::populate_triples)
            .await
    }

    /// Populate `count` presignatures on all participants concurrently.
    /// Returns the list of generated presignature IDs grouped by participant index.
    pub async fn populate_all_presignatures(&self, base_id: u64, count: usize) -> Vec<Vec<u64>> {
        self.populate_all(base_id, count, SimulatedParticipant::populate_presignatures)
            .await
    }

    /// Spawn 100ms background stockpile polling loop across all participants.
    pub fn spawn_background_polling(&self, include_presignatures: bool) -> BackgroundPollerGuard {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let handles = self
            .participants
            .iter()
            .map(|p| {
                tokio::spawn(
                    p.clone()
                        .run_polling_loop(stop_flag.clone(), include_presignatures),
                )
            })
            .collect();

        BackgroundPollerGuard { stop_flag, handles }
    }

    /// Run intermittent blocking Lua scripts on the Redis instance until stopped or completed.
    pub async fn run_intermittent_spike(
        pool: Pool,
        stop_flag: Arc<AtomicBool>,
        spike_ms: u64,
        num_spikes: usize,
    ) {
        let spike_script = Script::new(
            r#"
            local t0 = redis.call('time')
            local limit_ms = tonumber(ARGV[1])
            while true do
                local t1 = redis.call('time')
                local elapsed_ms = (tonumber(t1[1]) - tonumber(t0[1])) * 1000 + math.floor((tonumber(t1[2]) - tonumber(t0[2])) / 1000)
                if elapsed_ms >= limit_ms then
                    break
                end
            end
            return 1
        "#,
        );

        tokio::time::sleep(Duration::from_millis(15)).await;

        for _ in 0..num_spikes {
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }
            if let Ok(mut conn) = pool.get().await {
                let _: Result<i32, _> = spike_script.arg(spike_ms).invoke_async(&mut conn).await;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Spawn a task that periodically executes a blocking Lua script on Redis.
    pub fn spawn_intermittent_spike(
        &self,
        stop_flag: Arc<AtomicBool>,
        spike_ms: u64,
        num_spikes: usize,
    ) -> Option<tokio::task::JoinHandle<()>> {
        if spike_ms == 0 || num_spikes == 0 {
            return None;
        }
        Some(tokio::spawn(Self::run_intermittent_spike(
            self.pool.clone(),
            stop_flag,
            spike_ms,
            num_spikes,
        )))
    }

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
                    .map(|ids| ids[prune_count..].to_vec())
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
        let summaries = self
            .run_concurrent_insert_and_take(workload_items)
            .await?;
        if let Some(p) = poller {
            p.stop().await;
        }

        Ok(summaries)
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
                LatencySummary::empty("commit_reservation"),
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
            .map(|racer_id| {
                tokio::spawn(p.clone().race_proposals(
                    barrier.clone(),
                    base_id,
                    racer_id,
                    proposals_per_racer,
                ))
            })
            .collect();

        let mut all_peek = Vec::new();
        let mut all_commit = Vec::new();

        for task in racer_tasks {
            let (peek, commit) = task.await?;
            all_peek.extend(peek);
            all_commit.extend(commit);
        }
        let wall = race_start.elapsed();
        let (peek_wall, commit_wall) =
            partition_wall_by_active_time(wall, &all_peek, &all_commit);

        let s1 = LatencySummary::calculate("peek_mine_contended", &mut all_peek, peek_wall);
        let s2 = LatencySummary::calculate("commit_reservation", &mut all_commit, commit_wall);

        Ok(vec![s1, s2])
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
            return Ok(vec![LatencySummary::empty("saturated_insert_triple")]);
        }

        // 1. Continuous 100ms polling across all participants
        let poller = self.spawn_background_polling(false);

        // 2. Intermittent blocking spikes on Redis main thread (simulating large Lua scripts or BGSAVE stalls)
        let spike_stop = Arc::new(AtomicBool::new(false));
        let spike_handle =
            self.spawn_intermittent_spike(spike_stop.clone(), blocking_spike_ms, num_spikes);

        // 3. High-concurrency operations across participants
        let total_items = self.participants.len() * tasks_per_participant * items_per_task;
        let run_base_id = next_id_block(total_items as u64 + 10_000);
        let barrier = Arc::new(Barrier::new(
            self.participants.len() * tasks_per_participant,
        ));
        let overall_start = Instant::now();
        let participant_list = self.participant_ids();

        let mut worker_tasks = Vec::with_capacity(self.participants.len() * tasks_per_participant);
        for (p_idx, p) in self.participants.iter().enumerate() {
            for t_idx in 0..tasks_per_participant {
                let task_id = p_idx * tasks_per_participant + t_idx;
                let base_id = run_base_id + (task_id as u64 * items_per_task as u64);
                worker_tasks.push(tokio::spawn(p.clone().insert_triples_measured(
                    base_id,
                    items_per_task,
                    participant_list.clone(),
                    barrier.clone(),
                )));
            }
        }

        let mut all_latencies = Vec::new();
        let mut total_failures = 0;
        for task in worker_tasks {
            let (lat, fails) = task.await?;
            all_latencies.extend(lat);
            total_failures += fails;
        }
        let wall = overall_start.elapsed();

        poller.stop().await;
        if let Some(h) = spike_handle {
            spike_stop.store(true, Ordering::Relaxed);
            let _ = h.await;
        }

        let summary = LatencySummary::calculate_with_failures(
            "saturated_insert_triple",
            &mut all_latencies,
            wall,
            total_failures,
        );
        Ok(vec![summary])
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
                LatencySummary::empty("deep_commit_reservation"),
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

        println!(
            "   -> Launching {num_seekers} concurrent seekers (each evaluating exclusion lists of {exclusions_count} IDs)..."
        );
        let barrier = Arc::new(Barrier::new(num_seekers));
        let overall_start = Instant::now();

        let tasks: Vec<_> = (0..num_seekers)
            .map(|worker_id| {
                tokio::spawn(p.clone().seek_deep_stockpile(
                    barrier.clone(),
                    base_id,
                    worker_id,
                    seeks_per_worker,
                    exclusions_count,
                ))
            })
            .collect();

        let mut all_peek = Vec::new();
        let mut all_commit = Vec::new();

        for t in tasks {
            let (peek, commit) = t.await?;
            all_peek.extend(peek);
            all_commit.extend(commit);
        }
        let wall = overall_start.elapsed();
        let (peek_wall, commit_wall) =
            partition_wall_by_active_time(wall, &all_peek, &all_commit);

        let s1 = LatencySummary::calculate("deep_peek_mine", &mut all_peek, peek_wall);
        let s2 =
            LatencySummary::calculate("deep_commit_reservation", &mut all_commit, commit_wall);
        Ok(vec![s1, s2])
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
    ) -> anyhow::Result<Vec<LatencySummary>> {
        self.reset_diagnostics().await?;

        if self.participants.is_empty() || initial_stockpile == 0 || num_proposers == 0 {
            return Ok(vec![
                LatencySummary::empty("churn_peek_mine"),
                LatencySummary::empty("churn_commit_reservation"),
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
            "   -> Simulating {num_proposers} proposers with {abort_percent}% deliberation timeout/abort rate across {rounds_per_proposer} rounds..."
        );
        let barrier = Arc::new(Barrier::new(num_proposers));
        let overall_start = Instant::now();

        let tasks: Vec<_> = (0..num_proposers)
            .map(|proposer_id| {
                tokio::spawn(p.clone().run_proposer_churn(
                    barrier.clone(),
                    proposer_id,
                    rounds_per_proposer,
                    abort_percent,
                    15,
                ))
            })
            .collect();

        let mut all_peek = Vec::new();
        let mut all_commit = Vec::new();
        let mut total_aborts = 0;
        let mut total_commits = 0;

        for t in tasks {
            let (peek, commit, aborted, committed) = t.await?;
            all_peek.extend(peek);
            all_commit.extend(commit);
            total_aborts += aborted;
            total_commits += committed;
        }
        let wall = overall_start.elapsed();
        let (peek_wall, commit_wall) =
            partition_wall_by_active_time(wall, &all_peek, &all_commit);

        println!(
            "   -> Churn outcome: {total_commits} successfully committed, {total_aborts} dropped back to pool on timeout/reject"
        );

        let s1 = LatencySummary::calculate("churn_peek_mine", &mut all_peek, peek_wall);
        let s2 =
            LatencySummary::calculate("churn_commit_reservation", &mut all_commit, commit_wall);
        Ok(vec![s1, s2])
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
