use std::collections::HashMap;
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

        let deadpool_redis::redis::Value::Array(entries) = raw else {
            return Ok(Vec::new());
        };

        Ok(entries.into_iter().filter_map(parse_slowlog_entry).collect())
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

        let deadpool_redis::redis::Value::Array(entries) = raw else {
            return Ok(Vec::new());
        };

        Ok(entries.into_iter().filter_map(parse_latency_record).collect())
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
            let Some(rest) = line.strip_prefix("cmdstat_") else {
                continue;
            };
            let Some((cmd, values)) = rest.split_once(':') else {
                continue;
            };

            let mut calls = 0;
            let mut usec = 0;
            let mut usec_per_call = 0.0;
            for part in values.split(',') {
                let Some((k, v)) = part.split_once('=') else {
                    continue;
                };
                match k {
                    "calls" => calls = v.parse().unwrap_or(0),
                    "usec" => usec = v.parse().unwrap_or(0),
                    "usec_per_call" => usec_per_call = v.parse().unwrap_or(0.0),
                    _ => {}
                }
            }
            stats.insert(cmd.to_string(), CommandStat { calls, usec, usec_per_call });
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
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            match k.trim() {
                "used_memory_human" => used_memory_human = v.trim().to_string(),
                "used_memory_rss_human" => used_memory_rss_human = v.trim().to_string(),
                "mem_fragmentation_ratio" => {
                    fragmentation_ratio = v.trim().parse().unwrap_or(1.0)
                }
                _ => {}
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

fn parse_slowlog_entry(entry: deadpool_redis::redis::Value) -> Option<SlowlogRecord> {
    let deadpool_redis::redis::Value::Array(fields) = entry else {
        return None;
    };
    if fields.len() < 4 {
        return None;
    }
    let id = match fields[0] {
        deadpool_redis::redis::Value::Int(val) => val,
        _ => 0,
    };
    let timestamp = match fields[1] {
        deadpool_redis::redis::Value::Int(val) => val,
        _ => 0,
    };
    let duration_us = match fields[2] {
        deadpool_redis::redis::Value::Int(val) => val,
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

fn parse_latency_record(entry: deadpool_redis::redis::Value) -> Option<LatencyRecord> {
    let deadpool_redis::redis::Value::Array(fields) = entry else {
        return None;
    };
    if fields.len() < 4 {
        return None;
    }
    let event = match &fields[0] {
        deadpool_redis::redis::Value::BulkString(bytes) => {
            String::from_utf8_lossy(bytes).to_string()
        }
        _ => "unknown".to_string(),
    };
    let timestamp = match fields[1] {
        deadpool_redis::redis::Value::Int(val) => val,
        _ => 0,
    };
    let latest_latency_ms = match fields[2] {
        deadpool_redis::redis::Value::Int(val) => val,
        _ => 0,
    };
    let max_latency_ms = match fields[3] {
        deadpool_redis::redis::Value::Int(val) => val,
        _ => 0,
    };
    Some(LatencyRecord {
        event,
        timestamp,
        latest_latency_ms,
        max_latency_ms,
    })
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
    pub fn empty(op_name: impl Into<String>) -> Self {
        Self {
            op_name: op_name.into(),
            count: 0,
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

    pub fn calculate(op_name: impl Into<String>, samples: &mut [Duration], total_wall_time: Duration) -> Self {
        let op_name = op_name.into();
        if samples.is_empty() {
            return Self::empty(op_name);
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
    pub async fn populate_triples(&self, base_id: u64, count: usize, participants: &[Participant]) -> Vec<u64> {
        let mut ids = Vec::with_capacity(count);
        for i in 0..count {
            let id = base_id + i as u64;
            let pair = dummy_pair(id, participants);
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
    pub async fn populate_presignatures(&self, base_id: u64, count: usize, participants: &[Participant]) -> Vec<u64> {
        let mut ids = Vec::with_capacity(count);
        for i in 0..count {
            let id = base_id + i as u64;
            let presig = dummy_presignature(id, participants);
            let Some(mut slot) = self.presignatures.create_slot(id, self.participant).await else {
                continue;
            };
            if slot.insert(presig, self.participant).await {
                ids.push(id);
            }
        }
        ids
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
    pub pool: deadpool_redis::Pool,
    pub participants: Vec<SimulatedParticipant>,
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
    ) -> anyhow::Result<deadpool_redis::Pool> {
        let parsed_url = url::Url::parse(redis_url).context("invalid redis url")?;
        let mut builder = deadpool_redis::Config::from_url(parsed_url)
            .builder()?
            .runtime(deadpool_redis::Runtime::Tokio1);

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
        let cfg = deadpool_redis::Config::from_url(parsed_url);
        let pool = cfg
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .context("failed to create redis pool")?;

        Self::init(None, redis_url.to_string(), pool, num_participants).await
    }

    async fn init(
        redis: Option<Redis>,
        redis_url: String,
        pool: deadpool_redis::Pool,
        num_participants: usize,
    ) -> anyhow::Result<Self> {
        RedisDiagnostics::setup(&pool, 1000, 1).await?;

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
        })
    }

    pub fn participant_ids(&self) -> Vec<Participant> {
        self.participants.iter().map(|p| p.participant).collect()
    }

    /// Create or retrieve a triple storage handle for an arbitrary account and participant.
    pub fn triple_storage(&self, account_id: &AccountId, me: Participant) -> TripleStorage {
        if let Some(ref r) = self.redis {
            return r.triple_storage(account_id, me);
        }
        let t = TriplePair::storage(&self.pool, account_id);
        t.set_me(me);
        t
    }

    /// Create or retrieve a presignature storage handle for an arbitrary account and participant.
    pub fn presignature_storage(&self, account_id: &AccountId, me: Participant) -> PresignatureStorage {
        if let Some(ref r) = self.redis {
            return r.presignature_storage(account_id, me);
        }
        let p = Presignature::storage(&self.pool, account_id);
        p.set_me(me);
        p
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

    /// Helper to print scenario summary table and diagnostics.
    pub async fn report_results(&self, results: &[LatencySummary]) -> anyhow::Result<()> {
        print_summary_header();
        for r in results {
            r.print_row();
        }
        self.print_diagnostics().await
    }

    /// Populate `count` triples on all participants concurrently.
    /// Returns the list of generated triple IDs grouped by participant index.
    pub async fn populate_all_triples(&self, base_id: u64, count: usize) -> Vec<Vec<u64>> {
        let participant_list = self.participant_ids();
        let mut handles = Vec::with_capacity(self.participants.len());

        for (idx, p) in self.participants.iter().enumerate() {
            let p = p.clone();
            let p_list = participant_list.clone();
            let p_base = base_id + (idx as u64 * count as u64);

            handles.push(tokio::spawn(async move {
                p.populate_triples(p_base, count, &p_list).await
            }));
        }

        let mut results = Vec::with_capacity(handles.len());
        for h in handles {
            results.push(h.await.unwrap_or_default());
        }
        results
    }

    /// Populate `count` presignatures on all participants concurrently.
    /// Returns the list of generated presignature IDs grouped by participant index.
    pub async fn populate_all_presignatures(&self, base_id: u64, count: usize) -> Vec<Vec<u64>> {
        let participant_list = self.participant_ids();
        let mut handles = Vec::with_capacity(self.participants.len());

        for (idx, p) in self.participants.iter().enumerate() {
            let p = p.clone();
            let p_list = participant_list.clone();
            let p_base = base_id + (idx as u64 * count as u64);

            handles.push(tokio::spawn(async move {
                p.populate_presignatures(p_base, count, &p_list).await
            }));
        }

        let mut results = Vec::with_capacity(handles.len());
        for h in handles {
            results.push(h.await.unwrap_or_default());
        }
        results
    }

    /// Spawn 100ms background stockpile polling loop across all participants.
    pub fn spawn_background_polling(&self, include_presignatures: bool) -> BackgroundPollerGuard {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::with_capacity(self.participants.len());

        for p in &self.participants {
            let triples = p.triples.clone();
            let presignatures = p.presignatures.clone();
            let me = p.participant;
            let stop = stop_flag.clone();

            handles.push(tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_millis(100));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                while !stop.load(Ordering::Relaxed) {
                    interval.tick().await;
                    let _ = triples.len_generated().await;
                    let _ = triples.len_by_owner(me).await;
                    if include_presignatures {
                        let _ = presignatures.len_generated().await;
                        let _ = presignatures.len_by_owner(me).await;
                    }
                }
            }));
        }

        BackgroundPollerGuard { stop_flag, handles }
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
        let pool = self.pool.clone();
        Some(tokio::spawn(async move {
            let spike_script = deadpool_redis::redis::Script::new(r#"
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
            "#);

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
        }))
    }

    /// Sever all client connections to Redis using `CLIENT KILL TYPE normal SKIPME yes`.
    pub async fn kill_client_connections_on_pool(pool: &deadpool_redis::Pool) -> anyhow::Result<i64> {
        let mut conn = pool.get().await.context("failed to get connection")?;
        let count: i64 = deadpool_redis::redis::cmd("CLIENT")
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

        if self.participants.is_empty() || items_per_participant == 0 {
            return Ok(vec![
                LatencySummary::empty("concurrent_insert_triple"),
                LatencySummary::empty("concurrent_take_triple"),
            ]);
        }

        let run_base_id = next_id_block((self.participants.len() * items_per_participant) as u64 + 1000);
        let barrier = Arc::new(Barrier::new(self.participants.len()));
        let mut insert_tasks = Vec::with_capacity(self.participants.len());
        let overall_start = Instant::now();
        let participant_list = self.participant_ids();

        for (node_idx, p) in self.participants.iter().enumerate() {
            let triples = p.triples.clone();
            let me = p.participant;
            let barrier = barrier.clone();
            let participants = participant_list.clone();

            insert_tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                let mut insert_triple_latencies = Vec::with_capacity(items_per_participant);
                let base_id = run_base_id + (node_idx as u64 * items_per_participant as u64);

                for i in 0..items_per_participant {
                    let id = base_id + (i as u64);
                    let pair = dummy_pair(id, &participants);

                    let t0 = Instant::now();
                    let Some(mut slot) = triples.create_slot(id, me).await else {
                        continue;
                    };
                    slot.insert(pair, me).await;
                    insert_triple_latencies.push(t0.elapsed());
                }

                insert_triple_latencies
            }));
        }

        let mut all_insert_latencies = Vec::with_capacity(self.participants.len() * items_per_participant);
        for task in insert_tasks {
            all_insert_latencies.extend(task.await?);
        }
        let insert_wall = overall_start.elapsed();

        // Concurrent taking of the inserted items
        let barrier = Arc::new(Barrier::new(self.participants.len()));
        let mut take_tasks = Vec::with_capacity(self.participants.len());
        let take_start = Instant::now();

        for (node_idx, p) in self.participants.iter().enumerate() {
            let triples = p.triples.clone();
            let me = p.participant;
            let barrier = barrier.clone();

            take_tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                let mut take_latencies = Vec::with_capacity(items_per_participant);
                let base_id = run_base_id + (node_idx as u64 * items_per_participant as u64);

                for i in 0..items_per_participant {
                    let id = base_id + (i as u64);
                    let t0 = Instant::now();
                    triples.take(id, me).await;
                    take_latencies.push(t0.elapsed());
                }

                take_latencies
            }));
        }

        let mut all_take_latencies = Vec::with_capacity(self.participants.len() * items_per_participant);
        for task in take_tasks {
            all_take_latencies.extend(task.await?);
        }
        let take_wall = take_start.elapsed();

        let s1 = LatencySummary::calculate("concurrent_insert_triple", &mut all_insert_latencies, insert_wall);
        let s2 = LatencySummary::calculate("concurrent_take_triple", &mut all_take_latencies, take_wall);

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
        let all_ids = self.populate_all_triples(run_base_id, stockpile_count).await;

        // 2. Prepare remaining shares (simulating that `prune_count` items were consumed/outdated)
        let barrier = Arc::new(Barrier::new(self.participants.len()));
        let mut storm_tasks = Vec::new();
        let storm_start = Instant::now();

        for (node_idx, p) in self.participants.iter().enumerate() {
            let triples = p.triples.clone();
            let me = p.participant;
            let barrier = barrier.clone();
            let remaining_shares = all_ids.get(node_idx).map(|ids| ids[prune_count..].to_vec()).unwrap_or_default();

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

        Ok(vec![LatencySummary::calculate("remove_outdated_storm", &mut latencies, wall)])
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
        let summaries = self.bench_concurrent_insert_and_take(workload_items).await?;
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

        let p = self.participants.get(participant_idx).context("invalid participant index")?;
        let triples = p.triples.clone();
        let participant_list = self.participant_ids();

        println!("   -> Stockpiling {initial_stockpile} triples on participant {participant_idx}...");
        let base_id = next_id_block(initial_stockpile as u64 + 1000);
        p.populate_triples(base_id, initial_stockpile, &participant_list).await;

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

    /// SCENARIO 5: Production Cascading Saturation & Head-of-Line Blocking (reproducing 50ms - 6s latencies).
    /// Simulates production conditions:
    /// 1. 100ms background stockpile polling storms (continuous HLEN/SCARD).
    /// 2. High concurrency (many concurrent tasks competing for connection pool slots).
    /// 3. Intermittent Redis blocking events (simulating long remove_outdated Lua scripts or BGSAVE freezes).
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
        let spike_handle = self.spawn_intermittent_spike(spike_stop.clone(), blocking_spike_ms, num_spikes);

        // 3. High-concurrency operations across participants
        let total_items = self.participants.len() * tasks_per_participant * items_per_task;
        let run_base_id = next_id_block(total_items as u64 + 10_000);
        let barrier = Arc::new(Barrier::new(self.participants.len() * tasks_per_participant));
        let mut worker_tasks = Vec::new();
        let overall_start = Instant::now();
        let participant_list = self.participant_ids();

        for (p_idx, p) in self.participants.iter().enumerate() {
            for t_idx in 0..tasks_per_participant {
                let triples = p.triples.clone();
                let me = p.participant;
                let barrier = barrier.clone();
                let participants = participant_list.clone();
                let task_id = p_idx * tasks_per_participant + t_idx;
                let base_id = run_base_id + (task_id as u64 * items_per_task as u64);

                worker_tasks.push(tokio::spawn(async move {
                    barrier.wait().await;
                    let mut latencies = Vec::with_capacity(items_per_task);

                    for i in 0..items_per_task {
                        let id = base_id + (i as u64);
                        let pair = dummy_pair(id, &participants);

                        let t0 = Instant::now();
                        if let Some(mut slot) = triples.create_slot(id, me).await {
                            slot.insert(pair, me).await;
                        }
                        latencies.push(t0.elapsed());
                    }

                    latencies
                }));
            }
        }

        let mut all_latencies = Vec::new();
        for task in worker_tasks {
            all_latencies.extend(task.await?);
        }
        let wall = overall_start.elapsed();

        poller.stop().await;
        if let Some(h) = spike_handle {
            spike_stop.store(true, Ordering::Relaxed);
            let _ = h.await;
        }

        let summary = LatencySummary::calculate("saturated_insert_triple", &mut all_latencies, wall);
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
        self.populate_all_triples(triples_base, stockpile_per_participant).await;
        self.populate_all_presignatures(presigs_base, stockpile_per_participant).await;

        let pre_mem = RedisDiagnostics::fetch_memory_snapshot(&self.pool).await?;
        println!(
            "   -> Pre-clear keyspace: {} keys in Redis, Memory: {}",
            pre_mem.total_keys, pre_mem.used_memory_human
        );

        let barrier = Arc::new(Barrier::new(num_p * 2));
        let mut clear_triple_tasks = Vec::with_capacity(num_p);
        let mut clear_presig_tasks = Vec::with_capacity(num_p);
        let clear_start = Instant::now();

        for p in &self.participants {
            let triples = p.triples.clone();
            let b1 = barrier.clone();
            clear_triple_tasks.push(tokio::spawn(async move {
                b1.wait().await;
                let t0 = Instant::now();
                let ok = triples.clear().await;
                (t0.elapsed(), ok)
            }));

            let presignatures = p.presignatures.clone();
            let b2 = barrier.clone();
            clear_presig_tasks.push(tokio::spawn(async move {
                b2.wait().await;
                let t0 = Instant::now();
                let ok = presignatures.clear().await;
                (t0.elapsed(), ok)
            }));
        }

        let mut triple_latencies = Vec::with_capacity(num_p);
        for t in clear_triple_tasks {
            let (elapsed, ok) = t.await?;
            assert!(ok, "triples clear should succeed");
            triple_latencies.push(elapsed);
        }

        let mut presig_latencies = Vec::with_capacity(num_p);
        for t in clear_presig_tasks {
            let (elapsed, ok) = t.await?;
            assert!(ok, "presignatures clear should succeed");
            presig_latencies.push(elapsed);
        }
        let wall = clear_start.elapsed();

        let post_mem = RedisDiagnostics::fetch_memory_snapshot(&self.pool).await?;
        println!(
            "   -> Post-clear keyspace: {} keys remaining in Redis, Memory: {}",
            post_mem.total_keys, post_mem.used_memory_human
        );

        let s1 = LatencySummary::calculate("clear_triples_storm", &mut triple_latencies, wall);
        let s2 = LatencySummary::calculate("clear_presigs_storm", &mut presig_latencies, wall);
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
        let triple_stockpile_ids = self.populate_all_triples(stockpile_triples_base, items_per_participant).await;
        let presig_stockpile_ids = self.populate_all_presignatures(stockpile_presigs_base, items_per_participant).await;

        // 1. Background 100ms polling for all participants (both triples and presignatures)
        let poller = self.spawn_background_polling(true);

        // 2. Launch concurrent workers:
        // - Generators creating new triples
        // - Generators creating new presignatures
        // - Signers taking 1 triple + 1 presignature
        let barrier = Arc::new(Barrier::new(num_p * 3));
        let mut triple_gen_tasks = Vec::with_capacity(num_p);
        let mut presig_gen_tasks = Vec::with_capacity(num_p);
        let mut signer_tasks = Vec::with_capacity(num_p);
        let overall_start = Instant::now();

        for (node_idx, p) in self.participants.iter().enumerate() {
            let me = p.participant;
            let participants = participant_list.clone();

            // Triple generator task
            {
                let triples = p.triples.clone();
                let b = barrier.clone();
                let p_list = participants.clone();
                let base_id = gen_base + (node_idx as u64 * items_per_participant as u64 * 2);

                triple_gen_tasks.push(tokio::spawn(async move {
                    b.wait().await;
                    let mut latencies = Vec::with_capacity(items_per_participant);
                    for i in 0..items_per_participant {
                        let id = base_id + (i as u64);
                        let pair = dummy_pair(id, &p_list);
                        let t0 = Instant::now();
                        if let Some(mut slot) = triples.create_slot(id, me).await {
                            slot.insert(pair, me).await;
                        }
                        latencies.push(t0.elapsed());
                    }
                    latencies
                }));
            }

            // Presignature generator task
            {
                let presignatures = p.presignatures.clone();
                let b = barrier.clone();
                let p_list = participants.clone();
                let base_id = gen_base + (node_idx as u64 * items_per_participant as u64 * 2) + items_per_participant as u64;

                presig_gen_tasks.push(tokio::spawn(async move {
                    b.wait().await;
                    let mut latencies = Vec::with_capacity(items_per_participant);
                    for i in 0..items_per_participant {
                        let id = base_id + (i as u64);
                        let presig = dummy_presignature(id, &p_list);
                        let t0 = Instant::now();
                        if let Some(mut slot) = presignatures.create_slot(id, me).await {
                            slot.insert(presig, me).await;
                        }
                        latencies.push(t0.elapsed());
                    }
                    latencies
                }));
            }

            // Signer consumer task (takes 1 triple and 1 presignature per signature request)
            {
                let triples = p.triples.clone();
                let presignatures = p.presignatures.clone();
                let b = barrier.clone();
                let my_triple_ids = triple_stockpile_ids.get(node_idx).cloned().unwrap_or_default();
                let my_presig_ids = presig_stockpile_ids.get(node_idx).cloned().unwrap_or_default();

                signer_tasks.push(tokio::spawn(async move {
                    b.wait().await;
                    let count = my_triple_ids.len().min(my_presig_ids.len());
                    let mut take_triple_latencies = Vec::with_capacity(count);
                    let mut take_presig_latencies = Vec::with_capacity(count);

                    for i in 0..count {
                        let triple_id = my_triple_ids[i];
                        let presig_id = my_presig_ids[i];

                        let t0 = Instant::now();
                        let _ = triples.take(triple_id, me).await;
                        take_triple_latencies.push(t0.elapsed());

                        let t1 = Instant::now();
                        let _ = presignatures.take(presig_id, me).await;
                        take_presig_latencies.push(t1.elapsed());
                    }
                    (take_triple_latencies, take_presig_latencies)
                }));
            }
        }

        let mut all_insert_triples = Vec::with_capacity(num_p * items_per_participant);
        for t in triple_gen_tasks {
            all_insert_triples.extend(t.await?);
        }

        let mut all_insert_presigs = Vec::with_capacity(num_p * items_per_participant);
        for t in presig_gen_tasks {
            all_insert_presigs.extend(t.await?);
        }

        let mut all_take_triples = Vec::with_capacity(num_p * items_per_participant);
        let mut all_take_presigs = Vec::with_capacity(num_p * items_per_participant);
        for t in signer_tasks {
            let (tt, tp) = t.await?;
            all_take_triples.extend(tt);
            all_take_presigs.extend(tp);
        }
        let wall = overall_start.elapsed();

        poller.stop().await;

        let s1 = LatencySummary::calculate("mixed_insert_triple", &mut all_insert_triples, wall);
        let s2 = LatencySummary::calculate("mixed_insert_presig", &mut all_insert_presigs, wall);
        let s3 = LatencySummary::calculate("mixed_take_triple", &mut all_take_triples, wall);
        let s4 = LatencySummary::calculate("mixed_take_presig", &mut all_take_presigs, wall);

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
        let triple_ids_by_p = self.populate_all_triples(triples_base, items_per_participant).await;
        let presig_ids_by_p = self.populate_all_presignatures(presigs_base, items_per_participant).await;

        let threshold = (num_p * 2 / 3).max(1);
        let barrier = Arc::new(Barrier::new(num_p));
        let mut tasks = Vec::with_capacity(num_p);
        let prune_start = Instant::now();

        for (node_idx, p) in self.participants.iter().enumerate() {
            let triples = p.triples.clone();
            let presignatures = p.presignatures.clone();
            let barrier = barrier.clone();
            let my_triple_ids = triple_ids_by_p.get(node_idx).cloned().unwrap_or_default();
            let my_presig_ids = presig_ids_by_p.get(node_idx).cloned().unwrap_or_default();

            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                let t0 = Instant::now();
                let triple_res = triples.remove_holder_and_prune(target_peer, threshold, &my_triple_ids).await;
                let triple_elapsed = t0.elapsed();

                let t1 = Instant::now();
                let presig_res = presignatures.remove_holder_and_prune(target_peer, threshold, &my_presig_ids).await;
                let presig_elapsed = t1.elapsed();

                (triple_elapsed, triple_res, presig_elapsed, presig_res)
            }));
        }

        let mut all_triple_latencies = Vec::with_capacity(num_p);
        let mut all_presig_latencies = Vec::with_capacity(num_p);

        for t in tasks {
            let (t_lat, t_res, p_lat, p_res) = t.await?;
            assert!(t_res.is_ok(), "triples remove_holder_and_prune should succeed");
            assert!(p_res.is_ok(), "presignatures remove_holder_and_prune should succeed");
            all_triple_latencies.push(t_lat);
            all_presig_latencies.push(p_lat);
        }
        let wall = prune_start.elapsed();

        let s1 = LatencySummary::calculate("sync_prune_triples", &mut all_triple_latencies, wall);
        let s2 = LatencySummary::calculate("sync_prune_presigs", &mut all_presig_latencies, wall);
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
        let pool = self.pool.clone();
        let killer_barrier = barrier.clone();
        let killer_task = tokio::spawn(async move {
            killer_barrier.wait().await;
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
        });

        // 2. Active participant tasks
        let mut worker_tasks = Vec::with_capacity(num_p);
        let overall_start = Instant::now();

        for (node_idx, p) in self.participants.iter().enumerate() {
            let triples = p.triples.clone();
            let me = p.participant;
            let b = barrier.clone();
            let participants = participant_list.clone();
            let base_id = run_base_id + (node_idx as u64 * items_per_participant as u64);

            worker_tasks.push(tokio::spawn(async move {
                b.wait().await;
                let mut latencies = Vec::with_capacity(items_per_participant);
                let mut success_ids = Vec::new();
                let mut failure_count = 0;

                for i in 0..items_per_participant {
                    let id = base_id + (i as u64);
                    let pair = dummy_pair(id, &participants);

                    let t0 = Instant::now();
                    let success = match triples.create_slot(id, me).await {
                        Some(mut slot) => slot.insert(pair, me).await,
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
            }));
        }

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
        let mut take_tasks = Vec::with_capacity(all_success_ids.len());
        let take_start = Instant::now();

        for (node_idx, ids) in all_success_ids {
            let p = &self.participants[node_idx];
            let triples = p.triples.clone();
            let me = p.participant;

            take_tasks.push(tokio::spawn(async move {
                let mut take_lats = Vec::with_capacity(ids.len());
                for id in ids {
                    let t0 = Instant::now();
                    let _ = triples.take(id, me).await;
                    take_lats.push(t0.elapsed());
                }
                take_lats
            }));
        }

        let mut all_take_latencies = Vec::new();
        for t in take_tasks {
            all_take_latencies.extend(t.await?);
        }
        let take_wall = take_start.elapsed();

        let s1 = LatencySummary::calculate("insert_under_client_kill", &mut all_insert_latencies, insert_wall);
        let s2 = LatencySummary::calculate("take_post_reconnect", &mut all_take_latencies, take_wall);
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
