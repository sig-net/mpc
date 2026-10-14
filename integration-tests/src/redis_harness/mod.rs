pub mod config;
pub mod diagnostics;
pub mod participant;
pub mod scenarios;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use cait_sith::protocol::Participant;
pub use deadpool_redis::redis;
use deadpool_redis::{Config as RedisPoolConfig, Pool, Runtime as RedisRuntime};
use mpc_node::protocol::presignature::Presignature;
use mpc_node::storage::triple_storage::TriplePair;
use near_account_id::AccountId;
use redis::Script;

use crate::cluster::spawner::ClusterSpawner;
use crate::containers::Redis;

pub use config::RedisHarnessConfig;
pub use diagnostics::{
    partition_wall_by_active_time, print_summary_header, LatencySummary, MemorySnapshot,
    RedisDiagnostics, SlowlogRecord,
};
pub use participant::{
    dummy_pair, dummy_presignature, dummy_triple, next_id_block, BackgroundPollerGuard,
    SimulatedParticipant,
};

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
    pub config: RedisHarnessConfig,
}

impl RedisHarness {
    /// Initialize a harness using the provided `RedisHarnessConfig`.
    pub async fn new(config: RedisHarnessConfig) -> anyhow::Result<Self> {
        if let Some(ref url) = config.redis_url.clone() {
            Self::from_url_with_config(url, config).await
        } else {
            Self::spawn_with_config(config).await
        }
    }

    /// Spawn a fresh Redis container via testcontainers and prepare N simulated participants.
    /// Notice: No MPC node processes, no NEAR sandbox, and no blockchains are spawned.
    pub async fn spawn(num_participants: usize) -> anyhow::Result<Self> {
        Self::spawn_with_pool_config(num_participants, None, None).await
    }

    /// Spawn a fresh Redis container with full configuration.
    pub async fn spawn_with_config(config: RedisHarnessConfig) -> anyhow::Result<Self> {
        let spawner = ClusterSpawner::default()
            .network("bench-redis-harness")
            .init_network()
            .await
            .context("failed to init docker network")?;

        let redis = crate::containers::Redis::run(&spawner).await;
        let redis_url = redis.internal_address.clone();
        let pool = Self::build_pool(&redis_url, config.max_pool_size, config.pool_timeout)?;

        Self::init(Some(redis), redis_url, pool, config).await
    }

    /// Spawn a fresh Redis container with custom connection pool constraints (matching production deadpool settings).
    pub async fn spawn_with_pool_config(
        num_participants: usize,
        max_pool_size: Option<usize>,
        timeout: Option<Duration>,
    ) -> anyhow::Result<Self> {
        let config = RedisHarnessConfig::new(num_participants)
            .with_pool_size(max_pool_size)
            .with_pool_timeout(timeout);
        Self::spawn_with_config(config).await
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
        let config = RedisHarnessConfig::new(num_participants);
        Self::init(Some(redis), redis_url, pool, config).await
    }

    /// Connect to an existing external Redis instance at the given URL (e.g. redis://127.0.0.1:6379).
    pub async fn from_url(redis_url: &str, num_participants: usize) -> anyhow::Result<Self> {
        Self::from_url_with_pool_config(redis_url, num_participants, None, None).await
    }

    /// Connect to an existing external Redis instance with explicit configuration.
    pub async fn from_url_with_config(
        redis_url: &str,
        mut config: RedisHarnessConfig,
    ) -> anyhow::Result<Self> {
        config.redis_url = Some(redis_url.to_string());
        let pool = Self::build_pool(redis_url, config.max_pool_size, config.pool_timeout)?;
        Self::init(None, redis_url.to_string(), pool, config).await
    }

    /// Connect to an existing external Redis instance with explicit connection pool configuration.
    pub async fn from_url_with_pool_config(
        redis_url: &str,
        num_participants: usize,
        max_pool_size: Option<usize>,
        timeout: Option<Duration>,
    ) -> anyhow::Result<Self> {
        let config = RedisHarnessConfig::new(num_participants)
            .with_pool_size(max_pool_size)
            .with_pool_timeout(timeout)
            .with_redis_url(redis_url);
        Self::from_url_with_config(redis_url, config).await
    }

    async fn init(
        redis: Option<Redis>,
        redis_url: String,
        pool: Pool,
        config: RedisHarnessConfig,
    ) -> anyhow::Result<Self> {
        RedisDiagnostics::setup(&pool, 1000).await?;

        let mut participants = Vec::new();

        for i in 0..config.num_participants {
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

        let flush_between = config.flush_between;
        Ok(Self {
            redis,
            redis_url,
            pool,
            participants,
            flush_between,
            config,
        })
    }

    pub fn participant_ids(&self) -> Vec<Participant> {
        self.participants.iter().map(|p| p.participant).collect()
    }

    /// Enable or disable FLUSHDB between benchmark scenarios (default: true).
    pub fn set_flush_between(&mut self, flush: bool) {
        self.flush_between = flush;
        self.config.flush_between = flush;
    }

    /// Flush the Redis database (FLUSHDB).
    pub async fn flush_db(&self) -> anyhow::Result<()> {
        RedisDiagnostics::flush_db(&self.pool).await
    }

    /// Fetch memory snapshot and total key count (DBSIZE) from Redis.
    pub async fn memory_snapshot(&self) -> anyhow::Result<MemorySnapshot> {
        RedisDiagnostics::fetch_memory_snapshot(&self.pool).await
    }

    /// Clear all in-memory reservations across all participants' storage handles.
    pub async fn reset_reservations(&self) {
        for p in &self.participants {
            p.reset_reservations().await;
        }
    }

    /// Reset slowlog, clear in-memory reservations (and optionally FLUSHDB if flush_between is enabled)
    /// before running a test case, logging the pre-run keyspace and memory state.
    pub async fn reset_diagnostics(&self) -> anyhow::Result<()> {
        if self.flush_between {
            self.flush_db().await?;
        }
        self.reset_reservations().await;
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
        let slowlog = RedisDiagnostics::fetch_slowlog(&self.pool, 20).await?;
        println!("\n  [Redis Diagnostics]");
        if slowlog.is_empty() {
            println!("   Slowlog (>=1ms): None recorded (all commands executed under 1ms)");
        } else {
            println!("   Slowlog (top operations >=1ms):");
            for s in slowlog {
                let tag = if s.command.starts_with("HLEN") || s.command.starts_with("SCARD") {
                    " [background poller]"
                } else {
                    ""
                };
                println!(
                    "     * ID {}: {:>7.2}ms | Cmd: {}{}",
                    s.id,
                    s.duration_us as f64 / 1000.0,
                    s.command,
                    tag
                );
            }
        }

        let mem = RedisDiagnostics::fetch_memory_snapshot(&self.pool).await?;
        let status = self.pool.status();
        println!(
            "   Keyspace post-run: {} keys in Redis (DBSIZE) | Memory: used={} rss={} frag_ratio={:.2} | Pool: max={} active={} available={}",
            mem.total_keys,
            mem.used_memory_human,
            mem.used_memory_rss_human,
            mem.fragmentation_ratio,
            status.max_size,
            status.size,
            status.available
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
}
