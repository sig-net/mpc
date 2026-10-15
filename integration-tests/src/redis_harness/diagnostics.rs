use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use deadpool_redis::redis::{cmd, Script, Value};
use deadpool_redis::{Config as RedisPoolConfig, Hook, Pool, Runtime as RedisRuntime, Status};

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

/// Client object for interacting directly with the Redis connection pool,
/// server administration, diagnostics, and structural stress utilities.
#[derive(Clone)]
pub struct RedisDiagnosticsClient {
    pub pool: Pool,
}

impl RedisDiagnosticsClient {
    /// Initialize the Redis diagnostics client from a URL and options,
    /// constructing the connection pool and configuring slowlog thresholds.
    pub async fn new(
        redis_url: &str,
        max_pool_size: Option<usize>,
        timeout: Option<Duration>,
        slowlog_threshold_us: i64,
        slowlog_max_len: i64,
    ) -> anyhow::Result<Self> {
        let pool = Self::build_pool(redis_url, max_pool_size, timeout)?;
        let client = Self { pool };
        client.setup(slowlog_threshold_us, slowlog_max_len).await?;
        Ok(client)
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
                .recycle_timeout(Some(to))
                .post_create(Hook::sync_fn(move |conn, _| {
                    conn.set_response_timeout(to);
                    Ok(())
                }));
        }
        Ok(builder.build()?)
    }

    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    pub fn status(&self) -> Status {
        self.pool.status()
    }

    /// Configure Redis to log all commands slower than `slowlog_threshold_us` (e.g. 1000us = 1ms)
    /// and set maximum slowlog buffer to `slowlog_max_len`.
    pub async fn setup(
        &self,
        slowlog_threshold_us: i64,
        slowlog_max_len: i64,
    ) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await.context("failed to get connection")?;
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
            .arg(slowlog_max_len)
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
    pub async fn reset_slowlog(&self) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await.context("failed to get connection")?;
        cmd("SLOWLOG")
            .arg("RESET")
            .query_async::<()>(&mut conn)
            .await
            .context("failed to reset slowlog")?;
        Ok(())
    }

    /// Flush the Redis database (FLUSHDB).
    pub async fn flush_db(&self) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await.context("failed to get connection")?;
        cmd("FLUSHDB")
            .query_async::<()>(&mut conn)
            .await
            .context("failed to flush database")?;
        Ok(())
    }

    /// Fetch entries from Redis SLOWLOG.
    pub async fn fetch_slowlog(&self, count: usize) -> anyhow::Result<Vec<SlowlogRecord>> {
        let mut conn = self.pool.get().await.context("failed to get connection")?;
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
    pub async fn fetch_memory_snapshot(&self) -> anyhow::Result<MemorySnapshot> {
        let mut conn = self.pool.get().await.context("failed to get connection")?;
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

    /// Print slowlog entries and memory stats captured during the last run.
    pub async fn print_diagnostics(&self) -> anyhow::Result<()> {
        let slowlog = self.fetch_slowlog(20).await?;
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

        let mem = self.fetch_memory_snapshot().await?;
        let status = self.status();
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

    /// Sever all client connections to Redis using `CLIENT KILL TYPE normal SKIPME yes`.
    pub async fn kill_client_connections(&self) -> anyhow::Result<i64> {
        let mut conn = self.pool.get().await.context("failed to get connection")?;
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

    /// Helper task for disconnecting clients after a given delay.
    pub async fn run_client_killer(&self, barrier: Arc<tokio::sync::Barrier>, kill_delay_ms: u64) -> i64 {
        barrier.wait().await;
        tokio::time::sleep(Duration::from_millis(kill_delay_ms)).await;

        match self.kill_client_connections().await {
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

    /// Spawn a background task to disconnect clients after a delay.
    pub fn spawn_client_killer(
        &self,
        barrier: Arc<tokio::sync::Barrier>,
        kill_delay_ms: u64,
    ) -> tokio::task::JoinHandle<i64> {
        let client = self.clone();
        tokio::spawn(async move { client.run_client_killer(barrier, kill_delay_ms).await })
    }

    /// Configure Redis persistence options (AOF enabled/disabled and fsync policy).
    pub async fn configure_persistence(
        &self,
        append_only: bool,
        append_fsync: &str,
    ) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await.context("failed to get connection")?;
        let aof_val = if append_only { "yes" } else { "no" };
        let _: () = cmd("CONFIG")
            .arg("SET")
            .arg("appendonly")
            .arg(aof_val)
            .query_async(&mut conn)
            .await
            .context("failed to set appendonly config")?;
        if append_only {
            let _: () = cmd("CONFIG")
                .arg("SET")
                .arg("appendfsync")
                .arg(append_fsync)
                .query_async(&mut conn)
                .await
                .context("failed to set appendfsync config")?;
        }
        Ok(())
    }

    /// Trigger a background snapshot save via Redis BGSAVE.
    pub async fn trigger_bgsave(&self) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await.context("failed to get connection")?;
        let res: Result<(), _> = cmd("BGSAVE").query_async(&mut conn).await;
        if let Err(e) = res {
            tracing::warn!("BGSAVE notice: {e:#}");
        }
        Ok(())
    }

    /// Run intermittent blocking Lua scripts on the Redis instance until stopped or completed.
    pub async fn run_intermittent_spike(
        &self,
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
            match self.pool.get().await {
                Ok(mut conn) => {
                    if let Err(e) = spike_script.arg(spike_ms).invoke_async::<i32>(&mut conn).await
                    {
                        tracing::warn!(
                            "Failed to execute intermittent blocking Lua spike on Redis: {e:#}"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to get connection for blocking spike: {e:#}");
                }
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
        let client = self.clone();
        Some(tokio::spawn(async move {
            client
                .run_intermittent_spike(stop_flag, spike_ms, num_spikes)
                .await;
        }))
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
    pub attempts_ops_sec: f64,
    pub goodput_ops_sec: f64,
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
            attempts_ops_sec: 0.0,
            goodput_ops_sec: 0.0,
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
        let wall_sec = total_wall_time.as_secs_f64().max(0.0001);
        if samples.is_empty() {
            let mut summary = Self::empty(op_name);
            summary.failures = failures;
            summary.attempts_ops_sec = failures as f64 / wall_sec;
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

        let total_attempts = count + failures;
        let attempts_ops_sec = total_attempts as f64 / wall_sec;
        let goodput_ops_sec = count as f64 / wall_sec;

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
            attempts_ops_sec,
            goodput_ops_sec,
        }
    }

    pub fn print_row(&self) {
        let fmt_metric = |val: f64, min_samples: usize| -> String {
            if self.count < min_samples {
                "      n/a".to_string()
            } else {
                format!("{:>7.2}ms", val)
            }
        };

        let p50_str = fmt_metric(self.p50_ms, 1);
        let p90_str = fmt_metric(self.p90_ms, 10);
        let p95_str = fmt_metric(self.p95_ms, 20);
        let p99_str = fmt_metric(self.p99_ms, 20);
        let max_str = fmt_metric(self.max_ms, 1);

        println!(
            "{:<26} | {:>7} | {:>8} | {:>9} | {:>9} | {:>9} | {:>9} | {:>9} | {:>10.1} | {:>9.1}",
            self.op_name,
            self.count,
            self.failures,
            p50_str,
            p90_str,
            p95_str,
            p99_str,
            max_str,
            self.attempts_ops_sec,
            self.goodput_ops_sec,
        );
    }
}

pub fn print_summary_header() {
    println!("{:-<122}", "");
    println!(
        "{:<26} | {:>7} | {:>8} | {:>9} | {:>9} | {:>9} | {:>9} | {:>9} | {:>10} | {:>9}",
        "Operation", "Samples", "Failures", "p50", "p90", "p95", "p99", "Max", "Attempts/s", "Goodput/s"
    );
    println!("{:-<122}", "");
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
        (Duration::ZERO, Duration::ZERO)
    }
}

/// Partitions a combined wall duration between three interleaved operations
/// proportionally according to the total active time measured for each operation.
pub fn partition_wall_3(
    wall: Duration,
    op1_samples: &[Duration],
    op2_samples: &[Duration],
    op3_samples: &[Duration],
) -> (Duration, Duration, Duration) {
    let t1: Duration = op1_samples.iter().copied().sum();
    let t2: Duration = op2_samples.iter().copied().sum();
    let t3: Duration = op3_samples.iter().copied().sum();
    let total = t1 + t2 + t3;
    if total > Duration::ZERO {
        let total_secs = total.as_secs_f64();
        (
            wall.mul_f64(t1.as_secs_f64() / total_secs),
            wall.mul_f64(t2.as_secs_f64() / total_secs),
            wall.mul_f64(t3.as_secs_f64() / total_secs),
        )
    } else {
        (Duration::ZERO, Duration::ZERO, Duration::ZERO)
    }
}
