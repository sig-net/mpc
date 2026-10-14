use std::time::Duration;

use anyhow::Context as _;
use deadpool_redis::redis::{cmd, Value};
use deadpool_redis::Pool;

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

pub fn parse_slowlog_entry(entry: Value) -> Option<SlowlogRecord> {
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
    pub attempts_ops_sec: f64,
    pub goodput_ops_sec: f64,
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
            attempts_ops_sec: 0.0,
            goodput_ops_sec: 0.0,
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
        let throughput_ops_sec = goodput_ops_sec;

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
            throughput_ops_sec,
        }
    }

    pub fn print_row(&self) {
        let p50_str = if self.count == 0 {
            "      n/a".to_string()
        } else {
            format!("{:>7.2}ms", self.p50_ms)
        };
        let p90_str = if self.count < 10 {
            "      n/a".to_string()
        } else {
            format!("{:>7.2}ms", self.p90_ms)
        };
        let p95_str = if self.count < 20 {
            "      n/a".to_string()
        } else {
            format!("{:>7.2}ms", self.p95_ms)
        };
        let p99_str = if self.count < 20 {
            "      n/a".to_string()
        } else {
            format!("{:>7.2}ms", self.p99_ms)
        };
        let max_str = if self.count == 0 {
            "      n/a".to_string()
        } else {
            format!("{:>7.2}ms", self.max_ms)
        };

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
