use std::time::Duration;

/// Configuration options for initializing a `RedisHarness`.
#[derive(Debug, Clone, bon::Builder)]
pub struct RedisHarnessConfig {
    /// Number of simulated participants interacting with Redis.
    #[builder(default = 12)]
    pub num_participants: usize,
    /// Optional connection pool max size constraint (e.g. 8 for benchmarking connection constraints).
    pub max_pool_size: Option<usize>,
    /// Optional connection pool operation timeout.
    // `required` opts out of bon's implicit `None` default for `Option` fields,
    // allowing the harness's 5s default to be expressed here.
    #[builder(default = Some(Duration::from_secs(5)), required)]
    pub pool_timeout: Option<Duration>,
    /// Whether to execute FLUSHDB between benchmark scenarios for keyspace isolation.
    #[builder(default = true)]
    pub flush_between: bool,
    /// Optional external Redis instance URL (e.g. redis://127.0.0.1:6379).
    /// If None, an ephemeral isolated Docker container is spawned.
    pub redis_url: Option<String>,
    /// Explicitly allow destructive benchmark commands against an external Redis instance.
    #[builder(default = false)]
    pub allow_external_redis: bool,
    /// Slowlog threshold in microseconds. Commands taking longer than this are recorded (default: 1000us = 1ms).
    #[builder(default = 1000)]
    pub slowlog_threshold_us: i64,
    /// Maximum number of slowlog entries preserved in Redis memory (default: 1024).
    #[builder(default = 1024)]
    pub slowlog_max_len: i64,
    /// Docker network name when spawning an ephemeral Redis container (default: "bench-redis-harness").
    #[builder(default = "bench-redis-harness".to_owned())]
    pub docker_network: String,
}

impl Default for RedisHarnessConfig {
    fn default() -> Self {
        Self::builder().build()
    }
}
