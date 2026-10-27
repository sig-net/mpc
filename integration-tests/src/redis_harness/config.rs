use std::time::Duration;

/// Configuration options for initializing a `RedisHarness`.
#[derive(Debug, Clone)]
pub struct RedisHarnessConfig {
    /// Number of simulated participants interacting with Redis.
    pub num_participants: usize,
    /// Optional connection pool max size constraint (e.g. 8 for benchmarking connection constraints).
    pub max_pool_size: Option<usize>,
    /// Optional connection pool operation timeout.
    pub pool_timeout: Option<Duration>,
    /// Whether to execute FLUSHDB between benchmark scenarios for keyspace isolation.
    pub flush_between: bool,
    /// Optional external Redis instance URL (e.g. redis://127.0.0.1:6379).
    /// If None, an ephemeral isolated Docker container is spawned.
    pub redis_url: Option<String>,
    /// Slowlog threshold in microseconds. Commands taking longer than this are recorded (default: 1000us = 1ms).
    pub slowlog_threshold_us: i64,
    /// Maximum number of slowlog entries preserved in Redis memory (default: 1024).
    pub slowlog_max_len: i64,
    /// Docker network name when spawning an ephemeral Redis container (default: "bench-redis-harness").
    pub docker_network: String,
}

impl Default for RedisHarnessConfig {
    fn default() -> Self {
        Self {
            num_participants: 12,
            max_pool_size: Some(8),
            pool_timeout: Some(Duration::from_secs(5)),
            flush_between: true,
            redis_url: None,
            slowlog_threshold_us: 1000,
            slowlog_max_len: 1024,
            docker_network: "bench-redis-harness".to_string(),
        }
    }
}

impl RedisHarnessConfig {
    pub fn new(num_participants: usize) -> Self {
        Self {
            num_participants,
            ..Default::default()
        }
    }

    pub fn with_pool_size(mut self, pool_size: Option<usize>) -> Self {
        self.max_pool_size = pool_size;
        self
    }

    pub fn with_pool_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.pool_timeout = timeout;
        self
    }

    pub fn with_flush_between(mut self, flush: bool) -> Self {
        self.flush_between = flush;
        self
    }

    pub fn with_redis_url(mut self, url: impl Into<String>) -> Self {
        self.redis_url = Some(url.into());
        self
    }

    pub fn with_slowlog_threshold(mut self, threshold_us: i64) -> Self {
        self.slowlog_threshold_us = threshold_us;
        self
    }

    pub fn with_slowlog_max_len(mut self, max_len: i64) -> Self {
        self.slowlog_max_len = max_len;
        self
    }

    pub fn with_docker_network(mut self, network: impl Into<String>) -> Self {
        self.docker_network = network.into();
        self
    }
}
