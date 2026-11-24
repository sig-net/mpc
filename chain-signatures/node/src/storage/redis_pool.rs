//! A lightweight pool-like wrapper around a single multiplexed Redis connection.
//!
//! `deadpool-redis` pays an extra round trip (`UNWATCH` + `PING`) on every
//! checkout of an idle connection. This wrapper instead shares one
//! [`ConnectionManager`] per pool: it is multiplexed and cloneable, and makes
//! a best-effort, single-attempt reconnect after a dropped connection (for
//! example `CLIENT KILL`); a command can still fail once before recovery.
//! A [`Semaphore`] preserves the configured concurrency limit, and a permit
//! is held for as long as the caller holds the checked-out [`Connection`].
//!
//! The manager is created lazily on first checkout, so constructing a pool is
//! infallible and does not contact Redis - the same behavior deadpool had.
//!
//! `Status` is deliberately compatible with deadpool's diagnostics fields,
//! but the semantics are adapted to a multiplexed connection: `max_size` is
//! the concurrency limit (permits), `size` is 1 once the shared connection is
//! initialized (0 before), `available` is the number of free connection slots
//! (bounded by `size`), `active` is `size - available`, and `waiting` is the
//! number of checkouts waiting for a permit.

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use redis::aio::{ConnectionLike, ConnectionManager, ConnectionManagerConfig};
use redis::{
    Client, Cmd, ErrorKind, IntoConnectionInfo, Pipeline, RedisError, RedisFuture, RedisResult,
    Value,
};
use tokio::sync::{OnceCell, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

/// Similar to deadpool's `num_cpus::get() * 2` default (20 on a 10-CPU host).
fn default_max_size() -> usize {
    std::thread::available_parallelism()
        .ok()
        .map(|cpus| cpus.get().saturating_mul(2))
        .filter(|size| *size > 0)
        .unwrap_or(20)
}

fn pool_error(message: &'static str) -> RedisError {
    RedisError::from((ErrorKind::IoError, message))
}

/// Decrements the pool's waiting counter even when a `get()` future is
/// cancelled (timeout, caller abort, cancelled task).
struct WaitingGuard<'a>(&'a AtomicUsize);

impl Drop for WaitingGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Builder for a [`Pool`]. Construction is synchronous and does not connect.
#[derive(Clone, Debug)]
pub struct Config {
    client: Client,
    max_size: usize,
    wait_timeout: Option<Duration>,
    response_timeout: Option<Duration>,
}

impl Config {
    pub fn from_url(url: impl IntoConnectionInfo) -> RedisResult<Self> {
        Ok(Self {
            client: Client::open(url)?,
            max_size: default_max_size(),
            wait_timeout: None,
            response_timeout: None,
        })
    }

    /// Maximum number of concurrent checkouts. Must be at least one.
    pub fn max_size(mut self, max_size: usize) -> Self {
        self.max_size = max_size.max(1);
        self
    }

    /// Bound the entire checkout (permit acquisition plus lazy connection
    /// setup). `None` waits indefinitely.
    pub fn wait_timeout(mut self, wait_timeout: Option<Duration>) -> Self {
        self.wait_timeout = wait_timeout;
        self
    }

    /// Bound both connection setup and every Redis command.
    pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
        self.response_timeout = timeout;
        self
    }

    pub fn build(self) -> Pool {
        Pool {
            client: self.client,
            // Arc is essential: tokio's OnceCell::clone() makes an independent
            // cell, which would create a separate connection per clone.
            config: Arc::new(OnceCell::new()),
            response_timeout: self.response_timeout,
            semaphore: Arc::new(Semaphore::new(self.max_size)),
            max_size: self.max_size,
            wait_timeout: self.wait_timeout,
            waiting: Arc::new(AtomicUsize::new(0)),
        }
    }
}

/// A pool-like handle: clone it to share the same manager and permit budget.
#[derive(Clone)]
pub struct Pool {
    client: Client,
    config: Arc<OnceCell<ConnectionManager>>,
    response_timeout: Option<Duration>,
    semaphore: Arc<Semaphore>,
    max_size: usize,
    wait_timeout: Option<Duration>,
    waiting: Arc<AtomicUsize>,
}

impl fmt::Debug for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pool")
            .field("max_size", &self.max_size)
            .field("wait_timeout", &self.wait_timeout)
            .field("response_timeout", &self.response_timeout)
            .field("connected", &self.config.get().is_some())
            .finish_non_exhaustive()
    }
}

impl Pool {
    /// Build a pool for `url` with the optional size and timeout used by the
    /// benchmark harness and tests.
    pub fn new(
        url: impl IntoConnectionInfo,
        max_size: Option<usize>,
        timeout: Option<Duration>,
    ) -> RedisResult<Self> {
        let mut config = Config::from_url(url)?;
        if let Some(max_size) = max_size {
            config = config.max_size(max_size);
        }
        Ok(config.wait_timeout(timeout).timeout(timeout).build())
    }

    /// Check out a connection. The configured wait timeout bounds the whole
    /// path: waiting for a permit *and* the lazy connection setup. The waiting
    /// counter is maintained by an RAII guard, so cancellation cannot leak it.
    pub async fn get(&self) -> RedisResult<Connection> {
        self.waiting.fetch_add(1, Ordering::Relaxed);
        let _waiting = WaitingGuard(&self.waiting);

        let checkout = self.checkout();
        match self.wait_timeout {
            Some(wait_timeout) => timeout(wait_timeout, checkout)
                .await
                .map_err(|_| pool_error("timed out checking out a Redis connection"))?,
            None => checkout.await,
        }
    }

    async fn checkout(&self) -> RedisResult<Connection> {
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| pool_error("Redis pool is closed"))?;

        // Initialize once, lazily. Concurrent first checkouts share the same
        // connection attempt. A failed or cancelled attempt leaves the cell
        // empty so the next checkout retries, just like deadpool creating a
        // connection. The permit is held only while this future is alive, so
        // a timeout during setup returns it to the semaphore.
        let manager = self
            .config
            .get_or_try_init(|| async {
                let mut config = ConnectionManagerConfig::new()
                    // Best-effort single-attempt reconnect: the repository's
                    // backoff around `get()` handles retries, as deadpool did.
                    .set_number_of_retries(0);
                if let Some(response_timeout) = self.response_timeout {
                    config = config
                        .set_response_timeout(response_timeout)
                        .set_connection_timeout(response_timeout);
                }
                ConnectionManager::new_with_config(self.client.clone(), config).await
            })
            .await?
            .clone();

        Ok(Connection {
            manager,
            _permit: permit,
        })
    }

    /// Close this pool (and all of its clones), matching deadpool's `close()`.
    pub fn close(&self) {
        self.semaphore.close();
    }

    pub fn status(&self) -> Status {
        // One multiplexed TCP connection backs every permit. Report it as a
        // single pooled connection, as deadpool's diagnostics would. A closed
        // semaphore reports no available slots even though its raw permit
        // counter is unchanged.
        let size = usize::from(self.config.get().is_some());
        let closed = self.semaphore.is_closed();
        let available = if closed {
            0
        } else {
            self.semaphore.available_permits().min(size)
        };
        Status {
            max_size: self.max_size,
            size,
            available,
            active: if closed { 0 } else { size - available },
            waiting: self.waiting.load(Ordering::Relaxed),
        }
    }
}

/// A checked-out connection: holds a permit until dropped and dereferences to
/// the shared `ConnectionManager`, so existing `&mut conn` Redis calls work.
pub struct Connection {
    manager: ConnectionManager,
    _permit: OwnedSemaphorePermit,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection").finish_non_exhaustive()
    }
}

impl Deref for Connection {
    type Target = ConnectionManager;

    fn deref(&self) -> &Self::Target {
        &self.manager
    }
}

impl DerefMut for Connection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.manager
    }
}

// Generic Redis helpers (`Script::invoke_async`, `Pipeline::query_async`, ...)
// take `&mut impl ConnectionLike`, which does not use deref coercion. Delegate
// explicitly so all existing call sites keep working through the wrapper.
impl ConnectionLike for Connection {
    fn req_packed_command<'a>(&'a mut self, cmd: &'a Cmd) -> RedisFuture<'a, Value> {
        self.manager.req_packed_command(cmd)
    }

    fn req_packed_commands<'a>(
        &'a mut self,
        cmd: &'a Pipeline,
        offset: usize,
        count: usize,
    ) -> RedisFuture<'a, Vec<Value>> {
        self.manager.req_packed_commands(cmd, offset, count)
    }

    fn get_db(&self) -> i64 {
        self.manager.get_db()
    }
}

/// Diagnostics snapshot, compatible with deadpool's `Status` field names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub max_size: usize,
    pub size: usize,
    pub available: usize,
    pub active: usize,
    pub waiting: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::future::join_all;
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    /// Minimal loopback server that answers the two `CLIENT SETINFO` commands
    /// redis-rs sends while setting up a connection. With `respond = false` it
    /// accepts connections but never replies (a black-holed Redis).
    struct FakeRedis {
        url: String,
        connections: Arc<AtomicUsize>,
        task: JoinHandle<()>,
    }

    impl FakeRedis {
        async fn start(respond: bool) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("redis://{}", listener.local_addr().unwrap());
            let connections = Arc::new(AtomicUsize::new(0));
            let counter = connections.clone();
            let task = tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        break;
                    };
                    counter.fetch_add(1, Ordering::Relaxed);

                    if respond {
                        let mut buf = Vec::new();
                        let mut chunk = [0u8; 256];
                        while buf.len() < 4096 {
                            let Ok(Ok(n)) =
                                timeout(Duration::from_millis(200), stream.read(&mut chunk)).await
                            else {
                                break;
                            };
                            if n == 0 {
                                break;
                            }
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.windows(7).filter(|w| *w == &b"SETINFO"[..]).count() >= 2 {
                                break;
                            }
                        }
                        let _ = stream.write_all(b"+OK\r\n+OK\r\n").await;
                    }

                    // Hold the socket open; only a responding server answers
                    // later commands (the black-hole case never replies).
                    let mut chunk = [0u8; 256];
                    loop {
                        let Ok(n) = stream.read(&mut chunk).await else {
                            break;
                        };
                        if n == 0 {
                            break;
                        }
                        if respond && stream.write_all(b"+OK\r\n").await.is_err() {
                            break;
                        }
                    }
                }
            });
            Self {
                url,
                connections,
                task,
            }
        }
    }

    impl Drop for FakeRedis {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    #[test]
    fn status_reports_concurrency_limit_before_connection() {
        let pool = Config::from_url("redis://127.0.0.1:1/")
            .unwrap()
            .max_size(3)
            .build();
        assert_eq!(
            pool.status(),
            Status {
                max_size: 3,
                size: 0,
                available: 0,
                active: 0,
                waiting: 0,
            }
        );
        assert_eq!(pool.clone().status(), pool.status());
    }

    #[tokio::test]
    async fn an_unreachable_redis_fails_on_checkout_not_on_build() {
        let pool = Pool::new(
            "redis://127.0.0.1:1/",
            Some(1),
            Some(Duration::from_millis(200)),
        )
        .unwrap();
        assert!(pool.get().await.is_err());
        // A failed first checkout must not poison later attempts.
        assert!(pool.get().await.is_err());
    }

    #[tokio::test]
    async fn concurrent_first_checkouts_share_one_initialized_connection() {
        let redis = FakeRedis::start(true).await;
        let pool = Config::from_url(redis.url.as_str())
            .unwrap()
            .max_size(8)
            .wait_timeout(Some(Duration::from_secs(2)))
            .timeout(Some(Duration::from_secs(2)))
            .build();

        let connections = join_all((0..6).map(|_| pool.get())).await;
        assert!(
            connections.iter().all(|result| result.is_ok()),
            "all checkouts should succeed: {connections:?}"
        );
        assert_eq!(redis.connections.load(Ordering::Relaxed), 1);
        assert_eq!(pool.status().size, 1);

        drop(connections);
        assert_eq!(pool.status().available, 1);
        assert_eq!(pool.status().waiting, 0);
    }

    #[tokio::test]
    async fn second_checkout_times_out_while_permit_is_held() {
        let redis = FakeRedis::start(true).await;
        let pool = Config::from_url(redis.url.as_str())
            .unwrap()
            .max_size(1)
            .wait_timeout(Some(Duration::from_millis(60)))
            .timeout(Some(Duration::from_secs(2)))
            .build();

        let first = pool.get().await.unwrap();
        let started = Instant::now();
        assert!(pool.get().await.is_err(), "second checkout must time out");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "wait timeout should bound the second checkout"
        );
        assert_eq!(pool.status().available, 0);
        assert_eq!(pool.status().waiting, 0);

        drop(first);
        assert!(pool.get().await.is_ok(), "permit must be returned on drop");
    }

    #[tokio::test]
    async fn status_tracks_init_close_and_cancelled_waiters() {
        let redis = FakeRedis::start(true).await;
        let pool = Config::from_url(redis.url.as_str())
            .unwrap()
            .max_size(1)
            .wait_timeout(Some(Duration::from_secs(5)))
            .timeout(Some(Duration::from_secs(2)))
            .build();
        assert_eq!(pool.status().size, 0);

        let connection = pool.get().await.unwrap();
        assert_eq!(pool.status().size, 1);
        assert_eq!(pool.status().available, 0);
        assert_eq!(pool.status().active, 1);

        // Cancel a checkout while it is waiting on the held permit: the
        // waiting counter must be decremented by the RAII guard.
        let pending_pool = pool.clone();
        let pending = tokio::spawn(async move { pending_pool.get().await });
        for _ in 0..100 {
            if pool.status().waiting == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(pool.status().waiting, 1);
        pending.abort();
        let _ = pending.await;
        for _ in 0..100 {
            if pool.status().waiting == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(pool.status().waiting, 0);

        drop(connection);
        assert_eq!(pool.status().available, 1);
        assert_eq!(pool.status().active, 0);

        pool.close();
        assert_eq!(pool.status().available, 0);
        assert_eq!(pool.status().waiting, 0);
        assert!(pool.get().await.is_err());
    }

    #[tokio::test]
    async fn wait_timeout_bounds_black_holed_connection_setup() {
        let redis = FakeRedis::start(false).await;
        let pool = Config::from_url(redis.url.as_str())
            .unwrap()
            .max_size(1)
            .wait_timeout(Some(Duration::from_millis(80)))
            // Deliberately far longer than the wait timeout: without an
            // overall bound the checkout would hang on this response timeout.
            .timeout(Some(Duration::from_secs(10)))
            .build();

        let started = Instant::now();
        assert!(pool.get().await.is_err());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "wait timeout must also bound lazy connection setup"
        );
        assert_eq!(pool.status().size, 0, "cancelled init is not committed");
        assert_eq!(pool.status().waiting, 0);

        let started = Instant::now();
        assert!(pool.get().await.is_err());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the permit must be returned after a timed-out init"
        );
    }
}
