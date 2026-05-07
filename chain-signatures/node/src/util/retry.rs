use rand::Rng;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub enum Backoff {
    /// Sleep a fixed duration between retries.
    Fixed(Duration),

    /// Exponential backoff with jitter:
    /// delay = min(cap, base * 2^(attempt-1)) + rand(0..=jitter_max_ms)
    ExponentialJitter {
        base: Duration,
        cap: Duration,
        jitter_max_ms: u64,
    },

    /// Provide a custom function: attempt (1-based) -> delay
    Custom(Arc<dyn Fn(usize) -> Duration + Send + Sync>),
}

impl Backoff {
    pub fn delay(&self, attempt: usize) -> Duration {
        match self {
            Backoff::Fixed(d) => *d,
            Backoff::ExponentialJitter {
                base,
                cap,
                jitter_max_ms,
            } => compute_backoff_with_jitter(*base, *cap, attempt, *jitter_max_ms),
            Backoff::Custom(f) => (f)(attempt),
        }
    }
}

#[derive(Clone)]
pub struct RetryConfig {
    /// Total attempts including the first one. Must be >= 1.
    pub max_attempts: usize,
    /// timeout applied per attempt.
    pub per_attempt_timeout: Duration,
    /// Backoff strategy (default: exponential + 0 jitter).
    pub backoff: Backoff,
}

impl RetryConfig {
    pub fn new(max_attempts: usize, per_attempt_timeout: Duration, backoff: Backoff) -> Self {
        assert!(max_attempts >= 1, "max_attempts must be at least 1");
        Self {
            max_attempts,
            per_attempt_timeout,
            backoff,
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            per_attempt_timeout: Duration::from_secs(2),
            backoff: Backoff::ExponentialJitter {
                base: Duration::from_millis(500),
                cap: Duration::from_secs(10),
                jitter_max_ms: 0,
            },
        }
    }
}

#[derive(Debug)]
pub enum RetryError<E> {
    Exhausted {
        attempts: usize,
        last_error: E,
    },
    TimeoutExhausted {
        attempts: usize,
        last_timeout: Duration,
    },
}

/// Reason for a retry attempt (passed to hooks).
#[derive(Debug)]
pub enum RetryReason<'a, E> {
    Error(&'a E),
    Timeout(Duration),
}

pub fn compute_backoff_with_jitter(
    base: Duration,
    cap: Duration,
    attempt: usize,
    jitter_max_ms: u64,
) -> Duration {
    // Exponential: base * 2^(attempt-1)
    let pow = (attempt.saturating_sub(1)).min(16) as u32;
    let exp_ms = base.as_millis().saturating_mul(1u128 << pow);

    let bounded_ms = exp_ms.min(cap.as_millis());
    let mut delay = match u64::try_from(bounded_ms) {
        Ok(ms) => Duration::from_millis(ms),
        Err(_) => cap.min(Duration::from_millis(u64::MAX)),
    };

    if jitter_max_ms > 0 {
        let jitter = rand::thread_rng().gen_range(0..=jitter_max_ms);
        delay += Duration::from_millis(jitter);
    }
    delay
}

/// Generic retry for async ops returning Result<T, E>.
///
/// - attempt is 1..=max_attempts
/// - should_retry decides whether to continue retrying
/// - on_retry is invoked before sleeping (log/metrics/tracing)
pub async fn retry_async<T, E, Fut, Op, ShouldRetry, OnRetry>(
    cfg: RetryConfig,
    mut op: Op,
    mut should_retry: ShouldRetry,
    mut on_retry: OnRetry,
) -> Result<T, RetryError<E>>
where
    Fut: Future<Output = Result<T, E>>,
    Op: FnMut(usize) -> Fut,
    ShouldRetry: FnMut(usize, RetryReason<'_, E>) -> bool,
    OnRetry: FnMut(usize, RetryReason<'_, E>, Duration),
{
    assert!(cfg.max_attempts >= 1, "max_attempts must be at least 1");

    for attempt in 1..=cfg.max_attempts {
        match tokio::time::timeout(cfg.per_attempt_timeout, op(attempt)).await {
            Ok(Ok(v)) => return Ok(v),
            Ok(Err(e)) => {
                let is_last = attempt == cfg.max_attempts;
                if is_last || !should_retry(attempt, RetryReason::Error(&e)) {
                    return Err(RetryError::Exhausted {
                        attempts: attempt,
                        last_error: e,
                    });
                }
                let sleep_duration = cfg.backoff.delay(attempt);
                on_retry(attempt, RetryReason::Error(&e), sleep_duration);
                tokio::time::sleep(sleep_duration).await;
            }
            Err(_elapsed) => {
                let is_last = attempt == cfg.max_attempts;
                if is_last || !should_retry(attempt, RetryReason::Timeout(cfg.per_attempt_timeout))
                {
                    return Err(RetryError::TimeoutExhausted {
                        attempts: attempt,
                        last_timeout: cfg.per_attempt_timeout,
                    });
                }
                let sleep_duration = cfg.backoff.delay(attempt);
                on_retry(
                    attempt,
                    RetryReason::Timeout(cfg.per_attempt_timeout),
                    sleep_duration,
                );
                tokio::time::sleep(sleep_duration).await;
            }
        }
    }

    unreachable!("loop returns on success or exhausted");
}
