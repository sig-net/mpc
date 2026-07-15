//! Concurrency limiter for in-flight sign tasks.

use super::*;

#[derive(Debug)]
pub enum SignLimitError {
    Timeout,
    Closed,
}

/// A held concurrency slot; released back to the limiter on drop.
pub type SignPermit = OwnedSemaphorePermit;

/// Bounds how many sign tasks may hold a slot at once. Cloneable handle.
#[derive(Clone, Debug)]
pub struct SignLimiter {
    semaphore: Arc<Semaphore>,
    limit: usize,
}

impl SignLimiter {
    pub fn new(limit: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(limit)),
            limit,
        }
    }

    /// Acquire a slot, giving up after `timeout`.
    pub async fn acquire(&self, timeout: Duration) -> Result<SignPermit, SignLimitError> {
        match tokio::time::timeout(timeout, self.semaphore.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            // note, acquire error is effectively the same as closed.
            Ok(Err(_acquire_err)) => Err(SignLimitError::Closed),
            Err(_timeout) => Err(SignLimitError::Timeout),
        }
    }

    /// Configured slot limit.
    pub fn limit(&self) -> usize {
        self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sign_limiter_times_out_at_limit() {
        let limiter = SignLimiter::new(1);
        let permit = limiter
            .acquire(Duration::from_millis(10))
            .await
            .expect("first acquire should succeed");

        let second = limiter.acquire(Duration::from_millis(10)).await;
        assert!(matches!(second, Err(SignLimitError::Timeout)));

        drop(permit);

        let third = limiter.acquire(Duration::from_millis(10)).await;
        assert!(third.is_ok());
    }
}
