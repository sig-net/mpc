//! Concurrency limiter for in-flight sign tasks, backed by a resizable semaphore.

use super::*;

#[derive(Debug)]
pub enum SignLimitError {
    Timeout,
    Closed,
}

#[derive(Debug)]
struct SignLimitState {
    limit: usize,
    debt: usize,
}

#[derive(Clone, Debug)]
pub struct SignLimiter {
    semaphore: Arc<Semaphore>,
    state: Arc<RwLock<SignLimitState>>,
}

#[derive(Debug)]
pub struct SignPermit {
    permit: Option<OwnedSemaphorePermit>,
    state: Arc<RwLock<SignLimitState>>,
}

impl SignLimiter {
    pub fn new(limit: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(limit)),
            state: Arc::new(RwLock::new(SignLimitState { limit, debt: 0 })),
        }
    }

    /// Updates the limits for concurrent slots
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn update(&self, new_limit: usize) {
        let mut state = match self.state.write() {
            Ok(state) => state,
            Err(err) => {
                tracing::error!(new_limit, ?err, "unable to update SignLimiter limits");
                return;
            }
        };
        let old_limit = std::mem::replace(&mut state.limit, new_limit);

        // add more permits if the limit increased
        if new_limit > old_limit {
            let mut permits_to_add = new_limit - old_limit;
            if permits_to_add > 0 {
                let forgiven = permits_to_add.min(state.debt);
                state.debt -= forgiven;
                permits_to_add -= forgiven;
                self.semaphore.add_permits(permits_to_add);
            }
            return;
        }

        // remove permits or add to a debt where when the permit is dropped, we forget it.
        let permits_to_remove = old_limit - new_limit;
        if permits_to_remove == 0 {
            return;
        }

        let forgotten = self.semaphore.forget_permits(permits_to_remove);
        if forgotten < permits_to_remove {
            state.debt += permits_to_remove - forgotten;
        }
    }

    /// Try to acquire a spot with a timeout just in case we do not receive the slot in time.
    /// Returns a permit if successful, error otherwise.
    pub async fn acquire(&self, timeout: Duration) -> Result<SignPermit, SignLimitError> {
        let permit =
            match tokio::time::timeout(timeout, self.semaphore.clone().acquire_owned()).await {
                Ok(Ok(permit)) => permit,
                // note, acquire error is effectively the same as closed.
                Ok(Err(_acquire_err)) => return Err(SignLimitError::Closed),
                Err(_timeout) => return Err(SignLimitError::Timeout),
            };

        Ok(SignPermit {
            permit: Some(permit),
            state: Arc::clone(&self.state),
        })
    }

    pub fn limits(&self) -> usize {
        match self.state.read() {
            Ok(state) => state.limit,
            Err(err) => {
                tracing::error!(?err, "failed to acquire lock in SignLimiter::limits");
                0
            }
        }
    }
}

impl Drop for SignPermit {
    fn drop(&mut self) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        let mut state = match self.state.write() {
            Ok(state) => state,
            Err(err) => {
                tracing::error!(?err, "failed to acquire lock in SignPermit drop");
                return;
            }
        };
        if state.debt > 0 {
            state.debt -= 1;
            permit.forget();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sign_limiter_times_out_at_limit() {
        let semaphore = SignLimiter::new(1);
        let permit = semaphore
            .acquire(Duration::from_millis(10))
            .await
            .expect("first acquire should succeed");

        let second = semaphore.acquire(Duration::from_millis(10)).await;
        assert!(matches!(second, Err(SignLimitError::Timeout)));

        drop(permit);

        let third = semaphore.acquire(Duration::from_millis(10)).await;
        assert!(third.is_ok());
    }

    #[tokio::test]
    async fn sign_limiter_applies_reduced_limit_on_release() {
        let semaphore = SignLimiter::new(2);
        let first = semaphore
            .acquire(Duration::from_millis(10))
            .await
            .expect("first acquire should succeed");
        let second = semaphore
            .acquire(Duration::from_millis(10))
            .await
            .expect("second acquire should succeed");

        semaphore.update(1);

        drop(first);

        let third = semaphore.acquire(Duration::from_millis(10)).await;
        assert!(matches!(third, Err(SignLimitError::Timeout)));

        drop(second);

        let fourth = semaphore.acquire(Duration::from_millis(10)).await;
        assert!(fourth.is_ok());
    }
}
