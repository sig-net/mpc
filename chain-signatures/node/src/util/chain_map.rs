use enum_map::EnumMap;
use mpc_primitives::Chain;
use std::sync::Arc;
use tokio::sync::RwLock;

/// A map from [`Chain`] to values of type `T`, where each chain's value is
/// guarded by its own async [`RwLock`].
///
/// Cloning shares the underlying slots, matching `Arc` semantics. Chains have
/// independent locks, so concurrent operations on different chains never
/// contend.
#[derive(Debug)]
pub struct ChainMap<T>(Arc<EnumMap<Chain, RwLock<T>>>);

impl<T> Clone for ChainMap<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T: Default> Default for ChainMap<T> {
    fn default() -> Self {
        Self(Arc::new(EnumMap::default()))
    }
}

impl<T> ChainMap<T> {
    /// Applies `f` to the value for `chain` under a read lock.
    ///
    /// The lock is held only while `f` runs: `f` must not await.
    pub async fn read<R>(&self, chain: Chain, f: impl FnOnce(&T) -> R) -> R {
        let guard = self.0[chain].read().await;
        f(&guard)
    }

    /// Applies `f` to the value for `chain` under a write lock.
    ///
    /// The lock is held only while `f` runs: `f` must not await.
    pub async fn write<R>(&self, chain: Chain, f: impl FnOnce(&mut T) -> R) -> R {
        let mut guard = self.0[chain].write().await;
        f(&mut guard)
    }

    /// Returns the raw lock for `chain`.
    ///
    /// Only for critical sections that must hold the guard across an `await`;
    /// prefer [`read`](Self::read) or [`write`](Self::write) otherwise.
    pub fn lock(&self, chain: Chain) -> &RwLock<T> {
        &self.0[chain]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn clones_share_slots() {
        let map = ChainMap::<u64>::default();
        let clone = map.clone();

        map.write(Chain::Ethereum, |value| *value = 7).await;
        assert_eq!(clone.read(Chain::Ethereum, |value| *value).await, 7);
    }

    #[tokio::test]
    async fn chains_are_independent() {
        let map = ChainMap::<u64>::default();
        map.write(Chain::Ethereum, |value| *value = 1).await;
        assert_eq!(map.read(Chain::Solana, |value| *value).await, 0);
    }

    #[tokio::test]
    async fn lock_grants_direct_guard_access() {
        let map = ChainMap::<u64>::default();
        *map.lock(Chain::Solana).write().await = 5;
        assert_eq!(map.read(Chain::Solana, |value| *value).await, 5);
    }
}
