//! Scheduler view over [`Backlog`]: park / admit / wait, without cloning request
//! bodies into the spawner.

use super::MAX_LIVE_TASKS;
use super::organize::OrganizingPhase;
use crate::backlog::{Backlog, BacklogError};
use crate::sign_bidirectional::PublishState;

use cait_sith::protocol::Participant;
use mpc_primitives::{Chain, IndexedSignRequest, SignId};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::watch;

/// Whether a live slot may be stolen to wake a deliberator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivePhase {
    Organizing,
    Busy,
}

/// One admitted (live) request. Round and proposer flag survive respawn.
pub struct LiveSlot {
    pub request: Arc<IndexedSignRequest>,
    pub is_proposer: Arc<std::sync::atomic::AtomicBool>,
    pub round: Arc<std::sync::atomic::AtomicUsize>,
    pub phase: LivePhase,
}

/// Abstraction over the backlog used by [`super::SignatureSpawner`].
///
/// Durable request bodies stay in [`Backlog`]. This type tracks the live set
/// (≤ [`MAX_LIVE_TASKS`]), chain liveness for proposer fill, and wait-on-index.
#[derive(Clone)]
pub struct SignQueue {
    backlog: Backlog,
}

impl SignQueue {
    pub fn new(backlog: Backlog) -> Self {
        Self { backlog }
    }

    pub fn backlog(&self) -> &Backlog {
        &self.backlog
    }

    pub async fn get(&self, id: &SignId) -> Option<Arc<IndexedSignRequest>> {
        self.backlog.get_by_id(id).await
    }

    /// Wait until the indexer has the id, or `None` if removed / waiter cap.
    pub async fn wait(&self, id: SignId) -> Option<Arc<IndexedSignRequest>> {
        self.backlog.wait_indexed(id).await
    }

    pub fn subscribe_index(&self) -> watch::Receiver<usize> {
        self.backlog.subscribe_index()
    }

    /// Insert if missing. Stream already inserted; Near uses this as park.
    pub async fn park(&self, request: Arc<IndexedSignRequest>) {
        self.backlog.insert(request).await;
    }

    /// Oldest parked pending-generation requests where this node is the
    /// round-0 proposer. Does not admit. Only considers `live_chains`.
    pub async fn next_proposers(
        &self,
        n: usize,
        me: Participant,
        participants: &[Participant],
        live: &HashSet<SignId>,
        live_by_chain: &HashMap<Chain, usize>,
        live_chains: &HashSet<Chain>,
    ) -> Vec<Arc<IndexedSignRequest>> {
        if n == 0 {
            return Vec::new();
        }

        let mut per_chain: Vec<(Chain, Vec<Arc<IndexedSignRequest>>)> = Vec::new();
        for chain in Chain::iter() {
            if !live_chains.contains(&chain) {
                continue;
            }
            let parked = self.backlog.parked_generation(chain).await;
            let eligible: Vec<_> = parked
                .into_iter()
                .filter(|request| {
                    !live.contains(&request.id)
                        && is_round0_proposer(me, participants, &request.args.entropy)
                })
                .collect();
            if !eligible.is_empty() {
                per_chain.push((chain, eligible));
            }
        }

        per_chain.sort_by_key(|(chain, _)| live_by_chain.get(chain).copied().unwrap_or(0));

        let mut picked = Vec::with_capacity(n);
        let mut heads: Vec<usize> = vec![0; per_chain.len()];
        while picked.len() < n {
            let mut progressed = false;
            for (i, (_, eligible)) in per_chain.iter().enumerate() {
                if picked.len() >= n {
                    break;
                }
                let head = heads[i];
                if head >= eligible.len() {
                    continue;
                }
                picked.push(Arc::clone(&eligible[head]));
                heads[i] += 1;
                progressed = true;
            }
            if !progressed {
                break;
            }
        }
        picked
    }

    pub async fn mark_publishing(
        &self,
        chain: Chain,
        id: &SignId,
        publish: Arc<PublishState>,
    ) -> Result<(), BacklogError> {
        self.backlog.mark_publishing(chain, id, publish).await
    }
}

impl SignQueue {
    /// Remaining live slots under the global cap.
    pub fn free_slots(live_len: usize) -> usize {
        MAX_LIVE_TASKS.saturating_sub(live_len)
    }
}

pub(crate) fn is_round0_proposer(
    me: Participant,
    participants: &[Participant],
    entropy: &[u8; 32],
) -> bool {
    if participants.is_empty() {
        return false;
    }
    OrganizingPhase::proposer_per_round(0, participants, entropy) == me
}

/// Pick an Organizing live id to steal so a posit-woken deliberator can admit.
pub fn steal_organizing(live: &HashMap<SignId, LiveSlot>, except: SignId) -> Option<SignId> {
    live.iter()
        .find(|(id, slot)| **id != except && slot.phase == LivePhase::Organizing)
        .map(|(id, _)| *id)
}

pub fn live_by_chain(live: &HashMap<SignId, LiveSlot>) -> HashMap<Chain, usize> {
    let mut counts = HashMap::new();
    for slot in live.values() {
        *counts.entry(slot.request.chain).or_insert(0) += 1;
    }
    counts
}

/// Outcome of trying to admit a deliberator while at the live cap.
pub enum Steal {
    Slot,
    Organizing(SignId),
    None,
}

impl Steal {
    pub fn for_admit(live: &HashMap<SignId, LiveSlot>, waking: SignId) -> Self {
        if live.len() < MAX_LIVE_TASKS {
            return Steal::Slot;
        }
        match steal_organizing(live, waking) {
            Some(id) => Steal::Organizing(id),
            None => Steal::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpc_primitives::{IndexedSignRequest, SignKind};
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    fn request(id: u8, chain: Chain, entropy0: u8, ts: u64) -> Arc<IndexedSignRequest> {
        let mut entropy = [0u8; 32];
        entropy[0] = entropy0;
        Arc::new(IndexedSignRequest::new(
            SignId::new([id; 32]),
            mpc_primitives::SignArgs {
                entropy,
                epsilon: k256::Scalar::from(1u64),
                payload: k256::Scalar::from(2u64),
                path: "test".to_string(),
                key_version: 0,
            },
            chain,
            ts,
            SignKind::Sign,
        ))
    }

    fn participants(n: u32) -> Vec<Participant> {
        (0..n).map(Participant::from).collect()
    }

    fn slot(request: Arc<IndexedSignRequest>, phase: LivePhase) -> LiveSlot {
        LiveSlot {
            request,
            is_proposer: Arc::new(AtomicBool::new(false)),
            round: Arc::new(AtomicUsize::new(0)),
            phase,
        }
    }

    #[test]
    fn round0_proposer_matches_organize() {
        let parts = participants(3);
        let mut entropy = [0u8; 32];
        entropy[0] = 0xdf;
        let elected = OrganizingPhase::proposer_per_round(0, &parts, &entropy);
        assert!(is_round0_proposer(elected, &parts, &entropy));
        let other = parts.iter().copied().find(|p| *p != elected).unwrap();
        assert!(!is_round0_proposer(other, &parts, &entropy));
    }

    #[test]
    fn steal_skips_busy() {
        let a = request(1, Chain::Solana, 0, 1);
        let b = request(2, Chain::Ethereum, 0, 2);
        let mut live = HashMap::new();
        live.insert(a.id, slot(Arc::clone(&a), LivePhase::Busy));
        live.insert(b.id, slot(Arc::clone(&b), LivePhase::Organizing));
        assert_eq!(steal_organizing(&live, SignId::new([9; 32])), Some(b.id));
        live.get_mut(&b.id).unwrap().phase = LivePhase::Busy;
        assert_eq!(steal_organizing(&live, SignId::new([9; 32])), None);
    }

    #[tokio::test]
    async fn wait_resolves_on_insert() {
        let backlog = Backlog::new();
        let queue = SignQueue::new(backlog.clone());
        let req = request(7, Chain::Solana, 1, 10);
        let id = req.id;
        let wait = tokio::spawn({
            let queue = queue.clone();
            async move { queue.wait(id).await }
        });
        tokio::task::yield_now().await;
        backlog.insert(Arc::clone(&req)).await;
        let got = wait.await.unwrap().expect("indexed");
        assert_eq!(got.id, id);
    }

    #[tokio::test]
    async fn next_proposers_fair_and_fifo() {
        let backlog = Backlog::new();
        let queue = SignQueue::new(backlog.clone());
        let parts = participants(1);
        let me = parts[0];
        // entropy[0] % 1 + 0 % 1 = 0 → sole participant is always proposer.
        for (i, chain) in [Chain::Solana, Chain::Ethereum].into_iter().enumerate() {
            backlog
                .insert(request(10 + i as u8, chain, 0, 100 + i as u64))
                .await;
            backlog
                .insert(request(20 + i as u8, chain, 0, 200 + i as u64))
                .await;
        }
        let live = HashSet::new();
        let by_chain = HashMap::new();
        let live_chains = HashSet::from([Chain::Solana, Chain::Ethereum]);
        let picked = queue
            .next_proposers(3, me, &parts, &live, &by_chain, &live_chains)
            .await;
        assert_eq!(picked.len(), 3);
        // Fair round-robin: ties on live-count keep `Chain::iter` order
        // (Ethereum before Solana). Oldest of each chain first.
        assert_eq!(picked[0].chain, Chain::Ethereum);
        assert_eq!(picked[1].chain, Chain::Solana);
        assert_eq!(picked[2].chain, Chain::Ethereum);
        assert!(picked[0].unix_timestamp_indexed <= picked[2].unix_timestamp_indexed);
    }

    #[tokio::test]
    async fn next_proposers_skips_non_proposers() {
        let backlog = Backlog::new();
        let queue = SignQueue::new(backlog.clone());
        let parts = participants(3);
        let mut entropy = [0u8; 32];
        entropy[0] = 0xdf;
        let elected = OrganizingPhase::proposer_per_round(0, &parts, &entropy);
        let other = parts.iter().copied().find(|p| *p != elected).unwrap();
        backlog.insert(request(1, Chain::Solana, 0xdf, 1)).await;
        let live = HashSet::new();
        let by_chain = HashMap::new();
        let live_chains = HashSet::from([Chain::Solana]);
        let as_other = queue
            .next_proposers(4, other, &parts, &live, &by_chain, &live_chains)
            .await;
        assert!(as_other.is_empty());
        let as_me = queue
            .next_proposers(4, elected, &parts, &live, &by_chain, &live_chains)
            .await;
        assert_eq!(as_me.len(), 1);
    }
}
