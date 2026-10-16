use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use cait_sith::protocol::Participant;
use cait_sith::triples::{TriplePub, TripleShare};
use cait_sith::PresignOutput;
use deadpool_redis::Pool;
use elliptic_curve::CurveArithmetic;
use k256::Secp256k1;
use mpc_node::protocol::presignature::Presignature;
use mpc_node::protocol::triple::Triple;
use mpc_node::storage::protocol_storage::RemoveOutdatedResult;
use mpc_node::storage::triple_storage::TriplePair;
use mpc_node::storage::{PresignatureStorage, TripleStorage};
use near_account_id::AccountId;
use tokio::sync::Barrier;

static GLOBAL_ID_COUNTER: AtomicU64 = AtomicU64::new(10_000_000);

pub fn next_id_block(count: u64) -> u64 {
    GLOBAL_ID_COUNTER.fetch_add(count, Ordering::Relaxed)
}

/// The type of stockpile artifact to generate or manage in benchmark runs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StockpileKind {
    Triples,
    Presignatures,
}

/// Simulated participant storage handles in the isolated Redis harness.
#[derive(Clone)]
pub struct SimulatedParticipant {
    pub participant: Participant,
    pub account_id: AccountId,
    pub triples: TripleStorage,
    pub presignatures: PresignatureStorage,
}

impl SimulatedParticipant {
    /// Create a new participant with independent in-memory storage handles.
    pub fn new(pool: &Pool, account_id: &AccountId, participant: Participant) -> Self {
        let triples = TriplePair::storage(pool, account_id);
        triples.set_me(participant);
        let presignatures = Presignature::storage(pool, account_id);
        presignatures.set_me(participant);
        Self {
            participant,
            account_id: account_id.clone(),
            triples,
            presignatures,
        }
    }

    /// Clear all in-memory reservations across both triples and presignatures storage.
    pub async fn reset_reservations(&self) {
        self.triples.reset_reservations().await;
        self.presignatures.reset_reservations().await;
    }

    async fn populate_chunk(
        self,
        kind: StockpileKind,
        base_id: u64,
        count: usize,
        participants: Vec<Participant>,
    ) -> Vec<u64> {
        let mut ids = Vec::with_capacity(count);
        for i in 0..count {
            let id = base_id + i as u64;
            let inserted = match kind {
                StockpileKind::Triples => {
                    let pair = dummy_pair(id, &participants);
                    if let Some(mut slot) = self.triples.create_slot(id, self.participant).await {
                        slot.insert(pair, self.participant).await
                    } else {
                        false
                    }
                }
                StockpileKind::Presignatures => {
                    let presig = dummy_presignature(id, &participants);
                    if let Some(mut slot) =
                        self.presignatures.create_slot(id, self.participant).await
                    {
                        slot.insert(presig, self.participant).await
                    } else {
                        false
                    }
                }
            };
            if inserted {
                ids.push(id);
            }
        }
        ids
    }

    /// Populate `count` items (triples or presignatures) starting at `base_id`.
    /// Automatically chunks work across up to 8 concurrent worker tasks for high throughput.
    pub async fn populate(
        self,
        kind: StockpileKind,
        base_id: u64,
        count: usize,
        participants: Vec<Participant>,
    ) -> anyhow::Result<Vec<u64>> {
        if count == 0 {
            return Ok(Vec::new());
        }

        let num_workers = 8.min(count);
        let chunk_size = count.div_ceil(num_workers);
        let mut handles = Vec::with_capacity(num_workers);

        for w in 0..num_workers {
            let start = w * chunk_size;
            let end = (start + chunk_size).min(count);
            if start >= end {
                continue;
            }
            let chunk_count = end - start;
            let p_base = base_id + start as u64;

            handles.push(tokio::spawn(self.clone().populate_chunk(
                kind,
                p_base,
                chunk_count,
                participants.clone(),
            )));
        }

        let mut all_ids = Vec::with_capacity(count);
        for h in handles {
            let ids = h.await.context("participant populate task failed or panicked")?;
            all_ids.extend(ids);
        }
        all_ids.sort_unstable();
        anyhow::ensure!(
            all_ids.len() == count,
            "failed to populate expected stockpile {kind:?}: requested {count}, successfully created {}",
            all_ids.len()
        );
        Ok(all_ids)
    }

    /// Run the 100ms background stockpile polling loop until stopped.
    pub async fn run_polling_loop(self, stop: Arc<AtomicBool>, include_presignatures: bool) {
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        while !stop.load(Ordering::Relaxed) {
            interval.tick().await;
            let _ = self.triples.len_generated().await;
            let _ = self.triples.len_by_owner(self.participant).await;
            if include_presignatures {
                let _ = self.presignatures.len_generated().await;
                let _ = self.presignatures.len_by_owner(self.participant).await;
            }
        }
    }

    /// Concurrently insert a range of items (triples or presignatures), measuring latency per insert and tracking failures.
    pub async fn insert_measured(
        self,
        kind: StockpileKind,
        base_id: u64,
        count: usize,
        participants: Vec<Participant>,
        barrier: Arc<Barrier>,
    ) -> (Vec<Duration>, usize) {
        barrier.wait().await;
        let mut latencies = Vec::with_capacity(count);
        let mut failures = 0;

        for i in 0..count {
            let id = base_id + i as u64;
            let t0 = Instant::now();
            let success = match kind {
                StockpileKind::Triples => {
                    let pair = dummy_pair(id, &participants);
                    match self.triples.create_slot(id, self.participant).await {
                        Some(mut slot) => slot.insert(pair, self.participant).await,
                        None => false,
                    }
                }
                StockpileKind::Presignatures => {
                    let presig = dummy_presignature(id, &participants);
                    match self.presignatures.create_slot(id, self.participant).await {
                        Some(mut slot) => slot.insert(presig, self.participant).await,
                        None => false,
                    }
                }
            };
            if success {
                latencies.push(t0.elapsed());
            } else {
                failures += 1;
            }
        }

        (latencies, failures)
    }

    /// Concurrently take a list of triple IDs, measuring latency for each take and tracking failures.
    pub async fn take_triples(
        self,
        ids: Vec<u64>,
        barrier: Option<Arc<Barrier>>,
    ) -> (Vec<Duration>, usize) {
        if let Some(b) = barrier {
            b.wait().await;
        }
        let mut latencies = Vec::with_capacity(ids.len());
        let mut failures = 0;
        for id in ids {
            let t0 = Instant::now();
            if self.triples.take(id, self.participant).await.is_some() {
                latencies.push(t0.elapsed());
            } else {
                failures += 1;
            }
        }
        (latencies, failures)
    }

    /// Concurrently peek unreserved triples, measuring latency per peek and tracking empty results.
    pub async fn peek_triples_measured(
        self,
        barrier: Arc<Barrier>,
        count: usize,
    ) -> (Vec<Duration>, usize) {
        barrier.wait().await;
        let mut latencies = Vec::with_capacity(count);
        let mut failures = 0;
        for _ in 0..count {
            let t0 = Instant::now();
            let res = self.triples.peek_mine(&[]).await;
            if res.is_some() {
                latencies.push(t0.elapsed());
            } else {
                failures += 1;
            }
        }
        (latencies, failures)
    }

    /// Concurrently invoke remove_outdated on triples storage.
    pub async fn remove_outdated_shares(
        self,
        barrier: Arc<Barrier>,
        remaining_shares: Vec<u64>,
    ) -> (Duration, anyhow::Result<RemoveOutdatedResult<u64>>) {
        barrier.wait().await;
        let t0 = Instant::now();
        let res = self
            .triples
            .remove_outdated(self.participant, &remaining_shares)
            .await;
        (t0.elapsed(), res.map_err(anyhow::Error::from))
    }

    /// Concurrently clear storage for the given stockpile kind.
    pub async fn clear_measured(
        self,
        kind: StockpileKind,
        barrier: Arc<Barrier>,
    ) -> (Duration, bool) {
        barrier.wait().await;
        let t0 = Instant::now();
        let ok = match kind {
            StockpileKind::Triples => self.triples.clear().await,
            StockpileKind::Presignatures => self.presignatures.clear().await,
        };
        (t0.elapsed(), ok)
    }

    /// Concurrently invoke remove_holder_and_prune across both triples and presignatures.
    pub async fn prune_artifacts(
        self,
        barrier: Arc<Barrier>,
        target_peer: Participant,
        threshold: usize,
        triple_ids: Vec<u64>,
        presig_ids: Vec<u64>,
    ) -> (
        Duration,
        anyhow::Result<(Vec<u64>, Vec<u64>)>,
        Duration,
        anyhow::Result<(Vec<u64>, Vec<u64>)>,
    ) {
        barrier.wait().await;
        let t0 = Instant::now();
        let triple_res = self
            .triples
            .remove_holder_and_prune(target_peer, threshold, &triple_ids)
            .await;
        let triple_elapsed = t0.elapsed();

        let t1 = Instant::now();
        let presig_res = self
            .presignatures
            .remove_holder_and_prune(target_peer, threshold, &presig_ids)
            .await;
        let presig_elapsed = t1.elapsed();

        (
            triple_elapsed,
            triple_res.map_err(anyhow::Error::from),
            presig_elapsed,
            presig_res.map_err(anyhow::Error::from),
        )
    }

    /// Concurrently take pairs of (triple, presignature), measuring latency for each and tracking failures.
    pub async fn take_triple_and_presig_pairs(
        self,
        barrier: Arc<Barrier>,
        triple_ids: Vec<u64>,
        presig_ids: Vec<u64>,
    ) -> (Vec<Duration>, usize, Vec<Duration>, usize) {
        barrier.wait().await;
        let count = triple_ids.len().min(presig_ids.len());
        let mut take_triple_latencies = Vec::with_capacity(count);
        let mut take_presig_latencies = Vec::with_capacity(count);
        let mut triple_failures = 0;
        let mut presig_failures = 0;

        for i in 0..count {
            let triple_id = triple_ids[i];
            let presig_id = presig_ids[i];

            let t0 = Instant::now();
            if self.triples.take(triple_id, self.participant).await.is_some() {
                take_triple_latencies.push(t0.elapsed());
            } else {
                triple_failures += 1;
            }

            let t1 = Instant::now();
            if self.presignatures.take(presig_id, self.participant).await.is_some() {
                take_presig_latencies.push(t1.elapsed());
            } else {
                presig_failures += 1;
            }
        }

        (
            take_triple_latencies,
            triple_failures,
            take_presig_latencies,
            presig_failures,
        )
    }

    /// Concurrently peek and commit reservations in a proposer race.
    pub async fn race_proposals(
        self,
        barrier: Arc<Barrier>,
        base_id: u64,
        proposals_per_racer: usize,
    ) -> (Vec<Duration>, Vec<Duration>, Vec<Duration>) {
        barrier.wait().await;
        let mut peek_latencies = Vec::with_capacity(proposals_per_racer);
        let mut commit_win_latencies = Vec::with_capacity(proposals_per_racer);
        let mut commit_loss_latencies = Vec::new();

        let excluded: Vec<u64> = (0..5).map(|x| base_id + (x as u64)).collect();

        for _ in 0..proposals_per_racer {
            let t0 = Instant::now();
            let reservation = self.triples.peek_mine(&excluded).await;
            peek_latencies.push(t0.elapsed());

            let Some(reservation) = reservation else {
                continue;
            };
            let t1 = Instant::now();
            let taken = reservation.commit().await;
            if taken.is_some() {
                commit_win_latencies.push(t1.elapsed());
            } else {
                commit_loss_latencies.push(t1.elapsed());
                tracing::debug!(
                    "lost reservation race on commit, as expected in concurrent proposers"
                );
            }
        }

        (peek_latencies, commit_win_latencies, commit_loss_latencies)
    }

    /// Concurrently insert triples and track successful IDs vs failures (e.g. during client kill tests).
    pub async fn insert_triples_tracked(
        self,
        base_id: u64,
        count: usize,
        participants: Vec<Participant>,
        barrier: Arc<Barrier>,
    ) -> (Vec<Duration>, Vec<u64>, usize) {
        barrier.wait().await;
        let mut latencies = Vec::with_capacity(count);
        let mut success_ids = Vec::with_capacity(count);
        let mut failure_count = 0;

        for i in 0..count {
            let id = base_id + (i as u64);
            let pair = dummy_pair(id, &participants);

            let t0 = Instant::now();
            let success = match self.triples.create_slot(id, self.participant).await {
                Some(mut slot) => slot.insert(pair, self.participant).await,
                None => false,
            };

            if success {
                success_ids.push(id);
                latencies.push(t0.elapsed());
            } else {
                failure_count += 1;
            }
        }

        (latencies, success_ids, failure_count)
    }

    /// Concurrently peek available artifacts from a large stockpile with an exclusion list.
    pub async fn seek_deep_stockpile(
        self,
        barrier: Arc<Barrier>,
        base_id: u64,
        seeks_count: usize,
        exclusions_count: usize,
    ) -> (Vec<Duration>, Vec<Duration>, Vec<Duration>) {
        barrier.wait().await;
        let mut peek_latencies = Vec::with_capacity(seeks_count);
        let mut commit_win_latencies = Vec::with_capacity(seeks_count);
        let mut commit_loss_latencies = Vec::new();

        // Exclusion list covers the first `exclusions_count` IDs of the stockpile,
        // simulating accumulated rejected / timed-out IDs from prior reorg rounds.
        // This forces Lua's SMEMBERS to scan through the large exclusion set before
        // finding unexcluded items, reproducing near-exhaustion tail latency.
        let mut local_excluded: Vec<u64> = (0..exclusions_count)
            .map(|x| base_id + (x as u64))
            .collect();

        for _ in 0..seeks_count {
            let t0 = Instant::now();
            let reservation = self.triples.peek_mine(&local_excluded).await;
            peek_latencies.push(t0.elapsed());

            let Some(reservation) = reservation else {
                continue;
            };
            let id = reservation.id;
            let t1 = Instant::now();
            let taken = reservation.commit().await;
            if taken.is_some() {
                commit_win_latencies.push(t1.elapsed());
                local_excluded.push(id);
            } else {
                commit_loss_latencies.push(t1.elapsed());
                tracing::debug!("lost reservation race on commit in deep stockpile seek");
            }
        }

        (peek_latencies, commit_win_latencies, commit_loss_latencies)
    }

    /// Concurrently simulate proposer deliberation with partial timeout / reject drops.
    pub async fn run_proposer_churn(
        self,
        barrier: Arc<Barrier>,
        proposer_id: usize,
        rounds: usize,
        abort_percent: u8,
        deliberation_delay_ms: u64,
    ) -> (
        Vec<Duration>,
        Vec<Duration>,
        Vec<Duration>,
        Vec<Duration>,
        usize,
        usize,
    ) {
        barrier.wait().await;
        let mut peek_latencies = Vec::with_capacity(rounds);
        let mut commit_win_latencies = Vec::with_capacity(rounds);
        let mut commit_loss_latencies = Vec::new();
        let mut deliberation_latencies = Vec::with_capacity(rounds);
        let mut aborted_count = 0;
        let mut committed_count = 0;

        let mut local_excluded: Vec<u64> = Vec::new();

        for round_idx in 0..rounds {
            let t0 = Instant::now();
            let reservation = self.triples.peek_mine(&local_excluded).await;
            peek_latencies.push(t0.elapsed());

            let Some(reservation) = reservation else {
                continue;
            };

            if deliberation_delay_ms > 0 {
                let d0 = Instant::now();
                tokio::time::sleep(Duration::from_millis(deliberation_delay_ms)).await;
                deliberation_latencies.push(d0.elapsed());
            }

            let should_abort =
                ((proposer_id * 17 + round_idx * 31) % 100) < (abort_percent as usize);
            if should_abort {
                let id = reservation.id;
                // Dropping reservation aborts pending state without commit, returning item to Redis pool
                drop(reservation);
                local_excluded.push(id);
                aborted_count += 1;
            } else {
                let t1 = Instant::now();
                if reservation.commit().await.is_some() {
                    commit_win_latencies.push(t1.elapsed());
                    committed_count += 1;
                } else {
                    commit_loss_latencies.push(t1.elapsed());
                }
            }
        }

        (
            peek_latencies,
            commit_win_latencies,
            commit_loss_latencies,
            deliberation_latencies,
            aborted_count,
            committed_count,
        )
    }
}

/// Guard managing background polling tasks. Automatically stops and joins tasks on `.stop().await`.
pub struct BackgroundPollerGuard {
    pub(crate) stop_flag: Arc<AtomicBool>,
    pub(crate) handles: Vec<tokio::task::JoinHandle<()>>,
}

impl BackgroundPollerGuard {
    pub async fn stop(mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        let handles = std::mem::take(&mut self.handles);
        for h in handles {
            let _ = h.await;
        }
    }
}

impl Drop for BackgroundPollerGuard {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        for h in &self.handles {
            h.abort();
        }
    }
}

pub(crate) fn dummy_presignature(id: u64, participants: &[Participant]) -> Presignature {
    Presignature {
        id,
        output: PresignOutput {
            big_r: <Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            k: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
            sigma: <Secp256k1 as CurveArithmetic>::Scalar::ONE,
        },
        participants: participants.to_vec(),
        holders: Some(participants.to_vec()),
    }
}

pub(crate) fn dummy_pair(id: u64, participants: &[Participant]) -> TriplePair {
    TriplePair {
        id,
        triple0: dummy_triple(participants),
        triple1: dummy_triple(participants),
        holders: Some(participants.to_vec()),
    }
}

pub(crate) fn dummy_triple(participants: &[Participant]) -> Triple {
    Triple {
        share: TripleShare {
            a: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
            b: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
            c: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
        },
        public: TriplePub {
            big_a: <k256::Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            big_b: <k256::Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            big_c: <k256::Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            participants: participants.to_vec(),
            threshold: (participants.len() * 2 / 3).max(1),
        },
    }
}
