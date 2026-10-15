pub mod config;
pub mod diagnostics;
pub mod participant;
pub mod scenarios;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::Context as _;
use cait_sith::protocol::Participant;
pub use deadpool_redis::redis;
use deadpool_redis::Pool;
use mpc_node::protocol::presignature::Presignature;
use mpc_node::storage::triple_storage::TriplePair;
use near_account_id::AccountId;

use crate::cluster::spawner::ClusterSpawner;
use crate::containers::Redis;

pub use config::RedisHarnessConfig;
pub use diagnostics::{
    partition_wall_3, partition_wall_by_active_time, print_summary_header, LatencySummary,
    MemorySnapshot, RedisDiagnostics, RedisDiagnosticsClient, SlowlogRecord,
};
pub use participant::{
    dummy_pair, dummy_presignature, dummy_triple, next_id_block, BackgroundPollerGuard,
    SimulatedParticipant, StockpileKind,
};

/// Standalone Redis benchmark harness.
///
/// Spawns ONLY an isolated Redis container (zero MPC node processes, zero NEAR
/// sandbox, zero smart contracts, and zero external chains).
/// Interfaces with Redis purely through `redis.triple_storage(...)` and `redis.presignature_storage(...)`.
pub struct RedisHarness {
    pub redis: Option<Redis>,
    pub redis_url: String,
    pub client: RedisDiagnosticsClient,
    pub participants: Vec<SimulatedParticipant>,
    pub flush_between: bool,
    pub config: RedisHarnessConfig,
}

impl RedisHarness {
    /// Initialize the Redis benchmark harness from a `RedisHarnessConfig`.
    ///
    /// If `config.redis_url` is specified, connects to that instance;
    /// otherwise, automatically spins up an ephemeral isolated Docker Redis container.
    /// All participants strictly share the single configured connection pool.
    pub async fn new(config: RedisHarnessConfig) -> anyhow::Result<Self> {
        let (redis, redis_url) = if let Some(ref url) = config.redis_url {
            (None, url.clone())
        } else {
            let spawner = ClusterSpawner::default()
                .network("bench-redis-harness")
                .init_network()
                .await
                .context("failed to init docker network")?;
            let container = crate::containers::Redis::run(&spawner).await;
            let url = container.internal_address.clone();
            (Some(container), url)
        };

        let client = RedisDiagnosticsClient::new(
            &redis_url,
            config.max_pool_size,
            config.pool_timeout,
        )
        .await?;

        let mut participants = Vec::with_capacity(config.num_participants);
        for i in 0..config.num_participants {
            let participant = Participant::from(i as u32);
            let account_id: AccountId = format!("node-{i}.testnet").parse().unwrap();

            // All participants strictly share the harness pool
            let triples = TriplePair::storage(&client.pool, &account_id);
            triples.set_me(participant);
            let presignatures = Presignature::storage(&client.pool, &account_id);
            presignatures.set_me(participant);

            participants.push(SimulatedParticipant {
                participant,
                account_id,
                triples,
                presignatures,
            });
        }

        Ok(Self {
            redis,
            redis_url,
            client,
            participants,
            flush_between: config.flush_between,
            config,
        })
    }

    /// Access the underlying connection pool.
    pub fn pool(&self) -> &Pool {
        self.client.pool()
    }

    pub fn participant_ids(&self) -> Vec<Participant> {
        self.participants.iter().map(|p| p.participant).collect()
    }

    /// Enable or disable FLUSHDB between benchmark scenarios (default: true).
    pub fn set_flush_between(&mut self, flush: bool) {
        self.flush_between = flush;
        self.config.flush_between = flush;
    }

    /// Clear all in-memory reservations across all participants' storage handles.
    pub async fn reset_reservations(&self) {
        for p in &self.participants {
            p.reset_reservations().await;
        }
    }

    /// Reset slowlog, clear in-memory reservations (and optionally FLUSHDB if flush_between is enabled)
    /// before running a test case, logging the pre-run keyspace and memory state.
    pub async fn reset_diagnostics(&self) -> anyhow::Result<()> {
        if self.flush_between {
            self.client.flush_db().await?;
        }
        self.reset_reservations().await;
        self.client.reset_slowlog().await?;
        let mem = self.client.fetch_memory_snapshot().await?;
        println!(
            "   -> Keyspace pre-run: {} keys in Redis (DBSIZE), Memory: {}",
            mem.total_keys, mem.used_memory_human
        );
        Ok(())
    }

    /// Helper to print scenario summary table and diagnostics.
    pub async fn report_results(&self, results: &[LatencySummary]) -> anyhow::Result<()> {
        print_summary_header();
        for r in results {
            r.print_row();
        }
        self.client.print_diagnostics().await
    }

    /// Populate `count` items (triples or presignatures) for a single participant.
    pub async fn populate(
        &self,
        kind: StockpileKind,
        participant_idx: usize,
        base_id: u64,
        count: usize,
    ) -> anyhow::Result<Vec<u64>> {
        anyhow::ensure!(
            participant_idx < self.participants.len(),
            "invalid participant index {participant_idx} (total participants: {})",
            self.participants.len()
        );
        let p = &self.participants[participant_idx];
        let p_list = self.participant_ids();
        p.populate(kind, base_id, count, &p_list).await
    }

    /// Populate `count` items (triples or presignatures) across all participants concurrently.
    /// Returns the list of generated IDs grouped by participant index.
    pub async fn populate_all(
        &self,
        kind: StockpileKind,
        base_id: u64,
        count: usize,
    ) -> anyhow::Result<Vec<Vec<u64>>> {
        let p_list = self.participant_ids();
        let handles: Vec<_> = self
            .participants
            .iter()
            .enumerate()
            .map(|(idx, p)| {
                let p_base = base_id + (idx as u64 * count as u64);
                let p = p.clone();
                let p_list = p_list.clone();
                tokio::spawn(async move { p.populate(kind, p_base, count, &p_list).await })
            })
            .collect();

        let mut results = Vec::with_capacity(handles.len());
        for h in handles {
            results.push(h.await.context("participant populate task panicked")??);
        }
        Ok(results)
    }

    /// Convenience alias to populate triples on all participants concurrently.
    pub async fn populate_all_triples(
        &self,
        base_id: u64,
        count: usize,
    ) -> anyhow::Result<Vec<Vec<u64>>> {
        self.populate_all(StockpileKind::Triples, base_id, count).await
    }

    /// Convenience alias to populate presignatures on all participants concurrently.
    pub async fn populate_all_presignatures(
        &self,
        base_id: u64,
        count: usize,
    ) -> anyhow::Result<Vec<Vec<u64>>> {
        self.populate_all(StockpileKind::Presignatures, base_id, count).await
    }

    /// Spawn 100ms background stockpile polling loop across all participants.
    pub fn spawn_background_polling(&self, include_presignatures: bool) -> BackgroundPollerGuard {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let handles = self
            .participants
            .iter()
            .map(|p| {
                tokio::spawn(
                    p.clone()
                        .run_polling_loop(stop_flag.clone(), include_presignatures),
                )
            })
            .collect();

        BackgroundPollerGuard { stop_flag, handles }
    }
}
