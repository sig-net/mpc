pub mod config;
pub mod diagnostics;
pub mod gate;
pub mod participant;
pub mod scenarios;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::Context as _;
use cait_sith::protocol::Participant;
use deadpool_redis::Pool;
use near_account_id::AccountId;

use crate::cluster::spawner::ClusterSpawner;
use crate::containers::Redis;
use diagnostics::print_summary_header;

pub use config::RedisHarnessConfig;
pub use diagnostics::{LatencySummary, MemorySnapshot, RedisDiagnosticsClient, SlowlogRecord};
pub use gate::StartingGate;
pub use participant::{BackgroundPollerGuard, SimulatedParticipant, ArtifactKind};

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
                .network(&config.docker_network)
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
            config.slowlog_threshold_us,
            config.slowlog_max_len,
        )
        .await?;

        let mut participants = Vec::with_capacity(config.num_participants);
        for i in 0..config.num_participants {
            let participant = Participant::from(i as u32);
            let account_id: AccountId = format!("node-{i}.testnet").parse().unwrap();
            participants.push(SimulatedParticipant::new(
                client.pool(),
                &account_id,
                participant,
            ));
        }

        Ok(Self {
            redis,
            redis_url,
            client,
            participants,
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
        self.config.flush_between = flush;
    }

    /// Whether FLUSHDB runs between benchmark scenarios.
    pub fn flush_between(&self) -> bool {
        self.config.flush_between
    }

    /// Clear all triples storage across all participants concurrently.
    pub async fn clear_triples(&self) {
        futures::future::join_all(self.participants.iter().map(|p| p.triples.clear())).await;
    }

    /// Reset slowlog (and optionally FLUSHDB if flush_between is enabled)
    /// before running a test case, logging the pre-run keyspace and memory state.
    pub async fn reset_diagnostics(&self) -> anyhow::Result<()> {
        if self.config.flush_between {
            self.client.flush_db().await?;
        }
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
        kind: ArtifactKind,
        participant_idx: usize,
        base_id: u64,
        count: usize,
    ) -> anyhow::Result<Vec<u64>> {
        anyhow::ensure!(
            participant_idx < self.participants.len(),
            "invalid participant index {participant_idx} (total participants: {})",
            self.participants.len()
        );
        let p = self.participants[participant_idx].clone();
        let p_list = self.participant_ids();
        p.populate(kind, base_id, count, p_list).await
    }

    /// Populate `count` items (triples or presignatures) across all participants concurrently.
    /// Returns the list of generated IDs grouped by participant index.
    pub async fn populate_all(
        &self,
        kind: ArtifactKind,
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
                tokio::spawn(p.clone().populate(kind, p_base, count, p_list.clone()))
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
        self.populate_all(ArtifactKind::Triples, base_id, count).await
    }

    /// Convenience alias to populate presignatures on all participants concurrently.
    pub async fn populate_all_presignatures(
        &self,
        base_id: u64,
        count: usize,
    ) -> anyhow::Result<Vec<Vec<u64>>> {
        self.populate_all(ArtifactKind::Presignatures, base_id, count).await
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
