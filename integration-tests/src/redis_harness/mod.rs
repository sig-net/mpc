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
    SimulatedParticipant,
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

    async fn populate_all<F, Fut>(
        &self,
        base_id: u64,
        count: usize,
        f: F,
    ) -> anyhow::Result<Vec<Vec<u64>>>
    where
        F: Fn(SimulatedParticipant, u64, usize, Vec<Participant>) -> Fut,
        Fut: std::future::Future<Output = Vec<u64>> + Send + 'static,
    {
        let participant_list = self.participant_ids();
        let handles: Vec<_> = self
            .participants
            .iter()
            .enumerate()
            .map(|(idx, p)| {
                let p_base = base_id + (idx as u64 * count as u64);
                tokio::spawn(f(p.clone(), p_base, count, participant_list.clone()))
            })
            .collect();

        let mut results = Vec::with_capacity(handles.len());
        for h in handles {
            results.push(h.await.context("participant populate task failed or panicked")?);
        }
        Ok(results)
    }

    /// Populate `count` triples on all participants concurrently.
    /// Returns the list of generated triple IDs grouped by participant index.
    pub async fn populate_all_triples(
        &self,
        base_id: u64,
        count: usize,
    ) -> anyhow::Result<Vec<Vec<u64>>> {
        self.populate_all(base_id, count, SimulatedParticipant::populate_triples)
            .await
    }

    /// Populate `count` presignatures on all participants concurrently.
    /// Returns the list of generated presignature IDs grouped by participant index.
    pub async fn populate_all_presignatures(
        &self,
        base_id: u64,
        count: usize,
    ) -> anyhow::Result<Vec<Vec<u64>>> {
        self.populate_all(base_id, count, SimulatedParticipant::populate_presignatures)
            .await
    }

    /// Populate `count` triples for a single participant concurrently across worker tasks.
    pub async fn populate_triples_parallel(
        &self,
        participant: &SimulatedParticipant,
        base_id: u64,
        count: usize,
    ) -> anyhow::Result<Vec<u64>> {
        let num_workers = 8.min(count);
        let chunk_size = count.div_ceil(num_workers);
        let participant_list = self.participant_ids();

        let mut handles = Vec::with_capacity(num_workers);
        for w in 0..num_workers {
            let start = w * chunk_size;
            let end = (start + chunk_size).min(count);
            if start >= end {
                continue;
            }
            let chunk_count = end - start;
            let p_base = base_id + start as u64;
            let p = participant.clone();
            let p_list = participant_list.clone();

            handles.push(tokio::spawn(async move {
                let mut ids = Vec::with_capacity(chunk_count);
                for i in 0..chunk_count {
                    let id = p_base + i as u64;
                    let pair = dummy_pair(id, &p_list);
                    let Some(mut slot) = p.triples.create_slot(id, p.participant).await else {
                        continue;
                    };
                    if slot.insert(pair, p.participant).await {
                        ids.push(id);
                    }
                }
                ids
            }));
        }

        let mut all_ids = Vec::with_capacity(count);
        for h in handles {
            let ids = h.await.context("parallel populate task failed")?;
            all_ids.extend(ids);
        }
        all_ids.sort_unstable();
        anyhow::ensure!(
            all_ids.len() == count,
            "failed to populate expected triples: requested {}, got {}",
            count,
            all_ids.len()
        );
        Ok(all_ids)
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
