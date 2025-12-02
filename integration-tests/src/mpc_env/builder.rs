use crate::mpc_env::config::MpcEnvConfig;

/// Fluent builder for MpcEnv. For Phase 1 it's intentionally minimal — it
/// records desired features and will later construct the full environment.
// Not deriving Debug/Clone because builder contains boxed closures which
// are neither Debug nor Clone.
pub struct MpcEnvBuilder {
    pub config: MpcEnvConfig,
    /// non-cloneable filters stored here (closures) — applied only during build
    pub message_filters: Vec<(usize, crate::mpc_fixture::fixture_tasks::MessageFilter)>,
}

impl MpcEnvBuilder {
    pub fn new(nodes: usize, threshold: usize) -> Self {
        let mut cfg = MpcEnvConfig::default();
        cfg.nodes = nodes;
        cfg.threshold = threshold;
        Self { config: cfg, message_filters: Vec::new() }
    }

    pub fn enable_real_nodes(mut self) -> Self {
        self.config.enable_real_nodes = true;
        self
    }

    pub fn enable_near_sandbox(mut self) -> Self {
        self.config.enable_near_sandbox = true;
        self
    }

    /// Use preset fixture triples in the in-process setup
    pub fn with_preshared_triples(mut self) -> Self {
        self.config.use_preshared_triples = true;
        self
    }

    /// Configure using a preshared key set (skip key generation)
    pub fn with_preshared_key(mut self) -> Self {
        self.config.use_preshared_key = true;
        self
    }

    /// Attach a message filter for a specific node (only for in-process fixtures)
    pub fn with_outgoing_message_filter(
        mut self,
        node_idx: usize,
        filter: crate::mpc_fixture::fixture_tasks::MessageFilter,
    ) -> Self {
        self.message_filters.push((node_idx, filter));
        self
    }

    /// Stockpile presignatures from fixture inputs
    pub fn with_presignature_stockpile(mut self) -> Self {
        self.config.presignature_stockpile = true;
        self
    }

    pub fn with_min_triples_stockpile(mut self, value: u32) -> Self {
        self.config.min_triples = value;
        self
    }

    pub fn with_max_triples_stockpile(mut self, value: u32) -> Self {
        self.config.max_triples = value;
        self
    }

    pub fn with_min_presignatures_stockpile(mut self, value: u32) -> Self {
        self.config.min_presignatures = value;
        self
    }

    pub fn with_max_presignatures_stockpile(mut self, value: u32) -> Self {
        self.config.max_presignatures = value;
        self
    }

    pub fn with_signature_timeout_ms(mut self, ms: u64) -> Self {
        self.config.signature_timeout_ms = ms;
        self
    }

    pub fn with_presignature_timeout_ms(mut self, ms: u64) -> Self {
        self.config.presignature_timeout_ms = ms;
        self
    }

    pub fn with_triple_timeout_ms(mut self, ms: u64) -> Self {
        self.config.triple_timeout_ms = ms;
        self
    }

    /// Convenience: generate only triples (skip presignatures and signatures)
    pub fn only_generate_triples(self) -> Self {
        self.with_preshared_key()
            .with_min_presignatures_stockpile(0)
            .with_max_presignatures_stockpile(0)
    }

    /// Convenience: generate only presignatures (skip triple stockpiling)
    pub fn only_generate_presignatures(self) -> Self {
        self.with_preshared_key()
            .with_preshared_triples()
            .with_min_triples_stockpile(0)
            .with_max_triples_stockpile(0)
    }

    /// Convenience: generate only signatures (skip triple and presignature stockpiles)
    pub fn only_generate_signatures(self) -> Self {
        self.with_preshared_key()
            .with_presignature_stockpile()
            .with_min_triples_stockpile(0)
            .with_max_triples_stockpile(0)
            .with_min_presignatures_stockpile(0)
            .with_max_presignatures_stockpile(0)
    }

    /// Build the environment. In phase 1 this is a placeholder which will be
    /// expanded in later phases.
    pub async fn build(self) -> anyhow::Result<crate::mpc_env::MpcEnv> {
        // If disable_real_nodes, construct an in-process MpcFixture and attach
        // it to the environment. This delegates to the existing fixture
        // implementation.
        if !self.config.enable_real_nodes {
            // Build the in-process fixture using the existing builder
            let nodes = self.config.nodes as u32;
            let threshold = self.config.threshold;

            let mut fixture_builder = crate::mpc_fixture::MpcFixtureBuilder::new(nodes, threshold);

            if self.config.use_preshared_key {
                fixture_builder = fixture_builder.with_preshared_key();
            }

            if self.config.use_preshared_triples {
                fixture_builder = fixture_builder.with_preshared_triples();
            }

            if self.config.presignature_stockpile {
                fixture_builder = fixture_builder.with_presignature_stockpile();
            }

            fixture_builder = fixture_builder
                .with_min_triples_stockpile(self.config.min_triples)
                .with_max_triples_stockpile(self.config.max_triples)
                .with_min_presignatures_stockpile(self.config.min_presignatures)
                .with_max_presignatures_stockpile(self.config.max_presignatures)
                .with_signature_timeout_ms(self.config.signature_timeout_ms)
                .with_presignature_timeout_ms(self.config.presignature_timeout_ms)
                .with_triple_timeout_ms(self.config.triple_timeout_ms);

            // Apply outgoing message filters (if any)
            for (idx, filter) in self.message_filters.into_iter() {
                fixture_builder = fixture_builder.with_outgoing_message_filter(idx, filter);
            }

            let fixture = fixture_builder.build().await;

            return Ok(crate::mpc_env::MpcEnv {
                config: self.config,
                fixture: Some(fixture),
                cluster: None,
            });
        }

        // If requested, use the existing ClusterSpawner to build a fully-fledged
        // cluster (with real nodes). We use its IntoFuture implementation so
        // we can reuse existing setup logic and keep incremental changes for
        // later phases.
        if self.config.enable_real_nodes {
            // Build a cluster via the existing public spawn() API, adjusting
            // nodes and threshold.
            let spawner = crate::cluster::spawn()
                .nodes(self.config.nodes)
                .threshold(self.config.threshold);

            // ClusterSpawner implements IntoFuture so awaiting it resolves to
            // a Cluster instance.
            let cluster = spawner.await?;

            return Ok(crate::mpc_env::MpcEnv {
                config: self.config,
                fixture: None,
                cluster: Some(cluster),
            });
        }

        Ok(crate::mpc_env::MpcEnv {
            config: self.config,
            fixture: None,
            cluster: None,
        })
    }
}

impl Default for MpcEnvBuilder {
    fn default() -> Self {
        Self::new(3, 2)
    }
}
